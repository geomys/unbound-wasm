package unbound

// The replay harness: a replayHooks implementation that gives an Instance a
// virtual clock, virtual timers, and a scripted network of authoritative
// servers built from testZone trees. Everything runs on the calling
// goroutine: replies are pushed synchronously from the send hook, so
// resolutions are deterministic and never touch the real network or clock.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// A parsedQuery is one query received by the scripted authority.
type parsedQuery struct {
	id          uint16
	flags       uint16
	rawQuestion []byte // qname (original 0x20 case) + qtype + qclass
	qname       string // lowercase FQDN
	qtype       uint16
	qclass      uint16
	hasEDNS     bool
	do          bool
	tcp         bool
	server      netip.Addr
}

// A response is the structured reply the authority builds before encoding.
type response struct {
	rcode      int
	authAnswer bool
	answer     []zoneRR
	authority  []zoneRR
	additional []zoneRR
}

// A delivery is one packet the authority hands back, with an optional source
// address override (an invalid addr means the queried server itself).
type delivery struct {
	pkt  []byte
	from netip.Addr
}

// A testAuthority serves a set of zones, one server address per zone.
type testAuthority struct {
	t     *testing.T
	zones map[netip.Addr]*testZone
	// intercept, if set, runs on every query after the default reply is
	// built. The returned deliveries replace the default one; nil or
	// empty means drop the query.
	intercept func(q parsedQuery, reply []byte) []delivery
	queries   []parsedQuery // every query received, in order
}

func newTestAuthority(t *testing.T, root *testZone) *testAuthority {
	a := &testAuthority{t: t, zones: make(map[netip.Addr]*testZone)}
	var walk func(*testZone)
	walk = func(z *testZone) {
		if z.addr.IsValid() {
			a.zones[z.addr] = z
		}
		for _, c := range z.children {
			walk(c)
		}
	}
	walk(root)
	return a
}

// handle parses one query packet and returns the deliveries to make.
func (a *testAuthority) handle(server netip.AddrPort, pkt []byte, tcp bool) []delivery {
	q, err := parseQuery(pkt)
	if err != nil {
		a.t.Errorf("authority %v received bad query: %v", server, err)
		return nil
	}
	q.tcp = tcp
	q.server = server.Addr()
	a.queries = append(a.queries, q)
	z := a.zones[server.Addr()]
	if z == nil {
		a.t.Errorf("query for unknown server %v: %s %d", server, q.qname, q.qtype)
		return nil
	}
	resp := answerZone(z, q.qname, q.qtype)
	a.t.Logf("authority %s (%s): %s %d %s→ rcode %d, %d an, %d ns, %d ar",
		server.Addr(), z.name, q.qname, q.qtype, map[bool]string{true: "tcp ", false: ""}[tcp],
		resp.rcode, len(resp.answer), len(resp.authority), len(resp.additional))
	reply := encodeReply(q, resp)
	if a.intercept != nil {
		return a.intercept(q, reply)
	}
	return []delivery{{pkt: reply}}
}

// answerZone implements a minimal authoritative server for one zone.
func answerZone(z *testZone, qname string, qtype uint16) response {
	// The parent answers DS queries at a delegation point itself (RFC
	// 4035, Section 3.1.4.1); everything else at or below a cut is
	// referred.
	if cut, ok := z.zoneCut(qname); ok && !(qtype == typeDS && z.isDelegation(qname)) {
		return referral(z, cut)
	}
	resp := response{authAnswer: true}
	name := qname
	for range 8 { // in-zone CNAME chain limit
		if set := lookupSet(z, name, typeCNAME); set != nil && qtype != typeCNAME {
			resp.answer = append(resp.answer, withSigs(z, set)...)
			target := nameString(set[0].data)
			if _, below := z.zoneCut(target); below || !inZone(z, target) {
				return resp
			}
			name = target
			continue
		}
		break
	}
	if set := lookupSet(z, name, qtype); set != nil {
		resp.answer = append(resp.answer, withSigs(z, set)...)
		// Glue: in-zone addresses of any NS targets in the answer,
		// like a real authoritative server's additional section.
		if qtype == typeNS {
			for _, rr := range set {
				if a := lookupSet(z, nameString(rr.data), TypeA); a != nil {
					resp.additional = append(resp.additional, withSigs(z, a)...)
				}
			}
		}
		return resp
	}
	// NODATA or NXDOMAIN, with denial proofs when signed.
	resp.authority = withSigs(z, lookupSet(z, z.name, typeSOA))
	if hasName(z, name) {
		if nsec := lookupSet(z, name, typeNSEC); nsec != nil {
			resp.authority = append(resp.authority, withSigs(z, nsec)...)
		}
		return resp
	}
	resp.rcode = 3 // NXDOMAIN
	if !z.unsigned {
		proofs := map[string]bool{}
		addNSEC := func(covering string) {
			if rr := nsecCovering(z, covering); rr != nil && !proofs[rr.owner] {
				proofs[rr.owner] = true
				resp.authority = append(resp.authority, withSigs(z, []zoneRR{*rr})...)
			}
		}
		addNSEC(name)
		addNSEC("*." + closestEncloser(z, name))
	}
	return resp
}

func referral(z *testZone, cut string) response {
	resp := response{}
	resp.authority = append(resp.authority, lookupSet(z, cut, typeNS)...)
	if !z.unsigned {
		if ds := lookupSet(z, cut, typeDS); ds != nil {
			resp.authority = append(resp.authority, withSigs(z, ds)...)
		} else if nsec := lookupSet(z, cut, typeNSEC); nsec != nil {
			// Signed proof that the delegation has no DS.
			resp.authority = append(resp.authority, withSigs(z, nsec)...)
		}
	}
	for _, c := range z.children {
		if c.name == cut {
			resp.additional = append(resp.additional, lookupIn(c.rrs, c.nsOwner(), TypeA)...)
		}
	}
	return resp
}

func lookupSet(z *testZone, owner string, typ uint16) []zoneRR {
	rrs := z.signed
	if rrs == nil {
		rrs = z.rrs
	}
	return lookupIn(rrs, owner, typ)
}

func lookupIn(rrs []zoneRR, owner string, typ uint16) []zoneRR {
	var out []zoneRR
	for _, rr := range rrs {
		if rr.owner == owner && rr.typ == typ {
			out = append(out, rr)
		}
	}
	return out
}

// withSigs appends the RRSIGs covering the set's owner and type.
func withSigs(z *testZone, set []zoneRR) []zoneRR {
	if len(set) == 0 || z.unsigned {
		return set
	}
	out := append([]zoneRR(nil), set...)
	for _, rr := range z.signed {
		if rr.typ == typeRRSIG && rr.owner == set[0].owner &&
			binary.BigEndian.Uint16(rr.data[0:2]) == set[0].typ {
			out = append(out, rr)
		}
	}
	return out
}

func hasName(z *testZone, name string) bool {
	rrs := z.signed
	if rrs == nil {
		rrs = z.rrs
	}
	for _, rr := range rrs {
		if rr.owner == name {
			return true
		}
	}
	return false
}

func inZone(z *testZone, name string) bool {
	return name == z.name || z.name == "." || strings.HasSuffix(name, "."+z.name)
}

// closestEncloser returns the longest existing ancestor of name in z.
func closestEncloser(z *testZone, name string) string {
	for {
		i := strings.IndexByte(name, '.')
		if i < 0 || i == len(name)-1 {
			return z.name
		}
		name = name[i+1:]
		if hasName(z, name) {
			return name
		}
	}
}

// nsecCovering returns the NSEC record whose interval covers name.
func nsecCovering(z *testZone, name string) *zoneRR {
	for i, rr := range z.signed {
		if rr.typ != typeNSEC {
			continue
		}
		next := nameString(rr.data)
		if nsecCovers(rr.owner, next, name) {
			return &z.signed[i]
		}
	}
	return nil
}

func nsecCovers(owner, next, name string) bool {
	if owner == name {
		return false
	}
	if canonicalLess(owner, next) {
		return canonicalLess(owner, name) && canonicalLess(name, next)
	}
	// owner is the canonically last name; the interval wraps to the apex.
	return canonicalLess(owner, name) || canonicalLess(name, next)
}

// parseQuery decodes the fields of a query packet the authority needs.
func parseQuery(pkt []byte) (parsedQuery, error) {
	var q parsedQuery
	if len(pkt) < 12 {
		return q, fmt.Errorf("short packet (%d bytes)", len(pkt))
	}
	q.id = binary.BigEndian.Uint16(pkt[0:2])
	q.flags = binary.BigEndian.Uint16(pkt[2:4])
	if q.flags&0x8000 != 0 {
		return q, fmt.Errorf("QR set in query")
	}
	if qd := binary.BigEndian.Uint16(pkt[4:6]); qd != 1 {
		return q, fmt.Errorf("qdcount %d", qd)
	}
	off := 12
	start := off
	for {
		if off >= len(pkt) {
			return q, fmt.Errorf("truncated qname")
		}
		l := int(pkt[off])
		if l == 0 {
			off++
			break
		}
		if l > 63 {
			return q, fmt.Errorf("compressed or bad qname label")
		}
		off += 1 + l
	}
	if off+4 > len(pkt) {
		return q, fmt.Errorf("truncated question")
	}
	q.rawQuestion = append([]byte(nil), pkt[start:off+4]...)
	q.qname = nameString(pkt[start:off])
	q.qtype = binary.BigEndian.Uint16(pkt[off : off+2])
	q.qclass = binary.BigEndian.Uint16(pkt[off+2 : off+4])
	off += 4
	// A lone OPT record in the additional section is the only other
	// content the resolver sends.
	arcount := binary.BigEndian.Uint16(pkt[10:12])
	if arcount > 0 && off+11 <= len(pkt) && pkt[off] == 0 &&
		binary.BigEndian.Uint16(pkt[off+1:off+3]) == typeOPT {
		q.hasEDNS = true
		ttl := binary.BigEndian.Uint32(pkt[off+5 : off+9])
		q.do = ttl&0x8000 != 0
	}
	return q, nil
}

// nameString renders a wire name (uncompressed) as a lowercase FQDN.
func nameString(b []byte) string {
	if len(b) > 0 && b[0] == 0 {
		return "."
	}
	var sb strings.Builder
	for i := 0; i < len(b) && b[i] != 0; {
		l := int(b[i])
		i++
		sb.Write(b[i : i+l])
		sb.WriteByte('.')
		i += l
	}
	return strings.ToLower(sb.String())
}

// encodeReply builds the wire reply: header, echoed question, sections, and
// an OPT record mirroring the query's EDNS. Names are not compressed.
func encodeReply(q parsedQuery, resp response) []byte {
	flags := uint16(0x8000)          // QR
	flags |= q.flags & 0x0100        // echo RD
	flags |= uint16(resp.rcode) & 15 // rcode
	if resp.authAnswer {
		flags |= 0x0400 // AA
	}
	arcount := len(resp.additional)
	if q.hasEDNS {
		arcount++
	}
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[0:], q.id)
	binary.BigEndian.PutUint16(pkt[2:], flags)
	binary.BigEndian.PutUint16(pkt[4:], 1)
	binary.BigEndian.PutUint16(pkt[6:], uint16(len(resp.answer)))
	binary.BigEndian.PutUint16(pkt[8:], uint16(len(resp.authority)))
	binary.BigEndian.PutUint16(pkt[10:], uint16(arcount))
	pkt = append(pkt, q.rawQuestion...)
	appendRR := func(rr zoneRR) {
		pkt = append(pkt, packName(rr.owner)...)
		var fixed [10]byte
		binary.BigEndian.PutUint16(fixed[0:], rr.typ)
		binary.BigEndian.PutUint16(fixed[2:], 1) // IN
		binary.BigEndian.PutUint32(fixed[4:], rr.ttl)
		binary.BigEndian.PutUint16(fixed[8:], uint16(len(rr.data)))
		pkt = append(pkt, fixed[:]...)
		pkt = append(pkt, rr.data...)
	}
	for _, rr := range resp.answer {
		appendRR(rr)
	}
	for _, rr := range resp.authority {
		appendRR(rr)
	}
	for _, rr := range resp.additional {
		appendRR(rr)
	}
	if q.hasEDNS {
		var ttl uint32
		if q.do {
			ttl = 0x8000
		}
		pkt = append(pkt, 0) // root name
		var opt [8]byte
		binary.BigEndian.PutUint16(opt[0:], typeOPT)
		binary.BigEndian.PutUint16(opt[2:], 1232) // payload size
		binary.BigEndian.PutUint32(opt[4:], ttl)
		pkt = append(pkt, opt[:]...)
		pkt = append(pkt, 0, 0) // rdlength
	}
	return pkt
}

// replayNet implements replayHooks. The network side always runs on the
// goroutine driving the guest (hooks are called synchronously from guest
// exports). Timers come in two modes: virtual timers fired explicitly by
// resolveDriven, or — when realTime is set, for tests that go through
// Instance.Resolve — real timers on the wall clock, which need the mutex
// because they fire on their own goroutines.
type replayNet struct {
	t        *testing.T
	auth     *testAuthority
	elapsed  time.Duration
	realTime bool
	start    time.Time
	mu       sync.Mutex
	timers   map[uint64]*replayTimer
	real     map[uint64]*time.Timer
	nextTID  uint64
	tcpBufs  map[int32][]byte // per-socket inbound TCP stream reassembly
}

type replayTimer struct {
	deadline time.Duration
	state    *instanceState
}

func newReplayNet(t *testing.T, auth *testAuthority) *replayNet {
	return &replayNet{t: t, auth: auth, start: time.Now(),
		timers:  make(map[uint64]*replayTimer),
		real:    make(map[uint64]*time.Timer),
		tcpBufs: make(map[int32][]byte)}
}

func (r *replayNet) nowWall() time.Time {
	if r.realTime {
		return time.Now()
	}
	return sigBase.Add(r.elapsed)
}

func (r *replayNet) nowMono() time.Duration {
	if r.realTime {
		return time.Since(r.start)
	}
	return r.elapsed
}

func (r *replayNet) localPort(sock *hostSocket) int32 {
	if sock.bindPort != 0 {
		return int32(sock.bindPort)
	}
	return 30000 + sock.id
}

func (r *replayNet) timerStart(s *instanceState, ms int32) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextTID++
	tid := r.nextTID
	if r.realTime {
		r.real[tid] = time.AfterFunc(time.Duration(ms)*time.Millisecond, func() {
			r.mu.Lock()
			delete(r.real, tid)
			r.mu.Unlock()
			s.enqueue(hostEvent{kind: eventTimer, tid: tid})
		})
		return tid
	}
	r.timers[tid] = &replayTimer{deadline: r.elapsed + time.Duration(ms)*time.Millisecond, state: s}
	return tid
}

func (r *replayNet) timerStop(tid uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t := r.real[tid]; t != nil {
		t.Stop()
		delete(r.real, tid)
	}
	delete(r.timers, tid)
}

func (r *replayNet) connect(s *instanceState, sock *hostSocket, remote netip.AddrPort) int32 {
	sock.mu.Lock()
	sock.remote = remote
	sock.mu.Unlock()
	s.enqueue(hostEvent{kind: eventIO, sid: sock.id, flags: ioWrite})
	return 0
}

func (r *replayNet) sendTo(s *instanceState, sock *hostSocket, remote netip.AddrPort, data []byte) int32 {
	deliver := func(d delivery, tcp bool) {
		from := remote
		if d.from.IsValid() {
			from = netip.AddrPortFrom(d.from, remote.Port())
		}
		pkt := d.pkt
		if tcp {
			pkt = append(binary.BigEndian.AppendUint16(nil, uint16(len(pkt))), pkt...)
		}
		sock.push(pkt, from)
	}
	if sock.typ == socketTCP {
		buf := append(r.tcpBufs[sock.id], data...)
		for len(buf) >= 2 {
			n := int(binary.BigEndian.Uint16(buf))
			if len(buf) < 2+n {
				break
			}
			frame := buf[2 : 2+n]
			buf = buf[2+n:]
			for _, d := range r.auth.handle(remote, frame, true) {
				deliver(d, true)
			}
		}
		r.tcpBufs[sock.id] = buf
		return int32(len(data))
	}
	for _, d := range r.auth.handle(remote, data, false) {
		deliver(d, false)
	}
	return int32(len(data))
}

// fireNext advances the virtual clock to the earliest pending timer and
// fires it. It reports whether a timer existed.
func (r *replayNet) fireNext() bool {
	r.mu.Lock()
	var best uint64
	for tid, t := range r.timers {
		if best == 0 || t.deadline < r.timers[best].deadline ||
			(t.deadline == r.timers[best].deadline && tid < best) {
			best = tid
		}
	}
	if best == 0 {
		r.mu.Unlock()
		return false
	}
	t := r.timers[best]
	delete(r.timers, best)
	if t.deadline > r.elapsed {
		r.elapsed = t.deadline
	}
	r.mu.Unlock()
	t.state.enqueue(hostEvent{kind: eventTimer, tid: best})
	return true
}

// resolveDriven mirrors Instance.Resolve, but drives the event pump manually:
// when the guest is idle with no deliverable events, the earliest virtual
// timer fires. Resolutions that depend on timeouts stay fast and
// deterministic.
func resolveDriven(t *testing.T, net *replayNet, inst *Instance, name string, qtype uint16) (*Result, error) {
	t.Helper()
	ctx := context.Background()
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	p, err := inst.allocWrite(ctx, []byte(name))
	if err != nil {
		t.Fatal(err)
	}
	const classIN = 1
	out, err := inst.resolveStart.Call(ctx, uint64(p), uint64(len(name)), uint64(qtype), classIN)
	inst.free(ctx, p, uint32(len(name)))
	if err != nil {
		t.Fatal(err)
	}
	rid := int32(uint32(out[0]))
	if rid < 0 {
		t.Fatalf("resolve_start: errno %d", -rid)
	}
	defer inst.cancel(ctx, rid)
	for range 10000 {
		res, ready, err := inst.pollResult(ctx, rid, name, qtype)
		if err != nil {
			return nil, err
		}
		if ready {
			return res, nil
		}
		select {
		case ev, ok := <-inst.state.events:
			if !ok {
				t.Fatal("instance closed mid-resolution")
			}
			if err := inst.dispatch(ctx, ev); err != nil {
				return nil, err
			}
		default:
			if !net.fireNext() {
				t.Fatal("resolution stalled: no events and no pending timers")
			}
		}
	}
	t.Fatal("resolution did not converge")
	return nil, nil
}

// sortStrings is a tiny helper for stable assertions on answer sets.
func sortStrings(s []string) []string { sort.Strings(s); return s }
