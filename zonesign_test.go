package unbound

// Test-only DNSSEC zone construction: testZone builds a tree of authoritative
// zones, delegates between them, and signs every RRset with real keys through
// crypto/ecdsa, crypto/ed25519, or crypto/rsa, so resolutions in the replay
// harness exercise the host crypto provider end to end. Wire encoding is
// hand-rolled (no compression) because signing needs canonical RDATA anyway.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	typeNS     = 2
	typeCNAME  = 5
	typeSOA    = 6
	typeOPT    = 41
	typeDS     = 43
	typeRRSIG  = 46
	typeNSEC   = 47
	typeDNSKEY = 48

	algRSA256   = 8
	algECDSA256 = 13
	algEd25519  = 15
)

// sigBase is the wall-clock anchor for signature validity windows and for the
// replay harness clock, so virtual time and inception/expiration agree.
var sigBase = time.Now().Truncate(time.Second)

// A zoneRR is one resource record with canonical (lowercase, uncompressed)
// wire RDATA.
type zoneRR struct {
	owner string // lowercase FQDN
	typ   uint16
	ttl   uint32
	data  []byte
}

// A testKey is a zone signing key. wire is the algorithm number advertised
// in DNSKEY/DS/RRSIG records; it differs from the signing algorithm only for
// keys built by newTestKeyFake.
type testKey struct {
	alg    uint16
	wire   uint16
	signer crypto.Signer
	rdata  []byte // DNSKEY RDATA
	tag    uint16
}

// A testZone is one authoritative zone in the tree.
type testZone struct {
	name     string // lowercase FQDN, "." for root
	parent   *testZone
	key      *testKey
	unsigned bool // no DNSKEY/RRSIG/NSEC; parent publishes no DS
	rrs      []zoneRR
	children []*testZone
	addr     netip.Addr // address of this zone's single nameserver

	signed []zoneRR // rrs plus NSEC records and RRSIGs, after buildTree
}

// nsOwner returns the name of the zone's nameserver, inside the zone.
func (z *testZone) nsOwner() string {
	if z.name == "." {
		return "ns."
	}
	return "ns." + z.name
}

// newTestRoot creates a root zone served at addr.
func newTestRoot(alg uint16, addr netip.Addr) *testZone {
	z := &testZone{name: ".", key: newTestKey(alg), addr: addr}
	z.addAutoRRs()
	return z
}

// delegate creates a child zone at name, served at addr, and wires the
// delegation (NS at the cut; DS unless the child is unsigned).
func (z *testZone) delegate(name string, alg uint16, unsigned bool, addr netip.Addr) *testZone {
	name = strings.ToLower(name)
	c := &testZone{name: name, parent: z, addr: addr, unsigned: unsigned}
	if !unsigned {
		c.key = newTestKey(alg)
	}
	c.addAutoRRs()
	z.children = append(z.children, c)
	z.add(name, typeNS, 3600, packName(c.nsOwner()))
	return c
}

// addAutoRRs adds the apex SOA, NS, and nameserver glue.
func (z *testZone) addAutoRRs() {
	soa := packName(z.nsOwner())
	soa = append(soa, packName("hostmaster."+strings.TrimPrefix(z.name, "."))...)
	var t [20]byte
	binary.BigEndian.PutUint32(t[0:], 1)     // serial
	binary.BigEndian.PutUint32(t[4:], 1800)  // refresh
	binary.BigEndian.PutUint32(t[8:], 900)   // retry
	binary.BigEndian.PutUint32(t[12:], 7200) // expire
	binary.BigEndian.PutUint32(t[16:], 3600) // minimum
	z.add(z.name, typeSOA, 3600, append(soa, t[:]...))
	z.add(z.name, typeNS, 3600, packName(z.nsOwner()))
	a := z.addr.As4()
	z.add(z.nsOwner(), TypeA, 3600, a[:])
}

// add appends a record with the given canonical wire RDATA.
func (z *testZone) add(owner string, typ uint16, ttl uint32, data []byte) {
	z.rrs = append(z.rrs, zoneRR{strings.ToLower(owner), typ, ttl, data})
}

func (z *testZone) addA(owner string, ip string) {
	a := netip.MustParseAddr(ip).As4()
	z.add(owner, TypeA, 3600, a[:])
}

func (z *testZone) addTXT(owner string, s string) {
	z.add(owner, TypeTXT, 3600, append([]byte{byte(len(s))}, s...))
}

func (z *testZone) addCAA(owner string, flags byte, tag, value string) {
	data := append([]byte{flags, byte(len(tag))}, tag...)
	z.add(owner, TypeCAA, 3600, append(data, value...))
}

func (z *testZone) addCNAME(owner, target string) {
	z.add(owner, typeCNAME, 3600, packName(target))
}

// buildTree signs the whole tree: it publishes DS records in parents, adds
// DNSKEY RRsets and NSEC chains, and signs every authoritative RRset. Call
// once on the root after all records and delegations are in place.
func (z *testZone) buildTree() {
	// DS before signing, so the parent's DS RRset is in its NSEC chain
	// and gets signed like any other RRset.
	var walk func(*testZone)
	walk = func(zz *testZone) {
		for _, c := range zz.children {
			if !c.unsigned {
				zz.add(c.name, typeDS, 3600, dsRData(c.name, c.key))
			}
			walk(c)
		}
	}
	walk(z)
	var signAll func(*testZone)
	signAll = func(zz *testZone) {
		zz.sign()
		for _, c := range zz.children {
			signAll(c)
		}
	}
	signAll(z)
}

// zoneCut reports whether owner sits at or below a delegation in z, returning
// the cut name if so.
func (z *testZone) zoneCut(owner string) (string, bool) {
	for _, c := range z.children {
		if owner == c.name || strings.HasSuffix(owner, "."+c.name) {
			return c.name, true
		}
	}
	return "", false
}

// isDelegation reports whether owner is exactly a delegation point in z.
func (z *testZone) isDelegation(owner string) bool {
	for _, c := range z.children {
		if owner == c.name {
			return true
		}
	}
	return false
}

// sign fills z.signed with the zone's records, NSEC chain, and RRSIGs.
func (z *testZone) sign() {
	if z.unsigned {
		z.signed = z.rrs
		return
	}
	rrs := append([]zoneRR(nil), z.rrs...)
	rrs = append(rrs, zoneRR{z.name, typeDNSKEY, 3600, z.key.rdata})

	// NSEC chain over the canonically ordered authoritative owner names.
	types := map[string]map[uint16]bool{}
	for _, rr := range rrs {
		if types[rr.owner] == nil {
			types[rr.owner] = map[uint16]bool{}
		}
		types[rr.owner][rr.typ] = true
	}
	owners := make([]string, 0, len(types))
	for o := range types {
		owners = append(owners, o)
	}
	sort.Slice(owners, func(i, j int) bool { return canonicalLess(owners[i], owners[j]) })
	for i, o := range owners {
		next := owners[(i+1)%len(owners)]
		// The NSEC itself is signed at every owner, so RRSIG is always
		// in the bitmap, including at unsigned delegations.
		bitmapTypes := []uint16{typeNSEC, typeRRSIG}
		for t := range types[o] {
			bitmapTypes = append(bitmapTypes, t)
		}
		data := append(packName(next), typeBitmap(bitmapTypes)...)
		rrs = append(rrs, zoneRR{o, typeNSEC, 3600, data})
	}

	// Sign every RRset, except the NS set at delegation points (and the
	// glue beneath them, which our zones never hold — glue lives in the
	// child zone and is copied into referrals from there).
	z.signed = rrs
	for _, set := range groupRRSets(rrs) {
		if z.isDelegation(set[0].owner) && set[0].typ == typeNS {
			continue
		}
		z.signed = append(z.signed, z.rrsig(set, 0))
	}
}

// rrsig signs one RRset. A nonzero expireShift moves the validity window,
// e.g. a large negative shift produces an expired signature.
func (z *testZone) rrsig(set []zoneRR, expireShift time.Duration) zoneRR {
	return signRRSet(set, z.name, z.key, sigBase.Add(-24*time.Hour), sigBase.Add(30*24*time.Hour).Add(expireShift))
}

func signRRSet(set []zoneRR, signerName string, key *testKey, inception, expiration time.Time) zoneRR {
	owner, typ, ttl := set[0].owner, set[0].typ, set[0].ttl
	labels := countLabels(owner)
	rdataPrefix := make([]byte, 18)
	binary.BigEndian.PutUint16(rdataPrefix[0:], typ)
	rdataPrefix[2] = byte(key.wire)
	rdataPrefix[3] = byte(labels)
	binary.BigEndian.PutUint32(rdataPrefix[4:], ttl)
	binary.BigEndian.PutUint32(rdataPrefix[8:], uint32(expiration.Unix()))
	binary.BigEndian.PutUint32(rdataPrefix[12:], uint32(inception.Unix()))
	binary.BigEndian.PutUint16(rdataPrefix[16:], key.tag)
	rdataPrefix = append(rdataPrefix, packName(signerName)...)

	// RFC 4034, Section 3.1.8.1: signed data is the RRSIG RDATA through
	// the signer name, then the RRset with RRs sorted by canonical RDATA.
	msg := append([]byte(nil), rdataPrefix...)
	sorted := append([]zoneRR(nil), set...)
	sort.Slice(sorted, func(i, j int) bool {
		return string(sorted[i].data) < string(sorted[j].data)
	})
	for _, rr := range sorted {
		msg = append(msg, packName(rr.owner)...)
		var fixed [10]byte
		binary.BigEndian.PutUint16(fixed[0:], rr.typ)
		binary.BigEndian.PutUint16(fixed[2:], 1) // IN
		binary.BigEndian.PutUint32(fixed[4:], ttl)
		binary.BigEndian.PutUint16(fixed[8:], uint16(len(rr.data)))
		msg = append(msg, fixed[:]...)
		msg = append(msg, rr.data...)
	}

	sig := rawSign(key, msg)
	return zoneRR{owner, typeRRSIG, ttl, append(rdataPrefix, sig...)}
}

func rawSign(key *testKey, msg []byte) []byte {
	digest := sha256.Sum256(msg)
	switch key.alg {
	case algECDSA256:
		priv := key.signer.(*ecdsa.PrivateKey)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			panic(err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig
	case algEd25519:
		return ed25519.Sign(key.signer.(ed25519.PrivateKey), msg)
	case algRSA256:
		sig, err := rsa.SignPKCS1v15(rand.Reader, key.signer.(*rsa.PrivateKey), crypto.SHA256, digest[:])
		if err != nil {
			panic(err)
		}
		return sig
	}
	panic(fmt.Sprintf("unsupported test algorithm %d", key.alg))
}

var rsaTestKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

func newTestKey(alg uint16) *testKey {
	var signer crypto.Signer
	var pub []byte
	switch alg {
	case algECDSA256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		signer = k
		point, err := k.PublicKey.Bytes()
		if err != nil {
			panic(err)
		}
		pub = point[1:] // strip the uncompressed-point prefix: X || Y
	case algEd25519:
		p, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		signer = k
		pub = []byte(p)
	case algRSA256:
		k := rsaTestKey()
		signer = k
		n := k.N.Bytes()
		pub = append([]byte{3, 1, 0, 1}, n...) // exponent 65537
	default:
		panic(fmt.Sprintf("unsupported test algorithm %d", alg))
	}
	// DNSKEY RDATA: flags 257 (KSK), protocol 3, algorithm, key.
	rdata := append([]byte{1, 1, 3, byte(alg)}, pub...)
	return &testKey{alg: alg, wire: alg, signer: signer, rdata: rdata, tag: keyTag(rdata)}
}

// newTestKeyFake builds a key that advertises wireAlg in DNSKEY, DS, and
// RRSIG records while actually signing with Ed25519. Only useful when the
// validator never verifies the signatures, i.e. for unsupported-algorithm
// handling.
func newTestKeyFake(wireAlg uint16) *testKey {
	k := newTestKey(algEd25519)
	k.wire = wireAlg
	k.rdata[3] = byte(wireAlg)
	k.tag = keyTag(k.rdata)
	return k
}

// keyTag implements RFC 4034, Appendix B.
func keyTag(rdata []byte) uint16 {
	var sum uint32
	for i, b := range rdata {
		if i&1 == 0 {
			sum += uint32(b) << 8
		} else {
			sum += uint32(b)
		}
	}
	return uint16(sum + sum>>16)
}

// dsRData builds the SHA-256 DS RDATA for a zone key.
func dsRData(owner string, key *testKey) []byte {
	h := sha256.New()
	h.Write(packName(owner))
	h.Write(key.rdata)
	data := make([]byte, 4, 4+32)
	binary.BigEndian.PutUint16(data[0:], key.tag)
	data[2] = byte(key.wire)
	data[3] = 2 // SHA-256
	return h.Sum(data)
}

// trustAnchor renders the root DS record in zone file format for
// Config.TrustAnchors.
func (z *testZone) trustAnchor() []byte {
	ds := dsRData(z.name, z.key)
	return fmt.Appendf(nil, ". 3600 IN DS %d %d 2 %s\n",
		binary.BigEndian.Uint16(ds[0:2]), ds[2], hex.EncodeToString(ds[4:]))
}

// groupRRSets groups records into RRsets by owner and type.
func groupRRSets(rrs []zoneRR) [][]zoneRR {
	byKey := map[string][]zoneRR{}
	var order []string
	for _, rr := range rrs {
		k := fmt.Sprintf("%s/%d", rr.owner, rr.typ)
		if byKey[k] == nil {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], rr)
	}
	sets := make([][]zoneRR, 0, len(order))
	for _, k := range order {
		sets = append(sets, byKey[k])
	}
	return sets
}

// packName encodes a lowercase FQDN as an uncompressed wire name.
func packName(name string) []byte {
	name = strings.ToLower(name)
	if name == "." {
		return []byte{0}
	}
	var out []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			panic("bad test label in " + name)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func countLabels(name string) int {
	if name == "." {
		return 0
	}
	n := strings.Count(strings.TrimSuffix(name, "."), ".") + 1
	if strings.HasPrefix(name, "*.") {
		n--
	}
	return n
}

// canonicalLess implements RFC 4034, Section 6.1 name ordering: compare
// label sequences right to left, bytewise per label.
func canonicalLess(a, b string) bool {
	la, lb := nameLabels(a), nameLabels(b)
	for i := 0; i < len(la) && i < len(lb); i++ {
		if la[len(la)-1-i] != lb[len(lb)-1-i] {
			return la[len(la)-1-i] < lb[len(lb)-1-i]
		}
	}
	return len(la) < len(lb)
}

func nameLabels(name string) []string {
	if name == "." {
		return nil
	}
	return strings.Split(strings.TrimSuffix(name, "."), ".")
}

// typeBitmap encodes an NSEC type bitmap (RFC 4034, Section 4.1.2).
func typeBitmap(types []uint16) []byte {
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	var out []byte
	for i := 0; i < len(types); {
		window := byte(types[i] >> 8)
		var bits [32]byte
		maxByte := 0
		for ; i < len(types) && byte(types[i]>>8) == window; i++ {
			t := byte(types[i])
			bits[t/8] |= 0x80 >> (t % 8)
			maxByte = int(t / 8)
		}
		out = append(out, window, byte(maxByte+1))
		out = append(out, bits[:maxByte+1]...)
	}
	return out
}
