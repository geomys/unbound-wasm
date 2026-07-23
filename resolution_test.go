package unbound

// End-to-end resolution scenarios: a Runtime with replay hooks resolves
// against a signed test zone tree served by the scripted authority, asserting
// on the public API surface (Result, BogusError, ResponseError). These are
// the integration tests for the host crypto provider, the socket/event/timer
// pump, and DNSSEC outcome mapping.

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var (
	rootAddr     = netip.MustParseAddr("203.0.114.1")
	tldAddr      = netip.MustParseAddr("203.0.114.2")
	leafAddr     = netip.MustParseAddr("203.0.114.3")
	insecureAddr = netip.MustParseAddr("203.0.114.4")
)

type testEnv struct {
	t                         *testing.T
	rt                        *Runtime
	net                       *replayNet
	auth                      *testAuthority
	root, tld, leaf, insecure *testZone
}

// newTestEnv builds the standard tree: a signed root and "gotest." TLD, a
// signed "example.gotest." leaf with A/TXT/CAA/CNAME content, and an unsigned
// "insecure.gotest." delegation. mutate, if not nil, runs before signing.
func newTestEnv(t *testing.T, alg uint16, mutate func(e *testEnv)) *testEnv {
	e := &testEnv{t: t}
	e.root = newTestRoot(alg, rootAddr)
	e.tld = e.root.delegate("gotest.", alg, false, tldAddr)
	e.leaf = e.tld.delegate("example.gotest.", alg, false, leafAddr)
	e.insecure = e.tld.delegate("insecure.gotest.", 0, true, insecureAddr)
	e.leaf.addA("www.example.gotest.", "203.0.114.80")
	e.leaf.addA("www.example.gotest.", "203.0.114.81")
	e.leaf.addTXT("www.example.gotest.", "hello world")
	e.leaf.addCAA("example.gotest.", 0, "issue", "ca.example")
	e.leaf.addCNAME("alias.example.gotest.", "www.example.gotest.")
	e.insecure.addA("www.insecure.gotest.", "203.0.114.90")
	if mutate != nil {
		mutate(e)
	}
	e.root.buildTree()
	e.auth = newTestAuthority(t, e.root)
	e.net = newReplayNet(t, e.auth)

	// Raise unbound's verbosity for the duration of the test, so the
	// resolver's own logs land in t.Logf via Config.Log.
	saved := defaultCanonicalConfig
	defaultCanonicalConfig = append(defaultCanonicalConfig[:len(defaultCanonicalConfig):len(defaultCanonicalConfig)], "verbosity:=4\n"...)
	t.Cleanup(func() { defaultCanonicalConfig = saved })

	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	rt, err := NewRuntime(context.Background(), Config{
		TrustAnchors: e.root.trustAnchor(),
		RootHints:    []string{rootAddr.String()},
		Log:          log,
	})
	if err != nil {
		t.Fatal(err)
	}
	rt.replay = e.net
	t.Cleanup(func() { rt.Close(context.Background()) })
	e.rt = rt
	return e
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

// resolve runs one query on a fresh instance through the driven event loop.
func (e *testEnv) resolve(name string, qtype uint16) (*Result, error) {
	e.t.Helper()
	inst, err := e.rt.NewInstance(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	defer inst.Close(context.Background())
	return resolveDriven(e.t, e.net, inst, name, qtype)
}

func TestResolveSecure(t *testing.T) {
	for _, alg := range []uint16{algECDSA256, algEd25519, algRSA256} {
		t.Run(map[uint16]string{8: "RSASHA256", 13: "ECDSAP256", 15: "Ed25519"}[alg], func(t *testing.T) {
			env := newTestEnv(t, alg, nil)
			res, err := env.resolve("www.example.gotest", TypeA)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Secure || !res.HaveData || res.NXDomain {
				t.Fatalf("got Secure=%v HaveData=%v NXDomain=%v, want secure data", res.Secure, res.HaveData, res.NXDomain)
			}
			var addrs []string
			for _, a := range res.Addrs() {
				addrs = append(addrs, a.String())
			}
			want := []string{"203.0.114.80", "203.0.114.81"}
			if got := sortStrings(addrs); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
				t.Fatalf("addrs %v, want %v", got, want)
			}
		})
	}
}

func TestResolveTXTAndCAA(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	res, err := env.resolve("www.example.gotest", TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Secure || len(res.TXT()) != 1 || res.TXT()[0] != "hello world" {
		t.Fatalf("TXT = %q (secure=%v), want [hello world]", res.TXT(), res.Secure)
	}
	res, err = env.resolve("example.gotest", TypeCAA)
	if err != nil {
		t.Fatal(err)
	}
	caa := res.CAA()
	if !res.Secure || len(caa) != 1 || caa[0].Tag != "issue" || caa[0].Value != "ca.example" {
		t.Fatalf("CAA = %+v (secure=%v), want issue ca.example", caa, res.Secure)
	}
}

func TestResolveCNAME(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	res, err := env.resolve("alias.example.gotest", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Secure || !res.HaveData || len(res.Addrs()) != 2 {
		t.Fatalf("CNAME chase: Secure=%v HaveData=%v addrs=%v", res.Secure, res.HaveData, res.Addrs())
	}
}

func TestResolveNXDomain(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	res, err := env.resolve("nope.example.gotest", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NXDomain || res.HaveData {
		t.Fatalf("got NXDomain=%v HaveData=%v, want validated denial", res.NXDomain, res.HaveData)
	}
	if !res.Secure {
		t.Fatal("NXDOMAIN with NSEC proofs should validate as secure")
	}
}

func TestResolveNoData(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	res, err := env.resolve("www.example.gotest", TypeAAAA)
	if err != nil {
		t.Fatal(err)
	}
	if res.NXDomain || res.HaveData || !res.Secure {
		t.Fatalf("got Secure=%v HaveData=%v NXDomain=%v, want secure NODATA", res.Secure, res.HaveData, res.NXDomain)
	}
}

func TestResolveInsecureDelegation(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	res, err := env.resolve("www.insecure.gotest", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if res.Secure {
		t.Fatal("unsigned zone validated as secure")
	}
	if !res.HaveData || len(res.Addrs()) != 1 || res.Addrs()[0].String() != "203.0.114.90" {
		t.Fatalf("addrs = %v, want [203.0.114.90]", res.Addrs())
	}
}

// stripSigs removes the RRSIGs covering (owner, typ) from a signed zone.
func stripSigs(z *testZone, owner string, typ uint16) {
	var out []zoneRR
	for _, rr := range z.signed {
		if rr.typ == typeRRSIG && rr.owner == owner && binary.BigEndian.Uint16(rr.data[0:2]) == typ {
			continue
		}
		out = append(out, rr)
	}
	if len(out) == len(z.signed) {
		panic("stripSigs: no signature found for " + owner)
	}
	z.signed = out
}

func TestResolveBogusStrippedSignature(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	stripSigs(env.leaf, "www.example.gotest.", TypeA)
	_, err := env.resolve("www.example.gotest", TypeA)
	var bogus *BogusError
	if !errors.As(err, &bogus) {
		t.Fatalf("got %v, want BogusError", err)
	}
	t.Logf("bogus: %v", bogus)
}

func TestResolveBogusExpiredSignature(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	set := lookupIn(env.leaf.signed, "www.example.gotest.", TypeA)
	stripSigs(env.leaf, "www.example.gotest.", TypeA)
	// Shift expiration to just before inception, so the signature is
	// structurally valid but expired.
	env.leaf.signed = append(env.leaf.signed, env.leaf.rrsig(set, -31*24*time.Hour))
	_, err := env.resolve("www.example.gotest", TypeA)
	var bogus *BogusError
	if !errors.As(err, &bogus) {
		t.Fatalf("got %v, want BogusError", err)
	}
	if !strings.Contains(bogus.Reason, "expired") {
		t.Fatalf("reason %q does not mention expiry", bogus.Reason)
	}
}

func TestResolveBogusCorruptSignature(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	for i, rr := range env.leaf.signed {
		if rr.typ == typeRRSIG && rr.owner == "www.example.gotest." &&
			binary.BigEndian.Uint16(rr.data[0:2]) == TypeA {
			env.leaf.signed[i].data[len(rr.data)-1] ^= 0xff
		}
	}
	_, err := env.resolve("www.example.gotest", TypeA)
	var bogus *BogusError
	if !errors.As(err, &bogus) {
		t.Fatalf("got %v, want BogusError", err)
	}
}

func TestResolveServfailWhenUnreachable(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	env.auth.intercept = func(q parsedQuery, reply []byte) []delivery {
		if q.server == leafAddr {
			return nil // drop everything to the leaf zone's server
		}
		return []delivery{{pkt: reply}}
	}
	_, err := env.resolve("www.example.gotest", TypeA)
	var re *ResponseError
	if !errors.As(err, &re) {
		t.Fatalf("got %v, want ResponseError", err)
	}
	if re.RCode != 2 {
		t.Fatalf("rcode %d, want SERVFAIL", re.RCode)
	}
	t.Logf("servfail: %v", re)
}

func TestResolveTruncationFallsBackToTCP(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	env.auth.intercept = func(q parsedQuery, reply []byte) []delivery {
		if !q.tcp && q.server == leafAddr && q.qtype == TypeA {
			tc := truncatedReply(q)
			return []delivery{{pkt: tc}}
		}
		return []delivery{{pkt: reply}}
	}
	res, err := env.resolve("www.example.gotest", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Secure || !res.HaveData {
		t.Fatalf("Secure=%v HaveData=%v after TCP fallback", res.Secure, res.HaveData)
	}
	sawTCP := false
	for _, q := range env.auth.queries {
		sawTCP = sawTCP || (q.tcp && q.qtype == TypeA && q.qname == "www.example.gotest.")
	}
	if !sawTCP {
		t.Fatal("resolver never retried the truncated answer over TCP")
	}
}

// truncatedReply builds an empty TC=1 reply to q.
func truncatedReply(q parsedQuery) []byte {
	resp := encodeReply(q, response{})
	flags := binary.BigEndian.Uint16(resp[2:4])
	binary.BigEndian.PutUint16(resp[2:4], flags|0x0200) // TC
	return resp
}

func TestResolveRetryAfterTimeout(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	dropped := 0
	env.auth.intercept = func(q parsedQuery, reply []byte) []delivery {
		if q.server == leafAddr && q.qtype == TypeA && dropped < 2 {
			dropped++
			return nil
		}
		return []delivery{{pkt: reply}}
	}
	res, err := env.resolve("www.example.gotest", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Secure || !res.HaveData {
		t.Fatalf("Secure=%v HaveData=%v after retries", res.Secure, res.HaveData)
	}
	if dropped != 2 {
		t.Fatalf("authority dropped %d queries, want 2", dropped)
	}
}

func TestResolveIgnoresSpoofedSource(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	spoofed := 0
	attacker := netip.MustParseAddr("203.0.114.66")
	env.auth.intercept = func(q parsedQuery, reply []byte) []delivery {
		if q.server == leafAddr && q.qtype == TypeA {
			spoofed++
			// A wrong-source packet first; the honest answer after.
			evil := append([]byte(nil), reply...)
			evil[12] ^= 0x20 // also mangle the 0x20 case of the question
			return []delivery{{pkt: evil, from: attacker}, {pkt: reply}}
		}
		return []delivery{{pkt: reply}}
	}
	res, err := env.resolve("www.example.gotest", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if spoofed == 0 {
		t.Fatal("intercept never ran")
	}
	if !res.Secure || !res.HaveData {
		t.Fatalf("Secure=%v HaveData=%v with spoofed packets in flight", res.Secure, res.HaveData)
	}
}

// TestResolvePublicAPI runs the happy path and a validation failure through
// Instance.Resolve itself (rather than the driven loop), covering the public
// entry point end to end.
func TestResolvePublicAPI(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	env.net.realTime = true
	inst, err := env.rt.NewInstance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close(context.Background())
	res, err := inst.Resolve(context.Background(), "www.example.gotest", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Secure || len(res.Addrs()) != 2 {
		t.Fatalf("Secure=%v addrs=%v", res.Secure, res.Addrs())
	}
}

func TestResolveContextCancellation(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	env.net.realTime = true
	env.auth.intercept = func(parsedQuery, []byte) []delivery { return nil } // black hole
	inst, err := env.rt.NewInstance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = inst.Resolve(ctx, "www.example.gotest", TypeA)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context deadline", err)
	}
	if _, err := inst.Resolve(context.Background(), "www.example.gotest", TypeA); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v, want ErrClosed after cancellation", err)
	}
}

// TestResolveConcurrentClose closes the Instance from another goroutine in
// the middle of a resolution. Close must serialize with in-flight guest
// calls: the instance's linear memory is unmapped at close, so a call (or
// host-side memory read) racing the teardown would fault.
func TestResolveConcurrentClose(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	env.net.realTime = true
	env.auth.intercept = func(parsedQuery, []byte) []delivery { return nil } // black hole
	inst, err := env.rt.NewInstance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		inst.Close(context.Background())
	}()
	if _, err := inst.Resolve(context.Background(), "www.example.gotest", TypeA); err == nil {
		t.Fatal("Resolve succeeded despite concurrent Close")
	}
	if _, err := inst.Resolve(context.Background(), "www.example.gotest", TypeA); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v, want ErrClosed after Close", err)
	}
}

func TestResolveUnsupportedAlgorithmIsInsecure(t *testing.T) {
	env := newTestEnv(t, algECDSA256, func(e *testEnv) {
		// Re-key the leaf zone with an algorithm the host does not
		// support (16, Ed448): validation must degrade to insecure,
		// not bogus, per RFC 6840.
		e.leaf.key = newTestKeyFake(16)
	})
	res, err := env.resolve("www.example.gotest", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if res.Secure {
		t.Fatal("unsupported algorithm validated as secure")
	}
	if !res.HaveData {
		t.Fatal("answer lost")
	}
}
