package unbound

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// warmupClock is a replayHooks that only tells the time. Everything else
// fails the test: warmup promises to use no sockets or timers.
type warmupClock struct {
	t    *testing.T
	wall time.Time
	mono time.Duration
}

func (h *warmupClock) nowWall() time.Time     { return h.wall }
func (h *warmupClock) nowMono() time.Duration { return h.mono }
func (h *warmupClock) timerStart(*instanceState, int32) uint64 {
	h.t.Error("warmup started a timer")
	return 0
}
func (h *warmupClock) timerStop(uint64) { h.t.Error("warmup stopped a timer") }
func (h *warmupClock) connect(*instanceState, *hostSocket, netip.AddrPort) int32 {
	h.t.Error("warmup connected a socket")
	return -1
}
func (h *warmupClock) sendTo(*instanceState, *hostSocket, netip.AddrPort, []byte) int32 {
	h.t.Error("warmup sent a packet")
	return -1
}
func (h *warmupClock) localPort(*hostSocket) int32 { return 0 }

// warmImage builds a zygote template under the given clock and returns its
// memory image.
func warmImage(t *testing.T, wall time.Time, mono time.Duration) []byte {
	t.Helper()
	rt, err := NewRuntime(context.Background(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	rt.replay = &warmupClock{t: t, wall: wall, mono: mono}
	inst, err := rt.NewInstance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	inst.Close(context.Background())
	if rt.zygote == nil {
		t.Skip("no zygote on this platform")
	}
	return rt.zygote.image
}

// guestStackSize is the guest stack, the lowest region of linear memory
// (the build links with stack-first layout; keep in sync with the
// stack-size flag in build/build-module.sh). At export boundaries all of
// it is dead, so differences there are meaningless residue.
const guestStackSize = 1 << 20

// diffPositions returns the live-memory byte positions at which a and b
// differ, ignoring the dead stack region.
func diffPositions(t *testing.T, a, b []byte) map[int]bool {
	t.Helper()
	if len(a) != len(b) {
		t.Fatalf("image sizes differ: %d vs %d", len(a), len(b))
	}
	d := make(map[int]bool)
	for n := guestStackSize; n < len(a); n++ {
		if a[n] != b[n] {
			d[n] = true
		}
	}
	return d
}

// entropyStateBytes is the stored state warmup derives from the entropy
// import, all of which reseed redraws per clone: the 4-byte cache
// hash-table seed and the 16-byte DNS Cookie server secret.
const entropyStateBytes = 4 + 16

// TestZygoteWarmupDeterminism pins down how much stored state warmup
// derives from the clock and entropy imports. Two templates warmed under
// an identical clock differ only in entropy-derived bytes — the inventory
// reseed redraws per clone — and a template warmed under a shifted clock
// adds no difference at all, because warmup clears the one cached time.
// If an upstream Unbound update starts storing more entropy- or
// clock-derived state in the setup path, this fails, instead of clones
// silently sharing the new state.
func TestZygoteWarmupDeterminism(t *testing.T) {
	wall := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	a := warmImage(t, wall, time.Hour)
	b := warmImage(t, wall, time.Hour)
	c := warmImage(t, wall.Add(1000*24*time.Hour), 27*time.Hour)

	entropy := diffPositions(t, a, b)
	if len(entropy) > entropyStateBytes {
		t.Errorf("warmup stored %d entropy-derived bytes, expected at most %d (hash seed + cookie secret): update reseed for the new state",
			len(entropy), entropyStateBytes)
	}
	var clock []int
	for n := range diffPositions(t, a, c) {
		if !entropy[n] {
			clock = append(clock, n)
		}
	}
	if len(clock) > 0 {
		t.Errorf("warmup stored %d clock-derived bytes at %v; clones would share stale time", len(clock), clock)
	}
}

// TestZygoteCloneReseed checks that two fresh clones differ in their
// entropy-derived state — that is, reseed actually redrew it after the
// segment restore wrote the template's values back.
func TestZygoteCloneReseed(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	read := func(inst *Instance) []byte {
		var b []byte
		if err := inst.state.guest(func() error {
			mem := inst.mod.Memory()
			v, _ := mem.Read(0, mem.Size())
			b = append([]byte(nil), v...)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return b
	}
	a, err := env.rt.NewInstance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(context.Background())
	if env.rt.zygote == nil {
		t.Skip("no zygote on this platform")
	}
	b, err := env.rt.NewInstance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(context.Background())
	d := diffPositions(t, read(a), read(b))
	if len(d) == 0 {
		t.Fatal("fresh clones are identical: reseed did not redraw anything")
	}
	if len(d) > entropyStateBytes {
		t.Errorf("fresh clones differ in %d live bytes, expected at most %d (hash seed + cookie secret)",
			len(d), entropyStateBytes)
	}
}

func TestParseDataSegments(t *testing.T) {
	segs, err := parseDataSegments(embeddedModule)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) == 0 {
		t.Fatal("no data segments found")
	}
	var total uint64
	for _, s := range segs {
		total += uint64(s.len)
		// Segments must land in the initial memory, below the heap the
		// warmed image extends into.
		if uint64(s.off)+uint64(s.len) > 64<<20 {
			t.Fatalf("segment at %d+%d out of range", s.off, s.len)
		}
	}
	t.Logf("%d data segments, %d bytes", len(segs), total)
	if total == 0 {
		t.Fatal("empty data segments")
	}
}

// TestZygoteDisabled covers the full initialization path — including the
// guest's lazy context creation at the first resolution — which clones
// otherwise skip on every platform with a zygote.
func TestZygoteDisabled(t *testing.T) {
	disableZygote = true
	t.Cleanup(func() { disableZygote = false })
	env := newTestEnv(t, algECDSA256, nil)
	res, err := env.resolve("www.example.gotest", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Secure || len(res.Addrs()) != 2 {
		t.Fatalf("Secure=%v addrs=%v", res.Secure, res.Addrs())
	}
}

// TestZygoteCloneIndependence checks that clones do not share mutable
// state: closing one leaves another running, and both resolve correctly.
func TestZygoteCloneIndependence(t *testing.T) {
	env := newTestEnv(t, algECDSA256, nil)
	a, err := env.rt.NewInstance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(context.Background())
	if env.rt.zygote == nil {
		t.Skip("no zygote on this platform")
	}
	b, err := env.rt.NewInstance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	res, err := resolveDriven(t, env.net, b, "www.example.gotest", TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TXT()) != 1 {
		t.Fatalf("TXT = %q", res.TXT())
	}
	b.Close(context.Background())
	res, err = resolveDriven(t, env.net, a, "www.example.gotest", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Secure || len(res.Addrs()) != 2 {
		t.Fatalf("Secure=%v addrs=%v after sibling close", res.Secure, res.Addrs())
	}
}

// TestZygoteBadConfigSurfacesAtNewInstance: template warmup runs the
// context setup, so configuration the guest rejects fails NewInstance
// instead of the first resolution.
func TestZygoteBadConfigSurfacesAtNewInstance(t *testing.T) {
	rt, err := NewRuntime(context.Background(), Config{
		TrustAnchors: []byte("not a valid trust anchor\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	inst, err := rt.NewInstance(context.Background())
	if err == nil {
		// Without a zygote the error is deferred to the first resolve.
		if rt.zygote != nil {
			t.Fatal("NewInstance succeeded with a bogus trust anchor")
		}
		inst.Close(context.Background())
		t.Skip("no zygote on this platform")
	}
	if !strings.Contains(err.Error(), "warmup") {
		t.Fatalf("error %v does not point at warmup", err)
	}
}
