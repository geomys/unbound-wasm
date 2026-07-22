package unbound

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// The ABI is unstable while at v0: the embedded module and this host are
// built from the same source tree, and any version difference is a build
// inconsistency, not a compatibility case.
const abiVersion uint32 = 0

// A Runtime holds the compiled resolver module. Instances created from the
// same Runtime share compiled code but no other state.
//
// A Runtime is safe for concurrent use by multiple goroutines.
type Runtime struct {
	wazero   wazero.Runtime
	compiled wazero.CompiledModule
	cfg      Config
	replay   replayHooks // test-only; see replayHooks
	closed   atomic.Bool
	mu       sync.RWMutex
	states   map[string]*instanceState
}

// NewRuntime compiles the embedded resolver module.
func NewRuntime(ctx context.Context, cfg Config) (*Runtime, error) {
	for _, a := range cfg.RootHints {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("unbound: invalid RootHints address %q: %v", a, err)
		}
		if !egressAllowed(netip.AddrPortFrom(addr, 53)) {
			// Fail rather than let the egress policy silently drop
			// every query to this server.
			return nil, fmt.Errorf("unbound: RootHints address %q is not a public unicast address", a)
		}
	}
	// An empty TrustAnchors (nil or zero-length) selects the built-in IANA
	// root anchors: a caller that passes an empty slice must not silently end
	// up validating nothing. A non-empty slice is cloned, along with RootHints,
	// so later mutation of the caller's backing array cannot change what an
	// already-created Runtime validates against.
	if len(cfg.TrustAnchors) == 0 {
		cfg.TrustAnchors = defaultTrustAnchors
	} else {
		cfg.TrustAnchors = bytes.Clone(cfg.TrustAnchors)
	}
	cfg.RootHints = slices.Clone(cfg.RootHints)
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	const pageSize = 64 * 1024
	const maxPages = 1 << 32 / pageSize
	pages := uint32(64 << 20 / pageSize) // 64 MiB default
	if cfg.MemoryLimit > 0 {
		pages = uint32(min((cfg.MemoryLimit+pageSize-1)/pageSize, maxPages))
	}

	rc := wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(pages)
	wr := wazero.NewRuntimeWithConfig(ctx, rc)
	r := &Runtime{wazero: wr, cfg: cfg, states: make(map[string]*instanceState)}
	if err := r.instantiateHostModules(ctx); err != nil {
		wr.Close(ctx)
		return nil, fmt.Errorf("unbound: instantiate host ABI: %w", err)
	}
	compiled, err := wr.CompileModule(ctx, embeddedModule)
	if err != nil {
		wr.Close(ctx)
		return nil, fmt.Errorf("unbound: compile module: %w", err)
	}
	r.compiled = compiled
	return r, nil
}

// Close closes every live Instance and releases the compiled module.
// It is idempotent.
func (r *Runtime) Close(ctx context.Context) error {
	if r == nil || r.wazero == nil || !r.closed.CompareAndSwap(false, true) {
		return nil
	}
	r.mu.Lock()
	states := make([]*instanceState, 0, len(r.states))
	for name, state := range r.states {
		states = append(states, state)
		delete(r.states, name)
	}
	r.mu.Unlock()
	for _, state := range states {
		state.close()
	}
	return r.wazero.Close(ctx)
}

// NewInstance instantiates a fresh resolver with its own isolated memory and
// empty caches.
func (r *Runtime) NewInstance(ctx context.Context) (*Instance, error) {
	if r == nil || r.compiled == nil || r.closed.Load() {
		return nil, errors.New("unbound: nil or closed runtime")
	}
	name := "unbound-" + rand.Text()
	state := newInstanceState(r.cfg.Log.With("instance", name))
	state.replay = r.replay
	r.mu.Lock()
	r.states[name] = state
	r.mu.Unlock()

	mc := wazero.NewModuleConfig().WithName(name).WithStartFunctions("_initialize")
	mod, err := r.wazero.InstantiateModule(ctx, r.compiled, mc)
	if err != nil {
		r.removeState(name)
		state.close()
		return nil, fmt.Errorf("unbound: instantiate module: %w", err)
	}
	state.mod = mod
	inst := &Instance{runtime: r, state: state, mod: mod, name: name}
	if err := inst.bindExports(); err != nil {
		inst.Close(ctx)
		return nil, err
	}

	out, err := inst.abiVersion.Call(ctx)
	if err != nil {
		inst.Close(ctx)
		return nil, fmt.Errorf("unbound: read ABI version: %w", err)
	}
	if v := uint32(out[0]); v != abiVersion {
		inst.Close(ctx)
		return nil, fmt.Errorf("unbound: wasm ABI version mismatch: host v%d, guest v%d", abiVersion, v)
	}
	// On development machines without working IPv6, set
	// UNBOUND_WASM_DISABLE_IPV6=1 so the iterator never selects IPv6
	// targets. Unbound treats failed and blackholed sends like timeouts,
	// so every unreachable server otherwise costs a wasted attempt and a
	// spurious 0x20 caps fallback. Production hosts are expected to have
	// working IPv6.
	conf := defaultCanonicalConfig
	if os.Getenv("UNBOUND_WASM_DISABLE_IPV6") != "" {
		conf = append(conf[:len(conf):len(conf)], "do-ip6:=no\n"...)
	}
	var hints []byte
	if len(r.cfg.RootHints) > 0 {
		hints = []byte(strings.Join(r.cfg.RootHints, "\n") + "\n")
	}
	if err := inst.initialize(ctx, conf, r.cfg.TrustAnchors, hints); err != nil {
		inst.Close(ctx)
		return nil, err
	}
	return inst, nil
}

func (r *Runtime) state(mod api.Module) *instanceState {
	r.mu.RLock()
	s := r.states[mod.Name()]
	r.mu.RUnlock()
	if s == nil {
		panic("unbound: host call from unknown module " + mod.Name())
	}
	return s
}

func (r *Runtime) removeState(name string) {
	r.mu.Lock()
	delete(r.states, name)
	r.mu.Unlock()
}

// An Instance is a recursive resolver running in its own wasm sandbox, with
// its own memory, caches, and sockets.
//
// An Instance resolves one query at a time and is not safe for concurrent
// use, except for [Instance.Close]. For parallel queries, use one Instance
// per in-flight query: instances are cheap, and answers are never cached,
// so even sequential queries on a shared Instance are each resolved fresh.
type Instance struct {
	runtime *Runtime
	state   *instanceState
	mod     api.Module
	name    string
	closed  atomic.Bool

	// Guest exports, bound by bindExports.
	abiVersion    api.Function
	alloc         api.Function
	dealloc       api.Function
	initFn        api.Function
	resolveStart  api.Function
	ioReady       api.Function
	timerFired    api.Function
	resultGet     api.Function
	resolveCancel api.Function
}

// Name returns the unique random identifier of this Instance, of the form
// "unbound-" followed by [rand.Text]. It tags every log line the Instance
// emits, so it can correlate external records (such as validation evidence)
// with logs.
func (i *Instance) Name() string { return i.name }

func (i *Instance) bindExports() error {
	var err error
	lookup := func(name string) api.Function {
		f := i.mod.ExportedFunction(name)
		if f == nil && err == nil {
			err = fmt.Errorf("unbound: module lacks required export %q", name)
		}
		return f
	}
	i.abiVersion = lookup("unbound_wasm_abi_version")
	i.alloc = lookup("alloc")
	i.dealloc = lookup("dealloc")
	i.initFn = lookup("init")
	i.resolveStart = lookup("resolve_start")
	i.ioReady = lookup("io_ready")
	i.timerFired = lookup("timer_fired")
	i.resultGet = lookup("result_get")
	i.resolveCancel = lookup("resolve_cancel")
	return err
}

func (i *Instance) initialize(ctx context.Context, cfg, anchors, hints []byte) error {
	ptrs := make([]uint32, 3)
	vals := [][]byte{cfg, anchors, hints}
	for n, v := range vals {
		p, err := i.allocWrite(ctx, v)
		if err != nil {
			return err
		}
		ptrs[n] = p
		defer i.free(context.Background(), p, uint32(len(v)))
	}
	out, err := i.initFn.Call(ctx, uint64(ptrs[0]), uint64(len(cfg)), uint64(ptrs[1]), uint64(len(anchors)), uint64(ptrs[2]), uint64(len(hints)))
	if err != nil {
		return fmt.Errorf("unbound: guest init: %w", err)
	}
	if rc := int32(uint32(out[0])); rc != 0 {
		return fmt.Errorf("unbound: guest init failed: wasi errno %d", -rc)
	}
	return nil
}

// Resolve recursively resolves and validates name, which is interpreted as
// fully qualified (the trailing dot is optional), in the IN class.
//
// If the answer fails DNSSEC validation, it returns a [BogusError]; if
// resolution fails, it returns a [ResponseError]. If ctx is canceled
// mid-resolution, the whole Instance is closed, because the guest may be
// left in an inconsistent state.
//
// Transient failures surface as [ResponseError] and are not retried; callers
// with retry policies should retry on a fresh Instance.
func (i *Instance) Resolve(ctx context.Context, name string, qtype uint16) (*Result, error) {
	if i == nil || i.closed.Load() {
		return nil, ErrClosed
	}
	if name == "" {
		return nil, errors.New("unbound: empty name")
	}
	// A NUL would truncate the name when the guest turns it into a C string,
	// so "example.com.\x00.evil." would resolve example.com. while the host
	// matched the answer against the full string. Reject it, along with names
	// too long to be a valid presentation-format domain, before it reaches the
	// guest.
	if strings.IndexByte(name, 0) >= 0 {
		return nil, errors.New("unbound: name contains NUL")
	}
	if len(name) > 1024 {
		return nil, errors.New("unbound: name too long")
	}
	if name[len(name)-1] != '.' {
		name += "."
	}

	p, err := i.allocWrite(ctx, []byte(name))
	if err != nil {
		return nil, err
	}
	const classIN = 1
	out, err := i.resolveStart.Call(ctx, uint64(p), uint64(len(name)), uint64(qtype), classIN)
	i.free(context.Background(), p, uint32(len(name)))
	if err != nil {
		return nil, i.kill(fmt.Errorf("unbound: resolve_start: %w", err))
	}
	rid := int32(uint32(out[0]))
	if rid < 0 {
		return nil, fmt.Errorf("unbound: resolve_start failed: wasi errno %d", -rid)
	}
	defer i.cancel(context.Background(), rid)

	for {
		res, ready, err := i.pollResult(ctx, rid, name, qtype)
		if err != nil {
			return nil, err
		}
		if ready {
			return res, nil
		}
		select {
		case <-ctx.Done():
			i.Close(context.Background())
			return nil, ctx.Err()
		case <-i.state.done:
			return nil, i.stateErr()
		case ev, ok := <-i.state.events:
			if !ok {
				return nil, ErrClosed
			}
			if err := i.dispatch(ctx, ev); err != nil {
				return nil, err
			}
		}
	}
}

// stateErr reports why the instance shut down while Resolve was waiting for
// events: a recorded internal failure (which also tears the instance down),
// or ErrClosed for an ordinary close.
func (i *Instance) stateErr() error {
	if err := i.state.err; err != nil {
		return i.kill(err)
	}
	return ErrClosed
}

func (i *Instance) dispatch(ctx context.Context, ev hostEvent) error {
	var err error
	switch ev.kind {
	case eventIO:
		_, err = i.ioReady.Call(ctx, uint64(uint32(ev.sid)), uint64(uint32(ev.flags)))
	case eventTimer:
		_, err = i.timerFired.Call(ctx, uint64(ev.tid))
	}
	if err != nil {
		return i.kill(fmt.Errorf("unbound: dispatch event: %w", err))
	}
	return nil
}

func (i *Instance) pollResult(ctx context.Context, rid int32, qname string, qtype uint16) (*Result, bool, error) {
	const resultSize = 32
	p, err := i.allocWrite(ctx, make([]byte, resultSize))
	if err != nil {
		return nil, false, err
	}
	defer i.free(context.Background(), p, resultSize)
	out, err := i.resultGet.Call(ctx, uint64(uint32(rid)), uint64(p))
	if err != nil {
		return nil, false, i.kill(fmt.Errorf("unbound: result_get: %w", err))
	}
	rc := int32(uint32(out[0]))
	if rc == 0 {
		return nil, false, nil
	}
	if rc < 0 {
		return nil, false, fmt.Errorf("unbound: result_get failed: wasi errno %d", -rc)
	}
	b, ok := i.mod.Memory().Read(p, resultSize)
	if !ok {
		return nil, false, i.kill(errors.New("unbound: result structure outside guest memory"))
	}
	word := func(off int) uint32 { return binary.LittleEndian.Uint32(b[off : off+4]) }
	read := func(ptr, n uint32) ([]byte, error) {
		if n == 0 {
			return nil, nil
		}
		if n > 65535 {
			return nil, errors.New("unbound: result buffer exceeds ABI limit")
		}
		v, ok := i.mod.Memory().Read(ptr, n)
		if !ok {
			return nil, errors.New("unbound: result buffer outside guest memory")
		}
		return append([]byte(nil), v...), nil
	}
	why, err := read(word(8), word(12))
	if err != nil {
		return nil, false, i.kill(err)
	}
	packet, err := read(word(16), word(20))
	if err != nil {
		return nil, false, i.kill(err)
	}
	const secStatusSecure, secStatusBogus = 1, 2
	if word(0) == secStatusBogus {
		return nil, false, &BogusError{Reason: string(why), EDE: parseEDE(packet)}
	}
	const rcodeNoError, rcodeNXDomain = 0, 3
	// The libunbound callback rcode is only set for resolution errors;
	// for answers that did resolve, it is NOERROR and the DNS rcode
	// (NOERROR vs NXDOMAIN) is in the answer packet header, like
	// upstream's ub_resolve reads it from the reply flags.
	rcode := int(word(4))
	if rcode == rcodeNoError && len(packet) >= 4 {
		rcode = int(packet[3] & 0xf)
	}
	if rcode != rcodeNoError && rcode != rcodeNXDomain {
		return nil, false, &ResponseError{RCode: rcode, EDE: parseEDE(packet)}
	}
	res := &Result{
		Secure:       word(0) == secStatusSecure,
		NXDomain:     rcode == rcodeNXDomain,
		AnswerPacket: packet,
	}
	// HaveData and the typed records are computed host-side from the
	// answer packet, but only for NOERROR answers: an NXDOMAIN answer
	// cannot hold records of the queried type.
	if rcode == rcodeNoError {
		if err := res.parseAnswer(qname, qtype); err != nil {
			return nil, false, err
		}
	}
	return res, true, nil
}

func (i *Instance) allocWrite(ctx context.Context, b []byte) (uint32, error) {
	n := len(b)
	if n == 0 {
		n = 1
	}
	out, err := i.alloc.Call(ctx, uint64(n))
	if err != nil {
		return 0, fmt.Errorf("unbound: alloc: %w", err)
	}
	p := uint32(out[0])
	if p == 0 {
		return 0, errors.New("unbound: guest allocation failed")
	}
	if len(b) > 0 && !i.mod.Memory().Write(p, b) {
		return 0, errors.New("unbound: guest allocation outside memory")
	}
	return p, nil
}

func (i *Instance) free(ctx context.Context, p, n uint32) {
	if p != 0 {
		_, _ = i.dealloc.Call(ctx, uint64(p), uint64(n))
	}
}

func (i *Instance) cancel(ctx context.Context, rid int32) {
	if !i.closed.Load() {
		_, _ = i.resolveCancel.Call(ctx, uint64(uint32(rid)))
	}
}

// kill closes the Instance, which can't be trusted after an internal error,
// and returns err for convenience.
func (i *Instance) kill(err error) error {
	i.Close(context.Background())
	return err
}

// Close aborts any in-flight resolution, closes the instance's sockets and
// timers, and frees its sandbox memory. It is idempotent, and after Close all
// methods return [ErrClosed].
func (i *Instance) Close(ctx context.Context) error {
	if i == nil || !i.closed.CompareAndSwap(false, true) {
		return nil
	}
	i.state.close()
	i.runtime.removeState(i.name)
	return i.mod.Close(ctx)
}
