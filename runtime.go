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
	"github.com/tetratelabs/wazero/experimental"
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

	// The zygote template, built by the first NewInstance; see zygote.go.
	zygoteOnce sync.Once
	zygote     *zygote
	zygoteErr  error
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
	// Wait out any in-flight zygote initialization, and mark the Once done
	// so none starts later: the r.zygote read below is ordered after
	// whichever initialization ran, and its image file cannot leak.
	r.zygoteOnce.Do(func() {})
	r.mu.Lock()
	states := make([]*instanceState, 0, len(r.states))
	for name, state := range r.states {
		states = append(states, state)
		delete(r.states, name)
	}
	r.mu.Unlock()
	for _, state := range states {
		state.close()
		// Close each module before the wazero runtime sweeps it, so the
		// teardown serializes with in-flight guest calls (see closeModule).
		state.closeModule(ctx)
	}
	err := r.wazero.Close(ctx)
	if r.zygote != nil {
		// Existing mappings keep their own reference to the file.
		r.zygote.file.Close()
	}
	return err
}

// NewInstance instantiates a fresh resolver with its own isolated memory and
// empty caches. The first call builds the zygote template (see zygote.go),
// so configuration problems that the guest only detects at context creation
// surface here rather than at the first resolution.
func (r *Runtime) NewInstance(ctx context.Context) (*Instance, error) {
	if r == nil || r.compiled == nil || r.closed.Load() {
		return nil, errors.New("unbound: nil or closed runtime")
	}
	// The template is built with a background context: it is shared setup,
	// and must not be poisoned by the first caller's cancellation.
	r.zygoteOnce.Do(func() { r.initZygote(context.Background()) })
	if r.zygoteErr != nil {
		return nil, r.zygoteErr
	}
	if r.zygote != nil {
		return r.newClone(ctx)
	}
	return r.newFullInstance(ctx)
}

// newModuleInstance instantiates the compiled module with the given memory
// allocator and registers its state. Clones skip the start functions: their
// memory image is already past initialization.
func (r *Runtime) newModuleInstance(ctx context.Context, alloc experimental.MemoryAllocator, start bool) (*Instance, error) {
	name := "unbound-" + rand.Text()
	state := newInstanceState(r.cfg.Log.With("instance", name))
	state.replay = r.replay
	// Registration is fenced against closure under r.mu: a state added
	// while the runtime is open is guaranteed to be swept by Close's
	// closeModule loop, and none can be added afterwards.
	r.mu.Lock()
	if r.closed.Load() {
		r.mu.Unlock()
		return nil, errors.New("unbound: closed runtime")
	}
	r.states[name] = state
	r.mu.Unlock()

	mc := wazero.NewModuleConfig().WithName(name)
	if start {
		mc = mc.WithStartFunctions("_initialize")
	} else {
		mc = mc.WithStartFunctions()
	}
	// The allocator only applies to the guest's linear memory: the host
	// modules instantiated at Runtime creation define no memories.
	mod, err := r.wazero.InstantiateModule(
		experimental.WithMemoryAllocator(ctx, alloc), r.compiled, mc)
	if err != nil {
		r.removeState(name)
		state.close()
		return nil, fmt.Errorf("unbound: instantiate module: %w", err)
	}
	// Publish the module under the guest lock: if a concurrent Close swept
	// this state while it had no module yet, teardown has passed us by,
	// and this module must be closed here instead of used.
	state.guestMu.Lock()
	if state.modDead {
		state.guestMu.Unlock()
		mod.Close(ctx)
		r.removeState(name)
		state.close()
		return nil, errors.New("unbound: closed runtime")
	}
	state.mod = mod
	state.guestMu.Unlock()
	inst := &Instance{runtime: r, state: state, mod: mod, name: name}
	if err := inst.bindExports(); err != nil {
		inst.Close(ctx)
		return nil, err
	}
	return inst, nil
}

func (i *Instance) checkABIVersion(ctx context.Context) error {
	out, err := i.call(ctx, i.abiVersion)
	if err != nil {
		return fmt.Errorf("unbound: read ABI version: %w", err)
	}
	if v := uint32(out[0]); v != abiVersion {
		return fmt.Errorf("unbound: wasm ABI version mismatch: host v%d, guest v%d", abiVersion, v)
	}
	return nil
}

// newFullInstance takes the whole initialization path: instantiate, run
// _initialize, and feed the configuration to the guest's init.
func (r *Runtime) newFullInstance(ctx context.Context) (*Instance, error) {
	inst, err := r.newModuleInstance(ctx, guestMemoryAllocator, true)
	if err != nil {
		return nil, err
	}
	if err := inst.checkABIVersion(ctx); err != nil {
		inst.Close(ctx)
		return nil, err
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
// An Instance runs one Resolve or ResolveAll call at a time and is not safe
// for concurrent use, except for [Instance.Close]. Related queries that
// share a fate — such as one validation's A, AAAA, TXT, and CAA lookups —
// belong in a single [Instance.ResolveAll] batch, which resolves them
// concurrently in one sandbox. Independent resolutions belong on separate
// Instances; answers are never cached, so every query is resolved fresh
// either way.
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
	warmup        api.Function
	reseed        api.Function
	resolveStart  api.Function
	ioReady       api.Function
	timerFired    api.Function
	resultGet     api.Function
	resolveCancel api.Function
}

// call invokes a guest export under the instance's guest lock, so the
// module cannot be torn down mid-call. See instanceState.guest.
func (i *Instance) call(ctx context.Context, f api.Function, params ...uint64) (out []uint64, err error) {
	err = i.state.guest(func() error {
		var cerr error
		out, cerr = f.Call(ctx, params...)
		return cerr
	})
	return out, err
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
	i.warmup = lookup("warmup")
	i.reseed = lookup("reseed")
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
	out, err := i.call(ctx, i.initFn, uint64(ptrs[0]), uint64(len(cfg)), uint64(ptrs[1]), uint64(len(anchors)), uint64(ptrs[2]), uint64(len(hints)))
	if err != nil {
		return fmt.Errorf("unbound: guest init: %w", err)
	}
	if rc := int32(uint32(out[0])); rc != 0 {
		return fmt.Errorf("unbound: guest init failed: wasi errno %d", -rc)
	}
	return nil
}

// A Query is one name and type for [Instance.ResolveAll]. The name is
// interpreted as fully qualified (the trailing dot is optional), in the IN
// class.
type Query struct {
	Name string
	Type uint16
}

// A QueryError reports the failure of one query of an [Instance.ResolveAll]
// batch.
type QueryError struct {
	Query Query
	Err   error
}

func (e *QueryError) Error() string {
	return fmt.Sprintf("unbound: query %q type %d: %v", e.Query.Name, e.Query.Type, e.Err)
}

func (e *QueryError) Unwrap() error { return e.Err }

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
	results, err := i.ResolveAll(ctx, []Query{{Name: name, Type: qtype}})
	if err != nil {
		// Unwrap the QueryError so single-query callers see the exact
		// BogusError, ResponseError, or context error.
		var qe *QueryError
		if errors.As(err, &qe) {
			return nil, qe.Err
		}
		return nil, err
	}
	return results[0], nil
}

// ResolveAll resolves and validates every query concurrently within the
// instance, sharing its sockets and event loop. It returns one result per
// query, in order: results[i] is nil if and only if queries[i] failed, and
// the returned error joins a [QueryError] per failure (nil if every query
// succeeded). Per-query failures are the same as [Instance.Resolve]'s:
// [BogusError] for answers that fail DNSSEC validation, [ResponseError] for
// failed resolutions.
//
// A batch shares the instance's fate: if ctx is canceled mid-resolution the
// whole Instance is closed, and an instance failure fails every unsettled
// query. The guest caps a batch at 64 concurrent queries; queries past its
// capacity fail with an errno error.
func (i *Instance) ResolveAll(ctx context.Context, queries []Query) ([]*Result, error) {
	results := make([]*Result, len(queries))
	errs := make([]error, len(queries))
	// failUnsettled reports err for every query that has not settled yet.
	failUnsettled := func(err error) ([]*Result, error) {
		for n := range queries {
			if results[n] == nil && errs[n] == nil {
				errs[n] = err
			}
		}
		return results, joinQueryErrors(queries, errs)
	}
	if i == nil || i.closed.Load() {
		if len(queries) == 0 {
			// failUnsettled has no query to attach the error to.
			return nil, ErrClosed
		}
		return failUnsettled(ErrClosed)
	}

	names := make([]string, len(queries))
	rids := make([]int32, len(queries)) // 0 while not started
	defer func() {
		// Free the guest result slots, settled or not.
		for _, rid := range rids {
			if rid > 0 {
				i.cancel(context.Background(), rid)
			}
		}
	}()
	pending := 0
	for n, q := range queries {
		name, err := normalizeName(q.Name)
		if err != nil {
			errs[n] = err
			continue
		}
		names[n] = name
		p, err := i.allocWrite(ctx, []byte(name))
		if err != nil {
			return failUnsettled(err)
		}
		const classIN = 1
		out, err := i.call(ctx, i.resolveStart, uint64(p), uint64(len(name)), uint64(q.Type), classIN)
		i.free(context.Background(), p, uint32(len(name)))
		if err != nil {
			return failUnsettled(i.kill(fmt.Errorf("unbound: resolve_start: %w", err)))
		}
		rid := int32(uint32(out[0]))
		if rid < 0 {
			errs[n] = fmt.Errorf("unbound: resolve_start failed: wasi errno %d", -rid)
			continue
		}
		rids[n] = rid
		pending++
	}
	// With nothing in flight — an empty batch, or every query rejected
	// before reaching the guest — don't touch the guest at all: an
	// allocation failure here could not be attributed to any query.
	if pending == 0 {
		return results, joinQueryErrors(queries, errs)
	}

	p, err := i.allocWrite(ctx, make([]byte, resultSize))
	if err != nil {
		return failUnsettled(err)
	}
	defer i.free(context.Background(), p, resultSize)

	for pending > 0 {
		for n := range queries {
			if rids[n] == 0 || results[n] != nil || errs[n] != nil {
				continue
			}
			res, ready, fatal, err := i.pollResult(ctx, rids[n], p, names[n], queries[n].Type)
			switch {
			case fatal:
				// The poll killed the instance; nothing else can settle.
				return failUnsettled(err)
			case err != nil:
				errs[n] = err
				pending--
			case ready:
				results[n] = res
				pending--
			}
		}
		if pending == 0 {
			break
		}
		select {
		case <-ctx.Done():
			i.Close(context.Background())
			return failUnsettled(ctx.Err())
		case <-i.state.done:
			return failUnsettled(i.stateErr())
		case ev, ok := <-i.state.events:
			if !ok {
				return failUnsettled(ErrClosed)
			}
			if err := i.dispatch(ctx, ev); err != nil {
				return failUnsettled(err)
			}
		}
	}
	return results, joinQueryErrors(queries, errs)
}

func joinQueryErrors(queries []Query, errs []error) error {
	var joined []error
	for n, err := range errs {
		if err != nil {
			joined = append(joined, &QueryError{Query: queries[n], Err: err})
		}
	}
	return errors.Join(joined...)
}

// normalizeName validates a query name and appends the root dot if missing.
func normalizeName(name string) (string, error) {
	if name == "" {
		return "", errors.New("unbound: empty name")
	}
	// A NUL would truncate the name when the guest turns it into a C string,
	// so "example.com.\x00.evil." would resolve example.com. while the host
	// matched the answer against the full string. Reject it, along with names
	// too long to be a valid presentation-format domain, before it reaches the
	// guest.
	if strings.IndexByte(name, 0) >= 0 {
		return "", errors.New("unbound: name contains NUL")
	}
	if name[len(name)-1] != '.' {
		name += "."
	}
	// The bound applies to the normalized name, the form the guest sees.
	if len(name) > 1024 {
		return "", errors.New("unbound: name too long")
	}
	return name, nil
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
		_, err = i.call(ctx, i.ioReady, uint64(uint32(ev.sid)), uint64(uint32(ev.flags)))
	case eventTimer:
		_, err = i.call(ctx, i.timerFired, uint64(ev.tid))
	}
	if err != nil {
		return i.kill(fmt.Errorf("unbound: dispatch event: %w", err))
	}
	return nil
}

// resultSize is the size of the guest's result structure (abi/layout.json).
const resultSize = 32

// pollResult collects the result of rid if it is ready, writing the guest
// result structure to p, a caller-allocated resultSize-byte buffer. A true
// fatal reports an error that killed the instance, as opposed to an outcome
// of this one query.
func (i *Instance) pollResult(ctx context.Context, rid int32, p uint32, qname string, qtype uint16) (res *Result, ready, fatal bool, err error) {
	// The guest call and the reads of the result structure it points into
	// must happen under one guest block: nothing may touch guest memory
	// once the module is closed and its memory unmapped. Only copies of
	// the buffers escape the block; i.kill takes the same lock, so it runs
	// on the collected error afterwards.
	var rc int32
	var secStatus, cbRcode uint32
	var why, packet []byte
	gerr := i.state.guest(func() error {
		out, err := i.resultGet.Call(ctx, uint64(uint32(rid)), uint64(p))
		if err != nil {
			return fmt.Errorf("unbound: result_get: %w", err)
		}
		rc = int32(uint32(out[0]))
		if rc <= 0 {
			return nil
		}
		b, ok := i.mod.Memory().Read(p, resultSize)
		if !ok {
			return errors.New("unbound: result structure outside guest memory")
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
		secStatus, cbRcode = word(0), word(4)
		if why, err = read(word(8), word(12)); err != nil {
			return err
		}
		packet, err = read(word(16), word(20))
		return err
	})
	if gerr != nil {
		return nil, false, true, i.kill(gerr)
	}
	if rc == 0 {
		return nil, false, false, nil
	}
	if rc < 0 {
		return nil, false, false, fmt.Errorf("unbound: result_get failed: wasi errno %d", -rc)
	}
	const secStatusSecure, secStatusBogus = 1, 2
	if secStatus == secStatusBogus {
		return nil, false, false, &BogusError{Reason: string(why), EDE: parseEDE(packet)}
	}
	const rcodeNoError, rcodeNXDomain = 0, 3
	// The libunbound callback rcode is only set for resolution errors;
	// for answers that did resolve, it is NOERROR and the DNS rcode
	// (NOERROR vs NXDOMAIN) is in the answer packet header, like
	// upstream's ub_resolve reads it from the reply flags.
	rcode := int(cbRcode)
	if rcode == rcodeNoError && len(packet) >= 4 {
		rcode = int(packet[3] & 0xf)
	}
	if rcode != rcodeNoError && rcode != rcodeNXDomain {
		return nil, false, false, &ResponseError{RCode: rcode, EDE: parseEDE(packet)}
	}
	res = &Result{
		Secure:       secStatus == secStatusSecure,
		NXDomain:     rcode == rcodeNXDomain,
		AnswerPacket: packet,
	}
	// HaveData and the typed records are computed host-side from the
	// answer packet, but only for NOERROR answers: an NXDOMAIN answer
	// cannot hold records of the queried type.
	if rcode == rcodeNoError {
		if err := res.parseAnswer(qname, qtype); err != nil {
			return nil, false, false, err
		}
	}
	return res, true, false, nil
}

func (i *Instance) allocWrite(ctx context.Context, b []byte) (uint32, error) {
	var p uint32
	err := i.state.guest(func() error {
		n := len(b)
		if n == 0 {
			n = 1
		}
		out, err := i.alloc.Call(ctx, uint64(n))
		if err != nil {
			return fmt.Errorf("unbound: alloc: %w", err)
		}
		p = uint32(out[0])
		if p == 0 {
			return errors.New("unbound: guest allocation failed")
		}
		if len(b) > 0 && !i.mod.Memory().Write(p, b) {
			return errors.New("unbound: guest allocation outside memory")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return p, nil
}

func (i *Instance) free(ctx context.Context, p, n uint32) {
	if p != 0 {
		_, _ = i.call(ctx, i.dealloc, uint64(p), uint64(n))
	}
}

func (i *Instance) cancel(ctx context.Context, rid int32) {
	if !i.closed.Load() {
		_, _ = i.call(ctx, i.resolveCancel, uint64(uint32(rid)))
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
// methods return [ErrClosed]. A Close concurrent with a Resolve waits for the
// guest call in flight, if any, before freeing the sandbox memory; guest
// calls always return promptly, because no host import blocks.
func (i *Instance) Close(ctx context.Context) error {
	if i == nil || !i.closed.CompareAndSwap(false, true) {
		return nil
	}
	i.state.close()
	i.runtime.removeState(i.name)
	return i.state.closeModule(ctx)
}
