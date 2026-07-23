package unbound

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero/api"
)

var monotonicStart = time.Now()

type eventKind uint8

const (
	eventIO eventKind = iota + 1
	eventTimer
)

type hostEvent struct {
	kind  eventKind
	sid   int32
	flags int32
	tid   uint64
}

// replayHooks replaces real time and networking for the resolution scenario
// tests (replay_test.go), which need scripted servers and a virtual clock.
// Production instances always leave instanceState.replay nil.
type replayHooks interface {
	nowWall() time.Time
	nowMono() time.Duration
	timerStart(s *instanceState, ms int32) uint64
	timerStop(tid uint64)
	// connect and sendTo run instead of the real network operations
	// (and instead of the egress policy: the hooks are the network).
	connect(s *instanceState, sock *hostSocket, remote netip.AddrPort) int32
	sendTo(s *instanceState, sock *hostSocket, remote netip.AddrPort, data []byte) int32
	localPort(sock *hostSocket) int32
}

type instanceState struct {
	log        *slog.Logger
	mod        api.Module
	replay     replayHooks
	events     chan hostEvent
	done       chan struct{}
	once       sync.Once
	err        error // shutdown cause, set before done is closed; nil on ordinary close
	guestMu    sync.Mutex
	modDead    bool // set under guestMu once the module is closed
	socketsMu  sync.Mutex
	sockets    map[int32]*hostSocket
	nextSocket int32
	timersMu   sync.Mutex
	timers     map[uint64]*time.Timer
	nextTimer  atomic.Uint64
}

// guest runs fn holding the lock that closeModule takes before closing the
// wasm module, so the module — and with it the mmap backing its linear
// memory — cannot be freed while fn calls into the guest or reads guest
// memory. After closeModule, guest fails with ErrClosed.
func (s *instanceState) guest(fn func() error) error {
	s.guestMu.Lock()
	defer s.guestMu.Unlock()
	if s.modDead {
		return ErrClosed
	}
	return fn()
}

// closeModule closes the wasm module, waiting first for any in-flight
// guest call. The wait is short: guest calls never block, because no host
// import blocks. Closing the module frees its linear memory, which the
// memory allocator unmaps, so it must be unreachable first: that is what
// guestMu guarantees. Callers may not hold guestMu.
func (s *instanceState) closeModule(ctx context.Context) error {
	s.guestMu.Lock()
	defer s.guestMu.Unlock()
	s.modDead = true
	if s.mod == nil {
		return nil
	}
	return s.mod.Close(ctx)
}

// errEventQueueOverflow fails an instance whose bounded event buffer filled
// up. It is not a normal condition: it means a readiness event had to be
// dropped, so the guest's view of I/O is no longer trustworthy.
var errEventQueueOverflow = errors.New("unbound: host event queue overflowed")

func newInstanceState(log *slog.Logger) *instanceState {
	return &instanceState{
		log:        log,
		events:     make(chan hostEvent, 1024),
		done:       make(chan struct{}),
		sockets:    make(map[int32]*hostSocket),
		nextSocket: 1,
		timers:     make(map[uint64]*time.Timer),
	}
}

func (s *instanceState) enqueue(ev hostEvent) {
	select {
	case s.events <- ev:
	case <-s.done:
	default:
		// The buffer is full and cannot drain right now. This enqueue may be
		// running synchronously inside a guest export (a sock_connect or
		// sock_recv host call, for example), where blocking would wedge the
		// single dispatcher goroutine — and wazero cannot preempt a host call
		// blocked in Go, so the wedge would outlive the context deadline. Fail
		// the instance instead; Resolve then returns and the caller retries on
		// a fresh one.
		s.fail(errEventQueueOverflow)
	}
}

// close tears the instance down after ordinary use.
func (s *instanceState) close() { s.shutdown(nil) }

// fail tears the instance down because of err, waking a Resolve that is
// blocked waiting for events. The first cause wins; a later ordinary close
// does not overwrite it.
func (s *instanceState) fail(err error) { s.shutdown(err) }

func (s *instanceState) shutdown(err error) {
	s.once.Do(func() {
		s.err = err
		close(s.done)
		s.timersMu.Lock()
		for _, t := range s.timers {
			t.Stop()
		}
		s.timers = nil
		s.timersMu.Unlock()
		s.socketsMu.Lock()
		for _, sock := range s.sockets {
			sock.close()
		}
		s.sockets = nil
		s.socketsMu.Unlock()
	})
}

// instantiateHostModules registers the unbound_wasm host module, one Go
// function per import in abi/README.md. These are the only capabilities a
// guest has, along with the restricted WASI module.
func (r *Runtime) instantiateHostModules(ctx context.Context) error {
	b := r.wazero.NewHostModuleBuilder("unbound_wasm")
	export := func(name string, fn any) { b.NewFunctionBuilder().WithFunc(fn).Export(name) }

	export("sock_open", func(ctx context.Context, m api.Module, af, typ int32) int32 {
		return r.state(m).sockOpen(af, typ)
	})
	export("sock_bind", func(ctx context.Context, m api.Module, sid, port int32) int32 {
		return r.state(m).sockBind(ctx, sid, port)
	})
	export("sock_connect", r.hostSockConnect)
	export("sock_send", r.hostSockSend)
	export("sock_send_to", r.hostSockSendTo)
	export("sock_recv", func(ctx context.Context, m api.Module, sid int32, ptr, cap uint32) int32 {
		return r.state(m).sockRecv(m, sid, ptr, cap, false, 0, 0)
	})
	export("sock_recv_from", func(ctx context.Context, m api.Module, sid int32, ptr, cap, ipOut, portOut uint32) int32 {
		return r.state(m).sockRecv(m, sid, ptr, cap, true, ipOut, portOut)
	})
	export("sock_error", func(ctx context.Context, m api.Module, sid int32) int32 {
		return r.state(m).sockError(sid)
	})
	export("sock_local_port", func(ctx context.Context, m api.Module, sid int32) int32 {
		return r.state(m).sockLocalPort(sid)
	})
	export("sock_close", func(ctx context.Context, m api.Module, sid int32) {
		r.state(m).sockClose(sid)
	})

	export("timer_start", func(ctx context.Context, m api.Module, ms int32) int64 {
		return int64(r.state(m).timerStart(ms))
	})
	export("timer_stop", func(ctx context.Context, m api.Module, tid int64) {
		r.state(m).timerStop(uint64(tid))
	})
	export("now_wall_ms", func(ctx context.Context, m api.Module) int64 {
		if h := r.state(m).replay; h != nil {
			return h.nowWall().UnixMilli()
		}
		return time.Now().UnixMilli()
	})
	export("now_mono_ms", func(ctx context.Context, m api.Module) int64 {
		if h := r.state(m).replay; h != nil {
			return h.nowMono().Milliseconds()
		}
		return time.Since(monotonicStart).Milliseconds()
	})

	export("entropy", r.hostEntropy)
	export("crypto_supported", func(ctx context.Context, m api.Module, alg uint32) int32 {
		return b2i(cryptoSupported(alg))
	})
	export("crypto_verify", r.hostCryptoVerify)
	export("crypto_digest", r.hostCryptoDigest)
	export("nsec3_hash", r.hostNSEC3Hash)

	export("log_msg", r.hostLogMsg)
	export("abort_msg", r.hostAbortMsg)

	if _, err := b.Instantiate(ctx); err != nil {
		return err
	}
	return r.instantiateWASI(ctx)
}

func (r *Runtime) hostSockConnect(ctx context.Context, m api.Module, sid int32, ipPtr, ipLen uint32, port int32) int32 {
	ip, ok := readAddr(m, ipPtr, ipLen)
	if !ok {
		return -wasiEFAULT
	}
	return r.state(m).sockConnect(ctx, sid, ip, port)
}

func (r *Runtime) hostSockSend(ctx context.Context, m api.Module, sid int32, ptr, n uint32) int32 {
	buf, ok := readCopy(m, ptr, n)
	if !ok {
		return -wasiEFAULT
	}
	return r.state(m).sockSend(ctx, sid, buf)
}

func (r *Runtime) hostSockSendTo(ctx context.Context, m api.Module, sid int32, ipPtr, ipLen uint32, port int32, ptr, n uint32) int32 {
	ip, ok := readAddr(m, ipPtr, ipLen)
	if !ok {
		return -wasiEFAULT
	}
	buf, ok := readCopy(m, ptr, n)
	if !ok {
		return -wasiEFAULT
	}
	return r.state(m).sockSendTo(ctx, sid, ip, port, buf)
}

// hostEntropy panics rather than returning an error: entropy is void in the
// ABI, and a guest that could swallow an entropy failure would fall back to
// predictable query IDs and ports.
func (r *Runtime) hostEntropy(ctx context.Context, m api.Module, ptr, n uint32) {
	// Reject a request that cannot land in guest memory before allocating, so
	// a bogus length cannot make the host allocate far more than the guest's
	// own memory.
	if uint64(ptr)+uint64(n) > uint64(m.Memory().Size()) {
		panic("unbound entropy: guest memory out of range")
	}
	buf := make([]byte, n)
	rand.Read(buf)
	if !m.Memory().Write(ptr, buf) {
		panic("unbound entropy: guest memory out of range")
	}
}

func (r *Runtime) hostCryptoVerify(ctx context.Context, m api.Module, alg, kp, kn, dp, dn, sp, sn uint32) int32 {
	key, ok1 := readCopy(m, kp, kn)
	data, ok2 := readCopy(m, dp, dn)
	sig, ok3 := readCopy(m, sp, sn)
	if !ok1 || !ok2 || !ok3 {
		return 0
	}
	return b2i(cryptoVerify(alg, key, data, sig))
}

func (r *Runtime) hostCryptoDigest(ctx context.Context, m api.Module, alg, ptr, n, out uint32) int32 {
	data, ok := readCopy(m, ptr, n)
	if !ok {
		return 0
	}
	digest, ok := cryptoDigest(alg, data)
	if !ok || !m.Memory().Write(out, digest) {
		return 0
	}
	return 1
}

func (r *Runtime) hostNSEC3Hash(ctx context.Context, m api.Module, sp, sn, iters, np, nn, out uint32) int32 {
	salt, ok1 := readCopy(m, sp, sn)
	name, ok2 := readCopy(m, np, nn)
	if !ok1 || !ok2 {
		return 0
	}
	hash, ok := nsec3Hash(salt, iters, name)
	if !ok || !m.Memory().Write(out, hash) {
		return 0
	}
	return 1
}

func (r *Runtime) hostLogMsg(ctx context.Context, m api.Module, level int32, ptr, n uint32) {
	msg, ok := readCopy(m, ptr, n)
	if !ok {
		return
	}
	r.state(m).log.Log(ctx, mapLogLevel(level), string(msg))
}

// hostAbortMsg logs the guest's dying words and traps, which kills the
// calling instance.
func (r *Runtime) hostAbortMsg(ctx context.Context, m api.Module, code int32, ptr, n uint32) {
	msg, _ := readCopy(m, ptr, n)
	r.state(m).log.Log(ctx, slog.LevelError, string(msg))
	panic(fmt.Sprintf("unbound guest abort %d: %s", code, msg))
}

func b2i(b bool) int32 {
	if b {
		return 1
	}
	return 0
}

func readCopy(m api.Module, ptr, n uint32) ([]byte, bool) {
	b, ok := m.Memory().Read(ptr, n)
	if !ok {
		return nil, false
	}
	return append([]byte(nil), b...), true
}

func readAddr(m api.Module, ptr, n uint32) (netip.Addr, bool) {
	b, ok := readCopy(m, ptr, n)
	if !ok {
		return netip.Addr{}, false
	}
	if n == 4 {
		var a [4]byte
		copy(a[:], b)
		return netip.AddrFrom4(a), true
	}
	if n == 16 {
		var a [16]byte
		copy(a[:], b)
		return netip.AddrFrom16(a), true
	}
	return netip.Addr{}, false
}

func writeAddr(m api.Module, ptr uint32, addr netip.Addr) bool {
	var out [16]byte
	if addr.Is4() {
		a := addr.As4()
		copy(out[:4], a[:])
	} else {
		a := addr.As16()
		copy(out[:], a[:])
	}
	return m.Memory().Write(ptr, out[:])
}

func mapLogLevel(v int32) slog.Level {
	switch {
	case v <= 0:
		return slog.LevelDebug
	case v == 1:
		return slog.LevelInfo
	case v == 2:
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}

func putU32(m api.Module, ptr, value uint32) bool {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], value)
	return m.Memory().Write(ptr, b[:])
}

func (s *instanceState) timerStart(ms int32) uint64 {
	if ms < 0 {
		ms = 0
	}
	if s.replay != nil {
		return s.replay.timerStart(s, ms)
	}
	tid := s.nextTimer.Add(1)
	// Hold timersMu across creating and inserting the timer so its callback,
	// which also takes timersMu, cannot run its delete before the insert. A
	// zero-millisecond timer fires almost immediately, so without this the
	// callback could delete tid before it was recorded and leave a dead entry
	// in the map until instance close. time.AfterFunc only schedules; it does
	// not run the callback synchronously, so holding the lock is safe.
	s.timersMu.Lock()
	defer s.timersMu.Unlock()
	if s.timers == nil {
		return 0 // instance closed; ABI reports timer_start failure as 0
	}
	// maxTimersPerInstance backstops a memory-corrupted guest from exhausting
	// host timers; a well-behaved guest holds far fewer.
	const maxTimersPerInstance = 8192
	if len(s.timers) >= maxTimersPerInstance {
		return 0
	}
	t := time.AfterFunc(time.Duration(ms)*time.Millisecond, func() {
		s.timersMu.Lock()
		if s.timers != nil {
			delete(s.timers, tid)
		}
		s.timersMu.Unlock()
		s.enqueue(hostEvent{kind: eventTimer, tid: tid})
	})
	s.timers[tid] = t
	return tid
}

func (s *instanceState) timerStop(tid uint64) {
	if s.replay != nil {
		s.replay.timerStop(tid)
		return
	}
	s.timersMu.Lock()
	if t := s.timers[tid]; t != nil {
		t.Stop()
		delete(s.timers, tid)
	}
	s.timersMu.Unlock()
}
