package unbound

import (
	"context"
	"crypto/rand"
	"log/slog"
	"time"

	"github.com/tetratelabs/wazero/api"
)

// instantiateWASI registers the minimal wasi_snapshot_preview1 surface the
// guest links against: clock, entropy, stdout/stderr, and exit. Everything
// filesystem-shaped is refused with ENOSYS, and poll_oneoff traps, because
// readiness is only ever delivered through the unbound_wasm io_ready and
// timer_fired exports. A stock WASI provider must never be linked instead;
// it would bypass the capability model.
func (r *Runtime) instantiateWASI(ctx context.Context) error {
	b := r.wazero.NewHostModuleBuilder("wasi_snapshot_preview1")
	export := func(name string, fn any) { b.NewFunctionBuilder().WithFunc(fn).Export(name) }

	export("clock_time_get", r.wasiClockTimeGet)
	export("random_get", r.wasiRandomGet)
	export("fd_write", r.wasiFDWrite)
	export("proc_exit", func(ctx context.Context, m api.Module, code uint32) {
		_ = m.CloseWithExitCode(ctx, code)
	})

	// The environment is reported as empty rather than absent, because
	// wasi-libc initialization insists on reading it.
	export("environ_sizes_get", func(ctx context.Context, m api.Module, count, size uint32) uint32 {
		if !m.Memory().WriteUint32Le(count, 0) || !m.Memory().WriteUint32Le(size, 0) {
			return wasiEFAULT
		}
		return wasiSuccess
	})
	export("environ_get", func(context.Context, api.Module, uint32, uint32) uint32 { return wasiSuccess })

	// Linked by wasi-libc but unreachable: no filesystem or descriptor
	// capability is provided.
	export("fd_close", func(context.Context, api.Module, uint32) uint32 { return wasiENOSYS })
	export("fd_fdstat_get", func(context.Context, api.Module, uint32, uint32) uint32 { return wasiENOSYS })
	export("fd_fdstat_set_flags", func(context.Context, api.Module, uint32, uint32) uint32 { return wasiENOSYS })
	export("fd_prestat_get", func(context.Context, api.Module, uint32, uint32) uint32 { return wasiENOSYS })
	export("fd_prestat_dir_name", func(context.Context, api.Module, uint32, uint32, uint32) uint32 { return wasiENOSYS })
	export("fd_read", func(context.Context, api.Module, uint32, uint32, uint32, uint32) uint32 { return wasiENOSYS })
	export("fd_seek", func(context.Context, api.Module, uint32, uint64, uint32, uint32) uint32 { return wasiENOSYS })
	export("fd_sync", func(context.Context, api.Module, uint32) uint32 { return wasiENOSYS })
	export("path_open", func(context.Context, api.Module, uint32, uint32, uint32, uint32, uint32, uint64, uint64, uint32, uint32) uint32 {
		return wasiENOSYS
	})
	export("path_rename", func(context.Context, api.Module, uint32, uint32, uint32, uint32, uint32, uint32) uint32 {
		return wasiENOSYS
	})
	export("path_unlink_file", func(context.Context, api.Module, uint32, uint32, uint32) uint32 { return wasiENOSYS })

	export("poll_oneoff", func(context.Context, api.Module, uint32, uint32, uint32, uint32) uint32 {
		panic("unbound: forbidden WASI poll_oneoff")
	})

	_, err := b.Instantiate(ctx)
	return err
}

func (r *Runtime) wasiClockTimeGet(ctx context.Context, m api.Module, clockID uint32, precision uint64, out uint32) uint32 {
	var ns uint64
	switch clockID {
	case 0: // realtime
		if h := r.state(m).replay; h != nil {
			ns = uint64(h.nowWall().UnixNano())
			break
		}
		ns = uint64(time.Now().UnixNano())
	case 1: // monotonic
		if h := r.state(m).replay; h != nil {
			ns = uint64(h.nowMono().Nanoseconds())
			break
		}
		ns = uint64(time.Since(monotonicStart).Nanoseconds())
	default:
		return wasiEINVAL
	}
	if !m.Memory().WriteUint64Le(out, ns) {
		return wasiEFAULT
	}
	return wasiSuccess
}

func (r *Runtime) wasiRandomGet(ctx context.Context, m api.Module, ptr, n uint32) uint32 {
	// Reject a request that cannot land in guest memory before allocating, so
	// a bogus length cannot make the host allocate far more than the guest's
	// own memory.
	if uint64(ptr)+uint64(n) > uint64(m.Memory().Size()) {
		return wasiEFAULT
	}
	buf := make([]byte, n)
	rand.Read(buf)
	if !m.Memory().Write(ptr, buf) {
		return wasiEFAULT
	}
	return wasiSuccess
}

// wasiFDWrite accepts only stdout and stderr and forwards each write to the
// instance logger as a single message, at Info or Error respectively.
func (r *Runtime) wasiFDWrite(ctx context.Context, m api.Module, fd, iovs, count, written uint32) uint32 {
	if fd != 1 && fd != 2 {
		return wasiEBADF
	}
	var msg []byte
	for n := range count {
		base := iovs + n*8
		ptr, ok1 := m.Memory().ReadUint32Le(base)
		length, ok2 := m.Memory().ReadUint32Le(base + 4)
		if !ok1 || !ok2 {
			return wasiEFAULT
		}
		part, ok := m.Memory().Read(ptr, length)
		if !ok {
			return wasiEFAULT
		}
		msg = append(msg, part...)
	}
	if !m.Memory().WriteUint32Le(written, uint32(len(msg))) {
		return wasiEFAULT
	}
	level := slog.LevelInfo
	if fd == 2 {
		level = slog.LevelError
	}
	r.state(m).log.Log(ctx, level, string(msg))
	return wasiSuccess
}
