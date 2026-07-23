package unbound

// The zygote: the first NewInstance builds a template instance, runs the
// guest's warmup export (context creation is otherwise deferred to the
// first resolution), and snapshots its linear memory. Later instances are
// clones: their memory starts as a private copy-on-write mapping of the
// snapshot, so they skip all initialization work and physically share
// untouched pages with every other clone. See memory_unix.go for the
// mapping; on platforms without it, every instance takes the full path.
//
// Cloning memory is sound because the guest keeps all state in linear
// memory: after an export returns, the only mutable wasm global, the stack
// pointer, is back at its initial value. It is safe because a warmed
// instance holds no host resource identifiers (checked below) and the
// guest's randomness is stateless, drawn from the entropy import at every
// use, so clones share no seed.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/tetratelabs/wazero/experimental"
)

// disableZygote forces every instance through the full initialization path.
// It is a test hook to cover the non-template path on platforms that would
// otherwise always clone.
var disableZygote bool

type zygote struct {
	alloc experimental.MemoryAllocator
	file  *os.File // unlinked file holding image, mapped by clones
	image []byte
	// segs are the module's data segment ranges. Instantiation writes the
	// segments (the pristine initial data) over the mapped image, so these
	// ranges must be restored from the image afterwards.
	segs []segRange
}

type segRange struct{ off, len uint32 }

// initZygote runs once per Runtime, from the first NewInstance. On success
// r.zygote is set and instances are cloned; if the environment cannot
// support cloning, r.zygote stays nil and instances take the full path. An
// error from the guest's own setup (bad configuration, failed warmup) is
// recorded in r.zygoteErr and fails every NewInstance: it would fail any
// instance, just later and less clearly.
func (r *Runtime) initZygote(ctx context.Context) {
	if disableZygote || guestMemoryAllocator == nil {
		return
	}
	segs, err := parseDataSegments(embeddedModule)
	if err != nil {
		r.cfg.Log.Debug("unbound: zygote disabled", "err", err)
		return
	}

	inst, err := r.newFullInstance(ctx)
	if err != nil {
		r.zygoteErr = err
		return
	}
	defer inst.Close(ctx)
	out, err := inst.call(ctx, inst.warmup)
	if err != nil {
		r.zygoteErr = fmt.Errorf("unbound: warmup: %w", err)
		return
	}
	if rc := int32(uint32(out[0])); rc != 0 {
		r.zygoteErr = fmt.Errorf("unbound: guest warmup failed: wasi errno %d", -rc)
		return
	}
	// The ABI promises a warmed instance holds no host resource
	// identifiers; a socket or timer here would be dangling in every
	// clone, so verify rather than trust.
	inst.state.socketsMu.Lock()
	sockets := len(inst.state.sockets)
	inst.state.socketsMu.Unlock()
	inst.state.timersMu.Lock()
	timers := len(inst.state.timers)
	inst.state.timersMu.Unlock()
	if sockets != 0 || timers != 0 {
		r.zygoteErr = fmt.Errorf("unbound: warmed template holds %d sockets and %d timers", sockets, timers)
		return
	}

	var image []byte
	if err := inst.state.guest(func() error {
		mem := inst.mod.Memory()
		view, ok := mem.Read(0, mem.Size())
		if !ok {
			return errors.New("unbound: reading template memory failed")
		}
		image = append([]byte(nil), view...)
		return nil
	}); err != nil {
		r.zygoteErr = err
		return
	}
	for _, s := range segs {
		if uint64(s.off)+uint64(s.len) > uint64(len(image)) {
			r.zygoteErr = errors.New("unbound: data segment outside template memory")
			return
		}
	}

	f, err := os.CreateTemp("", "unbound-wasm-zygote-*")
	if err != nil {
		r.cfg.Log.Debug("unbound: zygote disabled", "err", err)
		return
	}
	os.Remove(f.Name())
	if _, err := f.Write(image); err != nil {
		f.Close()
		r.cfg.Log.Debug("unbound: zygote disabled", "err", err)
		return
	}
	z := &zygote{file: f, image: image, segs: segs}
	z.alloc = newImageAllocator(z)
	if z.alloc == nil {
		f.Close()
		return
	}
	r.zygote = z
}

// newClone instantiates the module over a copy-on-write mapping of the
// template image: no start functions run and init is not called, because
// the image is already past both. Only the data segments, which wazero
// writes during instantiation, must be restored from the image.
func (r *Runtime) newClone(ctx context.Context) (*Instance, error) {
	z := r.zygote
	inst, err := r.newModuleInstance(ctx, z.alloc, false)
	if err != nil {
		return nil, err
	}
	if err := inst.state.guest(func() error {
		mem := inst.mod.Memory()
		if got := mem.Size(); uint64(got) != uint64(len(z.image)) {
			return fmt.Errorf("unbound: clone memory is %d bytes, template %d", got, len(z.image))
		}
		for _, s := range z.segs {
			if !mem.Write(s.off, z.image[s.off:s.off+s.len]) {
				return errors.New("unbound: restoring data segment failed")
			}
		}
		return nil
	}); err != nil {
		inst.Close(ctx)
		return nil, err
	}
	// Redraw the entropy-derived state baked into the image, so clones do
	// not share it. This must follow the segment restore, which would
	// otherwise write the template's values back over the fresh ones.
	if _, err := inst.call(ctx, inst.reseed); err != nil {
		inst.Close(ctx)
		return nil, fmt.Errorf("unbound: reseed: %w", err)
	}
	if err := inst.checkABIVersion(ctx); err != nil {
		inst.Close(ctx)
		return nil, err
	}
	return inst, nil
}

// parseDataSegments returns the ranges the wasm binary's active data
// segments cover. It fails on anything unexpected — passive segments, or
// offsets that are not i32.const — and the caller then skips cloning.
func parseDataSegments(wasm []byte) ([]segRange, error) {
	if len(wasm) < 8 || string(wasm[0:4]) != "\x00asm" ||
		binary.LittleEndian.Uint32(wasm[4:8]) != 1 {
		return nil, errors.New("not a wasm v1 binary")
	}
	p := 8
	uleb := func() (uint64, error) {
		var v uint64
		var shift uint
		for {
			if p >= len(wasm) || shift > 63 {
				return 0, errors.New("bad leb128")
			}
			b := wasm[p]
			p++
			v |= uint64(b&0x7f) << shift
			if b&0x80 == 0 {
				return v, nil
			}
			shift += 7
		}
	}
	var segs []segRange
	for p < len(wasm) {
		id := wasm[p]
		p++
		size, err := uleb()
		if err != nil || uint64(len(wasm)-p) < size {
			return nil, errors.New("bad section size")
		}
		end := p + int(size)
		if id != 11 { // everything but the data section
			p = end
			continue
		}
		count, err := uleb()
		if err != nil {
			return nil, err
		}
		for range count {
			flags, err := uleb()
			if err != nil {
				return nil, err
			}
			if flags != 0 {
				// 1 is passive, 2 names a memory index; the
				// module uses neither.
				return nil, fmt.Errorf("data segment flags %d", flags)
			}
			// The offset expression: i32.const value, end.
			if p >= len(wasm) || wasm[p] != 0x41 {
				return nil, errors.New("data segment offset is not i32.const")
			}
			p++
			var off int64
			var shift uint
			for { // signed leb128
				if p >= len(wasm) || shift > 63 {
					return nil, errors.New("bad sleb128")
				}
				b := wasm[p]
				p++
				off |= int64(b&0x7f) << shift
				shift += 7
				if b&0x80 == 0 {
					if b&0x40 != 0 && shift < 64 {
						off |= -1 << shift
					}
					break
				}
			}
			if p >= len(wasm) || wasm[p] != 0x0b {
				return nil, errors.New("data segment offset expression too long")
			}
			p++
			n, err := uleb()
			if err != nil {
				return nil, err
			}
			if off < 0 || off > 1<<32-1 || n > 1<<32-1 {
				return nil, errors.New("data segment out of range")
			}
			p += int(n)
			if p > end {
				return nil, errors.New("data segment overflows section")
			}
			segs = append(segs, segRange{off: uint32(off), len: uint32(n)})
		}
		p = end
	}
	return segs, nil
}
