//go:build unix

package unbound

import (
	"math"

	"github.com/tetratelabs/wazero/experimental"
	"golang.org/x/sys/unix"
)

// guestMemoryAllocator backs guest linear memories with anonymous mmap
// regions instead of Go-heap slices. The maximum (the Runtime's memory
// limit) is reserved up front, so growth never copies or moves the buffer;
// the reservation is virtual, and pages consume physical memory only once
// the guest touches them. Free returns the pages to the OS as soon as the
// instance closes, without waiting for the garbage collector.
var guestMemoryAllocator experimental.MemoryAllocator = experimental.MemoryAllocatorFunc(mmapMemory)

func mmapMemory(_, maxBytes uint64) experimental.LinearMemory {
	if maxBytes > math.MaxInt {
		return &sliceMemory{}
	}
	buf, err := unix.Mmap(-1, 0, int(maxBytes),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return &sliceMemory{}
	}
	return &mmapMemoryRegion{buf: buf}
}

type mmapMemoryRegion struct {
	buf []byte // the full reservation; wasm sees prefixes of it
}

func (m *mmapMemoryRegion) Reallocate(size uint64) []byte {
	if size > uint64(len(m.buf)) {
		return nil
	}
	return m.buf[:size]
}

func (m *mmapMemoryRegion) Free() {
	if m.buf != nil {
		_ = unix.Munmap(m.buf)
		m.buf = nil
	}
}

// sliceMemory reallocates on growth like wazero's default memory. It is
// the fallback when a reservation cannot be mapped.
type sliceMemory struct{ buf []byte }

func (m *sliceMemory) Reallocate(size uint64) []byte {
	if size > uint64(cap(m.buf)) {
		b := make([]byte, size)
		copy(b, m.buf)
		m.buf = b
		return b
	}
	m.buf = m.buf[:size]
	return m.buf
}

func (m *sliceMemory) Free() { m.buf = nil }
