//go:build unix

package unbound

import (
	"math"
	"unsafe"

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

// newImageAllocator returns an allocator that backs each linear memory
// with a private (copy-on-write) mapping of the zygote's image file:
// clones physically share every page until they write it, and start with
// the template's warmed-up memory contents. Instantiation still writes
// the module's data segments over the mapping; the caller restores those
// ranges from the image (see Runtime.newClone).
func newImageAllocator(z *zygote) experimental.MemoryAllocator {
	return experimental.MemoryAllocatorFunc(func(_, maxBytes uint64) experimental.LinearMemory {
		if maxBytes <= math.MaxInt && int(maxBytes) >= len(z.image) {
			if buf, err := unix.Mmap(-1, 0, int(maxBytes),
				unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON); err == nil {
				_, err := unix.MmapPtr(int(z.file.Fd()), 0,
					unsafe.Pointer(unsafe.SliceData(buf)), uintptr(len(z.image)),
					unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_FIXED)
				if err == nil {
					return &imageMemory{buf: buf, imageLen: len(z.image)}
				}
				_ = unix.Munmap(buf)
			}
		}
		// Allocate has no error path, and returning nil would break
		// instantiation; degrade to a private Go-heap copy of the image.
		m := &sliceMemory{buf: make([]byte, len(z.image))}
		copy(m.buf, z.image)
		return m
	})
}

// imageMemory is one clone's linear memory: an anonymous reservation with
// the image mapped copy-on-write over its start. Its length never drops
// below the image, whose contents the instance depends on.
type imageMemory struct {
	buf      []byte // the full reservation
	imageLen int
}

func (m *imageMemory) Reallocate(size uint64) []byte {
	if size < uint64(m.imageLen) {
		size = uint64(m.imageLen)
	}
	if size > uint64(len(m.buf)) {
		return nil
	}
	return m.buf[:size]
}

func (m *imageMemory) Free() {
	if m.buf != nil {
		// Unmaps both the reservation and the image overlay within it.
		_ = unix.Munmap(m.buf)
		m.buf = nil
	}
}

// sliceMemory reallocates on growth like wazero's default memory. It is
// the fallback when a reservation cannot be mapped. Its buffer may start
// non-empty (an image copy); Reallocate never shrinks below that.
type sliceMemory struct{ buf []byte }

func (m *sliceMemory) Reallocate(size uint64) []byte {
	if size < uint64(len(m.buf)) {
		size = uint64(len(m.buf))
	}
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
