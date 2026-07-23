//go:build !unix

package unbound

import "github.com/tetratelabs/wazero/experimental"

// Without mmap, wazero's default Go-slice memory is used, and there is no
// copy-on-write image mapping, so the zygote stays disabled.
var guestMemoryAllocator experimental.MemoryAllocator

func newImageAllocator(*zygote) experimental.MemoryAllocator { return nil }
