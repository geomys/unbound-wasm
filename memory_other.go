//go:build !unix

package unbound

import "github.com/tetratelabs/wazero/experimental"

// Without mmap, wazero's default Go-slice memory is used.
var guestMemoryAllocator experimental.MemoryAllocator
