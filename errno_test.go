package unbound

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestWASIErrno(t *testing.T) {
	// The guest's wasi-libc uses WASI errno numbering, which does not
	// match the host operating system's: returning syscall values raw
	// would hand the guest garbage.
	for _, tt := range []struct {
		err  error
		want int32
	}{
		{nil, wasiSuccess},
		{syscall.EAGAIN, wasiEAGAIN},
		{&net.OpError{Op: "read", Err: syscall.ECONNREFUSED}, wasiECONNREFUSED},
		{context.DeadlineExceeded, wasiETIMEDOUT},
		{net.ErrClosed, wasiEBADF},
		{errors.New("inscrutable"), wasiEIO},
	} {
		if got := wasiErrno(tt.err); got != tt.want {
			t.Errorf("wasiErrno(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}
