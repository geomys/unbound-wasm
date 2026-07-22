package unbound

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// WASI errno values (wasi_snapshot_preview1), the numbering used across the
// ABI: the guest's libc is wasi-libc, so host calls must fail with these
// values, not the host operating system's errno values.
const (
	wasiSuccess       = 0
	wasiEACCES        = 2
	wasiEADDRINUSE    = 3
	wasiEADDRNOTAVAIL = 4
	wasiEAFNOSUPPORT  = 5
	wasiEAGAIN        = 6
	wasiEBADF         = 8
	wasiECONNREFUSED  = 14
	wasiECONNRESET    = 15
	wasiEFAULT        = 21
	wasiEHOSTUNREACH  = 23
	wasiEINVAL        = 28
	wasiEIO           = 29
	wasiENETUNREACH   = 40
	wasiEMFILE        = 41
	wasiENOSYS        = 52
	wasiENOTCONN      = 53
	wasiEPIPE         = 64
	wasiETIMEDOUT     = 73
)

// wasiErrno converts an error from the Go network stack to a WASI errno.
// Unrecognized errors report as EIO.
func wasiErrno(err error) int32 {
	if err == nil {
		return wasiSuccess
	}
	var op *net.OpError
	if errors.As(err, &op) {
		err = op.Err
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EACCES:
			return wasiEACCES
		case syscall.EADDRINUSE:
			return wasiEADDRINUSE
		case syscall.EADDRNOTAVAIL:
			return wasiEADDRNOTAVAIL
		case syscall.EAGAIN:
			return wasiEAGAIN
		case syscall.EBADF:
			return wasiEBADF
		case syscall.ECONNREFUSED:
			return wasiECONNREFUSED
		case syscall.ECONNRESET:
			return wasiECONNRESET
		case syscall.EHOSTUNREACH:
			return wasiEHOSTUNREACH
		case syscall.EINVAL:
			return wasiEINVAL
		case syscall.ENETUNREACH:
			return wasiENETUNREACH
		case syscall.ENOTCONN:
			return wasiENOTCONN
		case syscall.EPIPE:
			return wasiEPIPE
		case syscall.ETIMEDOUT:
			return wasiETIMEDOUT
		default:
			return wasiEIO
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return wasiETIMEDOUT
	}
	if errors.Is(err, net.ErrClosed) {
		return wasiEBADF
	}
	return wasiEIO
}
