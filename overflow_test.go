package unbound

import (
	"errors"
	"testing"
	"time"
)

// TestEnqueueOverflowFailsInsteadOfBlocking guards the event-queue deadlock
// fix: when the bounded buffer is full, enqueue must fail the instance so a
// Resolve waiting for events wakes, rather than block the caller. On the guest
// export path (a synchronous sock_connect or sock_recv) blocking would wedge
// the dispatcher goroutine, which wazero cannot preempt, past the deadline.
func TestEnqueueOverflowFailsInsteadOfBlocking(t *testing.T) {
	s := newInstanceState(nil)
	for i := 0; i < cap(s.events); i++ {
		s.events <- hostEvent{kind: eventTimer, tid: uint64(i)}
	}

	done := make(chan struct{})
	go func() {
		s.enqueue(hostEvent{kind: eventIO, sid: 1, flags: ioRead})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("enqueue blocked on a full buffer instead of failing the instance")
	}

	select {
	case <-s.done:
	default:
		t.Fatal("overflow did not shut the instance down")
	}
	if !errors.Is(s.err, errEventQueueOverflow) {
		t.Fatalf("s.err = %v, want errEventQueueOverflow", s.err)
	}
}
