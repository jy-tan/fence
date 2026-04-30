//go:build linux

package sandbox

import (
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestArgvRunnerShutdown_BeginIsIdempotent(t *testing.T) {
	s, err := newArgvRunnerShutdown()
	if err != nil {
		t.Fatalf("newArgvRunnerShutdown: %v", err)
	}
	defer s.Close()

	if s.Begun() {
		t.Fatal("expected Begun()=false before Begin()")
	}
	s.Begin()
	if !s.Begun() {
		t.Fatal("expected Begun()=true after Begin()")
	}

	// Subsequent calls must not panic, leak fds, or close the channel twice.
	s.Begin()
	s.Begin()

	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("Done() should be closed after Begin()")
	}
}

func TestArgvRunnerShutdown_BeginConcurrent(t *testing.T) {
	s, err := newArgvRunnerShutdown()
	if err != nil {
		t.Fatalf("newArgvRunnerShutdown: %v", err)
	}
	defer s.Close()

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			s.Begin()
		}()
	}
	wg.Wait()

	if !s.Begun() {
		t.Fatal("expected Begun()=true after concurrent Begin() calls")
	}
}

func TestArgvRunnerShutdown_CloseIsIdempotent(t *testing.T) {
	s, err := newArgvRunnerShutdown()
	if err != nil {
		t.Fatalf("newArgvRunnerShutdown: %v", err)
	}
	s.Close()
	s.Close() // must not panic; eventfd is closed exactly once
}

// TestWaitForArgvExecNotification_WakeFromShutdown verifies that
// waitForArgvExecNotification returns promptly with (false, nil) when the
// shutdown eventfd is signalled, even though the listener fd has no data.
// This is the load-bearing assertion for the WSL2 fix: the supervisor must
// be able to exit on demand rather than depending on close(listenerFD)
// waking a blocking ioctl.
func TestWaitForArgvExecNotification_WakeFromShutdown(t *testing.T) {
	listener := makeBlockingListenerFD(t)
	defer func() { _ = unix.Close(listener) }()

	s, err := newArgvRunnerShutdown()
	if err != nil {
		t.Fatalf("newArgvRunnerShutdown: %v", err)
	}
	defer s.Close()

	type result struct {
		ready bool
		err   error
	}
	resCh := make(chan result, 1)
	go func() {
		ready, err := waitForArgvExecNotification(listener, s.WakeFD())
		resCh <- result{ready: ready, err: err}
	}()

	// Give ppoll time to actually park before we wake it.
	time.Sleep(50 * time.Millisecond)
	s.Begin()

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("waitForArgvExecNotification returned err=%v, want nil", res.err)
		}
		if res.ready {
			t.Fatal("waitForArgvExecNotification returned ready=true on shutdown wake; want false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitForArgvExecNotification did not return after Begin(); shutdown wake-up is broken")
	}
}

// TestWaitForArgvExecNotification_ReadyFromListener verifies the happy
// path: when the listener fd has data, we return (true, nil) without
// being misled by the wake-fd.
func TestWaitForArgvExecNotification_ReadyFromListener(t *testing.T) {
	// Use a self-pipe as a stand-in for a seccomp_unotify listener.
	// ppoll only cares about POLLIN readability, so any readable fd works.
	var pipefd [2]int
	if err := unix.Pipe2(pipefd[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatalf("Pipe2: %v", err)
	}
	defer func() {
		_ = unix.Close(pipefd[0])
		_ = unix.Close(pipefd[1])
	}()

	s, err := newArgvRunnerShutdown()
	if err != nil {
		t.Fatalf("newArgvRunnerShutdown: %v", err)
	}
	defer s.Close()

	if _, err := unix.Write(pipefd[1], []byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	ready, err := waitForArgvExecNotification(pipefd[0], s.WakeFD())
	if err != nil {
		t.Fatalf("waitForArgvExecNotification: %v", err)
	}
	if !ready {
		t.Fatal("expected ready=true when listener has data")
	}
	if s.Begun() {
		t.Fatal("Begun() should remain false; ready signal must not be confused with shutdown")
	}
}

// TestWaitForArgvExecNotification_ListenerHup verifies that closing the
// listener fd surfaces as POLLHUP/POLLNVAL → EBADF, which the supervisor
// loop treats as a graceful exit.
func TestWaitForArgvExecNotification_ListenerHup(t *testing.T) {
	var pipefd [2]int
	if err := unix.Pipe2(pipefd[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("Pipe2: %v", err)
	}
	// Close the write end so the read end becomes POLLHUP-eligible.
	_ = unix.Close(pipefd[1])
	defer func() { _ = unix.Close(pipefd[0]) }()

	s, err := newArgvRunnerShutdown()
	if err != nil {
		t.Fatalf("newArgvRunnerShutdown: %v", err)
	}
	defer s.Close()

	ready, pollErr := waitForArgvExecNotification(pipefd[0], s.WakeFD())
	if ready {
		t.Fatal("expected ready=false on listener HUP")
	}
	// On HUP the read end is also "readable" (returns 0 bytes), so the
	// kernel may set POLLIN | POLLHUP. Either path is acceptable for the
	// supervisor: POLLIN → caller does the recv ioctl which returns
	// EBADF; POLLHUP-only → we surface EBADF directly here.
	if pollErr != nil && !errors.Is(pollErr, unix.EBADF) {
		t.Fatalf("waitForArgvExecNotification: got err=%v, want nil or EBADF", pollErr)
	}
}

// TestWaitForArgvExecNotification_NoWakeFD covers the test-only path
// where the supervisor is driven without a shutdown coordinator. ppoll
// must not deadlock; with a ready listener it should return promptly.
func TestWaitForArgvExecNotification_NoWakeFD(t *testing.T) {
	var pipefd [2]int
	if err := unix.Pipe2(pipefd[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatalf("Pipe2: %v", err)
	}
	defer func() {
		_ = unix.Close(pipefd[0])
		_ = unix.Close(pipefd[1])
	}()

	if _, err := unix.Write(pipefd[1], []byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	ready, err := waitForArgvExecNotification(pipefd[0], -1)
	if err != nil {
		t.Fatalf("waitForArgvExecNotification(wakeFD=-1): %v", err)
	}
	if !ready {
		t.Fatal("expected ready=true with valid listener and no wake-fd")
	}
}

// makeBlockingListenerFD returns an fd that ppoll will not consider ready
// for POLLIN. We use a fresh eventfd whose counter is 0 - reads block
// (or return EAGAIN with O_NONBLOCK) and ppoll without writers reports no
// readiness, which is what we need to simulate a parked seccomp listener.
func makeBlockingListenerFD(t *testing.T) int {
	t.Helper()
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		t.Fatalf("Eventfd: %v", err)
	}
	return fd
}
