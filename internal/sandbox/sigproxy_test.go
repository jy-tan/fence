package sandbox

import (
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// startSleepingChild spawns a long-lived child whose Process can be
// observed/signaled, and registers a cleanup to reap it.
func startSleepingChild(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

// driveForwarder runs f.run on a fresh goroutine fed by an unbuffered
// channel, sends each signal in order, and uses a trailing SIGWINCH
// as a barrier. Because the channel is unbuffered, the (i+1)-th send
// only completes once the consumer has received the i-th signal; the
// barrier guarantees that by the time it returns, the consumer has
// fully finished processing every signal in `sigs`.
//
// SIGWINCH is the barrier of choice because it never affects the
// escalation counter and never invokes OnEscalate, so it does not
// pollute assertions.
//
// The returned stop function tears down the goroutine and waits for
// it to exit; safe to call from t.Cleanup or defer.
func driveForwarder(t *testing.T, f *SignalForwarder, sigs ...os.Signal) (stop func()) {
	t.Helper()
	sigChan := make(chan os.Signal)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() { f.run(sigChan, done) })

	for _, s := range sigs {
		sigChan <- s
	}
	sigChan <- syscall.SIGWINCH

	return func() {
		close(done)
		wg.Wait()
	}
}

func TestSignalForwarder_StopIsIdempotent(t *testing.T) {
	cmd := startSleepingChild(t)
	stop := (&SignalForwarder{Cmd: cmd}).Start()
	stop()
	stop()
	stop()
}

func TestSignalForwarder_SIGWINCHDoesNotEscalate(t *testing.T) {
	cmd := startSleepingChild(t)

	var escalates atomic.Int32
	f := &SignalForwarder{
		Cmd:        cmd,
		OnEscalate: func() { escalates.Add(1) },
	}

	stop := driveForwarder(t, f, syscall.SIGWINCH, syscall.SIGWINCH, syscall.SIGWINCH)
	stop()

	if got := escalates.Load(); got != 0 {
		t.Fatalf("OnEscalate fired %d times for SIGWINCH-only stream; want 0", got)
	}
}

func TestSignalForwarder_FirstSignalDoesNotEscalate(t *testing.T) {
	cmd := startSleepingChild(t)

	var escalates atomic.Int32
	f := &SignalForwarder{
		Cmd:        cmd,
		OnEscalate: func() { escalates.Add(1) },
	}

	stop := driveForwarder(t, f, syscall.SIGINT)
	stop()

	if got := escalates.Load(); got != 0 {
		t.Fatalf("OnEscalate fired %d times after 1st signal; want 0", got)
	}
}

// awaitChildExit waits up to 2s for cmd.Wait() to return. Use after
// driving a forwarder with at least 2 escalation signals (SIGINT/
// SIGTERM/SIGHUP) to confirm the child was actually killed.
func awaitChildExit(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	waitErrCh := make(chan error, 1)
	go func() { waitErrCh <- cmd.Wait() }()
	select {
	case <-waitErrCh:
	case <-time.After(2 * time.Second):
		t.Fatal("child did not die within 2s of expected escalation")
	}
}

func TestSignalForwarder_SecondSignalEscalates(t *testing.T) {
	cmd := startSleepingChild(t)

	var escalates atomic.Int32
	f := &SignalForwarder{
		Cmd:        cmd,
		OnEscalate: func() { escalates.Add(1) },
	}

	stop := driveForwarder(t, f, syscall.SIGINT, syscall.SIGINT)
	awaitChildExit(t, cmd)
	stop()

	if got := escalates.Load(); got != 1 {
		t.Fatalf("OnEscalate fired %d times after 2nd signal; want 1", got)
	}
}

func TestSignalForwarder_SIGHUPParticipatesInEscalation(t *testing.T) {
	cmd := startSleepingChild(t)

	var escalates atomic.Int32
	f := &SignalForwarder{
		Cmd:        cmd,
		OnEscalate: func() { escalates.Add(1) },
	}

	stop := driveForwarder(t, f, syscall.SIGHUP, syscall.SIGHUP)
	awaitChildExit(t, cmd)
	stop()

	if got := escalates.Load(); got != 1 {
		t.Fatalf("OnEscalate after SIGHUP escalation fired %d times; want 1", got)
	}
}

func TestSignalForwarder_NilOnEscalateIsSafe(t *testing.T) {
	cmd := startSleepingChild(t)
	f := &SignalForwarder{Cmd: cmd, OnEscalate: nil}

	stop := driveForwarder(t, f, syscall.SIGINT, syscall.SIGINT)
	awaitChildExit(t, cmd)
	stop()
}

func TestSignalForwarder_NilProcessIgnored(t *testing.T) {
	// f.Cmd.Process is nil before Start(); run() must not panic.
	f := &SignalForwarder{Cmd: &exec.Cmd{}}

	stop := driveForwarder(t, f, syscall.SIGINT, syscall.SIGTERM)
	stop()
}
