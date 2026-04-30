package sandbox

import (
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
)

// SignalForwarder relays terminal signals from the host process to a
// running child (typically bwrap or another sandbox wrapper) with a
// 3-step escalation:
//
//   - 1st SIGINT/SIGTERM/SIGHUP: forward to the child directly. This
//     lets a TUI handle the signal as it would normally (e.g. single
//     Ctrl+C as cancel, not quit).
//   - 2nd: SIGKILL the child and fire OnEscalate.
//   - 3rd+: SIGKILL the child again and fire OnEscalate. Last resort.
//
// SIGWINCH is always forwarded to the child directly and never counts
// toward the escalation budget.
//
// The returned cleanup function is idempotent.
type SignalForwarder struct {
	// Cmd is the already-started child. The forwarder reads
	// Cmd.Process to deliver signals; it does not call Cmd.Start().
	Cmd *exec.Cmd

	// OnEscalate, if non-nil, is invoked once per escalation step
	// (the 2nd signal and again on the 3rd+). Used by the argv
	// runner to wake its supervisor goroutine via shutdown.Begin().
	OnEscalate func()
}

// Start subscribes to SIGINT/SIGTERM/SIGHUP/SIGWINCH and dispatches
// them to f.Cmd according to the escalation rules above. The returned
// stop function is safe to call multiple times.
func (f *SignalForwarder) Start() (stop func()) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGWINCH)
	done := make(chan struct{})
	var stopOnce sync.Once

	go f.run(sigChan, done)

	return func() {
		stopOnce.Do(func() {
			signal.Stop(sigChan)
			close(done)
		})
	}
}

// run is the dispatch loop. Exposed for direct testing via a
// caller-provided channel; production callers go through Start.
func (f *SignalForwarder) run(sigChan <-chan os.Signal, done <-chan struct{}) {
	sigCount := 0
	for {
		select {
		case <-done:
			return
		case sig, ok := <-sigChan:
			if !ok {
				return
			}
			if f.Cmd == nil || f.Cmd.Process == nil {
				continue
			}
			forwarded, ok := sig.(syscall.Signal)
			if !ok {
				continue
			}

			if forwarded == syscall.SIGWINCH {
				_ = f.Cmd.Process.Signal(forwarded)
				continue
			}

			sigCount++
			switch sigCount {
			case 1:
				_ = f.Cmd.Process.Signal(forwarded)
			default:
				_ = f.Cmd.Process.Kill()
				if f.OnEscalate != nil {
					f.OnEscalate()
				}
			}
		}
	}
}
