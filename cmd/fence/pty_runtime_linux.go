//go:build linux

package main

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

type resizeDebouncer struct {
	timer *time.Timer
	ch    <-chan time.Time
	delay time.Duration
}

func newResizeDebouncer(delay time.Duration) *resizeDebouncer {
	return &resizeDebouncer{delay: delay}
}

func (d *resizeDebouncer) Queue() {
	if d.timer == nil {
		d.timer = time.NewTimer(d.delay)
	} else {
		d.timer.Reset(d.delay)
	}
	d.ch = d.timer.C
}

func (d *resizeDebouncer) Channel() <-chan time.Time {
	return d.ch
}

func (d *resizeDebouncer) MarkHandled() {
	d.ch = nil
}

func (d *resizeDebouncer) Stop() {
	if d.timer != nil {
		d.timer.Stop()
	}
}

func startCommandWithPTY(execCmd *exec.Cmd) (func(), error) {
	// pty.Start sets up a controlling PTY for the child command and starts it.
	ptmx, err := pty.Start(execCmd)
	if err != nil {
		return nil, err
	}

	// Best-effort initial sizing (only matters when stdin is a terminal).
	_ = pty.InheritSize(os.Stdin, ptmx)

	restoreTTY := func() {}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		if oldState, err := term.MakeRaw(int(os.Stdin.Fd())); err == nil {
			restoreTTY = func() {
				_ = term.Restore(int(os.Stdin.Fd()), oldState)
			}
		}
	}

	done := make(chan struct{})
	var doneOnce sync.Once
	var cleanupOnce sync.Once

	// Signal relay: especially SIGWINCH (resize).
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGWINCH)
		defer signal.Stop(sigChan)

		debouncer := newResizeDebouncer(30 * time.Millisecond)
		defer debouncer.Stop()

		forwardResize := func() {
			debouncer.MarkHandled()
			_ = pty.InheritSize(os.Stdin, ptmx)
			forwardSIGWINCHToPTYForegroundPgrp(ptmx)
		}

		sigCount := 0
		for {
			select {
			case <-done:
				return
			case sig := <-sigChan:
				if execCmd.Process == nil {
					continue
				}

				if sig == syscall.SIGWINCH {
					debouncer.Queue()
					continue
				}

				sigCount++
				if sigCount >= 2 {
					_ = execCmd.Process.Kill()
					continue
				}

				// Prefer sending signals to the PTY foreground process group so
				// Ctrl-C/etc behave like a normal interactive terminal.
				if pgid, ok := ptyForegroundPgrp(ptmx); ok {
					_ = syscall.Kill(-pgid, sig.(syscall.Signal))
				} else {
					_ = execCmd.Process.Signal(sig)
				}
			case <-debouncer.Channel():
				forwardResize()
			}
		}
	}()

	// PTY I/O relay.
	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()

	go func() {
		_, _ = io.Copy(os.Stdout, ptmx)
		// If the command exits and the PTY drains, restore state.
		cleanupOnce.Do(func() {
			restoreTTY()
			_ = ptmx.Close()
		})
	}()

	return func() {
		doneOnce.Do(func() { close(done) })
		cleanupOnce.Do(func() {
			restoreTTY()
			_ = ptmx.Close()
		})
	}, nil
}

func forwardSIGWINCHToPTYForegroundPgrp(ptmx *os.File) {
	if pgid, ok := ptyForegroundPgrp(ptmx); ok {
		_ = syscall.Kill(-pgid, syscall.SIGWINCH)
	}
}

func ptyForegroundPgrp(ptmx *os.File) (int, bool) {
	pgid, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPGRP)
	if err != nil || pgid <= 0 {
		return 0, false
	}
	return pgid, true
}
