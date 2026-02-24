//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const maxSIGWINCHSignalsPerResize = 256

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
			fgPgid, signaledPgrp := forwardSIGWINCHToPTYForegroundPgrp(ptmx)

			// bwrap --new-session breaks the normal "SIGWINCH goes to the
			// controlling terminal foreground pgrp" behavior. Some TUIs end up
			// in a different session/pgrp, so also signal the process tree as a
			// bounded fallback.
			if execCmd.Process != nil {
				// Avoid double-signaling the root when it is already part of the
				// PTY foreground process group (common case for PTY-launched shells).
				if !signaledPgrp || !pidInProcessGroup(execCmd.Process.Pid, fgPgid) {
					_ = execCmd.Process.Signal(syscall.SIGWINCH)
				}
				signalSIGWINCHProcessTree(execCmd.Process.Pid, maxSIGWINCHSignalsPerResize)
			}
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

func forwardSIGWINCHToPTYForegroundPgrp(ptmx *os.File) (int, bool) {
	if pgid, ok := ptyForegroundPgrp(ptmx); ok {
		_ = syscall.Kill(-pgid, syscall.SIGWINCH)
		return pgid, true
	}
	return 0, false
}

func ptyForegroundPgrp(ptmx *os.File) (int, bool) {
	pgid, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPGRP)
	if err != nil || pgid <= 0 {
		return 0, false
	}
	return pgid, true
}

func pidInProcessGroup(pid int, pgid int) bool {
	if pid <= 0 || pgid <= 0 {
		return false
	}
	got, err := syscall.Getpgid(pid)
	return err == nil && got == pgid
}

func signalSIGWINCHProcessTree(rootPID int, maxSignals int) {
	if rootPID <= 0 || maxSignals <= 0 {
		return
	}

	children, parentPID := buildProcChildrenMap("/proc")
	if len(children) == 0 {
		return
	}

	queue := []int{rootPID}
	visited := make(map[int]bool)
	signaled := 0

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if visited[current] {
			continue
		}
		visited[current] = true

		for _, child := range children[current] {
			if !visited[child] {
				queue = append(queue, child)
			}
		}

		// Skip the root itself; we already signaled it directly.
		if current == rootPID {
			continue
		}

		// Guard against pid reuse / partial maps: only signal nodes that still
		// trace back to root in the parent map.
		if !isDescendantOfRoot(current, rootPID, parentPID) {
			continue
		}

		_ = syscall.Kill(current, syscall.SIGWINCH)
		signaled++
		if signaled >= maxSignals {
			return
		}
	}
}

func buildProcChildrenMap(procBasePath string) (map[int][]int, map[int]int) {
	children := make(map[int][]int)
	parentPID := make(map[int]int)

	entries, err := os.ReadDir(procBasePath)
	if err != nil {
		return children, parentPID
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		ppid, ok := readProcPPID(procBasePath, pid)
		if !ok || ppid <= 0 {
			continue
		}
		parentPID[pid] = ppid
		children[ppid] = append(children[ppid], pid)
	}

	return children, parentPID
}

func isDescendantOfRoot(pid, rootPID int, parentPID map[int]int) bool {
	if pid <= 0 || rootPID <= 0 {
		return false
	}
	current := pid
	for current > 0 {
		parent, ok := parentPID[current]
		if !ok {
			return false
		}
		if parent == rootPID {
			return true
		}
		if parent == current {
			return false
		}
		current = parent
	}
	return false
}

func readProcPPID(procBasePath string, pid int) (int, bool) {
	statusPath := fmt.Sprintf("%s/%d/status", procBasePath, pid)
	data, err := os.ReadFile(statusPath) //nolint:gosec // G304: intentional read of /proc/<pid>/status; pid is numeric and base is procfs
	if err != nil {
		return 0, false
	}
	return parsePPIDFromStatus(string(data))
}

func parsePPIDFromStatus(status string) (int, bool) {
	lines := strings.Split(status, "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, false
		}
		return ppid, true
	}
	return 0, false
}
