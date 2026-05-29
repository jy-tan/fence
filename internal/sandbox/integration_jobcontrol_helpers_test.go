//go:build darwin || linux

package sandbox

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

// Shared Ctrl-Z / fg job-control test harness. `ps -o state=` reports the same
// R/S/T codes on macOS and Linux, so the harness below is platform-agnostic;
// the per-OS files only carry the OS-named test entry points.

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func waitForOutput(output *lockedBuffer, needle string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(output.String(), needle) {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

// waitForProcessState polls `ps -o state= -p <pid>` until the reported state
// matches one of the pipe-separated patterns in want, or timeout elapses. `ps`
// reports a single-letter state code (R, S, T, etc.).
func waitForProcessState(t *testing.T, pid int, want string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	wants := strings.Split(want, "|")
	for time.Now().Before(deadline) {
		// #nosec G204 -- pid is an int from this test's own exec.Cmd.
		out, err := exec.Command("ps", "-o", "state=", "-p", strconv.Itoa(pid)).Output()
		if err == nil && len(out) > 0 {
			state := strings.TrimSpace(string(out))
			// `ps` returns codes like "T+" — first char is the canonical state.
			if len(state) > 0 {
				first := string(state[0])
				for _, w := range wants {
					if first == w {
						return true
					}
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

func buildFenceBinary(t *testing.T) string {
	t.Helper()
	fenceBin := t.TempDir() + "/fence"
	// #nosec G204 -- fixed args; output path is in TempDir.
	build := exec.Command("go", "build", "-o", fenceBin, "../../cmd/fence")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("failed to build fence: %v", err)
	}
	return fenceBin
}

// ctrlZSuspendsFence verifies that pressing Ctrl-Z (0x1A) while a blocking
// child runs inside fence causes both the child and fence itself to enter the
// stopped (T) state, and that delivering SIGCONT to fence resumes both.
//
// Before the SIGTSTP/SIGCONT handshake was added, fence kept blocking in Wait()
// while the inner pgrp was stopped, leaving the user's outer shell wedged with
// no "[1]+ Stopped …" notification. This test pins that regression down.
func ctrlZSuspendsFence(t *testing.T) {
	skipIfAlreadySandboxed(t)

	fenceBin := buildFenceBinary(t)

	// `fence sleep 30` is the smallest reproducer from the spec: a plain
	// blocking child with no job-control logic of its own.
	// #nosec G204 -- fenceBin built into TempDir above.
	cmd := exec.Command(fenceBin, "sleep", "30")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("failed to start fence sleep with PTY: %v", err)
	}
	defer func() {
		_ = ptmx.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	var output lockedBuffer
	go func() { _, _ = io.Copy(&output, ptmx) }()

	// Give fence a moment to spawn the child and hand off the TTY.
	time.Sleep(500 * time.Millisecond)

	// Send Ctrl-Z (0x1A) on the master side. The TTY driver delivers SIGTSTP
	// to the foreground pgrp (the child), the wait4 loop in fence sees the stop
	// and SIGSTOPs fence itself.
	if _, err := ptmx.Write([]byte{0x1A}); err != nil {
		t.Fatalf("failed to write Ctrl-Z: %v", err)
	}

	if !waitForProcessState(t, cmd.Process.Pid, "T", 2*time.Second) {
		t.Fatalf("fence (pid %d) did not enter stopped state after Ctrl-Z\noutput so far:\n%s", cmd.Process.Pid, output.String())
	}

	// Now resume fence; its wait4 loop should resume the child too.
	if err := syscall.Kill(cmd.Process.Pid, syscall.SIGCONT); err != nil {
		t.Fatalf("failed to SIGCONT fence: %v", err)
	}

	if !waitForProcessState(t, cmd.Process.Pid, "R|S", 2*time.Second) {
		t.Fatalf("fence (pid %d) did not resume after SIGCONT\noutput so far:\n%s", cmd.Process.Pid, output.String())
	}

	// Tear down: kill the inner sleep so fence exits cleanly.
	_ = cmd.Process.Kill()
}

// ctrlZBgStdinReadFgRecovery verifies that a child which reads from stdin can
// complete its read after a Ctrl-Z / fg round-trip. It exercises the fg
// recovery path of the SIGTTIN handling in waitWithJobControl: after Ctrl-Z
// stops fence+child, a SIGCONT (simulating fg) causes fence to re-grant the
// TTY to the child so the pending read can finish.
//
// Fully automating the bg+SIGTTIN sub-path — where the shell explicitly
// reclaims the TTY via tcsetpgrp before SIGCONTing fence — would require the
// test process to share a session with the PTY slave, which is not possible
// under the standard go test harness.
func ctrlZBgStdinReadFgRecovery(t *testing.T) {
	skipIfAlreadySandboxed(t)

	fenceBin := buildFenceBinary(t)

	// #nosec G204 -- fenceBin built into TempDir above.
	cmd := exec.Command(fenceBin, "sh", "-c", "printf 'READY\n'; read line; printf 'GOT\n'")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("failed to start fence command with PTY: %v", err)
	}

	var output lockedBuffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&output, ptmx)
		close(done)
	}()

	defer func() {
		_ = ptmx.Close()
		if cmd.Process != nil {
			_ = syscall.Kill(cmd.Process.Pid, syscall.SIGCONT)
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	if !waitForOutput(&output, "READY", 2*time.Second) {
		t.Fatalf("command did not become ready\noutput so far:\n%s", output.String())
	}

	if _, err := ptmx.Write([]byte{0x1A}); err != nil {
		t.Fatalf("failed to write Ctrl-Z: %v", err)
	}

	if !waitForProcessState(t, cmd.Process.Pid, "T", 2*time.Second) {
		t.Fatalf("fence did not enter stopped state after Ctrl-Z\noutput so far:\n%s", output.String())
	}

	// fg: resume fence; it re-grants the TTY to the child and SIGCONTs it.
	if err := syscall.Kill(cmd.Process.Pid, syscall.SIGCONT); err != nil {
		t.Fatalf("failed to SIGCONT fence: %v", err)
	}

	if !waitForProcessState(t, cmd.Process.Pid, "R|S", 2*time.Second) {
		t.Fatalf("fence did not resume after SIGCONT\noutput so far:\n%s", output.String())
	}

	// Feed the child's `read` so it can complete.
	if _, err := ptmx.Write([]byte("hello\n")); err != nil {
		t.Fatalf("failed to write input to PTY: %v", err)
	}

	if !waitForOutput(&output, "GOT", 5*time.Second) {
		t.Fatalf("child did not complete stdin read after fg\noutput so far:\n%s", output.String())
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("PTY output did not finish after child completed\noutput so far:\n%s", output.String())
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("fence exited with error: %v\noutput:\n%s", err, output.String())
	}
}

// ctrlZSuspendsFenceAndResumesChild verifies the full Ctrl-Z / fg round-trip:
// after the child is stopped and then resumed via SIGCONT, it finishes and
// fence exits cleanly (not blocked forever in waitWithJobControl).
func ctrlZSuspendsFenceAndResumesChild(t *testing.T) {
	skipIfAlreadySandboxed(t)

	fenceBin := buildFenceBinary(t)

	// #nosec G204 -- fenceBin built into TempDir above.
	cmd := exec.Command(fenceBin, "sh", "-c", "printf 'READY\\n'; sleep 1; printf 'DONE\\n'")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("failed to start fence command with PTY: %v", err)
	}

	var output lockedBuffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&output, ptmx)
		close(done)
	}()

	defer func() {
		_ = ptmx.Close()
		if cmd.Process != nil {
			// SIGCONT first so Kill/Wait cleanup cannot leave a stopped child behind.
			_ = syscall.Kill(cmd.Process.Pid, syscall.SIGCONT)
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	if !waitForOutput(&output, "READY", 2*time.Second) {
		t.Fatalf("command did not become ready\noutput so far:\n%s", output.String())
	}

	if _, err := ptmx.Write([]byte{0x1A}); err != nil {
		t.Fatalf("failed to write Ctrl-Z: %v", err)
	}

	if !waitForProcessState(t, cmd.Process.Pid, "T", 2*time.Second) {
		t.Fatalf("fence did not enter stopped state after Ctrl-Z\noutput so far:\n%s", output.String())
	}

	if err := syscall.Kill(cmd.Process.Pid, syscall.SIGCONT); err != nil {
		t.Fatalf("failed to SIGCONT fence: %v", err)
	}

	if !waitForOutput(&output, "DONE", 5*time.Second) {
		t.Fatalf("child did not resume and complete\noutput so far:\n%s", output.String())
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("PTY output did not finish after child completed\noutput so far:\n%s", output.String())
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("fence exited with error: %v\noutput:\n%s", err, output.String())
	}
}
