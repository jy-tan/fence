//go:build linux

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

// TestLinux_CtrlZSuspendsFenceAndResumesChild verifies the full Ctrl-Z / fg
// round-trip on Linux: pressing Ctrl-Z stops both the child and fence, and
// delivering SIGCONT resumes both so the child completes and fence exits cleanly.
func TestLinux_CtrlZSuspendsFenceAndResumesChild(t *testing.T) {
	skipIfAlreadySandboxed(t)

	fenceBin := t.TempDir() + "/fence"
	// #nosec G204 -- fixed args; output path is in TempDir.
	build := exec.Command("go", "build", "-o", fenceBin, "../../cmd/fence")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("failed to build fence: %v", err)
	}

	// #nosec G204 -- fenceBin built into TempDir above.
	cmd := exec.Command(fenceBin, "sh", "-c", "printf 'READY\\n'; sleep 1; printf 'DONE\\n'")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("failed to start fence command with PTY: %v", err)
	}

	var output linuxLockedBuffer
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

	if !linuxWaitForOutput(&output, "READY", 2*time.Second) {
		t.Fatalf("command did not become ready\noutput so far:\n%s", output.String())
	}

	if _, err := ptmx.Write([]byte{0x1A}); err != nil {
		t.Fatalf("failed to write Ctrl-Z: %v", err)
	}

	if !linuxWaitForProcessState(t, cmd.Process.Pid, "T", 2*time.Second) {
		t.Fatalf("fence did not enter stopped state after Ctrl-Z\noutput so far:\n%s", output.String())
	}

	if err := syscall.Kill(cmd.Process.Pid, syscall.SIGCONT); err != nil {
		t.Fatalf("failed to SIGCONT fence: %v", err)
	}

	if !linuxWaitForOutput(&output, "DONE", 5*time.Second) {
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

// TestLinux_CtrlZSuspendsFence verifies that pressing Ctrl-Z while a blocking
// child is running inside fence causes both the child and fence to enter the
// stopped (T) state, and that delivering SIGCONT resumes both.
func TestLinux_CtrlZSuspendsFence(t *testing.T) {
	skipIfAlreadySandboxed(t)

	fenceBin := t.TempDir() + "/fence"
	// #nosec G204 -- fixed args; output path is in TempDir.
	build := exec.Command("go", "build", "-o", fenceBin, "../../cmd/fence")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("failed to build fence: %v", err)
	}

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

	var output bytes.Buffer
	go func() { _, _ = io.Copy(&output, ptmx) }()

	// Give fence a moment to spawn the child and hand off the TTY.
	time.Sleep(500 * time.Millisecond)

	if _, err := ptmx.Write([]byte{0x1A}); err != nil {
		t.Fatalf("failed to write Ctrl-Z: %v", err)
	}

	if !linuxWaitForProcessState(t, cmd.Process.Pid, "T", 2*time.Second) {
		t.Fatalf("fence (pid %d) did not enter stopped state after Ctrl-Z\noutput so far:\n%s", cmd.Process.Pid, output.String())
	}

	if err := syscall.Kill(cmd.Process.Pid, syscall.SIGCONT); err != nil {
		t.Fatalf("failed to SIGCONT fence: %v", err)
	}

	if !linuxWaitForProcessState(t, cmd.Process.Pid, "R|S", 2*time.Second) {
		t.Fatalf("fence (pid %d) did not resume after SIGCONT\noutput so far:\n%s", cmd.Process.Pid, output.String())
	}

	_ = cmd.Process.Kill()
}

type linuxLockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *linuxLockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *linuxLockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func linuxWaitForOutput(output *linuxLockedBuffer, needle string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(output.String(), needle) {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

func linuxWaitForProcessState(t *testing.T, pid int, want string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	wants := strings.Split(want, "|")
	for time.Now().Before(deadline) {
		// #nosec G204 -- pid is an int from this test's own exec.Cmd.
		out, err := exec.Command("ps", "-o", "state=", "-p", strconv.Itoa(pid)).Output()
		if err == nil && len(out) > 0 {
			state := strings.TrimSpace(string(out))
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
