//go:build darwin

package sandbox

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

// TestMacOS_InteractiveShellHasJobControl verifies that running "fence bash"
// gives the user a fully functional interactive shell with job control.
//
// Without the process group handoff fix (Setpgid + parent-side tcsetpgrp),
// bash prints:
//
//	"cannot set terminal process group: Operation not permitted"
//	"no job control in this shell"
func TestMacOS_InteractiveShellHasJobControl(t *testing.T) {
	skipIfAlreadySandboxed(t)

	// Build the fence binary.
	fenceBin := t.TempDir() + "/fence"
	build := exec.Command("go", "build", "-o", fenceBin, "../../cmd/fence")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("failed to build fence: %v", err)
	}

	// Run "fence bash" with a PTY, the same way a user would from a terminal.
	cmd := exec.Command(fenceBin, "bash")
	cmd.Env = append(os.Environ(), "PS1=READY$ ")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("failed to start fence bash with PTY: %v", err)
	}
	defer ptmx.Close()

	var output bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&output, ptmx)
		close(done)
	}()

	// Wait for bash to start and print any warnings.
	time.Sleep(1 * time.Second)
	_, _ = ptmx.Write([]byte("exit\n"))

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("command timed out")
	}

	_ = cmd.Wait()

	out := output.String()
	if strings.Contains(out, "no job control") {
		t.Errorf("bash reported 'no job control' inside fence sandbox:\n%s", out)
	}
	if strings.Contains(out, "cannot set terminal process group") {
		t.Errorf("bash could not set terminal process group inside fence sandbox:\n%s", out)
	}
}
