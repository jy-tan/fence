//go:build darwin || linux

package main

import (
	"os/exec"
	"syscall"
	"testing"
)

// TestResolveExitCode verifies the non-job-control fallback exit-code mapping:
// a normal non-zero status passes through, and a signaled child maps to
// 128+signal (the shell convention) rather than ExitCode()'s -1.
func TestResolveExitCode(t *testing.T) {
	err := exec.Command("sh", "-c", "exit 7").Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError for `exit 7`, got %T (%v)", err, err)
	}
	if got := resolveExitCode(exitErr); got != 7 {
		t.Fatalf("resolveExitCode(exit 7) = %d, want 7", got)
	}

	err = exec.Command("sh", "-c", "kill -TERM $$").Run()
	exitErr, ok = err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError for self-SIGTERM, got %T (%v)", err, err)
	}
	ws, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		t.Fatalf("expected a signaled WaitStatus, got %#v", exitErr.Sys())
	}
	want := 128 + int(syscall.SIGTERM)
	if got := resolveExitCode(exitErr); got != want {
		t.Fatalf("resolveExitCode(SIGTERM) = %d, want %d", got, want)
	}
}
