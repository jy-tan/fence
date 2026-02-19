package sandbox

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestResolveExecutionShell_Default(t *testing.T) {
	path, flag, err := ResolveExecutionShell(ShellModeDefault, false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if filepath.Base(path) != "bash" {
		t.Fatalf("expected bash path, got %q", path)
	}
	if flag != "-c" {
		t.Fatalf("expected -c, got %q", flag)
	}
}

func TestResolveExecutionShell_DefaultLogin(t *testing.T) {
	_, flag, err := ResolveExecutionShell(ShellModeDefault, true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if flag != "-lc" {
		t.Fatalf("expected -lc, got %q", flag)
	}
}

func TestResolveExecutionShell_User(t *testing.T) {
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available in test environment")
	}
	t.Setenv("SHELL", bashPath)

	path, flag, err := ResolveExecutionShell(ShellModeUser, false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if path != bashPath {
		t.Fatalf("expected %q, got %q", bashPath, path)
	}
	if flag != "-c" {
		t.Fatalf("expected -c, got %q", flag)
	}
}

func TestResolveExecutionShell_UserRequiresAbsoluteShell(t *testing.T) {
	t.Setenv("SHELL", "bash")
	if _, _, err := ResolveExecutionShell(ShellModeUser, false); err == nil {
		t.Fatal("expected error for non-absolute $SHELL")
	}
}

func TestResolveExecutionShell_RejectsUnsupportedMode(t *testing.T) {
	if _, _, err := ResolveExecutionShell("custom", false); err == nil {
		t.Fatal("expected error for unsupported shell mode")
	}
}
