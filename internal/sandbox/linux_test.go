//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePathForMount_RegularPath(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "config")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	got, ok := resolvePathForMount(filePath)
	if !ok {
		t.Fatalf("expected path to be mountable")
	}
	if got != filePath {
		t.Fatalf("expected %q, got %q", filePath, got)
	}
}

func TestResolvePathForMount_SymlinkPath(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("failed to create target: %v", err)
	}
	link := filepath.Join(tmpDir, ".gitconfig")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	got, ok := resolvePathForMount(link)
	if !ok {
		t.Fatalf("expected symlink to resolve")
	}
	if got != target {
		t.Fatalf("expected resolved target %q, got %q", target, got)
	}
}

func TestResolvePathForMount_BrokenSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	link := filepath.Join(tmpDir, ".gitconfig")
	if err := os.Symlink(filepath.Join(tmpDir, "missing"), link); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	if got, ok := resolvePathForMount(link); ok {
		t.Fatalf("expected broken symlink to be skipped, got %q", got)
	}
}
