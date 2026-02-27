//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
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

func TestResolvePathForMount_PathWithSymlinkAncestor(t *testing.T) {
	tmpDir := t.TempDir()
	realDir := filepath.Join(tmpDir, "real")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatalf("failed to create real directory: %v", err)
	}
	aliasDir := filepath.Join(tmpDir, "alias")
	if err := os.Symlink(realDir, aliasDir); err != nil {
		t.Fatalf("failed to create alias symlink: %v", err)
	}
	targetFile := filepath.Join(realDir, "config")
	if err := os.WriteFile(targetFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("failed to create target file: %v", err)
	}

	got, ok := resolvePathForMount(filepath.Join(aliasDir, "config"))
	if !ok {
		t.Fatalf("expected path with symlink ancestor to resolve")
	}
	// Canonicalization should resolve symlinked ancestor components too.
	expected := targetFile
	if got != expected {
		t.Fatalf("expected mount path %q, got %q", expected, got)
	}
}

func TestResolvePathForMount_NonexistentPath(t *testing.T) {
	got, ok := resolvePathForMount(filepath.Join(t.TempDir(), "missing"))
	if ok {
		t.Fatalf("expected nonexistent path to be rejected, got %q", got)
	}
	if got != "" {
		t.Fatalf("expected empty resolved path for missing target, got %q", got)
	}
}

func TestWrapCommandLinuxWithOptions_DropsShellFromRuntimeDenyMounts(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	shellPath, _, err := ResolveExecutionShell(ShellModeDefault, false)
	if err != nil {
		t.Skipf("default shell unavailable: %v", err)
	}

	useDefaults := false
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{filepath.Base(shellPath)},
			UseDefaults: &useDefaults,
		},
	}
	cmd, err := WrapCommandLinuxWithOptions(cfg, "echo ok", nil, nil, LinuxSandboxOptions{
		UseLandlock: false,
		UseSeccomp:  false,
		UseEBPF:     false,
		ShellMode:   ShellModeDefault,
	})
	if err != nil {
		t.Fatalf("WrapCommandLinuxWithOptions failed: %v", err)
	}

	denyMountFragment := ShellQuote([]string{"--ro-bind", "/dev/null", shellPath, shellPath})
	if strings.Contains(cmd, denyMountFragment) {
		t.Fatalf("shell path should not be masked in runtime deny mounts: %s", shellPath)
	}
}

func TestParseMountInfoLineMountPoint(t *testing.T) {
	line := "2475 2474 0:406 / /run rw,nosuid,nodev - tmpfs tmpfs rw,size=1234k"
	mountPoint, ok := parseMountInfoLineMountPoint(line)
	if !ok {
		t.Fatalf("expected mount point to parse")
	}
	if mountPoint != "/run" {
		t.Fatalf("expected /run, got %q", mountPoint)
	}
}

func TestParseMountInfoLineMountPoint_UnescapesSpaces(t *testing.T) {
	line := "275 1 0:45 / /mnt/with\\040space rw,relatime - ext4 /dev/vda rw"
	mountPoint, ok := parseMountInfoLineMountPoint(line)
	if !ok {
		t.Fatalf("expected mount point to parse")
	}
	if mountPoint != "/mnt/with space" {
		t.Fatalf("expected unescaped mount point, got %q", mountPoint)
	}
}

func TestExpandRootsWithDescendantMounts(t *testing.T) {
	roots := []string{"/run", "/nix"}
	mountPoints := []string{
		"/",
		"/run",
		"/run/user",
		"/run/user/1000",
		"/nix",
		"/nix/store",
		"/var",
	}

	got := expandRootsWithDescendantMounts(roots, mountPoints)
	want := []string{"/nix", "/nix/store", "/run", "/run/user", "/run/user/1000"}
	if len(got) != len(want) {
		t.Fatalf("expected %d paths, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %q at index %d, got %q", want[i], i, got[i])
		}
	}
}
