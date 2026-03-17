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

func TestResolveLinuxDeviceMode(t *testing.T) {
	tests := []struct {
		name          string
		requested     config.DeviceMode
		euid          int
		bwrapSetuid   bool
		insideContain bool
		want          config.DeviceMode
	}{
		{
			name:      "explicit host mode wins",
			requested: config.DeviceModeHost,
			want:      config.DeviceModeHost,
		},
		{
			name:      "explicit minimal mode wins",
			requested: config.DeviceModeMinimal,
			want:      config.DeviceModeMinimal,
		},
		{
			name:          "auto prefers minimal in containers",
			requested:     config.DeviceModeAuto,
			insideContain: true,
			want:          config.DeviceModeMinimal,
		},
		{
			name:        "auto keeps host mode for setuid non-root bwrap",
			requested:   config.DeviceModeAuto,
			euid:        1000,
			bwrapSetuid: true,
			want:        config.DeviceModeHost,
		},
		{
			name:        "auto uses minimal for root even if bwrap is setuid",
			requested:   config.DeviceModeAuto,
			euid:        0,
			bwrapSetuid: true,
			want:        config.DeviceModeMinimal,
		},
		{
			name:      "empty requested mode behaves like auto",
			requested: "",
			want:      config.DeviceModeMinimal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveLinuxDeviceMode(tt.requested, tt.euid, tt.bwrapSetuid, tt.insideContain)
			if got != tt.want {
				t.Fatalf("resolveLinuxDeviceMode(%q, %d, %v, %v) = %q, want %q",
					tt.requested, tt.euid, tt.bwrapSetuid, tt.insideContain, got, tt.want)
			}
		})
	}
}

func TestWrapCommandLinuxWithOptions_UsesMinimalDevMode(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}

	cfg := &config.Config{
		Devices: config.DevicesConfig{
			Mode:  config.DeviceModeMinimal,
			Allow: []string{"/dev/null"},
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

	if !strings.Contains(cmd, ShellQuote([]string{"--dev", "/dev"})) {
		t.Fatalf("expected minimal /dev mount in command: %s", cmd)
	}
	if strings.Contains(cmd, ShellQuote([]string{"--dev-bind", "/dev", "/dev"})) {
		t.Fatalf("did not expect host /dev bind in minimal mode: %s", cmd)
	}
	if !strings.Contains(cmd, ShellQuote([]string{"--dev-bind", "/dev/null", "/dev/null"})) {
		t.Fatalf("expected explicit device passthrough in minimal mode: %s", cmd)
	}
}

func TestWrapCommandLinuxWithOptions_UsesHostDevMode(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}

	cfg := &config.Config{
		Devices: config.DevicesConfig{
			Mode:  config.DeviceModeHost,
			Allow: []string{"/dev/null"},
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

	if !strings.Contains(cmd, ShellQuote([]string{"--dev-bind", "/dev", "/dev"})) {
		t.Fatalf("expected host /dev bind in command: %s", cmd)
	}
	if strings.Contains(cmd, ShellQuote([]string{"--dev", "/dev"})) {
		t.Fatalf("did not expect minimal /dev mount in host mode: %s", cmd)
	}
	if strings.Contains(cmd, ShellQuote([]string{"--dev-bind", "/dev/null", "/dev/null"})) {
		t.Fatalf("did not expect per-device passthroughs in host mode: %s", cmd)
	}
}
