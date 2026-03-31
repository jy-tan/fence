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

func TestExpandGlobPatterns_DoubleStarMatchesCurrentDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "nested", "deeper")

	if err := os.MkdirAll(nestedDir, 0o700); err != nil {
		t.Fatalf("failed to create nested directories: %v", err)
	}

	tests := []struct {
		pattern string
		matches []string
	}{
		{
			pattern: "**/*.key",
			matches: []string{
				filepath.Join(tmpDir, "secret.key"),
				filepath.Join(tmpDir, "nested", "deeper", "secret.key"),
			},
		},
		{
			pattern: "**/.env",
			matches: []string{
				filepath.Join(tmpDir, ".env"),
				filepath.Join(tmpDir, "nested", "deeper", ".env"),
			},
		},
		{
			pattern: "**/.env.*",
			matches: []string{
				filepath.Join(tmpDir, ".env.local"),
				filepath.Join(tmpDir, "nested", "deeper", ".env.production"),
			},
		},
	}

	for _, tt := range tests {
		for _, path := range tt.matches {
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatalf("failed to create test file %q: %v", path, err)
			}
		}
	}

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(originalWD)
	}()

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			got := ExpandGlobPatterns([]string{tt.pattern})
			gotSet := make(map[string]bool, len(got))
			for _, path := range got {
				gotSet[path] = true
			}

			if len(gotSet) != len(tt.matches) {
				t.Fatalf("ExpandGlobPatterns(%s) returned %v, want exactly %v", tt.pattern, got, tt.matches)
			}
			for _, want := range tt.matches {
				if !gotSet[want] {
					t.Fatalf("ExpandGlobPatterns(%s) missing %q in %v", tt.pattern, want, got)
				}
			}
		})
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

func TestEffectiveLinuxForceNewSession(t *testing.T) {
	t.Run("defaults to strict outside interactive pty", func(t *testing.T) {
		if !effectiveLinuxForceNewSession(&config.Config{}, false, false) {
			t.Fatal("expected new-session to remain enabled outside interactive PTY sessions")
		}
	})

	t.Run("defaults off for interactive pty sessions", func(t *testing.T) {
		cfg := &config.Config{AllowPty: true}
		if effectiveLinuxForceNewSession(cfg, true, true) {
			t.Fatal("expected interactive PTY sessions to skip new-session by default")
		}
	})

	t.Run("explicit override wins", func(t *testing.T) {
		value := true
		cfg := &config.Config{
			AllowPty:        true,
			ForceNewSession: &value,
		}
		if !effectiveLinuxForceNewSession(cfg, true, true) {
			t.Fatal("expected explicit forceNewSession override to win")
		}
	})
}

func TestWrapCommandLinuxWithOptions_UsesMinimalDevMode(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}

	cfg := &config.Config{
		Devices: config.DevicesConfig{
			Mode:  config.DeviceModeMinimal,
			Allow: []string{"/dev/null", "/dev/fd", "/dev/fd"},
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

	for _, path := range linuxMinimalCoreDevicePaths {
		if !fileExists(path) {
			continue
		}
		fragment := ShellQuote([]string{"--dev-bind", path, path})
		if !strings.Contains(cmd, fragment) {
			t.Fatalf("expected core device passthrough for %s in minimal mode: %s", path, cmd)
		}
	}

	nullFragment := ShellQuote([]string{"--dev-bind", "/dev/null", "/dev/null"})
	if count := strings.Count(cmd, nullFragment); count != 1 {
		t.Fatalf("expected /dev/null passthrough exactly once in minimal mode, got %d: %s", count, cmd)
	}

	fdFragment := ShellQuote([]string{"--dev-bind", "/dev/fd", "/dev/fd"})
	if fileExists("/dev/fd") && strings.Count(cmd, fdFragment) != 1 {
		t.Fatalf("expected custom /dev/fd passthrough exactly once in minimal mode: %s", cmd)
	}
}

func TestWrapCommandLinuxWithOptions_RespectsForceNewSessionOverride(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}

	forceNewSession := false
	cfg := &config.Config{
		ForceNewSession: &forceNewSession,
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

	if strings.Contains(cmd, ShellQuote([]string{"--new-session"})) {
		t.Fatalf("did not expect --new-session when explicitly disabled: %s", cmd)
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

func TestWrapCommandLinuxWithOptions_RootBindPrecedesSpecialMounts(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}

	cfg := &config.Config{
		Devices: config.DevicesConfig{
			Mode: config.DeviceModeMinimal,
		},
		Filesystem: config.FilesystemConfig{
			AllowWrite: []string{"/"},
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

	rootBind := ShellQuote([]string{"--bind", "/", "/"})
	devMount := ShellQuote([]string{"--dev", "/dev"})
	nullBind := ShellQuote([]string{"--dev-bind", "/dev/null", "/dev/null"})

	rootIdx := strings.Index(cmd, rootBind)
	devIdx := strings.Index(cmd, devMount)
	nullIdx := strings.Index(cmd, nullBind)
	if rootIdx == -1 || devIdx == -1 || nullIdx == -1 {
		t.Fatalf("expected root bind, minimal /dev mount, and device passthroughs in command: %s", cmd)
	}
	if rootIdx > devIdx {
		t.Fatalf("expected root bind to appear before /dev mount: %s", cmd)
	}
	if rootIdx > nullIdx {
		t.Fatalf("expected root bind to appear before device passthroughs: %s", cmd)
	}
}
