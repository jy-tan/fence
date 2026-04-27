//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

func TestWrapCommandLinuxWithOptions_UsesStagedBootstrapShell(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}

	shellPath, _, err := ResolveExecutionShell(ShellModeDefault, false)
	if err != nil {
		t.Skipf("default shell unavailable: %v", err)
	}
	shellSource, ok := resolvePathForMount(shellPath)
	if !ok {
		t.Fatalf("expected shell path %q to be mountable", shellPath)
	}

	cmd, err := WrapCommandLinuxWithOptions(&config.Config{}, "echo ok", nil, nil, LinuxSandboxOptions{
		UseLandlock: false,
		UseSeccomp:  false,
		UseEBPF:     false,
		ShellMode:   ShellModeDefault,
	})
	if err != nil {
		t.Fatalf("WrapCommandLinuxWithOptions failed: %v", err)
	}

	stageFragment := ShellQuote([]string{"--ro-bind", shellSource, linuxBootstrapShellPath})
	if !strings.Contains(cmd, stageFragment) {
		t.Fatalf("expected staged shell mount in command: %s", cmd)
	}

	execFragment := ShellQuote([]string{"--", linuxBootstrapShellPath, "-c"})
	if !strings.Contains(cmd, execFragment) {
		t.Fatalf("expected sandbox to launch staged shell in command: %s", cmd)
	}
}

// TestAppendLinuxBootstrapWrapperArgs_ResolvesSymlinks verifies that the
// appendLinuxBootstrapWrapperArgs function resolves symlinks for shell and fence
// paths before passing them to --ro-bind. This is critical on usr-merged distros
// where /bin is a symlink to /usr/bin, as bwrap will fail if the destination path
// contains symlink components.
func TestAppendLinuxBootstrapWrapperArgs_ResolvesSymlinks(t *testing.T) {
	// Create a temporary directory with a real file and a symlink to it
	tmpDir := t.TempDir()

	// Create a real shell binary (just an empty file for testing)
	realShell := filepath.Join(tmpDir, "real-shell")
	if err := os.WriteFile(realShell, []byte("#!/bin/sh\necho test"), 0o600); err != nil {
		t.Fatalf("failed to create real shell: %v", err)
	}

	// Create a symlink to the shell
	symlinkShell := filepath.Join(tmpDir, "shell-link")
	if err := os.Symlink(realShell, symlinkShell); err != nil {
		t.Fatalf("failed to create shell symlink: %v", err)
	}

	// Create a real fence binary
	realFence := filepath.Join(tmpDir, "real-fence")
	if err := os.WriteFile(realFence, []byte("#!/bin/sh\necho fence"), 0o600); err != nil {
		t.Fatalf("failed to create real fence: %v", err)
	}

	// Create a symlink to the fence binary
	symlinkFence := filepath.Join(tmpDir, "fence-link")
	if err := os.Symlink(realFence, symlinkFence); err != nil {
		t.Fatalf("failed to create fence symlink: %v", err)
	}

	// Call appendLinuxBootstrapWrapperArgs with symlinked paths
	args := []string{"bwrap"}
	result, err := appendLinuxBootstrapWrapperArgs(args, symlinkFence, symlinkShell, "-c", "echo test", nil, nil, nil, false)
	if err != nil {
		t.Fatalf("appendLinuxBootstrapWrapperArgs returned error: %v", err)
	}

	// Verify that the resolved paths are used as --ro-bind sources with staged destinations
	// The function should resolve symlinks and mount to staged paths like /tmp/fence/bin/shell
	realShellBind := fmt.Sprintf("--ro-bind\x00%s\x00%s", realShell, linuxBootstrapShellPath)
	realFenceBind := fmt.Sprintf("--ro-bind\x00%s\x00%s", realFence, linuxBootstrapFencePath)

	// Convert args to a single string for easier checking
	argsStr := strings.Join(result, "\x00")

	// Check that the resolved shell path is used as source with staged destination
	if !strings.Contains(argsStr, realShellBind) {
		// Check if the unresolved symlink path is being used (indicates the bug)
		symlinkShellBind := fmt.Sprintf("--ro-bind\x00%s\x00%s", symlinkShell, linuxBootstrapShellPath)
		if strings.Contains(argsStr, symlinkShellBind) {
			t.Fatalf("BUG: appendLinuxBootstrapWrapperArgs uses unresolved shell symlink %q instead of resolved path %q. This will fail on usr-merged distros.", symlinkShell, realShell)
		}
		t.Fatalf("Expected --ro-bind with resolved shell path %q -> %q, but it was not found in args: %v", realShell, linuxBootstrapShellPath, result)
	}

	// Check that the resolved fence path is used as source with staged destination
	if !strings.Contains(argsStr, realFenceBind) {
		// Check if the unresolved symlink path is being used (indicates the bug)
		symlinkFenceBind := fmt.Sprintf("--ro-bind\x00%s\x00%s", symlinkFence, linuxBootstrapFencePath)
		if strings.Contains(argsStr, symlinkFenceBind) {
			t.Fatalf("BUG: appendLinuxBootstrapWrapperArgs uses unresolved fence symlink %q instead of resolved path %q. This will fail on usr-merged distros.", symlinkFence, realFence)
		}
		t.Fatalf("Expected --ro-bind with resolved fence path %q -> %q, but it was not found in args: %v", realFence, linuxBootstrapFencePath, result)
	}

	// Verify the bootstrap command uses staged paths, not host paths
	// The command should be: /tmp/fence/bin/fence --linux-bootstrap -- /tmp/fence/bin/shell -c <command>
	foundFenceStaged := false
	foundShellStaged := false
	for _, arg := range result {
		if arg == linuxBootstrapFencePath {
			foundFenceStaged = true
		}
		if arg == linuxBootstrapShellPath {
			foundShellStaged = true
		}
	}
	if !foundFenceStaged {
		t.Fatalf("Expected bootstrap command to use staged fence path %q, but it was not found in args: %v", linuxBootstrapFencePath, result)
	}
	if !foundShellStaged {
		t.Fatalf("Expected bootstrap command to use staged shell path %q, but it was not found in args: %v", linuxBootstrapShellPath, result)
	}
}

// TestAppendLinuxBootstrapWrapperArgs_HandlesNonexistentPaths verifies that
// appendLinuxBootstrapWrapperArgs returns an error for nonexistent paths,
// since planLinuxBootstrapExecutables cannot resolve them for mounting.
func TestAppendLinuxBootstrapWrapperArgs_HandlesNonexistentPaths(t *testing.T) {
	args := []string{"bwrap"}

	// Call with nonexistent paths - should return an error
	nonexistentPath := "/nonexistent/path/to/fence"
	nonexistentShell := "/nonexistent/path/to/shell"

	_, err := appendLinuxBootstrapWrapperArgs(args, nonexistentPath, nonexistentShell, "-c", "echo test", nil, nil, nil, false)

	// Should return an error since the paths cannot be resolved for staging
	if err == nil {
		t.Fatalf("BUG: appendLinuxBootstrapWrapperArgs did not return an error for nonexistent paths")
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

func TestLinuxDefaultCrossMountReadablePaths(t *testing.T) {
	paths := linuxDefaultCrossMountReadablePaths()

	for _, want := range []string{"/usr/local", "/opt", "/nix", "/snap"} {
		if !slices.Contains(paths, want) {
			t.Fatalf("linuxDefaultCrossMountReadablePaths() missing %q", want)
		}
	}

	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		for _, want := range []string{
			filepath.Join(home, ".nvm"),
			filepath.Join(home, ".pyenv"),
			filepath.Join(home, ".cargo/bin"),
			filepath.Join(home, ".local/bin"),
		} {
			if !slices.Contains(paths, want) {
				t.Fatalf("linuxDefaultCrossMountReadablePaths() missing %q", want)
			}
		}
	}

	for _, notWant := range []string{"/dev", "/proc", "/sys", "/run", "/tmp"} {
		if slices.Contains(paths, notWant) {
			t.Fatalf("linuxDefaultCrossMountReadablePaths() should not include special mount %q", notWant)
		}
	}
}

func TestLandlockHandledAccessFS(t *testing.T) {
	t.Run("includes ioctl_dev on ABI v5+", func(t *testing.T) {
		ruleset := &LandlockRuleset{abiVersion: 5}
		if ruleset.getHandledAccessFS()&LANDLOCK_ACCESS_FS_IOCTL_DEV == 0 {
			t.Fatal("expected handled access mask to include IOCTL_DEV on ABI v5+")
		}
	})

	t.Run("omits ioctl_dev before ABI v5", func(t *testing.T) {
		ruleset := &LandlockRuleset{abiVersion: 4}
		if ruleset.getHandledAccessFS()&LANDLOCK_ACCESS_FS_IOCTL_DEV != 0 {
			t.Fatal("did not expect handled access mask to include IOCTL_DEV before ABI v5")
		}
	})
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

	ptmxFragment := ShellQuote([]string{"--dev-bind", "/dev/ptmx", "/dev/ptmx"})
	if strings.Contains(cmd, ptmxFragment) {
		t.Fatalf("did not expect /dev/ptmx passthrough in minimal mode: %s", cmd)
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

func TestWrapCommandLinuxWithOptions_ExposedHostPathsEmitBinds(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}

	tmpDir := t.TempDir()
	roPath := filepath.Join(tmpDir, "override.yml")
	rwPath := filepath.Join(tmpDir, "scratch")
	if err := os.WriteFile(roPath, []byte("x: 1\n"), 0o600); err != nil {
		t.Fatalf("write override: %v", err)
	}
	if err := os.Mkdir(rwPath, 0o700); err != nil {
		t.Fatalf("mkdir scratch: %v", err)
	}

	cfg := &config.Config{}
	cmd, err := WrapCommandLinuxWithOptions(cfg, "true", nil, nil, LinuxSandboxOptions{
		UseLandlock: false,
		UseSeccomp:  false,
		UseEBPF:     false,
		ShellMode:   ShellModeDefault,
		ExposedHostPaths: []exposedHostPath{
			{path: roPath, writable: false},
			{path: rwPath, writable: true},
		},
	})
	if err != nil {
		t.Fatalf("WrapCommandLinuxWithOptions failed: %v", err)
	}

	roExpected := ShellQuote([]string{"--ro-bind", roPath, roPath})
	rwExpected := ShellQuote([]string{"--bind", rwPath, rwPath})
	tmpfsTmp := ShellQuote([]string{"--tmpfs", "/tmp"})

	roIdx := strings.Index(cmd, roExpected)
	rwIdx := strings.Index(cmd, rwExpected)
	tmpfsIdx := strings.Index(cmd, tmpfsTmp)
	if roIdx == -1 {
		t.Fatalf("expected read-only exposed-host-path bind %q in command: %s", roExpected, cmd)
	}
	if rwIdx == -1 {
		t.Fatalf("expected read-write exposed-host-path bind %q in command: %s", rwExpected, cmd)
	}
	if tmpfsIdx == -1 {
		t.Fatalf("expected --tmpfs /tmp in command: %s", cmd)
	}
	// The exposed host paths must be applied AFTER --tmpfs /tmp so that a
	// path under /tmp (the exact case that motivated ExposeHostPath) survives
	// the overmount.
	if roIdx <= tmpfsIdx {
		t.Fatalf("expected exposed --ro-bind to appear after --tmpfs /tmp: roIdx=%d tmpfsIdx=%d cmd=%s", roIdx, tmpfsIdx, cmd)
	}
	if rwIdx <= tmpfsIdx {
		t.Fatalf("expected exposed --bind to appear after --tmpfs /tmp: rwIdx=%d tmpfsIdx=%d cmd=%s", rwIdx, tmpfsIdx, cmd)
	}
}

func TestWrapCommandLinuxWithOptions_ExposedHostPathUnder_TmpSurvivesTmpfs(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}

	// Regression test for the motivating bug (see docs/sandbox-gaps.md and
	// docs/engineering/drift/... compose-override file under /tmp becoming
	// invisible). A caller passing a /tmp path to ExposedHostPaths must see
	// the --ro-bind emitted AFTER --tmpfs /tmp in the bwrap command.
	f, err := os.CreateTemp("", "fence-expose-tmp-*.yml")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	_ = f.Close()

	cfg := &config.Config{}
	cmd, err := WrapCommandLinuxWithOptions(cfg, "true", nil, nil, LinuxSandboxOptions{
		UseLandlock: false,
		UseSeccomp:  false,
		UseEBPF:     false,
		ShellMode:   ShellModeDefault,
		ExposedHostPaths: []exposedHostPath{
			{path: f.Name(), writable: false},
		},
	})
	if err != nil {
		t.Fatalf("WrapCommandLinuxWithOptions failed: %v", err)
	}

	tmpfsTmp := ShellQuote([]string{"--tmpfs", "/tmp"})
	bind := ShellQuote([]string{"--ro-bind", f.Name(), f.Name()})

	tmpfsIdx := strings.Index(cmd, tmpfsTmp)
	bindIdx := strings.Index(cmd, bind)
	if tmpfsIdx == -1 || bindIdx == -1 {
		t.Fatalf("expected both --tmpfs /tmp and --ro-bind of the tmp file in command:\n%s", cmd)
	}
	if bindIdx <= tmpfsIdx {
		t.Fatalf("exposed bind must come AFTER --tmpfs /tmp; bindIdx=%d tmpfsIdx=%d", bindIdx, tmpfsIdx)
	}
}

func TestLinuxLateMountPlanner_MaskedAncestorWinsOverChildReadOnly(t *testing.T) {
	planner := newLinuxLateMountPlanner()
	planner.Add("/tmp/secret", linuxLateMountMaskDir)
	planner.Add("/tmp/secret/id_rsa", linuxLateMountReadOnly)

	mounts := planner.Mounts()
	if len(mounts) != 1 {
		t.Fatalf("expected a single mount, got %#v", mounts)
	}
	if mounts[0].Path != "/tmp/secret" || mounts[0].Kind != linuxLateMountMaskDir {
		t.Fatalf("expected masked ancestor to win, got %#v", mounts)
	}
}

func TestLinuxLateMountPlanner_ReadOnlyAncestorKeepsChildMask(t *testing.T) {
	planner := newLinuxLateMountPlanner()
	planner.Add("/tmp/tools", linuxLateMountReadOnly)
	planner.Add("/tmp/tools/python3", linuxLateMountMaskFile)

	mounts := planner.Mounts()
	if len(mounts) != 2 {
		t.Fatalf("expected parent read-only mount and child mask, got %#v", mounts)
	}
	if mounts[0].Path != "/tmp/tools" || mounts[0].Kind != linuxLateMountReadOnly {
		t.Fatalf("expected read-only parent mount first, got %#v", mounts)
	}
	if mounts[1].Path != "/tmp/tools/python3" || mounts[1].Kind != linuxLateMountMaskFile {
		t.Fatalf("expected child mask to remain after parent read-only mount, got %#v", mounts)
	}
}

func TestLinuxLateMountPlanner_ReadOnlyAncestorPrunesChildReadOnly(t *testing.T) {
	planner := newLinuxLateMountPlanner()
	planner.Add("/tmp/secret/id_rsa", linuxLateMountReadOnly)
	planner.Add("/tmp/secret", linuxLateMountReadOnly)

	mounts := planner.Mounts()
	if len(mounts) != 1 {
		t.Fatalf("expected redundant child read-only mount to be removed, got %#v", mounts)
	}
	if mounts[0].Path != "/tmp/secret" || mounts[0].Kind != linuxLateMountReadOnly {
		t.Fatalf("expected parent read-only mount to remain, got %#v", mounts)
	}
}

func TestWrapCommandLinuxWithOptions_DenyReadDirectoryWinsOverSamePathDenyWrite(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}

	workspace := t.TempDir()
	secretDir := filepath.Join(workspace, "secret")
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		t.Fatalf("failed to create secret dir: %v", err)
	}

	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			DenyRead:  []string{secretDir},
			DenyWrite: []string{secretDir},
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

	maskFragment := ShellQuote([]string{"--tmpfs", secretDir})
	rebindFragment := ShellQuote([]string{"--ro-bind", secretDir, secretDir})
	if !strings.Contains(cmd, maskFragment) {
		t.Fatalf("expected denyRead directory mask in command: %s", cmd)
	}
	if strings.Contains(cmd, rebindFragment) {
		t.Fatalf("did not expect denyWrite to rebind a masked directory: %s", cmd)
	}
}

func TestWrapCommandLinuxWithOptions_DenyReadDirectoryWinsOverChildDenyWrite(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}

	workspace := t.TempDir()
	secretDir := filepath.Join(workspace, "secret")
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		t.Fatalf("failed to create secret dir: %v", err)
	}
	secretFile := filepath.Join(secretDir, "id_rsa")
	if err := os.WriteFile(secretFile, []byte("secret"), 0o600); err != nil {
		t.Fatalf("failed to create secret file: %v", err)
	}

	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			DenyRead:  []string{secretDir},
			DenyWrite: []string{secretFile},
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

	maskFragment := ShellQuote([]string{"--tmpfs", secretDir})
	rebindFragment := ShellQuote([]string{"--ro-bind", secretFile, secretFile})
	if !strings.Contains(cmd, maskFragment) {
		t.Fatalf("expected denyRead directory mask in command: %s", cmd)
	}
	if strings.Contains(cmd, rebindFragment) {
		t.Fatalf("did not expect denyWrite child rebind under a masked directory: %s", cmd)
	}
}

func TestWrapCommandLinuxWithOptions_DenyReadFileWinsOverSamePathDenyWrite(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}

	workspace := t.TempDir()
	secretFile := filepath.Join(workspace, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("secret"), 0o600); err != nil {
		t.Fatalf("failed to create secret file: %v", err)
	}

	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			DenyRead:  []string{secretFile},
			DenyWrite: []string{secretFile},
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

	maskFragment := ShellQuote([]string{"--ro-bind", "/dev/null", secretFile})
	rebindFragment := ShellQuote([]string{"--ro-bind", secretFile, secretFile})
	if !strings.Contains(cmd, maskFragment) {
		t.Fatalf("expected denyRead file mask in command: %s", cmd)
	}
	if strings.Contains(cmd, rebindFragment) {
		t.Fatalf("did not expect denyWrite to rebind a masked file: %s", cmd)
	}
}
