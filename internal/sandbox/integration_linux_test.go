//go:build linux

package sandbox

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Use-Tusk/fence/internal/config"
)

// ============================================================================
// Linux-Specific Integration Tests
// ============================================================================

// skipIfLandlockNotUsable skips tests that require the Landlock wrapper.
// The Landlock wrapper re-executes the binary with --landlock-apply, which only
// the fence CLI understands. Test binaries (e.g., sandbox.test) don't have this
// handler, so Landlock tests must be skipped when not running as the fence CLI.
// TODO: consider removing tests that call this function, for now can keep them
// as documentation.
func skipIfLandlockNotUsable(t *testing.T) {
	t.Helper()
	features := DetectLinuxFeatures()
	if !features.CanUseLandlock() {
		t.Skip("skipping: Landlock not available on this kernel")
	}
	exePath, _ := os.Executable()
	if !strings.Contains(filepath.Base(exePath), "fence") {
		t.Skip("skipping: Landlock wrapper requires fence CLI (test binary cannot use --landlock-apply)")
	}
}

// assertNetworkBlocked verifies that a network command was blocked.
// It checks for either a non-zero exit code OR the proxy's blocked message.
func assertNetworkBlocked(t *testing.T, result *SandboxTestResult) {
	t.Helper()
	blockedMessage := "Connection blocked by network allowlist"
	if result.Failed() {
		return // Command failed = blocked
	}
	if strings.Contains(result.Stdout, blockedMessage) || strings.Contains(result.Stderr, blockedMessage) {
		return // Proxy blocked the request
	}
	t.Errorf("expected network request to be blocked, but it succeeded\nstdout: %s\nstderr: %s",
		result.Stdout, result.Stderr)
}

func runUnderLinuxSandboxDirect(t *testing.T, cfg *config.Config, command string, workDir string) *SandboxTestResult {
	t.Helper()
	skipIfAlreadySandboxed(t)

	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return &SandboxTestResult{Error: err}
		}
	}

	wrappedCmd, err := WrapCommandLinuxWithOptions(cfg, command, nil, nil, LinuxSandboxOptions{
		UseLandlock: false,
		UseSeccomp:  false,
		UseEBPF:     false,
		ShellMode:   ShellModeDefault,
		WorkDir:     workDir,
	})
	if err != nil {
		return &SandboxTestResult{
			ExitCode: 1,
			Stderr:   err.Error(),
			Error:    err,
		}
	}

	return executeShellCommand(t, wrappedCmd, workDir)
}

func buildFenceCLIBinary(t *testing.T) string {
	t.Helper()

	fenceBin := filepath.Join(t.TempDir(), "fence")
	// #nosec G204 -- arguments are fixed in tests and output path is a test-controlled temp directory.
	build := exec.Command("go", "build", "-o", fenceBin, "../../cmd/fence")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("failed to build fence CLI: %v", err)
	}
	return fenceBin
}

// TestLinux_LandlockBlocksWriteOutsideWorkspace verifies that Landlock prevents
// writes to locations outside the allowed workspace.
func TestLinux_LandlockBlocksWriteOutsideWorkspace(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfLandlockNotUsable(t)

	workspace := createTempWorkspace(t)
	outsideFile := "/tmp/fence-test-outside-" + filepath.Base(workspace) + ".txt"
	defer func() { _ = os.Remove(outsideFile) }()

	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "touch "+outsideFile, workspace)

	assertBlocked(t, result)
	assertFileNotExists(t, outsideFile)
}

// TestLinux_LandlockAllowsWriteInWorkspace verifies writes within the workspace work.
func TestLinux_LandlockAllowsWriteInWorkspace(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "echo 'test content' > allowed.txt", workspace)

	assertAllowed(t, result)
	assertFileExists(t, filepath.Join(workspace, "allowed.txt"))

	// Verify content was written
	content, err := os.ReadFile(filepath.Join(workspace, "allowed.txt")) //nolint:gosec
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if !strings.Contains(string(content), "test content") {
		t.Errorf("expected file to contain 'test content', got: %s", string(content))
	}
}

// TestLinux_LandlockProtectsGitHooks verifies .git/hooks cannot be written to.
func TestLinux_LandlockProtectsGitHooks(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfLandlockNotUsable(t)

	workspace := createTempWorkspace(t)
	createGitRepo(t, workspace)
	cfg := testConfigWithWorkspace(workspace)

	hookPath := filepath.Join(workspace, ".git", "hooks", "pre-commit")
	result := runUnderSandbox(t, cfg, "echo '#!/bin/sh\nmalicious' > "+hookPath, workspace)

	assertBlocked(t, result)
	// Hook file should not exist or should be empty
	if content, err := os.ReadFile(hookPath); err == nil && strings.Contains(string(content), "malicious") { //nolint:gosec
		t.Errorf("malicious content should not have been written to git hook")
	}
}

// TestLinux_LandlockProtectsGitConfig verifies .git/config cannot be written to
// unless allowGitConfig is true.
func TestLinux_LandlockProtectsGitConfig(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfLandlockNotUsable(t)

	workspace := createTempWorkspace(t)
	createGitRepo(t, workspace)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.AllowGitConfig = false

	configPath := filepath.Join(workspace, ".git", "config")
	originalContent, _ := os.ReadFile(configPath) //nolint:gosec

	result := runUnderSandbox(t, cfg, "echo 'malicious=true' >> "+configPath, workspace)

	assertBlocked(t, result)

	// Verify content wasn't modified
	newContent, _ := os.ReadFile(configPath) //nolint:gosec
	if strings.Contains(string(newContent), "malicious") {
		t.Errorf("git config should not have been modified")
	}
	if string(newContent) != string(originalContent) {
		// Content was modified, which shouldn't happen
		t.Logf("original: %s", originalContent)
		t.Logf("new: %s", newContent)
	}
}

// TestLinux_LandlockAllowsGitConfigWhenEnabled verifies .git/config can be written
// when allowGitConfig is true.
func TestLinux_LandlockAllowsGitConfigWhenEnabled(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "socat")

	workspace := createTempWorkspace(t)
	createGitRepo(t, workspace)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.AllowGitConfig = true

	configPath := filepath.Join(workspace, ".git", "config")

	result := runUnderSandbox(t, cfg, "echo '[test]' >> "+configPath, workspace)

	assertAllowed(t, result)

	content, err := os.ReadFile(configPath) //nolint:gosec // test reads a temp repo config path created within the test
	if err != nil {
		t.Fatalf("failed to read git config: %v", err)
	}
	if !strings.Contains(string(content), "[test]") {
		t.Errorf("expected git config to include appended section, got:\n%s", content)
	}
}

// TestLinux_LandlockProtectsBashrc verifies shell config files are protected.
func TestLinux_LandlockProtectsBashrc(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfLandlockNotUsable(t)

	workspace := createTempWorkspace(t)
	bashrcPath := filepath.Join(workspace, ".bashrc")
	createTestFile(t, workspace, ".bashrc", "# original bashrc")

	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, "echo 'malicious' >> "+bashrcPath, workspace)

	assertBlocked(t, result)

	content, _ := os.ReadFile(bashrcPath) //nolint:gosec
	if strings.Contains(string(content), "malicious") {
		t.Errorf(".bashrc should be protected from writes")
	}
}

// TestLinux_LandlockAllowsReadSystemFiles verifies system files can be read.
func TestLinux_LandlockAllowsReadSystemFiles(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Reading /etc/passwd should work
	result := runUnderSandbox(t, cfg, "cat /etc/passwd | head -1", workspace)

	assertAllowed(t, result)
	if result.Stdout == "" {
		t.Errorf("expected to read /etc/passwd content")
	}
}

// TestLinux_LandlockBlocksWriteSystemFiles verifies system files cannot be written.
func TestLinux_LandlockBlocksWriteSystemFiles(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Attempting to write to /etc should fail
	result := runUnderSandbox(t, cfg, "touch /etc/fence-test-file", workspace)

	assertBlocked(t, result)
	assertFileNotExists(t, "/etc/fence-test-file")
}

// TestLinux_LandlockAllowsTmpFence verifies /tmp/fence is writable.
func TestLinux_LandlockAllowsTmpFence(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfLandlockNotUsable(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Ensure /tmp/fence exists
	_ = os.MkdirAll("/tmp/fence", 0o750)

	testFile := "/tmp/fence/test-file-" + filepath.Base(workspace)
	defer func() { _ = os.Remove(testFile) }()

	result := runUnderSandbox(t, cfg, "echo 'test' > "+testFile, workspace)

	assertAllowed(t, result)
	assertFileExists(t, testFile)
}

func TestLinux_LandlockWrapperPreservesRepoLocalFenceBinary(t *testing.T) {
	skipIfAlreadySandboxed(t)

	features := DetectLinuxFeatures()
	if !features.CanUseLandlock() {
		t.Skip("skipping: Landlock not available on this kernel")
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("skipping: home directory unavailable")
	}
	if sameDevice("/", home) {
		t.Skip("skipping: home directory is not on a separate mount")
	}

	sandboxRoot, err := os.MkdirTemp(home, ".fence-landlock-wrapper-*")
	if err != nil {
		t.Fatalf("failed to create home-based sandbox root: %v", err)
	}
	defer func() { _ = os.RemoveAll(sandboxRoot) }()

	allowedDir := filepath.Join(sandboxRoot, "allowed")
	if err := os.MkdirAll(allowedDir, 0o700); err != nil {
		t.Fatalf("failed to create allowWrite directory: %v", err)
	}

	fenceBin := filepath.Join(sandboxRoot, "fence")
	// #nosec G204 -- arguments are fixed in this test and output path is a test-controlled temp directory under $HOME.
	build := exec.Command("go", "build", "-o", fenceBin, "../../cmd/fence")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("failed to build fence: %v", err)
	}

	configJSON, err := json.Marshal(map[string]any{
		"filesystem": map[string]any{
			"allowWrite": []string{allowedDir},
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "test-fence.json")
	if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	result := executeShellCommand(t, ShellQuote([]string{fenceBin, "--settings", configPath, "--", "ls"}), allowedDir)

	assertAllowed(t, result)
}

// TestLinux_SymlinkedGlobalGitConfigDoesNotBreakSandbox reproduces issue #51
// conditions: HOME has a .gitconfig symlink to a different filesystem target.
func TestLinux_SymlinkedGlobalGitConfigDoesNotBreakSandbox(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	fakeHome := createTempWorkspace(t)
	gitconfigPath := filepath.Join(fakeHome, ".gitconfig")
	if err := os.Symlink("/proc/version", gitconfigPath); err != nil {
		t.Fatalf("failed to create symlinked .gitconfig: %v", err)
	}
	t.Setenv("HOME", fakeHome)

	cfg := testConfigWithWorkspace(workspace)
	result := runUnderSandbox(t, cfg, "echo 'sandbox ok'", workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "sandbox ok")
}

// TestLinux_RuntimeExecDeny_DoesNotCrashOnBinAliasPath verifies that enabling a
// runtime exec deny for "chroot" does not crash sandbox startup on usr-merged
// systems where /bin may be a symlink alias.
func TestLinux_RuntimeExecDeny_DoesNotCrashOnBinAliasPath(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "chroot")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Command.Deny = []string{"chroot"}
	cfg.Command.UseDefaults = boolPtr(false)

	result := runUnderSandbox(t, cfg, "echo 'sandbox ok'", workspace)
	assertAllowed(t, result)
	assertContains(t, result.Stdout, "sandbox ok")
}

// TestLinux_RuntimeExecDeny_ChrootBlockedWhenMountable verifies runtime exec
// deny blocks direct chroot execution (when the mask mount can be applied).
func TestLinux_RuntimeExecDeny_ChrootBlockedWhenMountable(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "chroot")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Command.Deny = []string{"chroot"}
	cfg.Command.UseDefaults = boolPtr(false)

	result := runUnderSandbox(t, cfg, "chroot --version", workspace)
	assertBlocked(t, result)
}

func TestLinux_RuntimeExecPolicyArgv_DeniesGitPushAllowsGitStatus(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "git")

	fenceBin := buildFenceCLIBinary(t)
	workspace := createTempWorkspace(t)

	scriptPath := filepath.Join(workspace, "spawn-git-commands.sh")
	script := "#!/bin/sh\nset -e\ngit --version >/dev/null 2>&1\necho STATUS_OK\ngit push origin main\necho PUSH_UNEXPECTED\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("failed to write test script: %v", err)
	}

	configJSON, err := json.Marshal(map[string]any{
		"filesystem": map[string]any{
			"allowWrite": []string{workspace},
		},
		"command": map[string]any{
			"deny":              []string{"git push"},
			"useDefaults":       false,
			"runtimeExecPolicy": "argv",
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "argv-runtime-fence.json")
	if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	result := executeShellCommand(t, ShellQuote([]string{fenceBin, "--settings", configPath, "--", "sh", "./spawn-git-commands.sh"}), workspace)
	assertBlocked(t, result)

	assertContains(t, result.Stdout, "STATUS_OK")
	if strings.Contains(result.Stdout, "PUSH_UNEXPECTED") {
		t.Fatalf("unexpected post-push marker found in stdout: %s", result.Stdout)
	}
	if strings.Contains(result.Stderr, "blocked by sandbox command policy") {
		t.Fatalf("expected runtime argv exec block, got preflight block: %s", result.Stderr)
	}
	assertContains(t, result.Stderr, "Runtime exec policy blocked")
}

func TestLinux_RuntimeExecPolicyArgv_GitStatusWorksInRepoRoot(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "git")

	fenceBin := buildFenceCLIBinary(t)
	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	workspace := filepath.Clean(filepath.Join(pkgDir, "../.."))
	if !isDirectory(filepath.Join(workspace, ".git")) {
		t.Skip("skipping: repository root .git directory not available")
	}

	configJSON, err := json.Marshal(map[string]any{
		"command": map[string]any{
			"deny":              []string{"git log"},
			"useDefaults":       false,
			"runtimeExecPolicy": "argv",
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "argv-runtime-home-repo.json")
	if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	result := executeShellCommand(
		t,
		ShellQuote([]string{
			fenceBin,
			"--settings", configPath,
			"--",
			"sh", "-c", "git rev-parse --show-toplevel >/dev/null && git status --short >/dev/null && echo OK",
		}),
		workspace,
	)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "OK")
}

// TestLinux_DenyPrecedence_DenyReadMandatoryAndRuntimeExec verifies denyRead
// still takes precedence when mandatory dangerous-path and runtime exec deny are
// also enabled in the same config.
func TestLinux_DenyPrecedence_DenyReadMandatoryAndRuntimeExec(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "chroot")

	workspace := createTempWorkspace(t)
	fakeHome := createTempWorkspace(t)
	t.Setenv("HOME", fakeHome)

	zshrcPath := createTestFile(t, fakeHome, ".zshrc", "secret zshrc content")

	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DenyRead = []string{"~/.zshrc"}
	cfg.Command.Deny = []string{"chroot"}
	cfg.Command.UseDefaults = boolPtr(false)

	result := runUnderSandbox(t, cfg, "cat "+zshrcPath, workspace)
	assertBlocked(t, result)
}

// TestLinux_RuntimeExecDeny_BadTargetDoesNotAbortAll is the intended behavior
// for the upcoming mount-planner refactor where unmountable deny entries are
// skipped instead of aborting sandbox startup.
func TestLinux_RuntimeExecDeny_BadTargetDoesNotAbortAll(t *testing.T) {
	t.Skip("pending mount-planner refactor: non-fatal handling for unmountable runtime deny targets")
}

// TestLinux_DenyReadBlocksFiles verifies that denyRead correctly blocks file access.
// This test ensures that when denyRead contains file paths (not directories),
// sandbox is properly set up and denies read access.
func TestLinux_DenyReadBlocksFiles(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	secretFile := createTestFile(t, workspace, "secret.txt", "secret content")

	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DenyRead = []string{secretFile}

	result := runUnderSandbox(t, cfg, "cat "+secretFile, workspace)

	// File should be blocked (cannot be read)
	assertBlocked(t, result)
}

// TestLinux_DenyReadBlocksDirectories verifies that denyRead correctly blocks directory access.
func TestLinux_DenyReadBlocksDirectories(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	secretDir := filepath.Join(workspace, "secret-dir")
	if err := os.MkdirAll(secretDir, 0o750); err != nil {
		t.Fatalf("failed to create secret directory: %v", err)
	}
	secretFile := createTestFile(t, secretDir, "data.txt", "secret data")

	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DenyRead = []string{secretDir}

	result := runUnderSandbox(t, cfg, "cat "+secretFile, workspace)

	// Directory should be blocked (cannot read files inside)
	assertBlocked(t, result)
}

// TestLinux_DefaultDenyReadDoesNotExposeDangerousHomeFiles verifies that
// mandatory dangerous-path protection does not re-expose files in defaultDenyRead mode.
func TestLinux_DefaultDenyReadDoesNotExposeDangerousHomeFiles(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	fakeHome := createTempWorkspace(t)
	t.Setenv("HOME", fakeHome)

	zshrcPath := createTestFile(t, fakeHome, ".zshrc", "secret zshrc content")

	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DefaultDenyRead = true

	result := runUnderSandbox(t, cfg, "cat "+zshrcPath, workspace)
	assertBlocked(t, result)
}

// TestLinux_DenyReadTakesPrecedenceOverMandatoryDangerousPath verifies explicit
// denyRead rules always win over mandatory dangerous-path write protection.
func TestLinux_DenyReadTakesPrecedenceOverMandatoryDangerousPath(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	fakeHome := createTempWorkspace(t)
	t.Setenv("HOME", fakeHome)

	zshrcPath := createTestFile(t, fakeHome, ".zshrc", "secret zshrc content")

	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DenyRead = []string{"~/.zshrc"}

	result := runUnderSandbox(t, cfg, "cat "+zshrcPath, workspace)
	assertBlocked(t, result)
}

// TestLinux_DenyReadTakesPrecedenceOverSamePathDenyWrite verifies that masking a
// directory still wins when the same directory also appears in denyWrite.
func TestLinux_DenyReadTakesPrecedenceOverSamePathDenyWrite(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	fakeHome := createTempWorkspace(t)
	t.Setenv("HOME", fakeHome)

	sshDir := filepath.Join(fakeHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("failed to create ssh dir: %v", err)
	}
	keyPath := createTestFile(t, sshDir, "id_rsa", "secret key")

	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DenyRead = []string{"~/.ssh"}
	cfg.Filesystem.DenyWrite = []string{"~/.ssh"}

	result := runUnderLinuxSandboxDirect(t, cfg, "cat "+keyPath, workspace)
	assertBlocked(t, result)
}

// TestLinux_DenyReadMaskedAncestorBeatsChildDenyWrite verifies that a later
// denyWrite self-bind cannot puncture a directory already masked by denyRead.
func TestLinux_DenyReadMaskedAncestorBeatsChildDenyWrite(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	fakeHome := createTempWorkspace(t)
	t.Setenv("HOME", fakeHome)

	sshDir := filepath.Join(fakeHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("failed to create ssh dir: %v", err)
	}
	keyPath := createTestFile(t, sshDir, "id_rsa", "secret key")

	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DenyRead = []string{"~/.ssh"}
	cfg.Filesystem.DenyWrite = []string{"~/.ssh/id_rsa"}

	result := runUnderLinuxSandboxDirect(t, cfg, "cat "+keyPath, workspace)
	assertBlocked(t, result)
}

// ============================================================================
// Network Blocking Tests
// ============================================================================

// TestLinux_NetworkBlocksCurl verifies that curl cannot reach the network.
func TestLinux_NetworkBlocksCurl(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "curl")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	// No domains allowed = all network blocked

	result := runUnderSandboxWithTimeout(t, cfg, "curl -s --connect-timeout 2 --max-time 3 http://example.com", workspace, 10*time.Second)

	assertNetworkBlocked(t, result)
}

// TestLinux_NetworkBlocksPing verifies that ping cannot reach the network.
func TestLinux_NetworkBlocksPing(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "ping")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandboxWithTimeout(t, cfg, "ping -c 1 -W 2 8.8.8.8", workspace, 10*time.Second)

	assertBlocked(t, result)
}

// TestLinux_NetworkBlocksNetcat verifies that nc cannot make connections.
func TestLinux_NetworkBlocksNetcat(t *testing.T) {
	skipIfAlreadySandboxed(t)

	// Try both nc and netcat
	ncCmd := "nc"
	if _, err := lookPathLinux("nc"); err != nil {
		if _, err := lookPathLinux("netcat"); err != nil {
			t.Skip("skipping: nc/netcat not found")
		}
		ncCmd = "netcat"
	}

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandboxWithTimeout(t, cfg, ncCmd+" -z -w 2 127.0.0.1 80", workspace, 10*time.Second)

	assertBlocked(t, result)
}

// TestLinux_NetworkBlocksSSH verifies that SSH cannot connect.
func TestLinux_NetworkBlocksSSH(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "ssh")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandboxWithTimeout(t, cfg, "ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no github.com", workspace, 10*time.Second)

	assertBlocked(t, result)
}

// TestLinux_NetworkBlocksDevTcp verifies /dev/tcp is blocked.
func TestLinux_NetworkBlocksDevTcp(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "bash")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandboxWithTimeout(t, cfg, "bash -c 'echo hi > /dev/tcp/127.0.0.1/80'", workspace, 10*time.Second)

	assertBlocked(t, result)
}

// TestLinux_ExposedPortAllowsHostReachability verifies the library-based Linux
// sandbox path can expose a localhost service back to the host.
func TestLinux_ExposedPortAllowsHostReachability(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "python3")

	features := DetectLinuxFeatures()
	if !features.CanUnshareNet {
		t.Skip("skipping: reverse bridge requires network namespace support")
	}

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Network.AllowLocalBinding = true
	markerName := "fence-exposed-port-marker.txt"
	markerBody := "sandbox reverse bridge ok"
	if err := os.WriteFile(filepath.Join(workspace, markerName), []byte(markerBody), 0o600); err != nil {
		t.Fatalf("failed to create marker file: %v", err)
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
		},
	}

	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to allocate test port: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()

		attemptErr := func() error {
			manager := NewManager(cfg, false, false)
			manager.SetExposedPorts([]int{port})
			defer manager.Cleanup()

			if err := manager.Initialize(); err != nil {
				return fmt.Errorf("initialize sandbox manager: %w", err)
			}

			command := "python3 -m http.server " + strconv.Itoa(port) + " --bind 127.0.0.1"
			wrappedCmd, err := manager.WrapCommandInDir(command, workspace)
			if err != nil {
				return fmt.Errorf("wrap command: %w", err)
			}

			cmd := exec.Command("/bin/sh", "-c", wrappedCmd) //nolint:gosec // wrappedCmd is generated from trusted test input via the sandbox manager
			cmd.Dir = workspace

			var stdout, stderr strings.Builder
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			if err := cmd.Start(); err != nil {
				return fmt.Errorf("start sandboxed server: %w", err)
			}
			defer func() {
				if cmd.Process != nil {
					_ = cmd.Process.Kill()
				}
				_ = cmd.Wait()
			}()

			url := "http://127.0.0.1:" + strconv.Itoa(port) + "/" + markerName
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				resp, err := client.Get(url)
				if err == nil {
					body, readErr := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if readErr == nil && resp.StatusCode == http.StatusOK && string(body) == markerBody {
						return nil
					}
					if readErr == nil {
						lastErr = fmt.Errorf("unexpected response from exposed port %d: status=%d body=%q", port, resp.StatusCode, string(body))
					} else {
						lastErr = readErr
					}
				} else {
					lastErr = err
				}

				if cmd.Process != nil && cmd.Process.Signal(syscall.Signal(0)) != nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			return fmt.Errorf("failed to reach sandboxed server via exposed port %d: %v\nstdout: %s\nstderr: %s", port, lastErr, stdout.String(), stderr.String())
		}()
		if attemptErr == nil {
			return
		}
		lastErr = attemptErr
	}

	t.Fatalf("failed to reach sandboxed server after retries: %v", lastErr)
}

// TestLinux_AllowLocalOutboundReachesHost verifies that with
// network.allowLocalOutbound=true and network.allowLocalOutboundPorts listing
// the service port, a sandboxed process can talk to a host loopback service
// while --unshare-net is still in force (i.e. external network remains
// blocked).
func TestLinux_AllowLocalOutboundReachesHost(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "curl")

	features := DetectLinuxFeatures()
	if !features.CanUnshareNet {
		t.Skip("skipping: localhost-outbound bridge requires network namespace support")
	}

	// Start a real HTTP server on the host's 127.0.0.1 so we can prove the
	// sandbox actually reaches the host loopback (not its own).
	const markerBody = "localhost-outbound bridge reached the host"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(markerBody))
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate test port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	trueVal := true
	cfg.Network.AllowLocalOutbound = &trueVal
	cfg.Network.AllowLocalOutboundPorts = []int{port}

	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/"
	// -sS: silent but show errors; --max-time bounds the overall request.
	result := runUnderSandboxWithTimeout(t, cfg, "curl -sS --max-time 5 "+url, workspace, 15*time.Second)

	if result.Failed() {
		t.Fatalf("expected curl to succeed reaching host loopback via bridge; exit=%d\nstdout: %s\nstderr: %s",
			result.ExitCode, result.Stdout, result.Stderr)
	}
	if !strings.Contains(result.Stdout, markerBody) {
		t.Fatalf("expected response body %q; got stdout=%q stderr=%q",
			markerBody, result.Stdout, result.Stderr)
	}
}

// TestLinux_AllowLocalOutboundWithoutPortsBlocked verifies the negative case:
// setting allowLocalOutbound=true but leaving allowLocalOutboundPorts empty
// does NOT grant access (since Linux needs explicit ports to bridge). This
// guards the security property: the boolean alone must never silently expose
// arbitrary host loopback services.
func TestLinux_AllowLocalOutboundWithoutPortsBlocked(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "curl")

	features := DetectLinuxFeatures()
	if !features.CanUnshareNet {
		t.Skip("skipping: test relies on network namespace isolation")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("should-not-be-reached"))
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate test port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	trueVal := true
	cfg.Network.AllowLocalOutbound = &trueVal
	// Intentionally leave AllowLocalOutboundPorts empty.

	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/"
	result := runUnderSandboxWithTimeout(t, cfg, "curl -sS --max-time 3 "+url, workspace, 10*time.Second)

	if !result.Failed() && strings.Contains(result.Stdout, "should-not-be-reached") {
		t.Fatalf("expected connection to host loopback to stay blocked without allowLocalOutboundPorts, but curl succeeded\nstdout: %s\nstderr: %s",
			result.Stdout, result.Stderr)
	}
}

// TestLinux_ProxyAllowsAllowedDomains verifies the proxy allows configured domains.
func TestLinux_ProxyAllowsAllowedDomains(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "curl")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithNetwork("httpbin.org")
	cfg.Filesystem.AllowWrite = []string{workspace}

	// This test requires actual network - skip in CI if network is unavailable
	if os.Getenv("FENCE_TEST_NETWORK") != "1" {
		t.Skip("skipping: set FENCE_TEST_NETWORK=1 to run network tests")
	}

	result := runUnderSandboxWithTimeout(t, cfg, "curl -s --connect-timeout 5 --max-time 10 https://httpbin.org/get", workspace, 15*time.Second)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "httpbin")
}

// ============================================================================
// Seccomp Tests (if available)
// ============================================================================

// TestLinux_SeccompBlocksDangerousSyscalls tests that dangerous syscalls are blocked.
func TestLinux_SeccompBlocksDangerousSyscalls(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfLandlockNotUsable(t) // Seccomp tests are unreliable in test environments

	features := DetectLinuxFeatures()
	if !features.HasSeccomp {
		t.Skip("skipping: seccomp not available")
	}

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Try to use ptrace (should be blocked by seccomp filter)
	result := runUnderSandbox(t, cfg, `python3 -c "import ctypes; ctypes.CDLL(None).ptrace(0, 0, 0, 0)"`, workspace)

	// ptrace should be blocked, causing an error
	assertBlocked(t, result)
}

// ============================================================================
// Python Compatibility Tests
// ============================================================================

// TestLinux_PythonMultiprocessingWorks verifies Python multiprocessing works.
func TestLinux_PythonMultiprocessingWorks(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "python3")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	// Python multiprocessing needs /dev/shm
	cfg.Filesystem.AllowWrite = append(cfg.Filesystem.AllowWrite, "/dev/shm")

	pythonCode := `
import multiprocessing
from multiprocessing import Lock, Process

def f(lock):
    with lock:
        print("Lock acquired in child process")

if __name__ == '__main__':
    lock = Lock()
    p = Process(target=f, args=(lock,))
    p.start()
    p.join()
    print("SUCCESS")
`
	// Write Python script to workspace
	scriptPath := createTestFile(t, workspace, "test_mp.py", pythonCode)

	result := runUnderSandboxWithTimeout(t, cfg, "python3 "+scriptPath, workspace, 30*time.Second)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "SUCCESS")
}

// TestLinux_PythonGetpwuidWorks verifies Python can look up user info.
func TestLinux_PythonGetpwuidWorks(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "python3")

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	result := runUnderSandbox(t, cfg, `python3 -c "import pwd, os; print(pwd.getpwuid(os.getuid()).pw_name)"`, workspace)

	assertAllowed(t, result)
	if result.Stdout == "" {
		t.Errorf("expected username output")
	}
}

func TestLinux_XDGRuntimeDirFallsBackWhenInheritedPathIsUnavailable(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	t.Setenv("XDG_RUNTIME_DIR", "/run/user/fence-test-missing")
	t.Setenv("TMPDIR", "/run/user/fence-test-missing/tmp")

	result := runUnderLinuxSandboxDirect(t, cfg, `printf 'XDG=%s\nTMP=%s\n' "$XDG_RUNTIME_DIR" "$TMPDIR" && test -n "$XDG_RUNTIME_DIR" && test -d "$XDG_RUNTIME_DIR" && test -w "$XDG_RUNTIME_DIR" && touch "$XDG_RUNTIME_DIR/fence-runtime-probe" && stat -c 'MODE=%a' "$XDG_RUNTIME_DIR" && test -d "$TMPDIR" && test -w "$TMPDIR" && touch "$TMPDIR/fence-tmp-probe" && echo OK`, workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "XDG=/tmp/fence-runtime-")
	assertContains(t, result.Stdout, "TMP=/tmp")
	assertContains(t, result.Stdout, "MODE=700")
	assertContains(t, result.Stdout, "OK")
}

func TestLinux_XDGRuntimeDirFallbackIsCleanedUpOnExit(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.AllowWrite = append(cfg.Filesystem.AllowWrite, "/tmp")

	t.Setenv("XDG_RUNTIME_DIR", "/run/user/fence-test-missing")
	t.Setenv("TMPDIR", "/run/user/fence-test-missing/tmp")

	result := runUnderLinuxSandboxDirect(t, cfg, `printf 'XDG=%s\n' "$XDG_RUNTIME_DIR" && touch "$XDG_RUNTIME_DIR/fence-runtime-probe" && echo OK`, workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "XDG=/tmp/fence-runtime-")
	assertContains(t, result.Stdout, "OK")

	var runtimeDir string
	for _, line := range strings.Split(result.Stdout, "\n") {
		if strings.HasPrefix(line, "XDG=") {
			runtimeDir = strings.TrimPrefix(line, "XDG=")
			break
		}
	}
	if runtimeDir == "" {
		t.Fatal("expected sandbox output to include XDG runtime dir")
	}
	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Fatalf("expected fallback runtime dir %q to be cleaned up, stat err=%v", runtimeDir, err)
	}
}

func TestLinux_XDGRuntimeDirPreservedWhenWritable(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	runtimeDir := filepath.Join(workspace, "runtime")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatalf("failed to create runtime dir: %v", err)
	}
	tmpDir := filepath.Join(workspace, "tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		t.Fatalf("failed to create tmp dir: %v", err)
	}

	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("TMPDIR", tmpDir)

	cfg := testConfigWithWorkspace(workspace)
	result := runUnderLinuxSandboxDirect(t, cfg, `printf 'XDG=%s\nTMP=%s\n' "$XDG_RUNTIME_DIR" "$TMPDIR" && touch "$XDG_RUNTIME_DIR/fence-runtime-probe" && touch "$TMPDIR/fence-tmp-probe" && echo OK`, workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "XDG="+runtimeDir)
	assertContains(t, result.Stdout, "OK")
	assertFileExists(t, filepath.Join(runtimeDir, "fence-runtime-probe"))

	// Some environments normalize inherited TMPDIR to the sandbox's /tmp even
	// when the original path is otherwise writable. The behavior we require is
	// that TMPDIR remains usable, not that it always keeps the exact host path.
	switch {
	case strings.Contains(result.Stdout, "TMP="+tmpDir):
		assertFileExists(t, filepath.Join(tmpDir, "fence-tmp-probe"))
	case strings.Contains(result.Stdout, "TMP=/tmp\n"):
		// The in-sandbox touch above already proved TMPDIR is usable.
	default:
		t.Fatalf("expected sandbox TMPDIR to remain %q or fall back to /tmp, got %q", tmpDir, result.Stdout)
	}
}

func TestLinux_PTYAllocationWorksInDirectSandbox(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "python3")

	workspace := createTempWorkspace(t)

	for _, mode := range []config.DeviceMode{config.DeviceModeMinimal, config.DeviceModeHost} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := testConfigWithWorkspace(workspace)
			cfg.AllowPty = true
			cfg.Devices.Mode = mode

			result := runUnderLinuxSandboxDirect(t, cfg, `python3 -c "import os; master, slave = os.openpty(); os.close(master); os.close(slave); print('OK')"`, workspace)

			assertAllowed(t, result)
			assertContains(t, result.Stdout, "OK")
		})
	}
}

func TestLinux_DefaultCrossMountToolchainPathsRemainVisible(t *testing.T) {
	skipIfAlreadySandboxed(t)

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("skipping: home directory unavailable")
	}

	var candidate string
	for _, path := range linuxDefaultCrossMountReadablePaths() {
		if !strings.HasPrefix(path, home+string(os.PathSeparator)) {
			continue
		}
		if fileExists(path) && !sameDevice("/", path) {
			candidate = path
			break
		}
	}
	if candidate == "" {
		t.Skip("skipping: no user toolchain path exists on a separate mount")
	}

	workspace, err := os.MkdirTemp(home, ".fence-crossmount-*")
	if err != nil {
		t.Fatalf("failed to create home-based workspace: %v", err)
	}
	defer func() { _ = os.RemoveAll(workspace) }()

	cfg := testConfigWithWorkspace(workspace)
	result := runUnderLinuxSandboxDirect(
		t,
		cfg,
		fmt.Sprintf(`test -e %q && echo OK`, candidate),
		workspace,
	)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "OK")
}

// ============================================================================
// Security Edge Case Tests
// ============================================================================

// TestLinux_SymlinkEscapeBlocked verifies symlink attacks are prevented.
func TestLinux_SymlinkEscapeBlocked(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Create a symlink pointing outside the workspace
	symlinkPath := filepath.Join(workspace, "escape")
	_ = os.Symlink("/etc", symlinkPath)

	// Try to write through the symlink
	result := runUnderSandbox(t, cfg, "echo 'test' > "+symlinkPath+"/fence-test", workspace)

	assertBlocked(t, result)
	assertFileNotExists(t, "/etc/fence-test")
}

// TestLinux_PathTraversalBlocked verifies path traversal attacks are prevented.
func TestLinux_PathTraversalBlocked(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfLandlockNotUsable(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Try to escape using ../../../
	result := runUnderSandbox(t, cfg, "touch ../../../../tmp/fence-escape-test", workspace)

	assertBlocked(t, result)
	assertFileNotExists(t, "/tmp/fence-escape-test")
}

// TestLinux_DeviceAccessBlocked verifies device files cannot be accessed.
func TestLinux_DeviceAccessBlocked(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Try to read /dev/mem (requires root anyway, but should be blocked)
	// Use a command that will exit non-zero if the file doesn't exist or can't be read
	result := runUnderSandbox(t, cfg, "test -r /dev/mem && cat /dev/mem", workspace)

	// Should fail (permission denied, blocked by sandbox, or device doesn't exist)
	assertBlocked(t, result)
}

// TestLinux_ProcSelfEnvReadable verifies /proc/self can be read for basic operations.
func TestLinux_ProcSelfEnvReadable(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)
	cfg := testConfigWithWorkspace(workspace)

	// Reading /proc/self/cmdline should work
	result := runUnderSandbox(t, cfg, "cat /proc/self/cmdline", workspace)

	assertAllowed(t, result)
}

// TestLinux_GlobPatternAllowsWriteToMatchingFile verifies that glob patterns
// like "~/.claude*" correctly allow writes to matching files (not just directories).
// The bug was that Landlock rules for files were silently failing because
// directory-only access rights (MAKE_*, REFER, etc.) were being applied.
func TestLinux_GlobPatternAllowsWriteToMatchingFile(t *testing.T) {
	skipIfAlreadySandboxed(t)

	workspace := createTempWorkspace(t)

	testFile := filepath.Join(workspace, ".testglob.json")
	if err := os.WriteFile(testFile, []byte(`{"initial": true}`), 0o600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Configure allowWrite with a glob pattern that matches the file
	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.AllowWrite = []string{
		workspace,
		filepath.Join(workspace, ".testglob*"),
	}

	// Try to append to the file (shouldn't fail)
	result := runUnderSandbox(t, cfg, "echo 'appended' >> "+testFile, workspace)

	assertAllowed(t, result)

	content, err := os.ReadFile(testFile) //nolint:gosec
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if !strings.Contains(string(content), "appended") {
		t.Errorf("expected file to contain 'appended', got: %s", string(content))
	}
}

// ============================================================================
// Helper functions
// ============================================================================

func lookPathLinux(cmd string) (string, error) {
	return exec.LookPath(cmd)
}
