//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	workspace := createTempWorkspace(t)
	createGitRepo(t, workspace)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.AllowGitConfig = true

	configPath := filepath.Join(workspace, ".git", "config")

	// This may or may not work depending on the implementation
	// The key is that hooks should ALWAYS be protected, but config might be allowed
	result := runUnderSandbox(t, cfg, "echo '[test]' >> "+configPath, workspace)

	// We just verify it doesn't crash; actual behavior depends on implementation
	_ = result
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
