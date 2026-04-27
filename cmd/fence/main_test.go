package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/sandbox"
	"github.com/spf13/cobra"
)

func TestPresentWrapCommandError_PreservesCommandBlockedError(t *testing.T) {
	err := presentWrapCommandError(&sandbox.CommandBlockedError{
		Command:       "ls",
		BlockedPrefix: "ls",
	})

	if got, want := err.Error(), `command blocked by sandbox command policy: "ls" matches "ls"`; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestPresentWrapCommandError_PreservesSSHBlockedError(t *testing.T) {
	err := presentWrapCommandError(&sandbox.SSHBlockedError{
		Host:          "example.com",
		RemoteCommand: "rm -rf /",
		Reason:        "host matches denied pattern \"example.com\"",
	})

	if got, want := err.Error(), `SSH command blocked: host matches denied pattern "example.com" (host: example.com, command: rm -rf /)`; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestPresentWrapCommandError_WrapsNonPolicyError(t *testing.T) {
	err := presentWrapCommandError(errors.New("boom"))

	if got, want := err.Error(), "failed to wrap command: boom"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

// minimalFenceConfigJSON returns a valid FENCE_CONFIG_JSON value for use in
// bootstrap integration tests. The outer process always sets this variable, so
// tests that invoke the binary directly must provide it too.
func minimalFenceConfigJSON(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(config.Default())
	if err != nil {
		t.Fatalf("failed to marshal default config: %v", err)
	}
	return string(data)
}

func TestStartCommandWithSignalProxy_CleanupIsIdempotent(t *testing.T) {
	execCmd := exec.Command("sh", "-c", "exit 0")
	cleanup, err := startCommandWithSignalProxy(execCmd)
	if err != nil {
		t.Fatalf("startCommandWithSignalProxy() error = %v", err)
	}

	if err := execCmd.Wait(); err != nil {
		t.Fatalf("execCmd.Wait() error = %v", err)
	}

	cleanup()
	cleanup()
}

func TestConfigureHostTTYChildProcessGroup_DirectTTY(t *testing.T) {
	execCmd := exec.Command("sh", "-c", "exit 0")

	configureHostTTYChildProcessGroup(execCmd, true, false)

	if execCmd.SysProcAttr == nil {
		t.Fatal("expected SysProcAttr to be configured for direct TTY sessions")
	}
	if !execCmd.SysProcAttr.Setpgid {
		t.Fatal("expected Setpgid to be enabled for direct TTY sessions")
	}
	if execCmd.SysProcAttr.Pgid != 0 {
		t.Fatalf("expected Pgid=0, got %d", execCmd.SysProcAttr.Pgid)
	}
}

func TestConfigureHostTTYChildProcessGroup_PTYRelay(t *testing.T) {
	execCmd := exec.Command("sh", "-c", "exit 0")

	configureHostTTYChildProcessGroup(execCmd, true, true)

	if execCmd.SysProcAttr != nil {
		t.Fatal("expected PTY relay sessions to leave SysProcAttr unset")
	}
}

func TestApplyCLIConfigOverrides_NilConfigWithForceNewSessionFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Bool("force-new-session", false, "")
	if err := cmd.Flags().Set("force-new-session", "true"); err != nil {
		t.Fatalf("failed to set force-new-session flag: %v", err)
	}

	cfg := applyCLIConfigOverrides(cmd, nil, true)
	if cfg == nil {
		t.Fatal("expected config to be initialized when nil")
	}
	if cfg.ForceNewSession == nil || !*cfg.ForceNewSession {
		t.Fatal("expected ForceNewSession override to be applied")
	}
}

func TestUpsertEnv(t *testing.T) {
	t.Run("replaces existing value", func(t *testing.T) {
		env := []string{"A=1", "FENCE_LOG_FILE=/tmp/old.log"}
		updated := upsertEnv(env, "FENCE_LOG_FILE", "/tmp/new.log")

		if !slices.Contains(updated, "FENCE_LOG_FILE=/tmp/new.log") {
			t.Fatalf("expected updated env entry, got %v", updated)
		}
		if slices.Contains(updated, "FENCE_LOG_FILE=/tmp/old.log") {
			t.Fatalf("expected old env entry to be replaced, got %v", updated)
		}
	})

	t.Run("appends missing value", func(t *testing.T) {
		env := []string{"A=1"}
		updated := upsertEnv(env, "FENCE_LOG_FILE", "/tmp/fence.log")

		if !slices.Contains(updated, "FENCE_LOG_FILE=/tmp/fence.log") {
			t.Fatalf("expected appended env entry, got %v", updated)
		}
	})
}

func TestLinuxBootstrapWrapper_SimpleCommand(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("--linux-bootstrap is only supported on Linux")
	}
	// Build the fence binary first
	buildCmd := exec.Command("go", "build", "-o", "/tmp/fence-test", ".")
	buildCmd.Dir = "."
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build fence: %v\n%s", err, output)
	}
	defer func() { _ = os.Remove("/tmp/fence-test") }()

	// Run with --linux-bootstrap -- echo hello
	cmd := exec.Command("/tmp/fence-test", "--linux-bootstrap", "--", "echo", "hello")
	cmd.Env = append(os.Environ(), "FENCE_CONFIG_JSON="+minimalFenceConfigJSON(t))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\n%s", err, output)
	}

	if !strings.Contains(string(output), "hello") {
		t.Errorf("expected output to contain 'hello', got: %s", output)
	}
}

func TestLinuxBootstrapWrapper_FlagParsing(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("--linux-bootstrap is only supported on Linux")
	}
	// Build the fence binary first
	buildCmd := exec.Command("go", "build", "-o", "/tmp/fence-test", ".")
	buildCmd.Dir = "."
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build fence: %v\n%s", err, output)
	}
	defer func() { _ = os.Remove("/tmp/fence-test") }()

	// Test that flags are parsed correctly and -- separates flags from command
	// Note: We don't pass socket paths here since we're just testing flag parsing
	cmd := exec.Command("/tmp/fence-test",
		"--linux-bootstrap",
		"--", "echo", "test")
	cmd.Env = append(os.Environ(), "FENCE_CONFIG_JSON="+minimalFenceConfigJSON(t))

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\n%s", err, output)
	}

	if !strings.Contains(string(output), "test") {
		t.Errorf("expected output to contain 'test', got: %s", output)
	}
}

func TestLinuxBootstrapWrapper_ExitCode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("--linux-bootstrap is only supported on Linux")
	}
	// Build the fence binary first
	buildCmd := exec.Command("go", "build", "-o", "/tmp/fence-test", ".")
	buildCmd.Dir = "."
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build fence: %v\n%s", err, output)
	}
	defer func() { _ = os.Remove("/tmp/fence-test") }()

	// Test that exit codes are properly propagated
	cmd := exec.Command("/tmp/fence-test", "--linux-bootstrap", "--", "sh", "-c", "exit 42")
	cmd.Env = append(os.Environ(), "FENCE_CONFIG_JSON="+minimalFenceConfigJSON(t))

	_ = cmd.Run()

	if cmd.ProcessState == nil {
		t.Fatal("ProcessState is nil")
	}

	exitCode := cmd.ProcessState.ExitCode()
	if exitCode != 42 {
		t.Errorf("expected exit code 42, got %d", exitCode)
	}
}

func TestLinuxBootstrapWrapper_CommandNotFound(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("--linux-bootstrap is only supported on Linux")
	}
	// Build the fence binary first
	buildCmd := exec.Command("go", "build", "-o", "/tmp/fence-test", ".")
	buildCmd.Dir = "."
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build fence: %v\n%s", err, output)
	}
	defer func() { _ = os.Remove("/tmp/fence-test") }()

	// Test command not found returns exit code 127
	cmd := exec.Command("/tmp/fence-test", "--linux-bootstrap", "--", "nonexistent-command-xyz")
	cmd.Env = append(os.Environ(), "FENCE_CONFIG_JSON="+minimalFenceConfigJSON(t))

	_ = cmd.Run()

	if cmd.ProcessState == nil {
		t.Fatal("ProcessState is nil")
	}

	exitCode := cmd.ProcessState.ExitCode()
	if exitCode != 127 {
		t.Errorf("expected exit code 127 for command not found, got %d", exitCode)
	}
}

func TestLinuxBootstrapWrapper_NoCommand(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("--linux-bootstrap is only supported on Linux")
	}
	// Build the fence binary first
	buildCmd := exec.Command("go", "build", "-o", "/tmp/fence-test", ".")
	buildCmd.Dir = "."
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build fence: %v\n%s", err, output)
	}
	defer func() { _ = os.Remove("/tmp/fence-test") }()

	// Test no command specified returns exit code 125 (ExitWrapperSetupFailed)
	cmd := exec.Command("/tmp/fence-test", "--linux-bootstrap")
	cmd.Env = append(os.Environ(), "FENCE_CONFIG_JSON="+minimalFenceConfigJSON(t))

	_ = cmd.Run()

	if cmd.ProcessState == nil {
		t.Fatal("ProcessState is nil")
	}

	exitCode := cmd.ProcessState.ExitCode()
	if exitCode != 125 {
		t.Errorf("expected exit code 125 for no command, got %d", exitCode)
	}
}
