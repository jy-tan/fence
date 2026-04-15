package main

import (
	"errors"
	"os/exec"
	"slices"
	"testing"

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
