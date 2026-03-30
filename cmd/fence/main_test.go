package main

import (
	"os/exec"
	"testing"

	"github.com/spf13/cobra"
)

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
