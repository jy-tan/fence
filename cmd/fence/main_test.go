package main

import (
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/Use-Tusk/fence/internal/sandbox"
	"github.com/spf13/cobra"
)

func TestParseExposePortFlag(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want sandbox.ExposedPort
	}{
		{
			name: "bare port defaults to loopback",
			in:   "3000",
			want: sandbox.ExposedPort{BindAddress: "127.0.0.1", Port: 3000},
		},
		{
			name: "explicit loopback",
			in:   "127.0.0.1:8080",
			want: sandbox.ExposedPort{BindAddress: "127.0.0.1", Port: 8080},
		},
		{
			name: "all interfaces opt-in",
			in:   "0.0.0.0:8080",
			want: sandbox.ExposedPort{BindAddress: "0.0.0.0", Port: 8080},
		},
		{
			name: "specific LAN interface",
			in:   "192.168.1.10:8080",
			want: sandbox.ExposedPort{BindAddress: "192.168.1.10", Port: 8080},
		},
		{
			name: "ipv6 loopback",
			in:   "[::1]:8080",
			want: sandbox.ExposedPort{BindAddress: "::1", Port: 8080},
		},
		{
			name: "ipv6 wildcard",
			in:   "[::]:8080",
			want: sandbox.ExposedPort{BindAddress: "::", Port: 8080},
		},
		{
			name: "whitespace tolerated",
			in:   "  4096  ",
			want: sandbox.ExposedPort{BindAddress: "127.0.0.1", Port: 4096},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseExposePortFlag(tc.in)
			if err != nil {
				t.Fatalf("parseExposePortFlag(%q) returned error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseExposePortFlag(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseExposePortFlag_Errors(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantErrSubs []string
	}{
		{
			name:        "empty",
			in:          "",
			wantErrSubs: []string{"empty value"},
		},
		{
			name:        "non-numeric port",
			in:          "abc",
			wantErrSubs: []string{"invalid --port", "must be an integer"},
		},
		{
			name:        "port out of range",
			in:          "70000",
			wantErrSubs: []string{"invalid --port", "out of range"},
		},
		{
			name:        "zero port",
			in:          "0",
			wantErrSubs: []string{"invalid --port", "out of range"},
		},
		{
			name:        "negative port handled by SplitHostPort",
			in:          "-1",
			wantErrSubs: []string{"invalid --port"},
		},
		{
			name:        "missing bind address",
			in:          ":3000",
			wantErrSubs: []string{"invalid --port", "missing bind address"},
		},
		{
			name:        "non-IP bind address",
			in:          "localhost:3000",
			wantErrSubs: []string{"invalid --port", "must be a literal IP", "hostnames are not supported"},
		},
		{
			name:        "ipv6 without brackets gets misparsed",
			in:          "::1:3000",
			wantErrSubs: []string{"invalid --port"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseExposePortFlag(tc.in)
			if err == nil {
				t.Fatalf("parseExposePortFlag(%q) succeeded, want error", tc.in)
			}
			msg := err.Error()
			for _, sub := range tc.wantErrSubs {
				if !strings.Contains(msg, sub) {
					t.Errorf("parseExposePortFlag(%q) error %q does not contain %q", tc.in, msg, sub)
				}
			}
		})
	}
}

func TestParseExposePortFlags_PreservesOrderAndCombinations(t *testing.T) {
	in := []string{"3000", "0.0.0.0:8080", "[::1]:9090"}
	got, err := parseExposePortFlags(in)
	if err != nil {
		t.Fatalf("parseExposePortFlags(%v) error: %v", in, err)
	}
	want := []sandbox.ExposedPort{
		{BindAddress: "127.0.0.1", Port: 3000},
		{BindAddress: "0.0.0.0", Port: 8080},
		{BindAddress: "::1", Port: 9090},
	}
	if len(got) != len(want) {
		t.Fatalf("parseExposePortFlags returned %d entries, want %d (got=%+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseExposePortFlags_EmptyInputReturnsNil(t *testing.T) {
	got, err := parseExposePortFlags(nil)
	if err != nil {
		t.Fatalf("parseExposePortFlags(nil) error: %v", err)
	}
	if got != nil {
		t.Errorf("parseExposePortFlags(nil) = %v, want nil", got)
	}
}

func TestFormatExposureList(t *testing.T) {
	in := []sandbox.ExposedPort{
		{BindAddress: "127.0.0.1", Port: 3000},
		{BindAddress: "0.0.0.0", Port: 8080},
	}
	got := formatExposureList(in)
	want := "127.0.0.1:3000, 0.0.0.0:8080"
	if got != want {
		t.Errorf("formatExposureList = %q, want %q", got, want)
	}
}

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

func TestConfigureRootFlagParsing_StopsAtFirstCommandArg(t *testing.T) {
	var settingsPath string
	var gotArgs []string
	cmd := &cobra.Command{
		Use:  "fence",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			gotArgs = args
			return nil
		},
	}
	cmd.Flags().StringVarP(&settingsPath, "settings", "s", "", "")
	configureRootFlagParsing(cmd)
	cmd.SetArgs([]string{"/bin/echo", "-s", "child-settings.json", "child"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}
	if settingsPath != "" {
		t.Fatalf("expected child -s to remain unparsed by Fence, got settingsPath=%q", settingsPath)
	}
	wantArgs := []string{"/bin/echo", "-s", "child-settings.json", "child"}
	if !slices.Equal(gotArgs, wantArgs) {
		t.Fatalf("args = %v, want %v", gotArgs, wantArgs)
	}
}

func TestConfigureRootFlagParsing_ParsesFlagsBeforeCommand(t *testing.T) {
	var settingsPath string
	var gotArgs []string
	cmd := &cobra.Command{
		Use:  "fence",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			gotArgs = args
			return nil
		},
	}
	cmd.Flags().StringVarP(&settingsPath, "settings", "s", "", "")
	configureRootFlagParsing(cmd)
	cmd.SetArgs([]string{"--settings", "fence.json", "/bin/echo", "child"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}
	if settingsPath != "fence.json" {
		t.Fatalf("settingsPath = %q, want %q", settingsPath, "fence.json")
	}
	wantArgs := []string{"/bin/echo", "child"}
	if !slices.Equal(gotArgs, wantArgs) {
		t.Fatalf("args = %v, want %v", gotArgs, wantArgs)
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
