//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

func TestNormalizeRuntimeExecArgv_UsesExecPathBasename(t *testing.T) {
	got := normalizeRuntimeExecArgv("/usr/bin/git", []string{"definitely-not-git", "push", "origin"})
	want := []string{"git", "push", "origin"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("normalizeRuntimeExecArgv() = %v, want %v", got, want)
	}
}

func TestMatchesRuntimeArgvPrefix(t *testing.T) {
	tests := []struct {
		name   string
		actual []string
		rule   string
		want   bool
	}{
		{
			name:   "multi-token prefix match",
			actual: []string{"git", "push", "origin", "main"},
			rule:   "git push",
			want:   true,
		},
		{
			name:   "quoted token preserved",
			actual: []string{"git", "commit", "-m", "hello world"},
			rule:   `git commit -m "hello world"`,
			want:   true,
		},
		{
			name:   "equals suffix match",
			actual: []string{"dd", "if=/dev/zero", "of=/tmp/out"},
			rule:   "dd if=",
			want:   true,
		},
		{
			name:   "different subcommand denied",
			actual: []string{"git", "status"},
			rule:   "git push",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesRuntimeArgvPrefix(tt.actual, tt.rule); got != tt.want {
				t.Fatalf("matchesRuntimeArgvPrefix(%v, %q) = %v, want %v", tt.actual, tt.rule, got, tt.want)
			}
		})
	}
}

func TestMatchRuntimeExecPolicy_AllowOverridesDeny(t *testing.T) {
	useDefaults := false
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:              []string{"git push"},
			Allow:             []string{"git push origin docs"},
			UseDefaults:       &useDefaults,
			RuntimeExecPolicy: config.RuntimeExecPolicyArgv,
		},
	}

	if _, blocked := matchRuntimeExecPolicy("/usr/bin/git", []string{"git", "push", "origin", "docs"}, cfg); blocked {
		t.Fatal("expected allow rule to override deny for runtime argv policy")
	}

	match, blocked := matchRuntimeExecPolicy("/usr/bin/git", []string{"git", "push", "origin", "main"}, cfg)
	if !blocked {
		t.Fatal("expected git push origin main to be blocked")
	}
	if match.BlockedPrefix != "git push" {
		t.Fatalf("blocked prefix = %q, want %q", match.BlockedPrefix, "git push")
	}
}

func TestEvaluateLinuxRuntimeExecDecisionForCandidate_BootstrapExecStillChecksContinueSafety(t *testing.T) {
	called := false
	decision := evaluateLinuxRuntimeExecDecisionForCandidate(
		1234,
		linuxBootstrapShellPath,
		[]string{"shell"},
		nil,
		&linuxArgvExecSupervisorState{},
		func(int) (int, error) {
			called = true
			return 2, nil
		},
	)
	if !called {
		t.Fatal("expected bootstrap exec to run CONTINUE safety checks")
	}
	if decision.Allow {
		t.Fatal("expected multithreaded bootstrap exec to be blocked")
	}
	if !strings.Contains(decision.Message, "multithreaded exec cannot be safely continued in argv mode") {
		t.Fatalf("expected multithreaded exec message, got: %s", decision.Message)
	}
}

func TestEvaluateLinuxRuntimeExecDecisionForCandidate_FirstBootstrapExecUsesOneTimeAllowance(t *testing.T) {
	state := &linuxArgvExecSupervisorState{
		allowOneMultithreadedBootstrapContinue: true,
	}

	decision := evaluateLinuxRuntimeExecDecisionForCandidate(
		1234,
		linuxBootstrapShellPath,
		[]string{"shell"},
		nil,
		state,
		func(int) (int, error) {
			return 2, nil
		},
	)
	if !decision.Allow {
		t.Fatalf("expected first multithreaded bootstrap exec to use one-time allowance, got: %s", decision.Message)
	}
	if state.allowOneMultithreadedBootstrapContinue {
		t.Fatal("expected multithreaded bootstrap allowance to be consumed")
	}
}

func TestIsLinuxBootstrapExecPath_OnlyAllowsStagedExecutables(t *testing.T) {
	if !isLinuxBootstrapExecPath(linuxBootstrapShellPath) {
		t.Fatalf("expected %q to be treated as a bootstrap exec path", linuxBootstrapShellPath)
	}
	if isLinuxBootstrapExecPath(filepath.Join(linuxBootstrapBinDir, "evil")) {
		t.Fatalf("unexpected bootstrap exec match for %q", filepath.Join(linuxBootstrapBinDir, "evil"))
	}
}

func TestWrapCommandLinuxWithOptions_ArgvRuntimeExecPolicyRequiresFenceCLI(t *testing.T) {
	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get executable path: %v", err)
	}
	if strings.Contains(filepath.Base(exePath), "fence") {
		t.Skip("current executable already looks like fence CLI")
	}

	useDefaults := false
	_, err = WrapCommandLinuxWithOptions(&config.Config{
		Command: config.CommandConfig{
			Deny:              []string{"git push"},
			UseDefaults:       &useDefaults,
			RuntimeExecPolicy: config.RuntimeExecPolicyArgv,
		},
	}, "echo ok", nil, nil, LinuxSandboxOptions{
		UseLandlock: false,
		UseSeccomp:  false,
		UseEBPF:     false,
		ShellMode:   ShellModeDefault,
	})
	if err == nil {
		t.Fatal("expected argv runtime exec policy to require fence CLI executable")
	}
	if !strings.Contains(err.Error(), "runtime supervisor") {
		t.Fatalf("expected runtime supervisor error, got: %v", err)
	}
}
