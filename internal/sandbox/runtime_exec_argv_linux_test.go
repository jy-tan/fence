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
			name:   "equals suffix can appear later",
			actual: []string{"dd", "of=/tmp/out", "if=/dev/zero"},
			rule:   "dd if=",
			want:   true,
		},
		{
			name:   "different subcommand denied",
			actual: []string{"git", "status"},
			rule:   "git push",
			want:   false,
		},
		{
			name:   "leading global flags before subcommand are skipped",
			actual: []string{"docker", "--debug", "run", "--privileged"},
			rule:   "docker run --privileged",
			want:   true,
		},
		{
			name:   "leading global flag value before subcommand is skipped",
			actual: []string{"docker", "--context", "prod", "run", "--privileged"},
			rule:   "docker run --privileged",
			want:   true,
		},
		{
			name:   "single short option value before subcommand is skipped",
			actual: []string{"git", "-C", "/tmp", "push"},
			rule:   "git push",
			want:   true,
		},
		{
			name:   "single short option without value still allows subcommand",
			actual: []string{"git", "-p", "push"},
			rule:   "git push",
			want:   true,
		},
		{
			name:   "path qualified rule is normalized",
			actual: []string{"git", "push", "origin", "main"},
			rule:   "/usr/bin/git push",
			want:   true,
		},
		{
			name:   "non equals tokens after subcommand stay positional",
			actual: []string{"docker", "run", "--name", "test", "--privileged"},
			rule:   "docker run --privileged",
			want:   false,
		},
		{
			name:   "positional args before subcommand are not skipped",
			actual: []string{"docker", "foo", "run", "--privileged"},
			rule:   "docker run --privileged",
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

func TestEvaluateLinuxRuntimeExecDecisionForCandidate_FirstBootstrapExecUsesConfiguredAllowance(t *testing.T) {
	state := &linuxArgvExecSupervisorState{
		remainingMultithreadedBootstrapContinues: 1,
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
		t.Fatalf("expected first multithreaded bootstrap exec to use configured allowance, got: %s", decision.Message)
	}
	if state.remainingMultithreadedBootstrapContinues != 0 {
		t.Fatal("expected multithreaded bootstrap allowance to be consumed")
	}
}

func TestEvaluateLinuxRuntimeExecDecisionForCandidate_BootstrapAllowanceCanCoverLandlockFlow(t *testing.T) {
	state := &linuxArgvExecSupervisorState{
		remainingMultithreadedBootstrapContinues: 2,
	}
	threadCountFunc := func(int) (int, error) {
		return 2, nil
	}

	for i := 0; i < 2; i++ {
		decision := evaluateLinuxRuntimeExecDecisionForCandidate(
			1234,
			linuxBootstrapShellPath,
			[]string{"shell"},
			nil,
			state,
			threadCountFunc,
		)
		if !decision.Allow {
			t.Fatalf("expected bootstrap allowance %d to be accepted, got: %s", i+1, decision.Message)
		}
	}

	if state.remainingMultithreadedBootstrapContinues != 0 {
		t.Fatalf("expected bootstrap allowance budget to be exhausted, got %d", state.remainingMultithreadedBootstrapContinues)
	}

	decision := evaluateLinuxRuntimeExecDecisionForCandidate(
		1234,
		linuxBootstrapShellPath,
		[]string{"shell"},
		nil,
		state,
		threadCountFunc,
	)
	if decision.Allow {
		t.Fatal("expected third multithreaded bootstrap exec to be blocked after budget is exhausted")
	}
}

func TestLinuxArgvExecMultithreadedBootstrapContinueBudget(t *testing.T) {
	if got := linuxArgvExecMultithreadedBootstrapContinueBudget(false); got != 1 {
		t.Fatalf("linuxArgvExecMultithreadedBootstrapContinueBudget(false) = %d, want 1", got)
	}
	if got := linuxArgvExecMultithreadedBootstrapContinueBudget(true); got != 2 {
		t.Fatalf("linuxArgvExecMultithreadedBootstrapContinueBudget(true) = %d, want 2", got)
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
