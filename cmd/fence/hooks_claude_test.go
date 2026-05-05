package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Use-Tusk/fence/internal/sandbox"
)

func TestBuildClaudePreToolUseResponse_WrapsBashCommand(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "")

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test",
			"description": "Run tests",
			"timeout": 120000,
			"run_in_background": true
		}
	}`

	response, changed, err := buildClaudePreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildClaudePreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected Bash command to be rewritten")
	}

	var decoded claudePreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput in response")
	}
	if decoded.HookSpecificOutput.PermissionDecision != "allow" {
		t.Fatalf("expected permissionDecision allow, got %q", decoded.HookSpecificOutput.PermissionDecision)
	}

	wantCommand := sandbox.ShellQuote([]string{"/usr/local/bin/fence", "-c", "npm test"})
	if got := decoded.HookSpecificOutput.UpdatedInput["command"]; got != wantCommand {
		t.Fatalf("expected wrapped command %q, got %#v", wantCommand, got)
	}
	if got := decoded.HookSpecificOutput.UpdatedInput["description"]; got != "Run tests" {
		t.Fatalf("expected description to be preserved, got %#v", got)
	}
	if got := decoded.HookSpecificOutput.UpdatedInput["run_in_background"]; got != true {
		t.Fatalf("expected run_in_background to be preserved, got %#v", got)
	}
	if got := decoded.HookSpecificOutput.UpdatedInput["timeout"]; got != float64(120000) {
		t.Fatalf("expected timeout to be preserved, got %#v", got)
	}
}

func TestBuildClaudePreToolUseResponse_SkipsPureCD(t *testing.T) {
	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "cd ../repo"
		}
	}`

	_, changed, err := buildClaudePreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildClaudePreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected pure cd command to be skipped")
	}
}

func TestBuildClaudePreToolUseResponse_SkipsAlreadyFencedCommand(t *testing.T) {
	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "/usr/local/bin/fence -c 'npm test'"
		}
	}`

	_, changed, err := buildClaudePreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildClaudePreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected already-fenced command to be skipped")
	}
}

func TestBuildClaudePreToolUseResponse_IgnoresNonBashEvent(t *testing.T) {
	input := `{
		"hook_event_name": "PostToolUse",
		"tool_name": "Read",
		"tool_input": {
			"file_path": "/tmp/test.txt"
		}
	}`

	_, changed, err := buildClaudePreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildClaudePreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected non-Bash event to be ignored")
	}
}

func TestBuildClaudePreToolUseResponse_InvalidJSON(t *testing.T) {
	_, _, err := buildClaudePreToolUseResponse(strings.NewReader(`{`), "/usr/local/bin/fence", nil)
	if err == nil {
		t.Fatal("expected invalid JSON to return an error")
	}
}

func TestBuildClaudePreToolUseResponse_LeavesCommandUnchangedInsideFence(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "1")

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test"
		}
	}`

	_, changed, err := buildClaudePreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildClaudePreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected command to stay unchanged when already inside Fence")
	}
}

func TestBuildClaudePreToolUseResponse_UsesPinnedSettings(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "")
	settingsPath := filepath.Join(t.TempDir(), "fence policy.json")
	if err := os.WriteFile(settingsPath, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test"
		}
	}`

	response, changed, err := buildClaudePreToolUseResponse(
		strings.NewReader(input),
		"/usr/local/bin/fence",
		[]string{"--settings", settingsPath},
	)
	if err != nil {
		t.Fatalf("buildClaudePreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected Bash command to be rewritten")
	}

	var decoded claudePreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	wantCommand := sandbox.ShellQuote([]string{"/usr/local/bin/fence", "--settings", settingsPath, "-c", "npm test"})
	if got := decoded.HookSpecificOutput.UpdatedInput["command"]; got != wantCommand {
		t.Fatalf("expected wrapped command %q, got %#v", wantCommand, got)
	}
}

func TestBuildClaudePreToolUseResponse_DeniesBlockedCommandInsideFence(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "1")

	settingsPath := filepath.Join(t.TempDir(), "fence.json")
	content := `{
  "command": {
    "deny": ["npm test"],
    "useDefaults": false
  }
}`
	if err := os.WriteFile(settingsPath, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test"
		}
	}`

	response, changed, err := buildClaudePreToolUseResponse(
		strings.NewReader(input),
		"/usr/local/bin/fence",
		[]string{"--settings", settingsPath},
	)
	if err != nil {
		t.Fatalf("buildClaudePreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected blocked command to produce a deny response")
	}

	var decoded claudePreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput in response")
	}
	if got := decoded.HookSpecificOutput.PermissionDecision; got != "deny" {
		t.Fatalf("expected permissionDecision deny, got %q", got)
	}
	if decoded.HookSpecificOutput.UpdatedInput != nil {
		t.Fatalf("expected deny response to omit updatedInput, got %#v", decoded.HookSpecificOutput.UpdatedInput)
	}
}

func TestBuildClaudePreToolUseResponse_UsesPayloadCWDForOuterDeny(t *testing.T) {
	repoDir := t.TempDir()
	settingsPath := filepath.Join(repoDir, "fence.json")
	content := `{
  "command": {
    "deny": ["ls"],
    "useDefaults": false
  }
}`
	if err := os.WriteFile(settingsPath, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "pwd && ls",
			"cwd": "` + repoDir + `"
		},
		"cwd": "` + repoDir + `"
	}`

	response, changed, err := buildClaudePreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildClaudePreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected blocked command to produce a deny response")
	}

	var decoded claudePreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput in response")
	}
	if got := decoded.HookSpecificOutput.PermissionDecision; got != "deny" {
		t.Fatalf("expected permissionDecision deny, got %q", got)
	}
	if decoded.HookSpecificOutput.UpdatedInput != nil {
		t.Fatalf("expected deny response to omit updatedInput, got %#v", decoded.HookSpecificOutput.UpdatedInput)
	}
}

func TestRunClaudePreToolUse_AcceptsCursorPayload(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "")

	input := `{
		"hook_event_name": "preToolUse",
		"tool_name": "Shell",
		"tool_input": {
			"command": "npm test",
			"timeout": 30000
		}
	}`

	var stdout bytes.Buffer
	if err := runClaudePreToolUse(strings.NewReader(input), &stdout, "/usr/local/bin/fence", nil); err != nil {
		t.Fatalf("runClaudePreToolUse() error = %v", err)
	}

	var decoded cursorPreToolUseResponse
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if got := decoded.Permission; got != "allow" {
		t.Fatalf("expected permission allow, got %q", got)
	}
	if !decoded.Continue {
		t.Fatal("expected continue=true in response")
	}
	wantCommand := sandbox.ShellQuote([]string{"/usr/local/bin/fence", "-c", "npm test"})
	if got := decoded.UpdatedInput["command"]; got != wantCommand {
		t.Fatalf("expected wrapped command %q, got %#v", wantCommand, got)
	}
}
