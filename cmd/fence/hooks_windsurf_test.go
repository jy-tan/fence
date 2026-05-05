package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildWindsurfHookBlockMessage_AllowsRunCommand(t *testing.T) {
	input := `{
		"agent_action_name": "pre_run_command",
		"tool_info": {
			"command_line": "npm test",
			"cwd": "/tmp/repo"
		}
	}`

	_, blocked, err := buildWindsurfHookBlockMessage(strings.NewReader(input), nil)
	if err != nil {
		t.Fatalf("buildWindsurfHookBlockMessage() error = %v", err)
	}
	if blocked {
		t.Fatal("expected allowed command not to block")
	}
}

func TestBuildWindsurfHookBlockMessage_BlocksDeniedRunCommand(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "fence.json")
	content := `{
  "command": {
    "deny": ["gh repo create"],
    "useDefaults": false
  }
}`
	if err := os.WriteFile(settingsPath, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	input := `{
		"agent_action_name": "pre_run_command",
		"tool_info": {
			"command_line": "gh repo create test --private",
			"cwd": "/tmp/repo"
		}
	}`

	message, blocked, err := buildWindsurfHookBlockMessage(strings.NewReader(input), []string{"--settings", settingsPath})
	if err != nil {
		t.Fatalf("buildWindsurfHookBlockMessage() error = %v", err)
	}
	if !blocked {
		t.Fatal("expected denied command to block")
	}
	if !strings.Contains(message, "gh repo create") {
		t.Fatalf("expected block message to mention matched command, got %q", message)
	}
}

func TestBuildWindsurfHookBlockMessage_BlocksDeniedWritePath(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "fence.json")
	content := `{
  "filesystem": {
    "allowWrite": ["` + filepath.Join(dir, "allowed") + `"]
  }
}`
	if err := os.WriteFile(settingsPath, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	input := `{
		"agent_action_name": "pre_write_code",
		"tool_info": {
			"file_path": "` + filepath.Join(dir, "blocked", "file.go") + `"
		}
	}`

	message, blocked, err := buildWindsurfHookBlockMessage(strings.NewReader(input), []string{"--settings", settingsPath})
	if err != nil {
		t.Fatalf("buildWindsurfHookBlockMessage() error = %v", err)
	}
	if !blocked {
		t.Fatal("expected denied write path to block")
	}
	if !strings.Contains(message, "not in allowWrite") {
		t.Fatalf("expected block message to mention allowWrite, got %q", message)
	}
}

func TestBuildWindsurfHookBlockMessage_IgnoresUnsupportedEvent(t *testing.T) {
	input := `{
		"agent_action_name": "post_run_command",
		"tool_info": {
			"command_line": "gh repo create test"
		}
	}`

	_, blocked, err := buildWindsurfHookBlockMessage(strings.NewReader(input), nil)
	if err != nil {
		t.Fatalf("buildWindsurfHookBlockMessage() error = %v", err)
	}
	if blocked {
		t.Fatal("expected unsupported post hook to be ignored")
	}
}

func TestRunWindsurfHook_WritesBlockMessageToStderr(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "fence.json")
	content := `{
  "command": {
    "deny": ["npm publish"],
    "useDefaults": false
  }
}`
	if err := os.WriteFile(settingsPath, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	input := `{
		"agent_action_name": "pre_run_command",
		"tool_info": {
			"command_line": "npm publish"
		}
	}`

	var stderr bytes.Buffer
	err := runWindsurfHook(strings.NewReader(input), &stderr, []string{"--settings", settingsPath})
	if err == nil {
		t.Fatal("expected denied command to return an error")
	}
	if !strings.Contains(stderr.String(), "npm publish") {
		t.Fatalf("expected stderr to contain block reason, got %q", stderr.String())
	}
}
