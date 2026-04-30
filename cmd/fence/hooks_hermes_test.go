package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeHermesFenceConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fence.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestBuildHermesPreToolUseResponse_AllowsTerminalNotInDeny(t *testing.T) {
	settings := writeHermesFenceConfig(t, `{
  "command": {"deny": ["git push"], "useDefaults": false}
}`)
	input := `{
		"hook_event_name": "pre_tool_call",
		"tool_name": "terminal",
		"tool_input": {"command": "git status"}
	}`
	resp, changed, err := buildHermesPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildHermesPreToolUseResponse: %v", err)
	}
	if changed {
		t.Fatalf("expected allow (changed=false), got body=%s", string(resp))
	}
}

func TestBuildHermesPreToolUseResponse_BlocksDeniedTerminal(t *testing.T) {
	settings := writeHermesFenceConfig(t, `{
  "command": {"deny": ["git push"], "useDefaults": false}
}`)
	input := `{
		"hook_event_name": "pre_tool_call",
		"tool_name": "terminal",
		"tool_input": {"command": "git push origin main"}
	}`
	resp, changed, err := buildHermesPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildHermesPreToolUseResponse: %v", err)
	}
	if !changed {
		t.Fatal("expected block")
	}
	var decoded hermesPreToolUseResponse
	if err := json.Unmarshal(resp, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Action != "block" {
		t.Fatalf("expected action=block, got %q", decoded.Action)
	}
	if !strings.Contains(decoded.Message, "terminal") {
		t.Errorf("expected message to mention tool name, got %q", decoded.Message)
	}
	if !strings.Contains(decoded.Message, "git push") {
		t.Errorf("expected message to surface matched rule, got %q", decoded.Message)
	}
}

func TestBuildHermesPreToolUseResponse_BlocksDangerousWrite(t *testing.T) {
	settings := writeHermesFenceConfig(t, `{
  "filesystem": {"allowWrite": ["/"]}
}`)
	input := `{
		"hook_event_name": "pre_tool_call",
		"tool_name": "write_file",
		"tool_input": {"path": "/home/user/.zshrc"}
	}`
	resp, changed, err := buildHermesPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildHermesPreToolUseResponse: %v", err)
	}
	if !changed {
		t.Fatal("expected dangerous write to be blocked")
	}
	var decoded hermesPreToolUseResponse
	if err := json.Unmarshal(resp, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Action != "block" {
		t.Fatalf("expected action=block, got %q", decoded.Action)
	}
}

func TestBuildHermesPreToolUseResponse_AllowsWriteUnderAllowList(t *testing.T) {
	settings := writeHermesFenceConfig(t, `{
  "filesystem": {"allowWrite": ["/workspace"]}
}`)
	input := `{
		"hook_event_name": "pre_tool_call",
		"tool_name": "patch",
		"tool_input": {"path": "/workspace/proj/file.go"}
	}`
	_, changed, err := buildHermesPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildHermesPreToolUseResponse: %v", err)
	}
	if changed {
		t.Fatal("expected allow")
	}
}

func TestBuildHermesPreToolUseResponse_BlocksWebExtractToBlockedHost(t *testing.T) {
	settings := writeHermesFenceConfig(t, `{
  "network": {"allowedDomains": ["api.openai.com"]}
}`)
	input := `{
		"hook_event_name": "pre_tool_call",
		"tool_name": "web_extract",
		"tool_input": {"url": "https://blocked.test/page"}
	}`
	resp, changed, err := buildHermesPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildHermesPreToolUseResponse: %v", err)
	}
	if !changed {
		t.Fatal("expected URL outside allowedDomains to be blocked")
	}
	var decoded hermesPreToolUseResponse
	if err := json.Unmarshal(resp, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Action != "block" {
		t.Errorf("expected action=block, got %q", decoded.Action)
	}
}

func TestBuildHermesPreToolUseResponse_AllowsWebExtractToAllowedHost(t *testing.T) {
	settings := writeHermesFenceConfig(t, `{
  "network": {"allowedDomains": ["*.openai.com"]}
}`)
	input := `{
		"hook_event_name": "pre_tool_call",
		"tool_name": "web_extract",
		"tool_input": {"url": "https://api.openai.com/v1/x"}
	}`
	_, changed, err := buildHermesPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildHermesPreToolUseResponse: %v", err)
	}
	if changed {
		t.Fatal("expected allowed host to pass")
	}
}

func TestBuildHermesPreToolUseResponse_UnknownToolSkips(t *testing.T) {
	settings := writeHermesFenceConfig(t, `{}`)
	input := `{
		"hook_event_name": "pre_tool_call",
		"tool_name": "memory_recall",
		"tool_input": {"query": "anything"}
	}`
	_, changed, err := buildHermesPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildHermesPreToolUseResponse: %v", err)
	}
	if changed {
		t.Fatal("expected unmapped tool to be a no-op")
	}
}

func TestBuildHermesPreToolUseResponse_NonPreToolCallEventNoOp(t *testing.T) {
	settings := writeHermesFenceConfig(t, `{
  "command": {"deny": ["git push"], "useDefaults": false}
}`)
	// Same shell-hook command line could conceivably get wired to
	// post_tool_call by an over-eager user; we should be a no-op rather
	// than parse-error.
	input := `{
		"hook_event_name": "post_tool_call",
		"tool_name": "terminal",
		"tool_input": {"command": "git push origin main"}
	}`
	_, changed, err := buildHermesPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildHermesPreToolUseResponse: %v", err)
	}
	if changed {
		t.Fatal("expected non-pre_tool_call event to be a no-op")
	}
}

func TestBuildHermesPreToolUseResponse_RelativeWritePathUsesEnvelopeCWD(t *testing.T) {
	settings := writeHermesFenceConfig(t, `{
  "filesystem": {"allowWrite": ["/workspace"]}
}`)
	input := `{
		"hook_event_name": "pre_tool_call",
		"tool_name": "write_file",
		"tool_input": {"path": "main.go"},
		"cwd": "/workspace/proj"
	}`
	_, changed, err := buildHermesPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildHermesPreToolUseResponse: %v", err)
	}
	if changed {
		t.Fatal("expected relative path resolved against envelope cwd to allow")
	}
}
