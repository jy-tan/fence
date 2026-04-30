package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeOpenclawFenceConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fence.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestBuildOpenclawPreToolUseResponse_AllowsExecNotInDeny(t *testing.T) {
	settings := writeOpenclawFenceConfig(t, `{
  "command": {"deny": ["git push"], "useDefaults": false}
}`)
	input := `{
		"hook_event_name": "before_tool_call",
		"tool_name": "exec",
		"tool_input": {"command": "git status"}
	}`
	resp, changed, err := buildOpenclawPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildOpenclawPreToolUseResponse: %v", err)
	}
	if changed {
		t.Fatalf("expected allow (changed=false), got body=%s", string(resp))
	}
}

func TestBuildOpenclawPreToolUseResponse_BlocksDeniedExec(t *testing.T) {
	settings := writeOpenclawFenceConfig(t, `{
  "command": {"deny": ["git push"], "useDefaults": false}
}`)
	input := `{
		"hook_event_name": "before_tool_call",
		"tool_name": "exec",
		"tool_input": {"command": "git push origin main"}
	}`
	resp, changed, err := buildOpenclawPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildOpenclawPreToolUseResponse: %v", err)
	}
	if !changed {
		t.Fatal("expected block")
	}
	var decoded openclawPreToolUseResponse
	if err := json.Unmarshal(resp, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Decision != "deny" {
		t.Fatalf("expected decision=deny, got %q", decoded.Decision)
	}
	if !strings.Contains(decoded.Reason, "exec") {
		t.Errorf("expected reason to mention tool name, got %q", decoded.Reason)
	}
	if !strings.Contains(decoded.Reason, "git push") {
		t.Errorf("expected reason to surface matched rule, got %q", decoded.Reason)
	}
}

func TestBuildOpenclawPreToolUseResponse_BashAliasesToExec(t *testing.T) {
	// External agents (Claude harness, Codex) may emit "bash" before
	// OpenClaw's normalizeToolName collapses it to "exec". Both names
	// should produce the same evaluation.
	settings := writeOpenclawFenceConfig(t, `{
  "command": {"deny": ["git push"], "useDefaults": false}
}`)
	input := `{
		"hook_event_name": "before_tool_call",
		"tool_name": "bash",
		"tool_input": {"command": "git push origin main"}
	}`
	_, changed, err := buildOpenclawPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildOpenclawPreToolUseResponse: %v", err)
	}
	if !changed {
		t.Fatal("expected bash to be treated as exec and blocked")
	}
}

func TestBuildOpenclawPreToolUseResponse_BlocksDangerousWrite(t *testing.T) {
	settings := writeOpenclawFenceConfig(t, `{
  "filesystem": {"allowWrite": ["/"]}
}`)
	for _, tool := range []string{"write", "edit", "apply_patch"} {
		t.Run(tool, func(t *testing.T) {
			input := `{
				"hook_event_name": "before_tool_call",
				"tool_name": "` + tool + `",
				"tool_input": {"path": "/home/user/.zshrc"}
			}`
			_, changed, err := buildOpenclawPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
			if err != nil {
				t.Fatalf("buildOpenclawPreToolUseResponse: %v", err)
			}
			if !changed {
				t.Fatalf("expected dangerous write via %s to be blocked", tool)
			}
		})
	}
}

func TestBuildOpenclawPreToolUseResponse_AllowsWriteUnderAllowList(t *testing.T) {
	settings := writeOpenclawFenceConfig(t, `{
  "filesystem": {"allowWrite": ["/workspace"]}
}`)
	input := `{
		"hook_event_name": "before_tool_call",
		"tool_name": "apply_patch",
		"tool_input": {"path": "/workspace/proj/file.go"}
	}`
	_, changed, err := buildOpenclawPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildOpenclawPreToolUseResponse: %v", err)
	}
	if changed {
		t.Fatal("expected allow")
	}
}

func TestBuildOpenclawPreToolUseResponse_BlocksWebFetchToBlockedHost(t *testing.T) {
	settings := writeOpenclawFenceConfig(t, `{
  "network": {"allowedDomains": ["api.openai.com"]}
}`)
	input := `{
		"hook_event_name": "before_tool_call",
		"tool_name": "web_fetch",
		"tool_input": {"url": "https://blocked.test/page"}
	}`
	_, changed, err := buildOpenclawPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildOpenclawPreToolUseResponse: %v", err)
	}
	if !changed {
		t.Fatal("expected URL outside allowedDomains to be blocked")
	}
}

func TestBuildOpenclawPreToolUseResponse_AllowsWebFetchToAllowedHost(t *testing.T) {
	settings := writeOpenclawFenceConfig(t, `{
  "network": {"allowedDomains": ["*.openai.com"]}
}`)
	input := `{
		"hook_event_name": "before_tool_call",
		"tool_name": "web_fetch",
		"tool_input": {"url": "https://api.openai.com/v1/x"}
	}`
	_, changed, err := buildOpenclawPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildOpenclawPreToolUseResponse: %v", err)
	}
	if changed {
		t.Fatal("expected allowed host to pass")
	}
}

func TestBuildOpenclawPreToolUseResponse_UnknownToolSkips(t *testing.T) {
	settings := writeOpenclawFenceConfig(t, `{}`)
	input := `{
		"hook_event_name": "before_tool_call",
		"tool_name": "memory_search",
		"tool_input": {"query": "anything"}
	}`
	_, changed, err := buildOpenclawPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildOpenclawPreToolUseResponse: %v", err)
	}
	if changed {
		t.Fatal("expected unmapped tool to be a no-op")
	}
}

func TestBuildOpenclawPreToolUseResponse_NonBeforeToolCallEventNoOp(t *testing.T) {
	// Defensive: if a future plugin version wires this binary to a
	// different hook event, we should be a no-op rather than parse
	// error.
	settings := writeOpenclawFenceConfig(t, `{
  "command": {"deny": ["git push"], "useDefaults": false}
}`)
	input := `{
		"hook_event_name": "after_tool_call",
		"tool_name": "exec",
		"tool_input": {"command": "git push origin main"}
	}`
	_, changed, err := buildOpenclawPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildOpenclawPreToolUseResponse: %v", err)
	}
	if changed {
		t.Fatal("expected non-before_tool_call event to be a no-op")
	}
}

func TestBuildOpenclawPreToolUseResponse_RelativeWritePathUsesEnvelopeCWD(t *testing.T) {
	settings := writeOpenclawFenceConfig(t, `{
  "filesystem": {"allowWrite": ["/workspace"]}
}`)
	input := `{
		"hook_event_name": "before_tool_call",
		"tool_name": "write",
		"tool_input": {"path": "main.go"},
		"cwd": "/workspace/proj"
	}`
	_, changed, err := buildOpenclawPreToolUseResponse(strings.NewReader(input), []string{"--settings", settings})
	if err != nil {
		t.Fatalf("buildOpenclawPreToolUseResponse: %v", err)
	}
	if changed {
		t.Fatal("expected relative path resolved against envelope cwd to allow")
	}
}

func TestWriteOpenclawHooksGuidance_DefaultMessage(t *testing.T) {
	var buf strings.Builder
	if err := writeOpenclawHooksGuidance(&buf, hookFenceOptions{}); err != nil {
		t.Fatalf("writeOpenclawHooksGuidance: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "openclaw plugins install @use-tusk/openclaw-fence") {
		t.Errorf("expected the canonical install one-liner, got:\n%s", out)
	}
	if !strings.Contains(out, "template: openclaw") {
		t.Errorf("expected the template recommendation, got:\n%s", out)
	}
}

func TestWriteOpenclawHooksGuidance_PolicyPin(t *testing.T) {
	var buf strings.Builder
	if err := writeOpenclawHooksGuidance(&buf, hookFenceOptions{TemplateName: "openclaw"}); err != nil {
		t.Fatalf("writeOpenclawHooksGuidance: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "template: openclaw") {
		t.Errorf("expected --template to surface in plugin-options hint, got:\n%s", out)
	}
	if !strings.Contains(out, "openclaw plugins install") {
		t.Errorf("install one-liner missing, got:\n%s", out)
	}
}
