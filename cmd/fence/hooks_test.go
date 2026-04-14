package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHooksPrintCmd_PrintsClaudeHookConfig(t *testing.T) {
	cmd := newHooksPrintCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--claude"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	hooksValue, ok := output["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("expected hooks object, got %#v", output["hooks"])
	}
	preToolUse, ok := hooksValue["PreToolUse"].([]any)
	if !ok || len(preToolUse) != 1 {
		t.Fatalf("expected one PreToolUse hook group, got %#v", hooksValue["PreToolUse"])
	}

	group, ok := preToolUse[0].(map[string]any)
	if !ok {
		t.Fatalf("expected hook group object, got %#v", preToolUse[0])
	}
	if got := group["matcher"]; got != "Bash" {
		t.Fatalf("expected matcher Bash, got %#v", got)
	}

	nestedHooks, ok := group["hooks"].([]any)
	if !ok || len(nestedHooks) != 1 {
		t.Fatalf("expected one nested hook, got %#v", group["hooks"])
	}
	nested, ok := nestedHooks[0].(map[string]any)
	if !ok {
		t.Fatalf("expected nested hook object, got %#v", nestedHooks[0])
	}
	if got := nested["type"]; got != "command" {
		t.Fatalf("expected command hook type, got %#v", got)
	}
	if got := nested["command"]; got != claudeHookCommand() {
		t.Fatalf("expected Claude helper command, got %#v", got)
	}
}

func TestHooksPrintCmd_PrintsClaudeHookConfigWithSettings(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "policy with spaces.json")

	cmd := newHooksPrintCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--claude", "--settings", settingsPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	hooksValue := output["hooks"].(map[string]any)
	preToolUse := hooksValue["PreToolUse"].([]any)
	group := preToolUse[0].(map[string]any)
	nested := group["hooks"].([]any)[0].(map[string]any)

	want := claudeHookCommandWithOptions(hookFenceOptions{SettingsPath: settingsPath})
	if got := nested["command"]; got != want {
		t.Fatalf("expected pinned Claude helper command %q, got %#v", want, got)
	}
}

func TestHooksPrintCmd_PrintsCursorHookConfig(t *testing.T) {
	cmd := newHooksPrintCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--cursor"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if got := output["version"]; got != float64(1) {
		t.Fatalf("expected version 1, got %#v", got)
	}

	hooksValue, ok := output["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("expected hooks object, got %#v", output["hooks"])
	}
	preToolUse, ok := hooksValue["preToolUse"].([]any)
	if !ok || len(preToolUse) != 1 {
		t.Fatalf("expected one preToolUse hook, got %#v", hooksValue["preToolUse"])
	}

	group, ok := preToolUse[0].(map[string]any)
	if !ok {
		t.Fatalf("expected hook object, got %#v", preToolUse[0])
	}
	if got := group["matcher"]; got != "Shell" {
		t.Fatalf("expected matcher Shell, got %#v", got)
	}
	if got := group["command"]; got != cursorHookCommand() {
		t.Fatalf("expected Cursor helper command, got %#v", got)
	}
}

func TestHooksPrintCmd_RequiresTargetFlag(t *testing.T) {
	cmd := newHooksPrintCmd()
	cmd.SetArgs(nil)

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected command to require a hook target flag")
	}
}

func TestInstallClaudeHook_CreatesSettingsFile(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), ".claude", "settings.json")

	changed, err := installClaudeHook(settingsPath)
	if err != nil {
		t.Fatalf("installClaudeHook() error = %v", err)
	}
	if !changed {
		t.Fatal("expected install to create the Claude hook")
	}

	doc := readHooksTestJSONFile(t, settingsPath)
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("expected hooks object, got %#v", doc["hooks"])
	}
	preToolUse, ok := hooks["PreToolUse"].([]any)
	if !ok || len(preToolUse) != 1 {
		t.Fatalf("expected one PreToolUse group, got %#v", hooks["PreToolUse"])
	}
}

func TestInstallClaudeHook_IsIdempotent(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), ".claude", "settings.json")

	changed, err := installClaudeHook(settingsPath)
	if err != nil {
		t.Fatalf("first installClaudeHook() error = %v", err)
	}
	if !changed {
		t.Fatal("expected first install to change the file")
	}

	changed, err = installClaudeHook(settingsPath)
	if err != nil {
		t.Fatalf("second installClaudeHook() error = %v", err)
	}
	if changed {
		t.Fatal("expected second install to be a no-op")
	}

	doc := readHooksTestJSONFile(t, settingsPath)
	hooks := doc["hooks"].(map[string]any)
	preToolUse := hooks["PreToolUse"].([]any)
	if len(preToolUse) != 1 {
		t.Fatalf("expected one PreToolUse group after repeated install, got %d", len(preToolUse))
	}
}

func TestInstallClaudeHookWithOptions_ReplacesExistingFenceHook(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), ".claude", "settings.json")

	changed, err := installClaudeHook(settingsPath)
	if err != nil {
		t.Fatalf("first installClaudeHook() error = %v", err)
	}
	if !changed {
		t.Fatal("expected first install to change the file")
	}

	hookOptions := hookFenceOptions{SettingsPath: filepath.Join(t.TempDir(), "policy.json")}
	changed, err = installClaudeHookWithOptions(settingsPath, hookOptions)
	if err != nil {
		t.Fatalf("installClaudeHookWithOptions() error = %v", err)
	}
	if !changed {
		t.Fatal("expected install with hook options to replace the existing Fence hook")
	}

	doc := readHooksTestJSONFile(t, settingsPath)
	hooks := doc["hooks"].(map[string]any)
	preToolUse := hooks["PreToolUse"].([]any)
	if len(preToolUse) != 1 {
		t.Fatalf("expected one PreToolUse group after replacement, got %d", len(preToolUse))
	}

	group := preToolUse[0].(map[string]any)
	nested := group["hooks"].([]any)[0].(map[string]any)
	want := claudeHookCommandWithOptions(hookOptions)
	if got := nested["command"]; got != want {
		t.Fatalf("expected updated hook command %q, got %#v", want, got)
	}
}

func TestUninstallClaudeHook_RemovesOnlyFenceHook(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), ".claude", "settings.json")
	content := `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "` + claudeHookCommandWithOptions(hookFenceOptions{SettingsPath: "/tmp/fence policy.json"}) + `"
          },
          {
            "type": "command",
            "command": "echo custom"
          }
        ]
      },
      {
        "matcher": "Edit",
        "hooks": [
          {
            "type": "command",
            "command": "echo keep"
          }
        ]
      }
    ]
  },
  "theme": "dark"
}`

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o750); err != nil {
		t.Fatalf("os.MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(settingsPath, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	changed, err := uninstallClaudeHook(settingsPath)
	if err != nil {
		t.Fatalf("uninstallClaudeHook() error = %v", err)
	}
	if !changed {
		t.Fatal("expected uninstall to remove the Claude hook")
	}

	doc := readHooksTestJSONFile(t, settingsPath)
	if got := doc["theme"]; got != "dark" {
		t.Fatalf("expected unrelated top-level settings to be preserved, got %#v", got)
	}

	hooks := doc["hooks"].(map[string]any)
	preToolUse := hooks["PreToolUse"].([]any)
	if len(preToolUse) != 2 {
		t.Fatalf("expected both PreToolUse groups to remain, got %d", len(preToolUse))
	}

	firstGroup := preToolUse[0].(map[string]any)
	nestedHooks := firstGroup["hooks"].([]any)
	if len(nestedHooks) != 1 {
		t.Fatalf("expected only custom Bash hook to remain, got %#v", nestedHooks)
	}
	nested := nestedHooks[0].(map[string]any)
	if got := nested["command"]; got != "echo custom" {
		t.Fatalf("expected custom hook to be preserved, got %#v", got)
	}
}

func TestInstallCursorHook_CreatesHooksFile(t *testing.T) {
	hooksPath := filepath.Join(t.TempDir(), ".cursor", "hooks.json")

	changed, err := installCursorHook(hooksPath)
	if err != nil {
		t.Fatalf("installCursorHook() error = %v", err)
	}
	if !changed {
		t.Fatal("expected install to create the Cursor hook")
	}

	doc := readHooksTestJSONFile(t, hooksPath)
	if got := doc["version"]; got != float64(1) {
		t.Fatalf("expected version 1, got %#v", got)
	}

	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("expected hooks object, got %#v", doc["hooks"])
	}
	preToolUse, ok := hooks["preToolUse"].([]any)
	if !ok || len(preToolUse) != 1 {
		t.Fatalf("expected one preToolUse hook, got %#v", hooks["preToolUse"])
	}
}

func TestUninstallCursorHook_RemovesOnlyFenceHook(t *testing.T) {
	hooksPath := filepath.Join(t.TempDir(), ".cursor", "hooks.json")
	content := `{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "matcher": "Shell",
        "command": "` + cursorHookCommand() + `"
      },
      {
        "matcher": "Read",
        "command": "echo keep"
      }
    ]
  },
  "theme": "dark"
}`

	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o750); err != nil {
		t.Fatalf("os.MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(hooksPath, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	changed, err := uninstallCursorHook(hooksPath)
	if err != nil {
		t.Fatalf("uninstallCursorHook() error = %v", err)
	}
	if !changed {
		t.Fatal("expected uninstall to remove the Cursor hook")
	}

	doc := readHooksTestJSONFile(t, hooksPath)
	if got := doc["theme"]; got != "dark" {
		t.Fatalf("expected unrelated top-level settings to be preserved, got %#v", got)
	}

	hooks := doc["hooks"].(map[string]any)
	preToolUse := hooks["preToolUse"].([]any)
	if len(preToolUse) != 1 {
		t.Fatalf("expected one remaining preToolUse hook, got %d", len(preToolUse))
	}

	group := preToolUse[0].(map[string]any)
	if got := group["command"]; got != "echo keep" {
		t.Fatalf("expected custom hook to be preserved, got %#v", got)
	}
}

func TestHooksInstallCmd_UsesExplicitFile(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), ".claude", "settings.local.json")

	cmd := newHooksInstallCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--claude", "--file", settingsPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	if !bytes.Contains(stdout.Bytes(), []byte("Installed Claude hook")) {
		t.Fatalf("expected install output, got %q", stdout.String())
	}

	doc := readHooksTestJSONFile(t, settingsPath)
	hooks := doc["hooks"].(map[string]any)
	if _, ok := hooks["PreToolUse"]; !ok {
		t.Fatalf("expected PreToolUse hooks in %q", settingsPath)
	}
}

func TestHooksInstallCmd_UsesFenceTemplateForClaude(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), ".claude", "settings.local.json")

	cmd := newHooksInstallCmd()
	cmd.SetArgs([]string{"--claude", "--file", settingsPath, "--template", "code"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	doc := readHooksTestJSONFile(t, settingsPath)
	hooks := doc["hooks"].(map[string]any)
	preToolUse := hooks["PreToolUse"].([]any)
	group := preToolUse[0].(map[string]any)
	nested := group["hooks"].([]any)[0].(map[string]any)
	want := claudeHookCommandWithOptions(hookFenceOptions{TemplateName: "code"})
	if got := nested["command"]; got != want {
		t.Fatalf("expected template-pinned hook command %q, got %#v", want, got)
	}
}

func TestHooksInstallCmd_UsesExplicitFileForCursor(t *testing.T) {
	hooksPath := filepath.Join(t.TempDir(), ".cursor", "hooks.local.json")

	cmd := newHooksInstallCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--cursor", "--file", hooksPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	if !bytes.Contains(stdout.Bytes(), []byte("Installed Cursor hook")) {
		t.Fatalf("expected install output, got %q", stdout.String())
	}

	doc := readHooksTestJSONFile(t, hooksPath)
	hooks := doc["hooks"].(map[string]any)
	if _, ok := hooks["preToolUse"]; !ok {
		t.Fatalf("expected preToolUse hooks in %q", hooksPath)
	}
}

func readHooksTestJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // test helper intentionally reads a caller-provided temp file
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	return doc
}
