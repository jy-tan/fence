package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fencesandbox/fence/internal/sandbox"
)

func TestBuildOpencodePreToolUseResponse_WrapsBashCommand(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "")

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test",
			"cwd": "/tmp/repo"
		}
	}`

	response, changed, err := buildOpencodePreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildOpencodePreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected Bash command to be rewritten")
	}

	var decoded opencodePreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.Decision != "wrap" {
		t.Fatalf("expected decision wrap, got %q", decoded.Decision)
	}
	if decoded.ToolInput == nil {
		t.Fatal("expected tool_input to be populated for wrap")
	}
	wantCommand := sandbox.ShellQuote([]string{"/usr/local/bin/fence", "-c", "npm test"})
	if got := decoded.ToolInput.Command; got != wantCommand {
		t.Fatalf("expected wrapped command %q, got %q", wantCommand, got)
	}
}

func TestBuildOpencodePreToolUseResponse_DeniesCommand(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "")

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
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "gh repo create test --private"
		}
	}`

	response, changed, err := buildOpencodePreToolUseResponse(
		strings.NewReader(input),
		"/usr/local/bin/fence",
		[]string{"--settings", settingsPath},
	)
	if err != nil {
		t.Fatalf("buildOpencodePreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected blocked command to produce a deny response")
	}

	var decoded opencodePreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.Decision != "deny" {
		t.Fatalf("expected decision deny, got %q", decoded.Decision)
	}
	if decoded.ToolInput != nil {
		t.Fatalf("expected tool_input omitted on deny, got %#v", decoded.ToolInput)
	}
	// Deny reason should mention the matched prefix so the plugin can surface
	// something meaningful to the user.
	if !strings.Contains(decoded.Reason, "gh repo create") {
		t.Fatalf("expected reason to mention the matched prefix, got %q", decoded.Reason)
	}
}

func TestBuildOpencodePreToolUseResponse_SkipsPureCD(t *testing.T) {
	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "cd ../repo"
		}
	}`

	_, changed, err := buildOpencodePreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildOpencodePreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected pure cd command to be skipped")
	}
}

func TestBuildOpencodePreToolUseResponse_SkipsAlreadyFencedCommand(t *testing.T) {
	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "/usr/local/bin/fence -c 'npm test'"
		}
	}`

	_, changed, err := buildOpencodePreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildOpencodePreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected already-fenced command to be skipped")
	}
}

func TestBuildOpencodePreToolUseResponse_LeavesCommandUnchangedInsideFence(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "1")

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test"
		}
	}`

	_, changed, err := buildOpencodePreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildOpencodePreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected command to stay unchanged when already inside Fence")
	}
}

func TestBuildOpencodePreToolUseResponse_DeniesBlockedCommandInsideFence(t *testing.T) {
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

	response, changed, err := buildOpencodePreToolUseResponse(
		strings.NewReader(input),
		"/usr/local/bin/fence",
		[]string{"--settings", settingsPath},
	)
	if err != nil {
		t.Fatalf("buildOpencodePreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected blocked command to produce a deny response even inside Fence")
	}

	var decoded opencodePreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.Decision != "deny" {
		t.Fatalf("expected decision deny, got %q", decoded.Decision)
	}
}

func TestBuildOpencodePreToolUseResponse_IgnoresNonBashEvent(t *testing.T) {
	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Read",
		"tool_input": {
			"file_path": "/tmp/test.txt"
		}
	}`

	_, changed, err := buildOpencodePreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildOpencodePreToolUseResponse() error = %v", err)
	}
	if changed {
		t.Fatal("expected non-Bash event to be ignored")
	}
}

func TestBuildOpencodePreToolUseResponse_AcceptsMissingHookEventName(t *testing.T) {
	// The plugin synthesises hook_event_name="PreToolUse"; defending against
	// future plugin-side schema changes that drop the field.
	t.Setenv(fenceSandboxEnvVar, "")

	input := `{
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test"
		}
	}`

	response, changed, err := buildOpencodePreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err != nil {
		t.Fatalf("buildOpencodePreToolUseResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected Bash command to be rewritten when hook_event_name is omitted")
	}

	var decoded opencodePreToolUseResponse
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded.Decision != "wrap" {
		t.Fatalf("expected decision wrap, got %q", decoded.Decision)
	}
}

func TestBuildOpencodePreToolUseResponse_InvalidJSON(t *testing.T) {
	_, _, err := buildOpencodePreToolUseResponse(strings.NewReader(`{`), "/usr/local/bin/fence", nil)
	if err == nil {
		t.Fatal("expected invalid JSON to return an error")
	}
}

func TestBuildOpencodePreToolUseResponse_MissingCommandField(t *testing.T) {
	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"description": "no command here"
		}
	}`

	_, _, err := buildOpencodePreToolUseResponse(strings.NewReader(input), "/usr/local/bin/fence", nil)
	if err == nil {
		t.Fatal("expected missing tool_input.command to return an error")
	}
}

func TestRunOpencodePreToolUse_NoOpEmitsEmptyStdout(t *testing.T) {
	// Pure cd should produce no stdout. The plugin treats empty stdout as
	// "allow unchanged"; this test pins that no-op contract.
	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "cd ../repo"
		}
	}`

	var stdout bytes.Buffer
	if err := runOpencodePreToolUse(strings.NewReader(input), &stdout, "/usr/local/bin/fence", nil); err != nil {
		t.Fatalf("runOpencodePreToolUse() error = %v", err)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("expected empty stdout for no-op, got %q", got)
	}
}

func TestRunOpencodePreToolUse_WrapEmitsJSONLine(t *testing.T) {
	t.Setenv(fenceSandboxEnvVar, "")

	input := `{
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test"
		}
	}`

	var stdout bytes.Buffer
	if err := runOpencodePreToolUse(strings.NewReader(input), &stdout, "/usr/local/bin/fence", nil); err != nil {
		t.Fatalf("runOpencodePreToolUse() error = %v", err)
	}

	out := stdout.String()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("expected stdout to end with newline, got %q", out)
	}

	var decoded opencodePreToolUseResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; stdout=%q", err, out)
	}
	if decoded.Decision != "wrap" {
		t.Fatalf("expected decision wrap, got %q", decoded.Decision)
	}
}

// ---------------------------------------------------------------------------
// install / uninstall / print tests
// ---------------------------------------------------------------------------

func TestInstallOpencodePlugin_CreatesConfigFile(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), ".config", "opencode", "opencode.json")

	changed, err := installOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("installOpencodePlugin() error = %v", err)
	}
	if !changed {
		t.Fatal("expected install to create the OpenCode config")
	}

	doc := readHooksTestJSONFile(t, configPath)
	plugins, ok := doc["plugin"].([]any)
	if !ok {
		t.Fatalf("expected plugin array, got %#v", doc["plugin"])
	}
	if len(plugins) != 1 || plugins[0] != opencodePluginPackageName {
		t.Fatalf("expected plugin to be %q, got %#v", opencodePluginPackageName, plugins)
	}
	if got := doc["$schema"]; got != "https://opencode.ai/config.json" {
		t.Fatalf("expected $schema to be set, got %#v", got)
	}
}

func TestInstallOpencodePlugin_IsIdempotent(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")

	changed, err := installOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("first installOpencodePlugin() error = %v", err)
	}
	if !changed {
		t.Fatal("expected first install to change the file")
	}

	changed, err = installOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("second installOpencodePlugin() error = %v", err)
	}
	if changed {
		t.Fatal("expected second install to be a no-op")
	}

	doc := readHooksTestJSONFile(t, configPath)
	plugins := doc["plugin"].([]any)
	if len(plugins) != 1 {
		t.Fatalf("expected one plugin entry after repeated install, got %d", len(plugins))
	}
}

func TestInstallOpencodePlugin_PreservesExistingPlugins(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")

	existing := `{
  "plugin": ["opencode-helicone-session"],
  "theme": "dracula"
}`
	if err := os.WriteFile(configPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	changed, err := installOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("installOpencodePlugin() error = %v", err)
	}
	if !changed {
		t.Fatal("expected install to add the Fence plugin")
	}

	doc := readHooksTestJSONFile(t, configPath)
	plugins := doc["plugin"].([]any)
	if len(plugins) != 2 {
		t.Fatalf("expected two plugins after install, got %d", len(plugins))
	}
	if plugins[0] != "opencode-helicone-session" {
		t.Fatalf("expected existing plugin preserved at index 0, got %#v", plugins[0])
	}
	if plugins[1] != opencodePluginPackageName {
		t.Fatalf("expected Fence plugin appended, got %#v", plugins[1])
	}
	if got := doc["theme"]; got != "dracula" {
		t.Fatalf("expected theme preserved, got %#v", got)
	}
}

func TestInstallOpencodePlugin_RejectsNonArrayPlugin(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")

	bad := `{"plugin": "not an array"}`
	if err := os.WriteFile(configPath, []byte(bad), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if _, err := installOpencodePlugin(configPath); err == nil {
		t.Fatal("expected install to reject non-array plugin field")
	}
}

func TestUninstallOpencodePlugin_RemovesOnlyFencePlugin(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")

	existing := `{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-helicone-session", "` + opencodePluginPackageName + `", "opencode-wakatime"],
  "theme": "dracula"
}`
	if err := os.WriteFile(configPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	changed, err := uninstallOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("uninstallOpencodePlugin() error = %v", err)
	}
	if !changed {
		t.Fatal("expected uninstall to remove the Fence plugin")
	}

	doc := readHooksTestJSONFile(t, configPath)
	plugins := doc["plugin"].([]any)
	if len(plugins) != 2 {
		t.Fatalf("expected two plugins after uninstall, got %d", len(plugins))
	}
	for _, p := range plugins {
		if p == opencodePluginPackageName {
			t.Fatalf("expected Fence plugin to be removed, found in %#v", plugins)
		}
	}
	if got := doc["theme"]; got != "dracula" {
		t.Fatalf("expected unrelated fields preserved, got %#v", got)
	}
}

func TestUninstallOpencodePlugin_DropsEmptyPluginArray(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")

	existing := `{
  "plugin": ["` + opencodePluginPackageName + `"],
  "theme": "dracula"
}`
	if err := os.WriteFile(configPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	changed, err := uninstallOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("uninstallOpencodePlugin() error = %v", err)
	}
	if !changed {
		t.Fatal("expected uninstall to remove the Fence plugin")
	}

	doc := readHooksTestJSONFile(t, configPath)
	if _, ok := doc["plugin"]; ok {
		t.Fatalf("expected plugin field removed when empty, got %#v", doc["plugin"])
	}
	if got := doc["theme"]; got != "dracula" {
		t.Fatalf("expected unrelated fields preserved, got %#v", got)
	}
}

func TestUninstallOpencodePlugin_AbsentFileIsNoOp(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "does-not-exist.json")

	changed, err := uninstallOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("uninstallOpencodePlugin() error = %v", err)
	}
	if changed {
		t.Fatal("expected uninstall on missing file to be a no-op")
	}
}

func TestUninstallOpencodePlugin_NotPresentIsNoOp(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")

	existing := `{"plugin": ["opencode-wakatime"]}`
	if err := os.WriteFile(configPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	changed, err := uninstallOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("uninstallOpencodePlugin() error = %v", err)
	}
	if changed {
		t.Fatal("expected uninstall when Fence plugin absent to be a no-op")
	}
}

func TestHooksPrintCmd_PrintsOpencodeConfig(t *testing.T) {
	cmd := newHooksPrintCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--opencode"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if got := output["$schema"]; got != "https://opencode.ai/config.json" {
		t.Fatalf("expected $schema set in printed snippet, got %#v", got)
	}
	plugins, ok := output["plugin"].([]any)
	if !ok || len(plugins) != 1 || plugins[0] != opencodePluginPackageName {
		t.Fatalf("expected plugin array containing Fence package, got %#v", output["plugin"])
	}
}

func TestHooksPrintCmd_RejectsOpencodeWithSettings(t *testing.T) {
	cmd := newHooksPrintCmd()
	cmd.SetArgs([]string{"--opencode", "--settings", "/tmp/policy.json"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected --opencode --settings to be rejected")
	}
	if !strings.Contains(err.Error(), "--settings/--template are not supported with --opencode") {
		t.Fatalf("expected explanatory error, got %v", err)
	}
}

func TestHooksInstallCmd_InstallsOpencodePlugin(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")

	cmd := newHooksInstallCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--opencode", "--file", configPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	if !bytes.Contains(stdout.Bytes(), []byte("Installed OpenCode plugin")) {
		t.Fatalf("expected install output, got %q", stdout.String())
	}

	doc := readHooksTestJSONFile(t, configPath)
	plugins, ok := doc["plugin"].([]any)
	if !ok || len(plugins) != 1 || plugins[0] != opencodePluginPackageName {
		t.Fatalf("expected plugin array containing Fence package, got %#v", doc["plugin"])
	}
}

func TestHooksUninstallCmd_RemovesOpencodePlugin(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")
	existing := `{"plugin": ["` + opencodePluginPackageName + `"]}`
	if err := os.WriteFile(configPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	cmd := newHooksUninstallCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--opencode", "--file", configPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	if !bytes.Contains(stdout.Bytes(), []byte("Removed OpenCode plugin")) {
		t.Fatalf("expected uninstall output, got %q", stdout.String())
	}
}

// ---------------------------------------------------------------------------
// resolveOpencodeConfigPath / .jsonc auto-detection
// ---------------------------------------------------------------------------

// withFakeHome sets HOME to a fresh temp dir for the duration of the test and
// returns the prepared ~/.config/opencode directory path. It exists to make
// resolveOpencodeConfigPath() (which reads os.UserHomeDir) deterministic.
func withFakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	configDir := filepath.Join(home, ".config", "opencode")
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatalf("os.MkdirAll() error = %v", err)
	}
	return configDir
}

func TestResolveOpencodeConfigPath_PrefersJSONCWhenItExists(t *testing.T) {
	configDir := withFakeHome(t)
	jsoncPath := filepath.Join(configDir, "opencode.jsonc")
	if err := os.WriteFile(jsoncPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	got := resolveOpencodeConfigPath()
	if got != jsoncPath {
		t.Fatalf("expected %q, got %q", jsoncPath, got)
	}
}

func TestResolveOpencodeConfigPath_PrefersJSONCEvenWhenJSONExists(t *testing.T) {
	// OpenCode's own loader iterates ["opencode.jsonc", "opencode.json"]; if
	// both exist, .jsonc wins. We match that so Fence edits the file OpenCode
	// will actually load.
	configDir := withFakeHome(t)
	jsoncPath := filepath.Join(configDir, "opencode.jsonc")
	jsonPath := filepath.Join(configDir, "opencode.json")
	for _, p := range []string{jsoncPath, jsonPath} {
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatalf("os.WriteFile(%q) error = %v", p, err)
		}
	}

	got := resolveOpencodeConfigPath()
	if got != jsoncPath {
		t.Fatalf("expected %q (jsonc preferred), got %q", jsoncPath, got)
	}
}

func TestResolveOpencodeConfigPath_FallsBackToJSON(t *testing.T) {
	configDir := withFakeHome(t)
	jsonPath := filepath.Join(configDir, "opencode.json")
	if err := os.WriteFile(jsonPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	got := resolveOpencodeConfigPath()
	if got != jsonPath {
		t.Fatalf("expected %q, got %q", jsonPath, got)
	}
}

func TestResolveOpencodeConfigPath_DefaultsToJSONWhenNeitherExists(t *testing.T) {
	configDir := withFakeHome(t)
	wantPath := filepath.Join(configDir, "opencode.json")

	got := resolveOpencodeConfigPath()
	if got != wantPath {
		t.Fatalf("expected default %q, got %q", wantPath, got)
	}
	// Resolver must not create the file.
	if _, err := os.Stat(got); !os.IsNotExist(err) {
		t.Fatalf("expected resolver not to create the file, stat err = %v", err)
	}
}

func TestHooksInstallCmd_OpencodeUsesExistingJSONCByDefault(t *testing.T) {
	configDir := withFakeHome(t)
	jsoncPath := filepath.Join(configDir, "opencode.jsonc")
	existing := `{
  // user comment
  "theme": "dracula"
}`
	if err := os.WriteFile(jsoncPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	cmd := newHooksInstallCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	// --force skips the "comments will be stripped" confirmation prompt; the
	// prompt itself is exercised by the dedicated TestConfirm... cases below.
	cmd.SetArgs([]string{"--opencode", "--force"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	if !bytes.Contains(stdout.Bytes(), []byte(jsoncPath)) {
		t.Fatalf("expected install output to reference the .jsonc path, got %q", stdout.String())
	}

	// Sibling .json must not be created when .jsonc was the target.
	if _, err := os.Stat(filepath.Join(configDir, "opencode.json")); !os.IsNotExist(err) {
		t.Fatalf("expected sibling opencode.json not to be created, stat err = %v", err)
	}

	// Plugin must land in the .jsonc file (re-marshaled as plain JSON; the
	// comment-stripping is acknowledged via --force in this test setup).
	doc := readHooksTestJSONFile(t, jsoncPath)
	plugins, ok := doc["plugin"].([]any)
	if !ok || len(plugins) != 1 || plugins[0] != opencodePluginPackageName {
		t.Fatalf("expected plugin array containing Fence package in .jsonc, got %#v", doc["plugin"])
	}

	// Even with --force, the warning still prints so the user knows what
	// happened. Only the y/N prompt and the abort path are skipped.
	if !bytes.Contains(stderr.Bytes(), []byte("comments")) {
		t.Fatalf("expected stderr warning about comment removal, got %q", stderr.String())
	}
	if bytes.Contains(stderr.Bytes(), []byte("Continue and strip")) {
		t.Fatalf("--force must skip the prompt, but it appeared in stderr: %q", stderr.String())
	}
}

func TestHooksInstallCmd_OpencodeFallsBackToJSONByDefault(t *testing.T) {
	configDir := withFakeHome(t)
	jsonPath := filepath.Join(configDir, "opencode.json")

	cmd := newHooksInstallCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--opencode"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	if !bytes.Contains(stdout.Bytes(), []byte(jsonPath)) {
		t.Fatalf("expected install output to reference the .json path, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr warning when no comments are present, got %q", stderr.String())
	}

	// Sibling .jsonc must not be created.
	if _, err := os.Stat(filepath.Join(configDir, "opencode.jsonc")); !os.IsNotExist(err) {
		t.Fatalf("expected sibling opencode.jsonc not to be created, stat err = %v", err)
	}
}

func TestHooksUninstallCmd_OpencodeUsesExistingJSONCByDefault(t *testing.T) {
	configDir := withFakeHome(t)
	jsoncPath := filepath.Join(configDir, "opencode.jsonc")
	existing := `{
  "plugin": ["` + opencodePluginPackageName + `"]
}`
	if err := os.WriteFile(jsoncPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	cmd := newHooksUninstallCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--opencode"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	if !bytes.Contains(stdout.Bytes(), []byte(jsoncPath)) {
		t.Fatalf("expected uninstall output to reference the .jsonc path, got %q", stdout.String())
	}
}

// ---------------------------------------------------------------------------
// hookConfigHasJSONCComments
// ---------------------------------------------------------------------------

func TestHookConfigHasJSONCComments(t *testing.T) {
	dir := t.TempDir()

	type tc struct {
		name    string
		content string
		want    bool
	}
	cases := []tc{
		{name: "plain JSON", content: `{"x": 1}`, want: false},
		{name: "line comment", content: "{\n  // hi\n  \"x\": 1\n}", want: true},
		{name: "block comment", content: "{\n  /* hi */\n  \"x\": 1\n}", want: true},
		{name: "comment-shaped string is not a comment", content: `{"x": "// not a comment"}`, want: false},
		{name: "block-shaped string is not a comment", content: `{"x": "/* not a comment */"}`, want: false},
		{name: "escaped quote inside string", content: `{"x": "say \"hi\" //joke"}`, want: false},
		{name: "trailing comma in object", content: `{"x": 1,}`, want: false},
		{name: "trailing comma in array", content: `{"a": [1, 2,]}`, want: false},
		{name: "comment after trailing comma", content: "{\n  \"a\": [1, 2,] // tail\n}", want: true},
		{name: "empty file", content: "", want: false},
		{name: "whitespace only", content: "   \n  ", want: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(dir, "config.json")
			if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
				t.Fatalf("os.WriteFile() error = %v", err)
			}
			got, err := hookConfigHasJSONCComments(path)
			if err != nil {
				t.Fatalf("hookConfigHasJSONCComments() error = %v", err)
			}
			if got != c.want {
				t.Fatalf("hookConfigHasJSONCComments() = %v, want %v for %s", got, c.want, c.name)
			}
		})
	}
}

func TestHookConfigHasJSONCComments_MissingFileIsNoComments(t *testing.T) {
	got, err := hookConfigHasJSONCComments(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("hookConfigHasJSONCComments() error = %v", err)
	}
	if got {
		t.Fatal("expected missing file to report no comments")
	}
}

// ---------------------------------------------------------------------------
// Byte-level (sjson) install/uninstall: comment & formatting preservation
// ---------------------------------------------------------------------------

// readJSONCFileForTest reads a JSON or JSONC file and returns the parsed map
// so tests can assert structural content without caring about comments.
func readJSONCFileForTest(t *testing.T, path string) map[string]any {
	t.Helper()
	doc, err := loadHookConfigDocument(path, "test config")
	if err != nil {
		t.Fatalf("loadHookConfigDocument() error = %v", err)
	}
	return doc
}

func TestInstallOpencodePlugin_PreservesCommentsWhenPluginArrayExists(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.jsonc")
	original := `{
  // top of file
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    // existing plugin we shouldn't disturb
    "opencode-helicone-session"
  ],
  "theme": "dracula" // pinned
}`
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	changed, err := installOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("installOpencodePlugin() error = %v", err)
	}
	if !changed {
		t.Fatal("expected install to change the file")
	}

	updated, err := os.ReadFile(configPath) //nolint:gosec // user-provided path is intentional
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	updatedStr := string(updated)

	// Every comment from the original file must survive the install.
	for _, want := range []string{
		"// top of file",
		"// existing plugin we shouldn't disturb",
		"// pinned",
	} {
		if !strings.Contains(updatedStr, want) {
			t.Fatalf("expected comment %q to survive install, output was:\n%s", want, updatedStr)
		}
	}

	// Existing plugin entry must remain; new entry must be appended.
	doc := readJSONCFileForTest(t, configPath)
	plugins, ok := doc["plugin"].([]any)
	if !ok {
		t.Fatalf("expected plugin array, got %#v", doc["plugin"])
	}
	if len(plugins) != 2 {
		t.Fatalf("expected 2 plugin entries, got %d (%#v)", len(plugins), plugins)
	}
	if plugins[0] != "opencode-helicone-session" {
		t.Fatalf("expected existing plugin preserved at index 0, got %#v", plugins[0])
	}
	if plugins[1] != opencodePluginPackageName {
		t.Fatalf("expected Fence plugin at index 1, got %#v", plugins[1])
	}

	// Sibling fields and their values must be intact.
	if doc["theme"] != "dracula" {
		t.Fatalf("expected theme preserved, got %#v", doc["theme"])
	}
	if doc["$schema"] != "https://opencode.ai/config.json" {
		t.Fatalf("expected $schema preserved, got %#v", doc["$schema"])
	}
}

func TestInstallOpencodePlugin_IsByteIdempotentWhenAlreadyInstalled(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.jsonc")
	original := `{
  // hello
  "plugin": [
    "` + opencodePluginPackageName + `"
  ]
}`
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	changed, err := installOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("installOpencodePlugin() error = %v", err)
	}
	if changed {
		t.Fatal("expected install to be a no-op when plugin already installed")
	}

	// File must be untouched byte-for-byte.
	updated, err := os.ReadFile(configPath) //nolint:gosec // user-provided path is intentional
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if string(updated) != original {
		t.Fatalf("expected file unchanged, got:\n%s\n\nwant:\n%s", string(updated), original)
	}
}

func TestUninstallOpencodePlugin_PreservesCommentsWhenRemoving(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.jsonc")
	original := `{
  // top of file
  "plugin": [
    "opencode-helicone-session",
    "` + opencodePluginPackageName + `",
    "opencode-wakatime"
  ],
  "theme": "dracula" // pinned
}`
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	changed, err := uninstallOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("uninstallOpencodePlugin() error = %v", err)
	}
	if !changed {
		t.Fatal("expected uninstall to change the file")
	}

	updated, err := os.ReadFile(configPath) //nolint:gosec // user-provided path is intentional
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	updatedStr := string(updated)

	// Comments survive.
	for _, want := range []string{"// top of file", "// pinned"} {
		if !strings.Contains(updatedStr, want) {
			t.Fatalf("expected comment %q to survive uninstall, output was:\n%s", want, updatedStr)
		}
	}
	// Fence plugin string must be gone.
	if strings.Contains(updatedStr, opencodePluginPackageName) {
		t.Fatalf("expected Fence plugin removed, but it's still present:\n%s", updatedStr)
	}

	// Other plugins survive in original order.
	doc := readJSONCFileForTest(t, configPath)
	plugins := doc["plugin"].([]any)
	if len(plugins) != 2 {
		t.Fatalf("expected 2 remaining plugins, got %d (%#v)", len(plugins), plugins)
	}
	if plugins[0] != "opencode-helicone-session" || plugins[1] != "opencode-wakatime" {
		t.Fatalf("expected siblings preserved in order, got %#v", plugins)
	}
}

// TestUninstallOpencodePlugin_RemovesAllDuplicateEntries pins that the byte-edit
// path strips every occurrence of the Fence plugin, not just the first.
// Hand-edited configs can have duplicates; leaving stragglers behind would
// silently leave the plugin active after uninstall reports success.
func TestUninstallOpencodePlugin_RemovesAllDuplicateEntries(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.jsonc")
	original := `{
  // top
  "plugin": [
    "` + opencodePluginPackageName + `",
    "opencode-helicone-session",
    "` + opencodePluginPackageName + `"
  ]
}`
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	changed, err := uninstallOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("uninstallOpencodePlugin() error = %v", err)
	}
	if !changed {
		t.Fatal("expected uninstall to change the file")
	}

	updated, err := os.ReadFile(configPath) //nolint:gosec // user-provided path is intentional
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	updatedStr := string(updated)

	if strings.Contains(updatedStr, opencodePluginPackageName) {
		t.Fatalf("expected ALL Fence plugin entries removed, got:\n%s", updatedStr)
	}
	if !strings.Contains(updatedStr, "// top") {
		t.Fatalf("expected comment preserved, got:\n%s", updatedStr)
	}

	doc := readJSONCFileForTest(t, configPath)
	plugins := doc["plugin"].([]any)
	if len(plugins) != 1 || plugins[0] != "opencode-helicone-session" {
		t.Fatalf("expected only the unrelated plugin to remain, got %#v", plugins)
	}
}

// TestUninstallOpencodePlugin_DropsPluginFieldWhenLastEntryRemoved pins the
// last-entry-removal contract: the byte-edit path defers to the structured
// rewrite when removing the final plugin entry (because sjson's field-level
// delete itself strips comments around the deleted field — see the comment
// on removeStringFromOpencodePluginArray). The result is that the `plugin`
// field is removed and other JSON fields survive structurally, but comments
// in the file are stripped. The cobra layer's comment-stripping warning is
// expected to fire in this case, asserted separately at the cobra-level
// integration test below.
func TestUninstallOpencodePlugin_DropsPluginFieldWhenLastEntryRemoved(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.jsonc")
	original := `{
  // top of file
  "plugin": [
    "` + opencodePluginPackageName + `"
  ],
  "theme": "dracula"
}`
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	changed, err := uninstallOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("uninstallOpencodePlugin() error = %v", err)
	}
	if !changed {
		t.Fatal("expected uninstall to change the file")
	}

	doc := readJSONCFileForTest(t, configPath)
	if _, ok := doc["plugin"]; ok {
		t.Fatalf("expected plugin field removed when empty, got %#v", doc["plugin"])
	}
	if doc["theme"] != "dracula" {
		t.Fatalf("expected theme preserved, got %#v", doc["theme"])
	}
}

// TestUninstallOpencodePlugin_DropsPluginFieldWhenAllEntriesAreDuplicates
// covers the corner where every entry in the array is the Fence plugin.
// Removing all of them empties the array, which we drop entirely (matching
// the single-entry case) — comments are stripped, but the field structure
// is correct.
func TestUninstallOpencodePlugin_DropsPluginFieldWhenAllEntriesAreDuplicates(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.jsonc")
	original := `{
  "plugin": [
    "` + opencodePluginPackageName + `",
    "` + opencodePluginPackageName + `"
  ],
  "theme": "dracula"
}`
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	changed, err := uninstallOpencodePlugin(configPath)
	if err != nil {
		t.Fatalf("uninstallOpencodePlugin() error = %v", err)
	}
	if !changed {
		t.Fatal("expected uninstall to change the file")
	}

	doc := readJSONCFileForTest(t, configPath)
	if _, ok := doc["plugin"]; ok {
		t.Fatalf("expected plugin field removed when all entries were duplicates, got %#v", doc["plugin"])
	}
	if doc["theme"] != "dracula" {
		t.Fatalf("expected theme preserved, got %#v", doc["theme"])
	}
}

// ---------------------------------------------------------------------------
// Cobra-level: comment-stripping warning is suppressed when sjson preserves
// ---------------------------------------------------------------------------

func TestHooksInstallCmd_OpencodeSuppressesWarningWhenCommentsPreserved(t *testing.T) {
	configDir := withFakeHome(t)
	jsoncPath := filepath.Join(configDir, "opencode.jsonc")
	original := `{
  // a comment we expect to keep
  "plugin": [
    "opencode-helicone-session"
  ]
}`
	if err := os.WriteFile(jsoncPath, []byte(original), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	cmd := newHooksInstallCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--opencode"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	if bytes.Contains(stderr.Bytes(), []byte("comments")) {
		t.Fatalf("expected no comment-stripping warning when sjson preserves comments, got %q", stderr.String())
	}

	// And the comment really did survive.
	got, err := os.ReadFile(jsoncPath) //nolint:gosec // user-provided path is intentional
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !strings.Contains(string(got), "// a comment we expect to keep") {
		t.Fatalf("expected comment preserved, got:\n%s", string(got))
	}
}

// ---------------------------------------------------------------------------
// confirmJSONCCommentLossOrAbort: prompt + force + abort behavior
// ---------------------------------------------------------------------------

func TestConfirmJSONCCommentLoss_NoCommentsProceedsSilently(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"plugin": []}`), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	var stderr bytes.Buffer
	if !confirmJSONCCommentLossOrAbort(strings.NewReader(""), &stderr, path, false) {
		t.Fatal("expected proceed=true when file has no comments")
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected silent proceed, got stderr %q", stderr.String())
	}
}

func TestConfirmJSONCCommentLoss_ByteEditPathProceedsSilently(t *testing.T) {
	// File has comments AND a plugin array, so byte-edit will preserve them
	// — confirmation should be skipped.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonc")
	content := `{
  // top
  "plugin": [
    "x"
  ]
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	var stderr bytes.Buffer
	if !confirmJSONCCommentLossOrAbort(strings.NewReader(""), &stderr, path, false) {
		t.Fatal("expected proceed=true when byte-edit will preserve comments")
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected silent proceed, got stderr %q", stderr.String())
	}
}

func TestConfirmJSONCCommentLoss_PromptYesProceeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonc")
	content := `{
  // we will lose this
  "theme": "dracula"
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	var stderr bytes.Buffer
	if !confirmJSONCCommentLossOrAbort(strings.NewReader("y\n"), &stderr, path, false) {
		t.Fatal("expected proceed=true after user answers y")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("contains comments")) {
		t.Fatalf("expected warning in stderr, got %q", stderr.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("Continue and strip")) {
		t.Fatalf("expected prompt in stderr, got %q", stderr.String())
	}
}

func TestConfirmJSONCCommentLoss_PromptNoAborts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonc")
	content := `{
  // important
  "theme": "dracula"
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	var stderr bytes.Buffer
	if confirmJSONCCommentLossOrAbort(strings.NewReader("n\n"), &stderr, path, false) {
		t.Fatal("expected proceed=false after user answers n")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("Aborted")) {
		t.Fatalf("expected Aborted message in stderr, got %q", stderr.String())
	}
}

func TestConfirmJSONCCommentLoss_PromptEmptyResponseAborts(t *testing.T) {
	// Default of [y/N] is no — pressing enter alone must abort.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonc")
	content := `{
  // important
  "theme": "dracula"
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	var stderr bytes.Buffer
	if confirmJSONCCommentLossOrAbort(strings.NewReader("\n"), &stderr, path, false) {
		t.Fatal("expected proceed=false on empty response (default no)")
	}
}

func TestConfirmJSONCCommentLoss_ForceSkipsPromptButStillWarns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonc")
	content := `{
  // top
  "theme": "dracula"
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	var stderr bytes.Buffer
	if !confirmJSONCCommentLossOrAbort(strings.NewReader(""), &stderr, path, true) {
		t.Fatal("expected proceed=true with force=true")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("contains comments")) {
		t.Fatalf("expected warning even with force=true, got %q", stderr.String())
	}
	if bytes.Contains(stderr.Bytes(), []byte("Continue and strip")) {
		t.Fatalf("force=true must skip the prompt, got %q", stderr.String())
	}
}

func TestHooksInstallCmd_OpencodePromptDeclinedDoesNotWriteFile(t *testing.T) {
	configDir := withFakeHome(t)
	jsoncPath := filepath.Join(configDir, "opencode.jsonc")
	original := `{
  // important
  "theme": "dracula"
}`
	if err := os.WriteFile(jsoncPath, []byte(original), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	cmd := newHooksInstallCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader("n\n"))
	cmd.SetArgs([]string{"--opencode"})

	// The user declined; the cobra command should exit cleanly (not error)
	// after printing "Aborted." and leaving the file untouched.
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() returned error after user decline: %v", err)
	}

	if !bytes.Contains(stderr.Bytes(), []byte("Aborted")) {
		t.Fatalf("expected Aborted message, got stderr=%q", stderr.String())
	}
	if bytes.Contains(stdout.Bytes(), []byte("Installed")) {
		t.Fatalf("expected no install confirmation in stdout, got %q", stdout.String())
	}

	// File contents must be unchanged byte-for-byte.
	got, err := os.ReadFile(jsoncPath) //nolint:gosec // user-provided path is intentional
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if string(got) != original {
		t.Fatalf("expected file unchanged after decline, got:\n%s\n\nwant:\n%s", string(got), original)
	}
}

func TestHooksInstallCmd_OpencodePromptAcceptedWritesFile(t *testing.T) {
	configDir := withFakeHome(t)
	jsoncPath := filepath.Join(configDir, "opencode.jsonc")
	original := `{
  // ok strip me
  "theme": "dracula"
}`
	if err := os.WriteFile(jsoncPath, []byte(original), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	cmd := newHooksInstallCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader("y\n"))
	cmd.SetArgs([]string{"--opencode"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	if !bytes.Contains(stdout.Bytes(), []byte("Installed OpenCode plugin")) {
		t.Fatalf("expected install confirmation, got stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	// Plugin must have been installed.
	doc := readHooksTestJSONFile(t, jsoncPath)
	plugins, ok := doc["plugin"].([]any)
	if !ok || len(plugins) != 1 || plugins[0] != opencodePluginPackageName {
		t.Fatalf("expected plugin installed, got %#v", doc["plugin"])
	}
}
