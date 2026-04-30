package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// readTestFile is a thin wrapper around os.ReadFile that fails the test on
// error. Centralizing the read also keeps gosec G304 nolint annotations in
// one place — every caller passes a path constructed from t.TempDir().
func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test-controlled path under t.TempDir()
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	return data
}

func TestHermesInstall_FreshFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	changed, err := installHermesHook(path, hookFenceOptions{})
	if err != nil {
		t.Fatalf("installHermesHook: %v", err)
	}
	if !changed {
		t.Error("expected changed=true on fresh install")
	}

	body := string(readTestFile(t, path))
	for _, want := range []string{
		"hooks:",
		"pre_tool_call:",
		"matcher: terminal",
		"matcher: ^(patch|write_file)$",
		"matcher: web_extract",
		"command: fence " + hermesPreToolUseMode,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output, got:\n%s", want, body)
		}
	}
}

func TestHermesInstall_PreservesUserContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	original := `# user comment that should survive
display:
  skin: ares
hooks:
  pre_tool_call:
    - matcher: "memory_recall"
      command: ~/scripts/redact.sh
  post_tool_call:
    - matcher: ".*"
      command: ~/scripts/audit.sh
`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := installHermesHook(path, hookFenceOptions{}); err != nil {
		t.Fatalf("installHermesHook: %v", err)
	}

	body := string(readTestFile(t, path))

	// User-authored entries survive.
	if !strings.Contains(body, "memory_recall") {
		t.Errorf("user-authored pre_tool_call entry was lost:\n%s", body)
	}
	if !strings.Contains(body, "audit.sh") {
		t.Errorf("user-authored post_tool_call entry was lost:\n%s", body)
	}
	if !strings.Contains(body, "skin: ares") {
		t.Errorf("unrelated config key was lost:\n%s", body)
	}
	// Fence entries got added.
	if !strings.Contains(body, hermesPreToolUseMode) {
		t.Errorf("fence install entries missing:\n%s", body)
	}
}

func TestHermesInstall_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	if _, err := installHermesHook(path, hookFenceOptions{}); err != nil {
		t.Fatalf("installHermesHook (1): %v", err)
	}
	first := readTestFile(t, path)

	if _, err := installHermesHook(path, hookFenceOptions{}); err != nil {
		t.Fatalf("installHermesHook (2): %v", err)
	}
	second := readTestFile(t, path)

	// Idempotence: byte-equal on the second install. The file is
	// rewritten regardless (per docstring), but the YAML output should
	// be stable because the dispatch table and entry shape are stable.
	if string(first) != string(second) {
		t.Errorf("expected idempotent install; diff:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}

	// Count Fence entries: should be exactly one matcher per dispatch
	// domain group, no duplicates from the second install.
	wantEntries := len(hermesInstallEntries())
	gotEntries := strings.Count(string(second), hermesPreToolUseMode)
	if gotEntries != wantEntries {
		t.Errorf("expected %d Fence entries after re-install, got %d:\n%s", wantEntries, gotEntries, second)
	}
}

func TestHermesUninstall_RemovesOnlyFenceEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	original := `display:
  skin: ares
hooks:
  pre_tool_call:
    - matcher: "memory_recall"
      command: ~/scripts/redact.sh
`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := installHermesHook(path, hookFenceOptions{}); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := uninstallHermesHook(path); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	body := string(readTestFile(t, path))

	if strings.Contains(body, hermesPreToolUseMode) {
		t.Errorf("Fence entries still present after uninstall:\n%s", body)
	}
	if !strings.Contains(body, "memory_recall") {
		t.Errorf("user-authored entry was removed:\n%s", body)
	}
	if !strings.Contains(body, "skin: ares") {
		t.Errorf("unrelated key removed:\n%s", body)
	}
}

func TestHermesUninstall_DropsEmptyContainers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	if _, err := installHermesHook(path, hookFenceOptions{}); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := uninstallHermesHook(path); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	data := readTestFile(t, path)
	var decoded yaml.Node
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	root := unwrapYAMLDocument(&decoded)
	if root != nil && findYAMLChild(root, "hooks") != nil {
		t.Errorf("expected empty hooks container to be removed, got:\n%s", string(data))
	}
}

func TestHermesUninstall_NoOpOnFreshFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	changed, err := uninstallHermesHook(path)
	if err != nil {
		t.Fatalf("uninstallHermesHook: %v", err)
	}
	if changed {
		t.Errorf("expected no-op on missing file")
	}
}

func TestHermesInstall_PinsPolicyOption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	settings := filepath.Join(dir, "fence.json")
	if err := os.WriteFile(settings, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile fence.json: %v", err)
	}
	opts, err := hookFenceOptions{SettingsPath: settings}.normalized()
	if err != nil {
		t.Fatalf("normalized: %v", err)
	}

	if _, err := installHermesHook(path, opts); err != nil {
		t.Fatalf("installHermesHook: %v", err)
	}
	body := string(readTestFile(t, path))
	if !strings.Contains(body, "--settings") || !strings.Contains(body, settings) {
		t.Errorf("expected --settings to be pinned in command, got:\n%s", body)
	}
}

func TestHermesEmptyPolicyAdvice_FlagsEmptyAllowLists(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "fence.json")
	// command-only config: hook will deny write_file and web_extract.
	if err := os.WriteFile(settingsPath, []byte(`{
  "command": {"deny": ["git push"], "useDefaults": false}
}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	opts, err := hookFenceOptions{SettingsPath: settingsPath}.normalized()
	if err != nil {
		t.Fatalf("normalized: %v", err)
	}
	advice := hermesEmptyPolicyAdvice(opts)
	if len(advice) == 0 {
		t.Fatal("expected advice when both allow lists are empty")
	}
	joined := strings.Join(advice, "\n")
	if !strings.Contains(joined, "filesystem.allowWrite is empty") {
		t.Errorf("expected filesystem warning, got:\n%s", joined)
	}
	if !strings.Contains(joined, "network.allowedDomains is empty") {
		t.Errorf("expected network warning, got:\n%s", joined)
	}
	if !strings.Contains(joined, "--template hermes") {
		t.Errorf("expected template suggestion, got:\n%s", joined)
	}
}

func TestHermesEmptyPolicyAdvice_QuietWhenTemplateCovers(t *testing.T) {
	// The hermes template ships allowWrite + allowedDomains; advice
	// should be empty.
	advice := hermesEmptyPolicyAdvice(hookFenceOptions{TemplateName: "hermes"})
	if len(advice) != 0 {
		t.Errorf("expected no advice when template covers both domains, got:\n%v", advice)
	}
}

func TestHermesInstallEntries_StableOrdering(t *testing.T) {
	a := hermesInstallEntries()
	b := hermesInstallEntries()
	if len(a) != len(b) {
		t.Fatalf("len(a)=%d len(b)=%d", len(a), len(b))
	}
	for i := range a {
		if a[i].Matcher != b[i].Matcher {
			t.Errorf("entry %d matcher unstable: %q vs %q", i, a[i].Matcher, b[i].Matcher)
		}
	}
}
