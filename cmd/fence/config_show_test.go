package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

func TestLoadActiveConfigAudit_ProjectConfigChain(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))

	basePath := config.ResolveDefaultConfigPath()
	writeConfigShowTestFile(t, basePath, `{
		"network": {
			"allowedDomains": ["base.example.com"]
		},
		"filesystem": {
			"allowWrite": ["/tmp"]
		}
	}`)

	repoDir := t.TempDir()
	repoPath := filepath.Join(repoDir, "fence.json")
	writeConfigShowTestFile(t, repoPath, `{
		"extends": "@base",
		"network": {
			"allowedDomains": ["repo.example.com"]
		}
	}`)

	audit, err := loadActiveConfigAudit(repoDir, "", "")
	if err != nil {
		t.Fatalf("loadActiveConfigAudit() error = %v", err)
	}

	if audit.Root.Kind != config.ResolutionStepKindFile {
		t.Fatalf("expected root file config, got %q", audit.Root.Kind)
	}
	if audit.Root.Path != repoPath {
		t.Fatalf("expected root path %q, got %q", repoPath, audit.Root.Path)
	}
	if audit.RootSource != activeConfigRootSourceProject {
		t.Fatalf("expected root source %q, got %q", activeConfigRootSourceProject, audit.RootSource)
	}
	if len(audit.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(audit.Steps))
	}
	if audit.Steps[0].Kind != config.ResolutionStepKindSpecial || audit.Steps[0].Name != "@base" {
		t.Fatalf("expected first step to be @base, got %+v", audit.Steps[0])
	}
	if audit.Steps[1].Kind != config.ResolutionStepKindFile || audit.Steps[1].Path != basePath {
		t.Fatalf("expected second step to be %q, got %+v", basePath, audit.Steps[1])
	}
	if audit.Config == nil {
		t.Fatal("expected resolved config")
	}
	if !slices.Contains(audit.Config.Network.AllowedDomains, "base.example.com") {
		t.Fatalf("expected base domain in resolved config, got %v", audit.Config.Network.AllowedDomains)
	}
	if !slices.Contains(audit.Config.Network.AllowedDomains, "repo.example.com") {
		t.Fatalf("expected repo domain in resolved config, got %v", audit.Config.Network.AllowedDomains)
	}
}

func TestWriteConfigShowOutput_SeparatesChainAndJSON(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))
	basePath := config.ResolveDefaultConfigPath()

	audit := &activeConfigAudit{
		Root: config.ResolutionStep{
			Kind: config.ResolutionStepKindFile,
			Path: "/repo/fence.json",
		},
		RootSource: activeConfigRootSourceProject,
		Steps: []config.ResolutionStep{
			{
				Kind: config.ResolutionStepKindSpecial,
				Name: "@base",
			},
			{
				Kind: config.ResolutionStepKindFile,
				Path: basePath,
			},
			{
				Kind: config.ResolutionStepKindTemplate,
				Name: "code",
			},
		},
		Config: &config.Config{
			Devices: config.DevicesConfig{
				Mode: config.DeviceModeMinimal,
			},
			Network: config.NetworkConfig{
				AllowedDomains: []string{"github.com"},
			},
			Command: config.CommandConfig{
				AcceptSharedBinaryCannotRuntimeDeny: []string{"python"},
			},
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := writeConfigShowOutput(&stdout, &stderr, audit); err != nil {
		t.Fatalf("writeConfigShowOutput() error = %v", err)
	}

	expectedChain := strings.Join([]string{
		"Active config chain:",
		"project config: /repo/fence.json",
		"└── @base user config: " + basePath,
		"    └── builtin template: code",
		"",
		"",
	}, "\n")
	if stderr.String() != expectedChain {
		t.Fatalf("unexpected chain output:\n%s", stderr.String())
	}

	output := stdout.String()
	if strings.Contains(output, "Active config chain") {
		t.Fatalf("expected stdout to contain JSON only, got %q", output)
	}
	if !strings.Contains(output, `"github.com"`) {
		t.Fatalf("expected resolved network JSON in stdout, got %q", output)
	}
	if !strings.Contains(output, `"devices"`) {
		t.Fatalf("expected devices JSON in stdout, got %q", output)
	}
	if !strings.Contains(output, `"acceptSharedBinaryCannotRuntimeDeny"`) {
		t.Fatalf("expected command exception JSON in stdout, got %q", output)
	}
}

func TestConfigShowCmd_UsesSettingsFlag(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))

	repoDir := t.TempDir()
	writeConfigShowTestFile(t, filepath.Join(repoDir, "fence.json"), `{
		"network": {
			"allowedDomains": ["local.example.com"]
		}
	}`)

	settingsPath := filepath.Join(t.TempDir(), "custom.json")
	writeConfigShowTestFile(t, settingsPath, `{
		"network": {
			"allowedDomains": ["settings.example.com"]
		}
	}`)

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error = %v", err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("os.Chdir() error = %v", err)
	}
	defer func() {
		_ = os.Chdir(originalWD)
	}()

	cmd := newConfigShowCmd()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--settings", settingsPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error = %v", err)
	}

	if strings.Contains(stdout.String(), "local.example.com") {
		t.Fatalf("expected local auto-discovered config to be ignored, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "settings.example.com") {
		t.Fatalf("expected settings file config in stdout, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "settings file: "+settingsPath) {
		t.Fatalf("expected stderr to mention settings file path, got %q", stderr.String())
	}
}

func TestLoadActiveConfigAudit_MissingSettingsFileErrors(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "missing.json")

	_, err := loadActiveConfigAudit("", settingsPath, "")
	if err == nil {
		t.Fatal("expected missing --settings path to return an error")
	}
	if got := err.Error(); !strings.Contains(got, "settings file not found: "+settingsPath) {
		t.Fatalf("expected missing settings error to include path, got %q", got)
	}
}

func TestLoadActiveConfigAudit_FallsBackToUserConfig(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))

	basePath := config.ResolveDefaultConfigPath()
	writeConfigShowTestFile(t, basePath, `{
		"network": {
			"allowedDomains": ["base.example.com"]
		}
	}`)

	audit, err := loadActiveConfigAudit(t.TempDir(), "", "")
	if err != nil {
		t.Fatalf("loadActiveConfigAudit() error = %v", err)
	}

	if audit.Root.Kind != config.ResolutionStepKindFile {
		t.Fatalf("expected root file config, got %q", audit.Root.Kind)
	}
	if audit.Root.Path != basePath {
		t.Fatalf("expected root path %q, got %q", basePath, audit.Root.Path)
	}
	if audit.RootSource != activeConfigRootSourceUser {
		t.Fatalf("expected root source %q, got %q", activeConfigRootSourceUser, audit.RootSource)
	}

	chain := formatConfigChain(audit)
	if !strings.Contains(chain, "user config: "+basePath) {
		t.Fatalf("expected chain to use user config label, got %q", chain)
	}
}

func writeConfigShowTestFile(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("failed to create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}
