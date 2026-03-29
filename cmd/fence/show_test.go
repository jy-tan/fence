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
	writeShowTestFile(t, basePath, `{
		"network": {
			"allowedDomains": ["base.example.com"]
		},
		"filesystem": {
			"allowWrite": ["/tmp"]
		}
	}`)

	repoDir := t.TempDir()
	repoPath := filepath.Join(repoDir, "fence.json")
	writeShowTestFile(t, repoPath, `{
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

	if len(audit.Steps) != 2 {
		t.Fatalf("expected 2 resolution steps, got %d", len(audit.Steps))
	}
	if audit.Steps[0].Kind != config.ResolutionStepKindSpecial || audit.Steps[0].Name != "@base" {
		t.Fatalf("expected first step to be @base, got %+v", audit.Steps[0])
	}
	if audit.Steps[1].Kind != config.ResolutionStepKindFile || audit.Steps[1].Path != basePath {
		t.Fatalf("expected second step to be base file %q, got %+v", basePath, audit.Steps[1])
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
	if len(audit.Config.Filesystem.AllowWrite) != 1 || audit.Config.Filesystem.AllowWrite[0] != "/tmp" {
		t.Fatalf("expected inherited allowWrite, got %v", audit.Config.Filesystem.AllowWrite)
	}
}

func TestWriteShowOutput_SeparatesChainAndJSON(t *testing.T) {
	audit := &activeConfigAudit{
		Root: config.ResolutionStep{
			Kind: config.ResolutionStepKindFile,
			Path: "/repo/fence.json",
		},
		Steps: []config.ResolutionStep{
			{
				Kind: config.ResolutionStepKindSpecial,
				Name: "@base",
			},
			{
				Kind: config.ResolutionStepKindFile,
				Path: "/Users/test/.config/fence/fence.json",
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
	if err := writeShowOutput(&stdout, &stderr, audit); err != nil {
		t.Fatalf("writeShowOutput() error = %v", err)
	}

	expectedChain := strings.Join([]string{
		"Active config chain:",
		"file: /repo/fence.json",
		"└── @base",
		"    └── file: /Users/test/.config/fence/fence.json",
		"        └── template: code",
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

func writeShowTestFile(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("failed to create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}
