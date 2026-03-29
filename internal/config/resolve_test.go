package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestResolveExtendsBaseKeyword(t *testing.T) {
	t.Run("merges the user default config", func(t *testing.T) {
		basePath := configureDefaultConfigHome(t)
		writeResolveTestFile(t, basePath, `{
			"allowPty": true,
			"network": {
				"allowedDomains": ["base.example.com"]
			},
			"filesystem": {
				"allowWrite": ["/tmp"]
			}
		}`)

		cfg := &Config{
			Extends: "@base",
			Network: NetworkConfig{
				AllowedDomains: []string{"child.example.com"},
			},
		}

		result, err := ResolveExtends(cfg, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Extends != "" {
			t.Errorf("expected extends to be cleared, got %q", result.Extends)
		}
		if !result.AllowPty {
			t.Error("expected AllowPty to be inherited from @base config")
		}
		if !slices.Contains(result.Network.AllowedDomains, "base.example.com") {
			t.Errorf("expected base.example.com in allowed domains, got %v", result.Network.AllowedDomains)
		}
		if !slices.Contains(result.Network.AllowedDomains, "child.example.com") {
			t.Errorf("expected child.example.com in allowed domains, got %v", result.Network.AllowedDomains)
		}
		if len(result.Filesystem.AllowWrite) != 1 || result.Filesystem.AllowWrite[0] != "/tmp" {
			t.Errorf("expected AllowWrite [/tmp], got %v", result.Filesystem.AllowWrite)
		}
	})

	t.Run("falls back to built-in defaults when no user config exists", func(t *testing.T) {
		configureDefaultConfigHome(t)

		cfg := &Config{
			Extends: "@base",
			Network: NetworkConfig{
				AllowedDomains: []string{"child.example.com"},
			},
		}

		result, err := ResolveExtends(cfg, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Extends != "" {
			t.Errorf("expected extends to be cleared, got %q", result.Extends)
		}
		if result.AllowPty {
			t.Error("expected AllowPty to stay false when @base config is missing")
		}
		if len(result.Network.AllowedDomains) != 1 || result.Network.AllowedDomains[0] != "child.example.com" {
			t.Errorf("expected only child.example.com, got %v", result.Network.AllowedDomains)
		}
	})

	t.Run("continues resolving @base through templates", func(t *testing.T) {
		basePath := configureDefaultConfigHome(t)
		writeResolveTestFile(t, basePath, `{
			"extends": "company",
			"network": {
				"allowedDomains": ["base.example.com"]
			}
		}`)

		loadTemplate := func(name string) (*Config, error) {
			if name != "company" {
				return nil, fmt.Errorf("template %q not found", name)
			}
			return &Config{
				AllowPty: true,
				Network: NetworkConfig{
					AllowedDomains: []string{"template.example.com"},
				},
			}, nil
		}

		cfg := &Config{
			Extends: "@base",
			Network: NetworkConfig{
				AllowedDomains: []string{"child.example.com"},
			},
		}

		result, err := ResolveExtends(cfg, loadTemplate)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.AllowPty {
			t.Error("expected AllowPty from template inherited through @base")
		}
		for _, domain := range []string{"template.example.com", "base.example.com", "child.example.com"} {
			if !slices.Contains(result.Network.AllowedDomains, domain) {
				t.Errorf("expected %q in allowed domains, got %v", domain, result.Network.AllowedDomains)
			}
		}
	})

	t.Run("detects circular @base references", func(t *testing.T) {
		basePath := configureDefaultConfigHome(t)
		writeResolveTestFile(t, basePath, `{
			"extends": "@base"
		}`)

		cfg := &Config{Extends: "@base"}

		_, err := ResolveExtends(cfg, nil)
		if err == nil {
			t.Fatal("expected circular extends error")
		}
		if !strings.Contains(err.Error(), "circular extends") {
			t.Fatalf("expected circular extends error, got %v", err)
		}
	})
}

func TestResolveExtends_RequiresTemplateLoader(t *testing.T) {
	cfg := &Config{Extends: "company"}

	_, err := ResolveExtends(cfg, nil)
	if err == nil {
		t.Fatal("expected error when template loader is missing")
	}
	if !strings.Contains(err.Error(), "template loader") {
		t.Fatalf("expected template loader error, got %v", err)
	}
}

func TestResolveExtendsFromPath_DetectsSymlinkCycles(t *testing.T) {
	tmpDir := t.TempDir()
	childPath := filepath.Join(tmpDir, "child.json")
	basePath := filepath.Join(tmpDir, "base.json")
	aliasPath := filepath.Join(tmpDir, "child-alias.json")

	writeResolveTestFile(t, childPath, `{
		"extends": "./base.json",
		"network": {
			"allowedDomains": ["child.example.com"]
		}
	}`)
	writeResolveTestFile(t, basePath, `{
		"extends": "./child-alias.json",
		"network": {
			"allowedDomains": ["base.example.com"]
		}
	}`)

	if err := os.Symlink(childPath, aliasPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	cfg, err := Load(childPath)
	if err != nil {
		t.Fatalf("failed to load child config: %v", err)
	}

	_, err = ResolveExtendsFromPath(cfg, childPath, nil)
	if err == nil {
		t.Fatal("expected circular extends error")
	}
	if !strings.Contains(err.Error(), "circular extends") {
		t.Fatalf("expected circular extends error, got %v", err)
	}
}

func configureDefaultConfigHome(t *testing.T) string {
	t.Helper()

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))

	return ResolveDefaultConfigPath()
}

func writeResolveTestFile(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("failed to create directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}
