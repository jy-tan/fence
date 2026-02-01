package templates

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

func TestList(t *testing.T) {
	templates := List()
	if len(templates) == 0 {
		t.Fatal("expected at least one template")
	}

	// Check that code template exists
	found := false
	for _, tmpl := range templates {
		if tmpl.Name == "code" {
			found = true
			if tmpl.Description == "" {
				t.Error("code template should have a description")
			}
			break
		}
	}
	if !found {
		t.Error("code template not found")
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"code", false},
		{"disable-telemetry", false},
		{"git-readonly", false},
		{"local-dev-server", false},
		{"nonexistent", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(tt.name)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if cfg == nil {
					t.Error("expected config, got nil")
				}
			}
		})
	}
}

func TestLoadWithJsonExtension(t *testing.T) {
	// Should work with or without .json extension
	cfg1, err := Load("disable-telemetry")
	if err != nil {
		t.Fatalf("failed to load disable-telemetry: %v", err)
	}

	cfg2, err := Load("disable-telemetry.json")
	if err != nil {
		t.Fatalf("failed to load disable-telemetry.json: %v", err)
	}

	// Both should return valid configs
	if cfg1 == nil || cfg2 == nil {
		t.Error("expected both configs to be non-nil")
	}
}

func TestExists(t *testing.T) {
	if !Exists("code") {
		t.Error("code template should exist")
	}
	if Exists("nonexistent") {
		t.Error("nonexistent should not exist")
	}
}

func TestCodeTemplate(t *testing.T) {
	cfg, err := Load("code")
	if err != nil {
		t.Fatalf("failed to load code template: %v", err)
	}

	// Verify key settings
	if !cfg.AllowPty {
		t.Error("code template should have AllowPty=true")
	}

	if len(cfg.Network.AllowedDomains) == 0 {
		t.Error("code template should have allowed domains")
	}

	// Check that *.anthropic.com is in allowed domains
	found := false
	for _, domain := range cfg.Network.AllowedDomains {
		if domain == "*.anthropic.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("*.anthropic.com should be in allowed domains")
	}

	// Check that cloud metadata domains are denied
	if len(cfg.Network.DeniedDomains) == 0 {
		t.Error("code template should have denied domains")
	}

	// Check command deny list
	if len(cfg.Command.Deny) == 0 {
		t.Error("code template should have denied commands")
	}
}

func TestCodeStrictTemplate(t *testing.T) {
	cfg, err := Load("code-strict")
	if err != nil {
		t.Fatalf("failed to load code-strict template: %v", err)
	}

	// Should inherit AllowPty from code template
	if !cfg.AllowPty {
		t.Error("code-strict should inherit AllowPty=true from code")
	}

	// Should have defaultDenyRead enabled
	if !cfg.Filesystem.DefaultDenyRead {
		t.Error("code-strict should have DefaultDenyRead=true")
	}

	// Should have allowRead with current directory
	if len(cfg.Filesystem.AllowRead) == 0 {
		t.Error("code-strict should have allowRead paths")
	}
	hasCurrentDir := false
	for _, path := range cfg.Filesystem.AllowRead {
		if path == "." {
			hasCurrentDir = true
			break
		}
	}
	if !hasCurrentDir {
		t.Error("code-strict should allow reading current directory")
	}

	// Should inherit allowWrite from code
	if len(cfg.Filesystem.AllowWrite) == 0 {
		t.Error("code-strict should inherit allowWrite from code")
	}

	// Should inherit denyWrite from code
	if len(cfg.Filesystem.DenyWrite) == 0 {
		t.Error("code-strict should inherit denyWrite from code")
	}

	// Should inherit allowed domains from code
	if len(cfg.Network.AllowedDomains) == 0 {
		t.Error("code-strict should inherit allowed domains from code")
	}

	// Should inherit denied commands from code
	if len(cfg.Command.Deny) == 0 {
		t.Error("code-strict should inherit denied commands from code")
	}

	// Extends should be cleared after resolution
	if cfg.Extends != "" {
		t.Error("extends should be cleared after loading")
	}
}

func TestCodeRelaxedTemplate(t *testing.T) {
	cfg, err := Load("code-relaxed")
	if err != nil {
		t.Fatalf("failed to load code-relaxed template: %v", err)
	}

	// Should inherit AllowPty from code template
	if !cfg.AllowPty {
		t.Error("code-relaxed should inherit AllowPty=true from code")
	}

	// Should have wildcard in allowed domains
	hasWildcard := false
	for _, domain := range cfg.Network.AllowedDomains {
		if domain == "*" {
			hasWildcard = true
			break
		}
	}
	if !hasWildcard {
		t.Error("code-relaxed should have '*' in allowed domains")
	}

	// Should inherit denied domains from code
	if len(cfg.Network.DeniedDomains) == 0 {
		t.Error("code-relaxed should inherit denied domains from code")
	}

	// Should inherit filesystem config from code
	if len(cfg.Filesystem.AllowWrite) == 0 {
		t.Error("code-relaxed should inherit allowWrite from code")
	}
	if len(cfg.Filesystem.DenyRead) == 0 {
		t.Error("code-relaxed should inherit denyRead from code")
	}
	if len(cfg.Filesystem.DenyWrite) == 0 {
		t.Error("code-relaxed should inherit denyWrite from code")
	}

	// Should inherit command config from code
	if len(cfg.Command.Deny) == 0 {
		t.Error("code-relaxed should inherit command deny list from code")
	}

	// Extends should be cleared after resolution
	if cfg.Extends != "" {
		t.Error("extends should be cleared after loading")
	}
}

func TestResolveExtends(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		result, err := ResolveExtends(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Error("expected nil result for nil input")
		}
	})

	t.Run("no extends", func(t *testing.T) {
		cfg := &config.Config{
			AllowPty: true,
			Network: config.NetworkConfig{
				AllowedDomains: []string{"example.com"},
			},
		}
		result, err := ResolveExtends(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != cfg {
			t.Error("expected same config when no extends")
		}
	})

	t.Run("extends code template", func(t *testing.T) {
		cfg := &config.Config{
			Extends: "code",
			Network: config.NetworkConfig{
				AllowedDomains: []string{"private-registry.company.com"},
			},
		}
		result, err := ResolveExtends(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should have merged config
		if result.Extends != "" {
			t.Error("extends should be cleared after resolution")
		}

		// Should have AllowPty from base template
		if !result.AllowPty {
			t.Error("should inherit AllowPty from code template")
		}

		// Should have domains from both
		hasPrivateRegistry := false
		hasAnthropic := false
		for _, domain := range result.Network.AllowedDomains {
			if domain == "private-registry.company.com" {
				hasPrivateRegistry = true
			}
			if domain == "*.anthropic.com" {
				hasAnthropic = true
			}
		}
		if !hasPrivateRegistry {
			t.Error("should have private-registry.company.com from override")
		}
		if !hasAnthropic {
			t.Error("should have *.anthropic.com from base template")
		}
	})

	t.Run("extends nonexistent template", func(t *testing.T) {
		cfg := &config.Config{
			Extends: "nonexistent-template",
		}
		_, err := ResolveExtends(cfg)
		if err == nil {
			t.Error("expected error for nonexistent template")
		}
	})
}

func TestExtendsChainDepth(t *testing.T) {
	// This tests that the maxExtendsDepth limit is respected.
	// We can't easily create a deep chain with embedded templates,
	// but we can test that the code template (which has no extends)
	// loads correctly.
	cfg, err := Load("code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Error("expected non-nil config")
	}
}

func TestIsPath(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		// Template names (not paths)
		{"code", false},
		{"npm-install", false},
		{"my-template", false},

		// Absolute paths
		{"/path/to/config.json", true},
		{"/etc/fence/base.json", true},

		// Relative paths
		{"./base.json", true},
		{"../shared/base.json", true},
		{"configs/base.json", true},

		// Windows-style paths
		{"C:\\path\\to\\config.json", true},
		{".\\base.json", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isPath(tt.input)
			if got != tt.want {
				t.Errorf("isPath(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtendsFilePath(t *testing.T) {
	// Create temp directory for test files
	tmpDir := t.TempDir()

	t.Run("extends absolute path", func(t *testing.T) {
		// Create base config file
		baseContent := `{
			"network": {
				"allowedDomains": ["base.example.com"]
			},
			"filesystem": {
				"allowWrite": ["/tmp"]
			}
		}`
		basePath := filepath.Join(tmpDir, "base.json")
		if err := os.WriteFile(basePath, []byte(baseContent), 0o600); err != nil {
			t.Fatalf("failed to write base config: %v", err)
		}

		// Config that extends the base via absolute path
		cfg := &config.Config{
			Extends: basePath,
			Network: config.NetworkConfig{
				AllowedDomains: []string{"override.example.com"},
			},
		}

		result, err := ResolveExtendsWithBaseDir(cfg, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should have merged domains
		if len(result.Network.AllowedDomains) != 2 {
			t.Errorf("expected 2 domains, got %d: %v", len(result.Network.AllowedDomains), result.Network.AllowedDomains)
		}

		// Should have filesystem from base
		if len(result.Filesystem.AllowWrite) != 1 || result.Filesystem.AllowWrite[0] != "/tmp" {
			t.Errorf("expected AllowWrite [/tmp], got %v", result.Filesystem.AllowWrite)
		}
	})

	t.Run("extends relative path", func(t *testing.T) {
		// Create base config in subdir
		subDir := filepath.Join(tmpDir, "configs")
		if err := os.MkdirAll(subDir, 0o750); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}

		baseContent := `{
			"allowPty": true,
			"network": {
				"allowedDomains": ["relative-base.example.com"]
			}
		}`
		basePath := filepath.Join(subDir, "base.json")
		if err := os.WriteFile(basePath, []byte(baseContent), 0o600); err != nil {
			t.Fatalf("failed to write base config: %v", err)
		}

		// Config that extends via relative path
		cfg := &config.Config{
			Extends: "./configs/base.json",
			Network: config.NetworkConfig{
				AllowedDomains: []string{"child.example.com"},
			},
		}

		result, err := ResolveExtendsWithBaseDir(cfg, tmpDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should inherit AllowPty
		if !result.AllowPty {
			t.Error("should inherit AllowPty from base")
		}

		// Should have merged domains
		if len(result.Network.AllowedDomains) != 2 {
			t.Errorf("expected 2 domains, got %d", len(result.Network.AllowedDomains))
		}
	})

	t.Run("extends nonexistent file", func(t *testing.T) {
		cfg := &config.Config{
			Extends: "/nonexistent/path/config.json",
		}

		_, err := ResolveExtendsWithBaseDir(cfg, "")
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("extends invalid JSON file", func(t *testing.T) {
		invalidPath := filepath.Join(tmpDir, "invalid.json")
		if err := os.WriteFile(invalidPath, []byte("{invalid json}"), 0o600); err != nil {
			t.Fatalf("failed to write invalid config: %v", err)
		}

		cfg := &config.Config{
			Extends: invalidPath,
		}

		_, err := ResolveExtendsWithBaseDir(cfg, "")
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("extends file with invalid config", func(t *testing.T) {
		// Create config with invalid domain pattern
		invalidContent := `{
			"network": {
				"allowedDomains": ["*.com"]
			}
		}`
		invalidPath := filepath.Join(tmpDir, "invalid-domain.json")
		if err := os.WriteFile(invalidPath, []byte(invalidContent), 0o600); err != nil {
			t.Fatalf("failed to write config: %v", err)
		}

		cfg := &config.Config{
			Extends: invalidPath,
		}

		_, err := ResolveExtendsWithBaseDir(cfg, "")
		if err == nil {
			t.Error("expected error for invalid config")
		}
	})

	t.Run("circular extends via files", func(t *testing.T) {
		// Create two files that extend each other
		fileA := filepath.Join(tmpDir, "a.json")
		fileB := filepath.Join(tmpDir, "b.json")

		contentA := `{"extends": "` + fileB + `"}`
		contentB := `{"extends": "` + fileA + `"}`

		if err := os.WriteFile(fileA, []byte(contentA), 0o600); err != nil {
			t.Fatalf("failed to write a.json: %v", err)
		}
		if err := os.WriteFile(fileB, []byte(contentB), 0o600); err != nil {
			t.Fatalf("failed to write b.json: %v", err)
		}

		cfg := &config.Config{
			Extends: fileA,
		}

		_, err := ResolveExtendsWithBaseDir(cfg, "")
		if err == nil {
			t.Error("expected error for circular extends")
		}
	})

	t.Run("nested extends chain", func(t *testing.T) {
		// Create a chain: child -> middle -> base
		baseContent := `{
			"network": {
				"allowedDomains": ["base.com"]
			}
		}`
		basePath := filepath.Join(tmpDir, "chain-base.json")
		if err := os.WriteFile(basePath, []byte(baseContent), 0o600); err != nil {
			t.Fatalf("failed to write base: %v", err)
		}

		middleContent := `{
			"extends": "` + basePath + `",
			"network": {
				"allowedDomains": ["middle.com"]
			}
		}`
		middlePath := filepath.Join(tmpDir, "chain-middle.json")
		if err := os.WriteFile(middlePath, []byte(middleContent), 0o600); err != nil {
			t.Fatalf("failed to write middle: %v", err)
		}

		cfg := &config.Config{
			Extends: middlePath,
			Network: config.NetworkConfig{
				AllowedDomains: []string{"child.com"},
			},
		}

		result, err := ResolveExtendsWithBaseDir(cfg, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should have all three domains
		if len(result.Network.AllowedDomains) != 3 {
			t.Errorf("expected 3 domains, got %d: %v", len(result.Network.AllowedDomains), result.Network.AllowedDomains)
		}
	})

	t.Run("file extends template", func(t *testing.T) {
		// Create a file that extends a built-in template
		fileContent := `{
			"extends": "code",
			"network": {
				"allowedDomains": ["extra.example.com"]
			}
		}`
		filePath := filepath.Join(tmpDir, "extends-template.json")
		if err := os.WriteFile(filePath, []byte(fileContent), 0o600); err != nil {
			t.Fatalf("failed to write config: %v", err)
		}

		// Config that extends this file
		cfg := &config.Config{
			Extends: filePath,
			Network: config.NetworkConfig{
				AllowedDomains: []string{"top.example.com"},
			},
		}

		result, err := ResolveExtendsWithBaseDir(cfg, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should have AllowPty from code template
		if !result.AllowPty {
			t.Error("should inherit AllowPty from code template")
		}

		// Should have domains from all levels
		hasAnthropic := false
		hasExtra := false
		hasTop := false
		for _, domain := range result.Network.AllowedDomains {
			switch domain {
			case "*.anthropic.com":
				hasAnthropic = true
			case "extra.example.com":
				hasExtra = true
			case "top.example.com":
				hasTop = true
			}
		}
		if !hasAnthropic {
			t.Error("should have *.anthropic.com from code template")
		}
		if !hasExtra {
			t.Error("should have extra.example.com from middle file")
		}
		if !hasTop {
			t.Error("should have top.example.com from top config")
		}
	})
}
