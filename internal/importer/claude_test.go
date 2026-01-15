package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertClaudeToFence(t *testing.T) {
	tests := []struct {
		name     string
		settings *ClaudeSettings
		wantCmd  struct {
			allow []string
			deny  []string
		}
		wantFS struct {
			denyRead   []string
			allowWrite []string
			denyWrite  []string
		}
	}{
		{
			name: "empty settings",
			settings: &ClaudeSettings{
				Permissions: ClaudePermissions{},
			},
			wantCmd: struct {
				allow []string
				deny  []string
			}{},
			wantFS: struct {
				denyRead   []string
				allowWrite []string
				denyWrite  []string
			}{},
		},
		{
			name: "bash allow rules",
			settings: &ClaudeSettings{
				Permissions: ClaudePermissions{
					Allow: []string{
						"Bash(npm run lint)",
						"Bash(npm run test:*)",
						"Bash(git status)",
					},
				},
			},
			wantCmd: struct {
				allow []string
				deny  []string
			}{
				allow: []string{"npm run lint", "npm run test", "git status"},
			},
		},
		{
			name: "bash deny rules",
			settings: &ClaudeSettings{
				Permissions: ClaudePermissions{
					Deny: []string{
						"Bash(curl:*)",
						"Bash(sudo:*)",
						"Bash(rm -rf /)",
					},
				},
			},
			wantCmd: struct {
				allow []string
				deny  []string
			}{
				deny: []string{"curl", "sudo", "rm -rf /"},
			},
		},
		{
			name: "read deny rules",
			settings: &ClaudeSettings{
				Permissions: ClaudePermissions{
					Deny: []string{
						"Read(./.env)",
						"Read(./secrets/**)",
						"Read(~/.ssh/*)",
					},
				},
			},
			wantFS: struct {
				denyRead   []string
				allowWrite []string
				denyWrite  []string
			}{
				denyRead: []string{"./.env", "./secrets/**", "~/.ssh/*"},
			},
		},
		{
			name: "write allow rules",
			settings: &ClaudeSettings{
				Permissions: ClaudePermissions{
					Allow: []string{
						"Write(./output/**)",
						"Write(./build)",
					},
				},
			},
			wantFS: struct {
				denyRead   []string
				allowWrite []string
				denyWrite  []string
			}{
				allowWrite: []string{"./output/**", "./build"},
			},
		},
		{
			name: "write deny rules",
			settings: &ClaudeSettings{
				Permissions: ClaudePermissions{
					Deny: []string{
						"Write(./.git/**)",
						"Edit(./package-lock.json)",
					},
				},
			},
			wantFS: struct {
				denyRead   []string
				allowWrite []string
				denyWrite  []string
			}{
				denyWrite: []string{"./.git/**", "./package-lock.json"},
			},
		},
		{
			name: "ask rules converted to deny",
			settings: &ClaudeSettings{
				Permissions: ClaudePermissions{
					Ask: []string{
						"Write(./config.json)",
						"Bash(npm publish)",
					},
				},
			},
			wantCmd: struct {
				allow []string
				deny  []string
			}{
				deny: []string{"npm publish"},
			},
			wantFS: struct {
				denyRead   []string
				allowWrite []string
				denyWrite  []string
			}{
				denyWrite: []string{"./config.json"},
			},
		},
		{
			name: "global tool rules are skipped",
			settings: &ClaudeSettings{
				Permissions: ClaudePermissions{
					Allow: []string{
						"Read",
						"Grep",
						"LS",
						"Bash(npm run build)", // This should be included
					},
					Deny: []string{
						"Edit",
						"Bash(sudo:*)", // This should be included
					},
				},
			},
			wantCmd: struct {
				allow []string
				deny  []string
			}{
				allow: []string{"npm run build"},
				deny:  []string{"sudo"},
			},
		},
		{
			name: "mixed rules",
			settings: &ClaudeSettings{
				Permissions: ClaudePermissions{
					Allow: []string{
						"Bash(npm install)",
						"Bash(npm run:*)",
						"Write(./dist/**)",
					},
					Deny: []string{
						"Bash(curl:*)",
						"Read(./.env)",
						"Write(./.git/**)",
					},
					Ask: []string{
						"Bash(git push)",
					},
				},
			},
			wantCmd: struct {
				allow []string
				deny  []string
			}{
				allow: []string{"npm install", "npm run"},
				deny:  []string{"curl", "git push"},
			},
			wantFS: struct {
				denyRead   []string
				allowWrite []string
				denyWrite  []string
			}{
				denyRead:   []string{"./.env"},
				allowWrite: []string{"./dist/**"},
				denyWrite:  []string{"./.git/**"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ConvertClaudeToFence(tt.settings)

			assert.ElementsMatch(t, tt.wantCmd.allow, cfg.Command.Allow, "command.allow mismatch")
			assert.ElementsMatch(t, tt.wantCmd.deny, cfg.Command.Deny, "command.deny mismatch")
			assert.ElementsMatch(t, tt.wantFS.denyRead, cfg.Filesystem.DenyRead, "filesystem.denyRead mismatch")
			assert.ElementsMatch(t, tt.wantFS.allowWrite, cfg.Filesystem.AllowWrite, "filesystem.allowWrite mismatch")
			assert.ElementsMatch(t, tt.wantFS.denyWrite, cfg.Filesystem.DenyWrite, "filesystem.denyWrite mismatch")
		})
	}
}

func TestNormalizeClaudeCommand(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"npm:*", "npm"},
		{"curl:*", "curl"},
		{"npm run test:*", "npm run test"},
		{"git status", "git status"},
		{"sudo rm -rf", "sudo rm -rf"},
		{"", ""},
		{"  npm  ", "npm"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeClaudeCommand(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadClaudeSettings(t *testing.T) {
	t.Run("valid settings", func(t *testing.T) {
		tmpDir := t.TempDir()
		settingsPath := filepath.Join(tmpDir, "settings.json")

		content := `{
  "permissions": {
    "allow": ["Bash(npm install)", "Read"],
    "deny": ["Bash(sudo:*)"],
    "ask": ["Write"]
  }
}`
		err := os.WriteFile(settingsPath, []byte(content), 0o600) //nolint:gosec // test file
		require.NoError(t, err)

		settings, err := LoadClaudeSettings(settingsPath)
		require.NoError(t, err)

		assert.Equal(t, []string{"Bash(npm install)", "Read"}, settings.Permissions.Allow)
		assert.Equal(t, []string{"Bash(sudo:*)"}, settings.Permissions.Deny)
		assert.Equal(t, []string{"Write"}, settings.Permissions.Ask)
	})

	t.Run("settings with comments (JSONC)", func(t *testing.T) {
		tmpDir := t.TempDir()
		settingsPath := filepath.Join(tmpDir, "settings.json")

		content := `{
  // This is a comment
  "permissions": {
    "allow": ["Bash(npm install)"],
    "deny": [], // Another comment
    "ask": []
  }
}`
		err := os.WriteFile(settingsPath, []byte(content), 0o600) //nolint:gosec // test file
		require.NoError(t, err)

		settings, err := LoadClaudeSettings(settingsPath)
		require.NoError(t, err)

		assert.Equal(t, []string{"Bash(npm install)"}, settings.Permissions.Allow)
	})

	t.Run("empty file", func(t *testing.T) {
		tmpDir := t.TempDir()
		settingsPath := filepath.Join(tmpDir, "settings.json")

		err := os.WriteFile(settingsPath, []byte(""), 0o600) //nolint:gosec // test file
		require.NoError(t, err)

		settings, err := LoadClaudeSettings(settingsPath)
		require.NoError(t, err)
		assert.NotNil(t, settings)
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := LoadClaudeSettings("/nonexistent/path/settings.json")
		assert.Error(t, err)
	})

	t.Run("invalid json", func(t *testing.T) {
		tmpDir := t.TempDir()
		settingsPath := filepath.Join(tmpDir, "settings.json")

		err := os.WriteFile(settingsPath, []byte("not json"), 0o600) //nolint:gosec // test file
		require.NoError(t, err)

		_, err = LoadClaudeSettings(settingsPath)
		assert.Error(t, err)
	})
}

func TestImportFromClaude(t *testing.T) {
	t.Run("successful import with default extends", func(t *testing.T) {
		tmpDir := t.TempDir()
		settingsPath := filepath.Join(tmpDir, "settings.json")

		content := `{
  "permissions": {
    "allow": ["Bash(npm install)", "Write(./dist/**)"],
    "deny": ["Bash(curl:*)", "Read(./.env)"],
    "ask": ["Bash(git push)"]
  }
}`
		err := os.WriteFile(settingsPath, []byte(content), 0o600) //nolint:gosec // test file
		require.NoError(t, err)

		result, err := ImportFromClaude(settingsPath, DefaultImportOptions())
		require.NoError(t, err)

		assert.Equal(t, settingsPath, result.SourcePath)
		assert.Equal(t, 5, result.RulesImported)
		assert.Equal(t, "code", result.Config.Extends) // default extends

		// Check converted config
		assert.Contains(t, result.Config.Command.Allow, "npm install")
		assert.Contains(t, result.Config.Command.Deny, "curl")
		assert.Contains(t, result.Config.Command.Deny, "git push") // ask -> deny
		assert.Contains(t, result.Config.Filesystem.AllowWrite, "./dist/**")
		assert.Contains(t, result.Config.Filesystem.DenyRead, "./.env")
	})

	t.Run("import with no extend", func(t *testing.T) {
		tmpDir := t.TempDir()
		settingsPath := filepath.Join(tmpDir, "settings.json")

		content := `{
  "permissions": {
    "allow": ["Bash(npm install)"],
    "deny": [],
    "ask": []
  }
}`
		err := os.WriteFile(settingsPath, []byte(content), 0o600) //nolint:gosec // test file
		require.NoError(t, err)

		opts := ImportOptions{Extends: ""}
		result, err := ImportFromClaude(settingsPath, opts)
		require.NoError(t, err)

		assert.Equal(t, "", result.Config.Extends) // no extends
		assert.Contains(t, result.Config.Command.Allow, "npm install")
	})

	t.Run("import with custom extend", func(t *testing.T) {
		tmpDir := t.TempDir()
		settingsPath := filepath.Join(tmpDir, "settings.json")

		content := `{
  "permissions": {
    "allow": ["Bash(npm install)"],
    "deny": [],
    "ask": []
  }
}`
		err := os.WriteFile(settingsPath, []byte(content), 0o600) //nolint:gosec // test file
		require.NoError(t, err)

		opts := ImportOptions{Extends: "local-dev-server"}
		result, err := ImportFromClaude(settingsPath, opts)
		require.NoError(t, err)

		assert.Equal(t, "local-dev-server", result.Config.Extends)
	})

	t.Run("warnings for global rules", func(t *testing.T) {
		tmpDir := t.TempDir()
		settingsPath := filepath.Join(tmpDir, "settings.json")

		content := `{
  "permissions": {
    "allow": ["Read", "Grep", "Bash(npm install)"],
    "deny": ["Edit"],
    "ask": ["Write"]
  }
}`
		err := os.WriteFile(settingsPath, []byte(content), 0o600) //nolint:gosec // test file
		require.NoError(t, err)

		result, err := ImportFromClaude(settingsPath, DefaultImportOptions())
		require.NoError(t, err)

		// Should have warnings for global rules: Read, Grep, Edit, Write (all global)
		assert.Len(t, result.Warnings, 4)

		// Verify the warnings mention the right rules
		warningsStr := strings.Join(result.Warnings, " ")
		assert.Contains(t, warningsStr, "Read")
		assert.Contains(t, warningsStr, "Grep")
		assert.Contains(t, warningsStr, "Edit")
		assert.Contains(t, warningsStr, "Write")
		assert.Contains(t, warningsStr, "skipped")
	})
}

func TestWriteConfig(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "fence.json")

	cfg := &config.Config{}
	cfg.Command.Allow = []string{"npm install"}
	cfg.Command.Deny = []string{"curl"}
	cfg.Filesystem.DenyRead = []string{"./.env"}

	err := WriteConfig(cfg, outputPath)
	require.NoError(t, err)

	// Verify the file was written correctly
	data, err := os.ReadFile(outputPath) //nolint:gosec // test reads file we just wrote
	require.NoError(t, err)

	assert.Contains(t, string(data), `"npm install"`)
	assert.Contains(t, string(data), `"curl"`)
	assert.Contains(t, string(data), `"./.env"`)
}

func TestMarshalConfigJSON(t *testing.T) {
	t.Run("omits empty arrays", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Command.Allow = []string{"npm install"}
		// Leave all other arrays empty

		data, err := MarshalConfigJSON(cfg)
		require.NoError(t, err)

		output := string(data)
		assert.Contains(t, output, `"npm install"`)
		assert.NotContains(t, output, `"allowedDomains"`)
		assert.NotContains(t, output, `"deniedDomains"`)
		assert.NotContains(t, output, `"denyRead"`)
		assert.NotContains(t, output, `"allowWrite"`)
		assert.NotContains(t, output, `"denyWrite"`)
		assert.NotContains(t, output, `"network"`) // entire network section should be omitted
	})

	t.Run("includes extends field", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Extends = "code"
		cfg.Command.Allow = []string{"npm install"}

		data, err := MarshalConfigJSON(cfg)
		require.NoError(t, err)

		output := string(data)
		assert.Contains(t, output, `"extends": "code"`)
	})

	t.Run("includes non-empty arrays", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Network.AllowedDomains = []string{"example.com"}
		cfg.Filesystem.DenyRead = []string{".env"}
		cfg.Command.Deny = []string{"sudo"}

		data, err := MarshalConfigJSON(cfg)
		require.NoError(t, err)

		output := string(data)
		assert.Contains(t, output, `"example.com"`)
		assert.Contains(t, output, `".env"`)
		assert.Contains(t, output, `"sudo"`)
	})
}

func TestFormatConfigWithComment(t *testing.T) {
	t.Run("adds comment when extends is set", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Extends = "code"
		cfg.Command.Allow = []string{"npm install"}

		output, err := FormatConfigWithComment(cfg)
		require.NoError(t, err)

		assert.Contains(t, output, `// This config extends "code".`)
		assert.Contains(t, output, `// Network, filesystem, and command rules from "code" are inherited.`)
		assert.Contains(t, output, `"npm install"`)
	})

	t.Run("no comment when extends is empty", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Command.Allow = []string{"npm install"}

		output, err := FormatConfigWithComment(cfg)
		require.NoError(t, err)

		assert.NotContains(t, output, "//")
		assert.Contains(t, output, `"npm install"`)
	})
}

func TestIsGlobalToolRule(t *testing.T) {
	tests := []struct {
		rule     string
		expected bool
	}{
		{"Read", true},
		{"Write", true},
		{"Grep", true},
		{"LS", true},
		{"Bash", true},
		{"Read(./.env)", false},
		{"Write(./dist/**)", false},
		{"Bash(npm install)", false},
		{"Bash(curl:*)", false},
	}

	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			assert.Equal(t, tt.expected, isGlobalToolRule(tt.rule))
		})
	}
}

func TestAppendUnique(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		value    string
		expected []string
	}{
		{
			name:     "append to empty",
			slice:    []string{},
			value:    "a",
			expected: []string{"a"},
		},
		{
			name:     "append new value",
			slice:    []string{"a", "b"},
			value:    "c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "skip duplicate",
			slice:    []string{"a", "b"},
			value:    "a",
			expected: []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendUnique(tt.slice, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}
