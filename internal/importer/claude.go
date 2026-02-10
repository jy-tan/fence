// Package importer provides functionality to import settings from other tools.
package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/tidwall/jsonc"
)

// ClaudeSettings represents the Claude Code settings.json structure.
type ClaudeSettings struct {
	Permissions ClaudePermissions `json:"permissions"`
}

// ClaudePermissions represents the permissions block in Claude Code settings.
type ClaudePermissions struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
	Ask   []string `json:"ask"`
}

// ClaudeSettingsPaths returns the standard paths where Claude Code stores settings.
func ClaudeSettingsPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	paths := []string{
		filepath.Join(home, ".claude", "settings.json"),
	}

	// Also check project-level settings in current directory
	cwd, err := os.Getwd()
	if err == nil {
		paths = append(paths,
			filepath.Join(cwd, ".claude", "settings.json"),
			filepath.Join(cwd, ".claude", "settings.local.json"),
		)
	}

	return paths
}

// DefaultClaudeSettingsPath returns the default user-level Claude settings path.
func DefaultClaudeSettingsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", "settings.json")
}

// LoadClaudeSettings loads Claude Code settings from a file.
func LoadClaudeSettings(path string) (*ClaudeSettings, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided path - intentional
	if err != nil {
		return nil, fmt.Errorf("failed to read Claude settings: %w", err)
	}

	// Handle empty file
	if len(strings.TrimSpace(string(data))) == 0 {
		return &ClaudeSettings{}, nil
	}

	var settings ClaudeSettings
	if err := json.Unmarshal(jsonc.ToJSON(data), &settings); err != nil {
		return nil, fmt.Errorf("invalid JSON in Claude settings: %w", err)
	}

	return &settings, nil
}

// ConvertClaudeToFence converts Claude Code settings to a fence config.
func ConvertClaudeToFence(settings *ClaudeSettings) *config.Config {
	cfg := config.Default()

	// Process allow rules
	for _, rule := range settings.Permissions.Allow {
		processClaudeRule(rule, cfg, true)
	}

	// Process deny rules
	for _, rule := range settings.Permissions.Deny {
		processClaudeRule(rule, cfg, false)
	}

	// Process ask rules (treat as deny for fence, since fence doesn't have interactive prompts)
	// Users can review and move to allow if needed
	for _, rule := range settings.Permissions.Ask {
		processClaudeRule(rule, cfg, false)
	}

	return cfg
}

// bashPattern matches Bash permission rules like "Bash(npm run test:*)" or "Bash(curl:*)"
var bashPattern = regexp.MustCompile(`^Bash\((.+)\)$`)

// readPattern matches Read permission rules like "Read(./.env)" or "Read(./secrets/**)"
var readPattern = regexp.MustCompile(`^Read\((.+)\)$`)

// writePattern matches Write permission rules like "Write(./output/**)"
var writePattern = regexp.MustCompile(`^Write\((.+)\)$`)

// editPattern matches Edit permission rules (similar to Write)
var editPattern = regexp.MustCompile(`^Edit\((.+)\)$`)

// processClaudeRule processes a single Claude permission rule and updates the fence config.
func processClaudeRule(rule string, cfg *config.Config, isAllow bool) {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return
	}

	// Handle Bash(command) rules
	if matches := bashPattern.FindStringSubmatch(rule); len(matches) == 2 {
		cmd := normalizeClaudeCommand(matches[1])
		if cmd != "" {
			if isAllow {
				cfg.Command.Allow = appendUnique(cfg.Command.Allow, cmd)
			} else {
				cfg.Command.Deny = appendUnique(cfg.Command.Deny, cmd)
			}
		}
		return
	}

	// Handle Read(path) rules
	if matches := readPattern.FindStringSubmatch(rule); len(matches) == 2 {
		path := normalizeClaudePath(matches[1])
		if path != "" {
			if !isAllow {
				// Read deny -> filesystem.denyRead
				cfg.Filesystem.DenyRead = appendUnique(cfg.Filesystem.DenyRead, path)
			}
			// Note: fence doesn't have an "allowRead" concept - everything is readable by default
		}
		return
	}

	// Handle Write(path) rules
	if matches := writePattern.FindStringSubmatch(rule); len(matches) == 2 {
		path := normalizeClaudePath(matches[1])
		if path != "" {
			if isAllow {
				cfg.Filesystem.AllowWrite = appendUnique(cfg.Filesystem.AllowWrite, path)
			} else {
				cfg.Filesystem.DenyWrite = appendUnique(cfg.Filesystem.DenyWrite, path)
			}
		}
		return
	}

	// Handle Edit(path) rules (same as Write)
	if matches := editPattern.FindStringSubmatch(rule); len(matches) == 2 {
		path := normalizeClaudePath(matches[1])
		if path != "" {
			if isAllow {
				cfg.Filesystem.AllowWrite = appendUnique(cfg.Filesystem.AllowWrite, path)
			} else {
				cfg.Filesystem.DenyWrite = appendUnique(cfg.Filesystem.DenyWrite, path)
			}
		}
		return
	}

	// Handle bare tool names (e.g., "Read", "Write", "Bash")
	// These are global permissions that don't map directly to fence's path-based model
	// We skip them as they don't provide actionable path/command restrictions
}

// normalizeClaudeCommand converts Claude's command format to fence format.
// Claude uses "npm:*" style, fence uses "npm" for prefix matching.
func normalizeClaudeCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)

	// Handle wildcard patterns like "npm:*" -> "npm"
	// Claude uses ":" as separator, fence uses space-separated commands
	// Also handles "npm run test:*" -> "npm run test"
	cmd = strings.TrimSuffix(cmd, ":*")

	return cmd
}

// normalizeClaudePath converts Claude's path format to fence format.
func normalizeClaudePath(path string) string {
	path = strings.TrimSpace(path)

	// Claude uses ./ prefix for relative paths, fence doesn't require it
	// but fence does support it, so we can keep it

	// Convert ** glob patterns - both Claude and fence support these
	// No conversion needed

	return path
}

// appendUnique appends a value to a slice if it's not already present.
func appendUnique(slice []string, value string) []string {
	for _, v := range slice {
		if v == value {
			return slice
		}
	}
	return append(slice, value)
}

// ImportResult contains the result of an import operation.
type ImportResult struct {
	Config        *config.Config
	SourcePath    string
	RulesImported int
	Warnings      []string
}

// ImportOptions configures the import behavior.
type ImportOptions struct {
	// Extends specifies a template or file to extend. Empty string means no extends.
	Extends string
}

// DefaultImportOptions returns the default import options.
// By default, imports extend the "code" template for sensible defaults.
func DefaultImportOptions() ImportOptions {
	return ImportOptions{
		Extends: "code",
	}
}

// ImportFromClaude imports settings from Claude Code and returns a fence config.
// If path is empty, it tries the default Claude settings path.
func ImportFromClaude(path string, opts ImportOptions) (*ImportResult, error) {
	if path == "" {
		path = DefaultClaudeSettingsPath()
	}

	if path == "" {
		return nil, fmt.Errorf("could not determine Claude settings path")
	}

	settings, err := LoadClaudeSettings(path)
	if err != nil {
		return nil, err
	}

	cfg := ConvertClaudeToFence(settings)

	// Set extends if specified
	if opts.Extends != "" {
		cfg.Extends = opts.Extends
	}

	result := &ImportResult{
		Config:     cfg,
		SourcePath: path,
		RulesImported: len(settings.Permissions.Allow) +
			len(settings.Permissions.Deny) +
			len(settings.Permissions.Ask),
	}

	// Add warnings for rules that couldn't be fully converted
	for _, rule := range settings.Permissions.Allow {
		if isGlobalToolRule(rule) {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Global tool permission %q skipped (fence uses path/command-based rules)", rule))
		}
	}
	for _, rule := range settings.Permissions.Deny {
		if isGlobalToolRule(rule) {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Global tool permission %q skipped (fence uses path/command-based rules)", rule))
		}
	}
	for _, rule := range settings.Permissions.Ask {
		if isGlobalToolRule(rule) {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Global tool permission %q skipped (fence uses path/command-based rules)", rule))
		} else {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Ask rule %q converted to deny (fence doesn't support interactive prompts)", rule))
		}
	}

	return result, nil
}

// isGlobalToolRule checks if a rule is a global tool permission (no path/command specified).
func isGlobalToolRule(rule string) bool {
	rule = strings.TrimSpace(rule)
	// Global rules are bare tool names without parentheses
	return !strings.Contains(rule, "(")
}

// MarshalConfigJSON marshals a fence config to clean JSON, omitting empty arrays
// and with fields in a logical order (extends first).
func MarshalConfigJSON(cfg *config.Config) ([]byte, error) {
	return config.MarshalConfigJSON(cfg)
}

// FormatConfigWithComment returns the config JSON with a comment header
// explaining that values are inherited from the extended template.
func FormatConfigWithComment(cfg *config.Config) (string, error) {
	return config.FormatConfigForFile(cfg, config.FileWriteOptions{
		HeaderLines: importHeaderLines(cfg),
	})
}

// WriteConfig writes a fence config to a file.
func WriteConfig(cfg *config.Config, path string) error {
	return config.WriteConfigFile(cfg, path, config.FileWriteOptions{
		HeaderLines: importHeaderLines(cfg),
	})
}

func importHeaderLines(cfg *config.Config) []string {
	if cfg.Extends == "" {
		return nil
	}
	return []string{
		fmt.Sprintf("// This config extends %q.", cfg.Extends),
		fmt.Sprintf("// Network, filesystem, and command rules from %q are inherited.", cfg.Extends),
		"// Only your additional rules are shown below.",
		"// Run `fence --list-templates` to see available templates.",
		"// Configuration reference: https://github.com/Use-Tusk/fence/blob/main/docs/configuration.md",
	}
}
