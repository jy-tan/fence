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

// cleanNetworkConfig is used for JSON output with omitempty to skip empty fields.
type cleanNetworkConfig struct {
	AllowedDomains      []string `json:"allowedDomains,omitempty"`
	DeniedDomains       []string `json:"deniedDomains,omitempty"`
	AllowUnixSockets    []string `json:"allowUnixSockets,omitempty"`
	AllowAllUnixSockets bool     `json:"allowAllUnixSockets,omitempty"`
	AllowLocalBinding   bool     `json:"allowLocalBinding,omitempty"`
	AllowLocalOutbound  *bool    `json:"allowLocalOutbound,omitempty"`
	HTTPProxyPort       int      `json:"httpProxyPort,omitempty"`
	SOCKSProxyPort      int      `json:"socksProxyPort,omitempty"`
}

// cleanFilesystemConfig is used for JSON output with omitempty to skip empty fields.
type cleanFilesystemConfig struct {
	DenyRead       []string `json:"denyRead,omitempty"`
	AllowWrite     []string `json:"allowWrite,omitempty"`
	DenyWrite      []string `json:"denyWrite,omitempty"`
	AllowGitConfig bool     `json:"allowGitConfig,omitempty"`
}

// cleanCommandConfig is used for JSON output with omitempty to skip empty fields.
type cleanCommandConfig struct {
	Deny        []string `json:"deny,omitempty"`
	Allow       []string `json:"allow,omitempty"`
	UseDefaults *bool    `json:"useDefaults,omitempty"`
}

// cleanConfig is used for JSON output with fields in desired order and omitempty.
type cleanConfig struct {
	Extends    string                 `json:"extends,omitempty"`
	AllowPty   bool                   `json:"allowPty,omitempty"`
	Network    *cleanNetworkConfig    `json:"network,omitempty"`
	Filesystem *cleanFilesystemConfig `json:"filesystem,omitempty"`
	Command    *cleanCommandConfig    `json:"command,omitempty"`
}

// MarshalConfigJSON marshals a fence config to clean JSON, omitting empty arrays
// and with fields in a logical order (extends first).
func MarshalConfigJSON(cfg *config.Config) ([]byte, error) {
	clean := cleanConfig{
		Extends:  cfg.Extends,
		AllowPty: cfg.AllowPty,
	}

	// Network config - only include if non-empty
	network := cleanNetworkConfig{
		AllowedDomains:      cfg.Network.AllowedDomains,
		DeniedDomains:       cfg.Network.DeniedDomains,
		AllowUnixSockets:    cfg.Network.AllowUnixSockets,
		AllowAllUnixSockets: cfg.Network.AllowAllUnixSockets,
		AllowLocalBinding:   cfg.Network.AllowLocalBinding,
		AllowLocalOutbound:  cfg.Network.AllowLocalOutbound,
		HTTPProxyPort:       cfg.Network.HTTPProxyPort,
		SOCKSProxyPort:      cfg.Network.SOCKSProxyPort,
	}
	if !isNetworkEmpty(network) {
		clean.Network = &network
	}

	// Filesystem config - only include if non-empty
	filesystem := cleanFilesystemConfig{
		DenyRead:       cfg.Filesystem.DenyRead,
		AllowWrite:     cfg.Filesystem.AllowWrite,
		DenyWrite:      cfg.Filesystem.DenyWrite,
		AllowGitConfig: cfg.Filesystem.AllowGitConfig,
	}
	if !isFilesystemEmpty(filesystem) {
		clean.Filesystem = &filesystem
	}

	// Command config - only include if non-empty
	command := cleanCommandConfig{
		Deny:        cfg.Command.Deny,
		Allow:       cfg.Command.Allow,
		UseDefaults: cfg.Command.UseDefaults,
	}
	if !isCommandEmpty(command) {
		clean.Command = &command
	}

	return json.MarshalIndent(clean, "", "  ")
}

func isNetworkEmpty(n cleanNetworkConfig) bool {
	return len(n.AllowedDomains) == 0 &&
		len(n.DeniedDomains) == 0 &&
		len(n.AllowUnixSockets) == 0 &&
		!n.AllowAllUnixSockets &&
		!n.AllowLocalBinding &&
		n.AllowLocalOutbound == nil &&
		n.HTTPProxyPort == 0 &&
		n.SOCKSProxyPort == 0
}

func isFilesystemEmpty(f cleanFilesystemConfig) bool {
	return len(f.DenyRead) == 0 &&
		len(f.AllowWrite) == 0 &&
		len(f.DenyWrite) == 0 &&
		!f.AllowGitConfig
}

func isCommandEmpty(c cleanCommandConfig) bool {
	return len(c.Deny) == 0 &&
		len(c.Allow) == 0 &&
		c.UseDefaults == nil
}

// FormatConfigWithComment returns the config JSON with a comment header
// explaining that values are inherited from the extended template.
func FormatConfigWithComment(cfg *config.Config) (string, error) {
	data, err := MarshalConfigJSON(cfg)
	if err != nil {
		return "", err
	}

	var output strings.Builder

	// Add comment about inherited values if extending a template
	if cfg.Extends != "" {
		output.WriteString(fmt.Sprintf("// This config extends %q.\n", cfg.Extends))
		output.WriteString(fmt.Sprintf("// Network, filesystem, and command rules from %q are inherited.\n", cfg.Extends))
		output.WriteString("// Only your additional rules are shown below.\n")
		output.WriteString("// Run `fence --list-templates` to see available templates.\n")
	}

	output.Write(data)
	output.WriteByte('\n')

	return output.String(), nil
}

// WriteConfig writes a fence config to a file.
func WriteConfig(cfg *config.Config, path string) error {
	output, err := FormatConfigWithComment(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, []byte(output), 0o644); err != nil { //nolint:gosec // config file permissions
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
