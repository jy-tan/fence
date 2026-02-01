// Package config defines the configuration types and loading for fence.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tidwall/jsonc"
)

// Config is the main configuration for fence.
type Config struct {
	Extends    string           `json:"extends,omitempty"`
	Network    NetworkConfig    `json:"network"`
	Filesystem FilesystemConfig `json:"filesystem"`
	Command    CommandConfig    `json:"command"`
	SSH        SSHConfig        `json:"ssh"`
	AllowPty   bool             `json:"allowPty,omitempty"`
}

// NetworkConfig defines network restrictions.
type NetworkConfig struct {
	AllowedDomains      []string `json:"allowedDomains"`
	DeniedDomains       []string `json:"deniedDomains"`
	AllowUnixSockets    []string `json:"allowUnixSockets,omitempty"`
	AllowAllUnixSockets bool     `json:"allowAllUnixSockets,omitempty"`
	AllowLocalBinding   bool     `json:"allowLocalBinding,omitempty"`
	AllowLocalOutbound  *bool    `json:"allowLocalOutbound,omitempty"` // If nil, defaults to AllowLocalBinding value
	HTTPProxyPort       int      `json:"httpProxyPort,omitempty"`
	SOCKSProxyPort      int      `json:"socksProxyPort,omitempty"`
}

// FilesystemConfig defines filesystem restrictions.
type FilesystemConfig struct {
	DefaultDenyRead bool     `json:"defaultDenyRead,omitempty"` // If true, deny reads by default except system paths and AllowRead
	AllowRead       []string `json:"allowRead"`                 // Paths to allow reading (used when DefaultDenyRead is true)
	DenyRead        []string `json:"denyRead"`
	AllowWrite      []string `json:"allowWrite"`
	DenyWrite       []string `json:"denyWrite"`
	AllowGitConfig  bool     `json:"allowGitConfig,omitempty"`
}

// CommandConfig defines command restrictions.
type CommandConfig struct {
	Deny        []string `json:"deny"`
	Allow       []string `json:"allow"`
	UseDefaults *bool    `json:"useDefaults,omitempty"`
}

// SSHConfig defines SSH command restrictions.
// SSH commands are filtered using an allowlist by default for security.
type SSHConfig struct {
	AllowedHosts     []string `json:"allowedHosts"`               // Host patterns to allow SSH to (supports wildcards like *.example.com)
	DeniedHosts      []string `json:"deniedHosts"`                // Host patterns to deny SSH to (checked before allowed)
	AllowedCommands  []string `json:"allowedCommands"`            // Commands allowed over SSH (allowlist mode)
	DeniedCommands   []string `json:"deniedCommands"`             // Commands denied over SSH (checked before allowed)
	AllowAllCommands bool     `json:"allowAllCommands,omitempty"` // If true, use denylist mode instead of allowlist
	InheritDeny      bool     `json:"inheritDeny,omitempty"`      // If true, also apply global command.deny rules
}

// DefaultDeniedCommands returns commands that are blocked by default.
// These are system-level dangerous commands that are rarely needed by AI agents.
var DefaultDeniedCommands = []string{
	// System control - can crash/reboot the machine
	"shutdown",
	"reboot",
	"halt",
	"poweroff",
	"init 0",
	"init 6",
	"systemctl poweroff",
	"systemctl reboot",
	"systemctl halt",

	// Kernel/module manipulation
	"insmod",
	"rmmod",
	"modprobe",
	"kexec",

	// Disk/partition manipulation (including common variants)
	"mkfs",
	"mkfs.ext2",
	"mkfs.ext3",
	"mkfs.ext4",
	"mkfs.xfs",
	"mkfs.btrfs",
	"mkfs.vfat",
	"mkfs.ntfs",
	"fdisk",
	"parted",
	"dd if=",

	// Container escape vectors
	"docker run -v /:/",
	"docker run --privileged",

	// Chroot/namespace escape
	"chroot",
	"unshare",
	"nsenter",
}

// Default returns the default configuration with all network blocked.
func Default() *Config {
	return &Config{
		Network: NetworkConfig{
			AllowedDomains: []string{},
			DeniedDomains:  []string{},
		},
		Filesystem: FilesystemConfig{
			DenyRead:   []string{},
			AllowWrite: []string{},
			DenyWrite:  []string{},
		},
		Command: CommandConfig{
			Deny:  []string{},
			Allow: []string{},
			// UseDefaults defaults to true (nil = true)
		},
		SSH: SSHConfig{
			AllowedHosts:    []string{},
			DeniedHosts:     []string{},
			AllowedCommands: []string{},
			DeniedCommands:  []string{},
		},
	}
}

// DefaultConfigPath returns the default config file path.
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".fence.json"
	}
	return filepath.Join(home, ".fence.json")
}

// Load loads configuration from a file path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided config path - intentional
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Handle empty file
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}

	var cfg Config
	if err := json.Unmarshal(jsonc.ToJSON(data), &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON in config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	for _, domain := range c.Network.AllowedDomains {
		if err := validateDomainPattern(domain); err != nil {
			return fmt.Errorf("invalid allowed domain %q: %w", domain, err)
		}
	}
	for _, domain := range c.Network.DeniedDomains {
		if err := validateDomainPattern(domain); err != nil {
			return fmt.Errorf("invalid denied domain %q: %w", domain, err)
		}
	}

	if slices.Contains(c.Filesystem.AllowRead, "") {
		return errors.New("filesystem.allowRead contains empty path")
	}
	if slices.Contains(c.Filesystem.DenyRead, "") {
		return errors.New("filesystem.denyRead contains empty path")
	}
	if slices.Contains(c.Filesystem.AllowWrite, "") {
		return errors.New("filesystem.allowWrite contains empty path")
	}
	if slices.Contains(c.Filesystem.DenyWrite, "") {
		return errors.New("filesystem.denyWrite contains empty path")
	}

	if slices.Contains(c.Command.Deny, "") {
		return errors.New("command.deny contains empty command")
	}
	if slices.Contains(c.Command.Allow, "") {
		return errors.New("command.allow contains empty command")
	}

	// SSH config
	for _, host := range c.SSH.AllowedHosts {
		if err := validateHostPattern(host); err != nil {
			return fmt.Errorf("invalid ssh.allowedHosts %q: %w", host, err)
		}
	}
	for _, host := range c.SSH.DeniedHosts {
		if err := validateHostPattern(host); err != nil {
			return fmt.Errorf("invalid ssh.deniedHosts %q: %w", host, err)
		}
	}
	if slices.Contains(c.SSH.AllowedCommands, "") {
		return errors.New("ssh.allowedCommands contains empty command")
	}
	if slices.Contains(c.SSH.DeniedCommands, "") {
		return errors.New("ssh.deniedCommands contains empty command")
	}

	return nil
}

// UseDefaultDeniedCommands returns whether to use the default deny list.
func (c *CommandConfig) UseDefaultDeniedCommands() bool {
	return c.UseDefaults == nil || *c.UseDefaults
}

func validateDomainPattern(pattern string) error {
	if pattern == "localhost" {
		return nil
	}

	if strings.Contains(pattern, "://") || strings.Contains(pattern, "/") || strings.Contains(pattern, ":") {
		return errors.New("domain pattern cannot contain protocol, path, or port")
	}

	// Handle wildcard patterns
	if strings.HasPrefix(pattern, "*.") {
		domain := pattern[2:]
		// Must have at least one more dot after the wildcard
		if !strings.Contains(domain, ".") {
			return errors.New("wildcard pattern too broad (e.g., *.com not allowed)")
		}
		if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
			return errors.New("invalid domain format")
		}
		// Check each part has content
		parts := strings.Split(domain, ".")
		if len(parts) < 2 {
			return errors.New("wildcard pattern too broad")
		}
		if slices.Contains(parts, "") {
			return errors.New("invalid domain format")
		}
		return nil
	}

	// Reject other uses of wildcards
	if strings.Contains(pattern, "*") {
		return errors.New("only *.domain.com wildcard patterns are allowed")
	}

	// Regular domains must have at least one dot
	if !strings.Contains(pattern, ".") || strings.HasPrefix(pattern, ".") || strings.HasSuffix(pattern, ".") {
		return errors.New("invalid domain format")
	}

	return nil
}

// validateHostPattern validates an SSH host pattern.
// Host patterns are more permissive than domain patterns:
// - Can contain wildcards anywhere (e.g., prod-*.example.com, *.example.com)
// - Can be IP addresses
// - Can be simple hostnames without dots
func validateHostPattern(pattern string) error {
	if pattern == "" {
		return errors.New("empty host pattern")
	}

	// Reject patterns with protocol or path
	if strings.Contains(pattern, "://") || strings.Contains(pattern, "/") {
		return errors.New("host pattern cannot contain protocol or path")
	}

	// Reject patterns with port (user@host:port style)
	// But allow colons for IPv6 addresses
	if strings.Contains(pattern, ":") && !strings.Contains(pattern, "::") && !isIPv6Pattern(pattern) {
		return errors.New("host pattern cannot contain port; specify port in SSH command instead")
	}

	// Reject patterns with @ (should be just the host, not user@host)
	if strings.Contains(pattern, "@") {
		return errors.New("host pattern should not contain username; specify just the host")
	}

	return nil
}

// isIPv6Pattern checks if a pattern looks like an IPv6 address.
func isIPv6Pattern(pattern string) bool {
	// IPv6 addresses contain multiple colons
	colonCount := strings.Count(pattern, ":")
	return colonCount >= 2
}

// MatchesDomain checks if a hostname matches a domain pattern.
func MatchesDomain(hostname, pattern string) bool {
	hostname = strings.ToLower(hostname)
	pattern = strings.ToLower(pattern)

	// "*" matches all domains
	if pattern == "*" {
		return true
	}

	// Wildcard pattern like *.example.com
	if strings.HasPrefix(pattern, "*.") {
		baseDomain := pattern[2:]
		return strings.HasSuffix(hostname, "."+baseDomain)
	}

	// Exact match
	return hostname == pattern
}

// MatchesHost checks if a hostname matches an SSH host pattern.
// SSH host patterns support wildcards anywhere in the pattern.
func MatchesHost(hostname, pattern string) bool {
	hostname = strings.ToLower(hostname)
	pattern = strings.ToLower(pattern)

	// "*" matches all hosts
	if pattern == "*" {
		return true
	}

	// If pattern contains no wildcards, do exact match
	if !strings.Contains(pattern, "*") {
		return hostname == pattern
	}

	// Convert glob pattern to a simple matcher
	// Split pattern by * and check each part
	return matchGlob(hostname, pattern)
}

// matchGlob performs simple glob matching with * wildcards.
func matchGlob(s, pattern string) bool {
	// Handle edge cases
	if pattern == "*" {
		return true
	}
	if pattern == "" {
		return s == ""
	}

	// Split pattern by * and match parts
	parts := strings.Split(pattern, "*")

	// Check prefix (before first *)
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]

	// Check suffix (after last *)
	if len(parts) > 1 {
		last := parts[len(parts)-1]
		if !strings.HasSuffix(s, last) {
			return false
		}
		s = s[:len(s)-len(last)]
	}

	// Check middle parts (between *s)
	for i := 1; i < len(parts)-1; i++ {
		part := parts[i]
		if part == "" {
			continue
		}
		idx := strings.Index(s, part)
		if idx < 0 {
			return false
		}
		s = s[idx+len(part):]
	}

	return true
}

// Merge combines a base config with an override config.
// Values in override take precedence. Slice fields are appended (base + override).
// The Extends field is cleared in the result since inheritance has been resolved.
func Merge(base, override *Config) *Config {
	if base == nil {
		if override == nil {
			return Default()
		}
		result := *override
		result.Extends = ""
		return &result
	}
	if override == nil {
		result := *base
		result.Extends = ""
		return &result
	}

	result := &Config{
		// AllowPty: true if either config enables it
		AllowPty: base.AllowPty || override.AllowPty,

		Network: NetworkConfig{
			// Append slices (base first, then override additions)
			AllowedDomains:   mergeStrings(base.Network.AllowedDomains, override.Network.AllowedDomains),
			DeniedDomains:    mergeStrings(base.Network.DeniedDomains, override.Network.DeniedDomains),
			AllowUnixSockets: mergeStrings(base.Network.AllowUnixSockets, override.Network.AllowUnixSockets),

			// Boolean fields: override wins if set, otherwise base
			AllowAllUnixSockets: base.Network.AllowAllUnixSockets || override.Network.AllowAllUnixSockets,
			AllowLocalBinding:   base.Network.AllowLocalBinding || override.Network.AllowLocalBinding,

			// Pointer fields: override wins if set, otherwise base
			AllowLocalOutbound: mergeOptionalBool(base.Network.AllowLocalOutbound, override.Network.AllowLocalOutbound),

			// Port fields: override wins if non-zero
			HTTPProxyPort:  mergeInt(base.Network.HTTPProxyPort, override.Network.HTTPProxyPort),
			SOCKSProxyPort: mergeInt(base.Network.SOCKSProxyPort, override.Network.SOCKSProxyPort),
		},

		Filesystem: FilesystemConfig{
			// Boolean fields: true if either enables it
			DefaultDenyRead: base.Filesystem.DefaultDenyRead || override.Filesystem.DefaultDenyRead,

			// Append slices
			AllowRead:  mergeStrings(base.Filesystem.AllowRead, override.Filesystem.AllowRead),
			DenyRead:   mergeStrings(base.Filesystem.DenyRead, override.Filesystem.DenyRead),
			AllowWrite: mergeStrings(base.Filesystem.AllowWrite, override.Filesystem.AllowWrite),
			DenyWrite:  mergeStrings(base.Filesystem.DenyWrite, override.Filesystem.DenyWrite),

			// Boolean fields: override wins if set
			AllowGitConfig: base.Filesystem.AllowGitConfig || override.Filesystem.AllowGitConfig,
		},

		Command: CommandConfig{
			// Append slices
			Deny:  mergeStrings(base.Command.Deny, override.Command.Deny),
			Allow: mergeStrings(base.Command.Allow, override.Command.Allow),

			// Pointer field: override wins if set
			UseDefaults: mergeOptionalBool(base.Command.UseDefaults, override.Command.UseDefaults),
		},

		SSH: SSHConfig{
			// Append slices
			AllowedHosts:    mergeStrings(base.SSH.AllowedHosts, override.SSH.AllowedHosts),
			DeniedHosts:     mergeStrings(base.SSH.DeniedHosts, override.SSH.DeniedHosts),
			AllowedCommands: mergeStrings(base.SSH.AllowedCommands, override.SSH.AllowedCommands),
			DeniedCommands:  mergeStrings(base.SSH.DeniedCommands, override.SSH.DeniedCommands),

			// Boolean fields: true if either enables it
			AllowAllCommands: base.SSH.AllowAllCommands || override.SSH.AllowAllCommands,
			InheritDeny:      base.SSH.InheritDeny || override.SSH.InheritDeny,
		},
	}

	return result
}

// mergeStrings appends two string slices, removing duplicates.
func mergeStrings(base, override []string) []string {
	if len(base) == 0 {
		return override
	}
	if len(override) == 0 {
		return base
	}

	seen := make(map[string]bool, len(base))
	result := make([]string, 0, len(base)+len(override))

	for _, s := range base {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, s := range override {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// mergeOptionalBool returns override if non-nil, otherwise base.
func mergeOptionalBool(base, override *bool) *bool {
	if override != nil {
		return override
	}
	return base
}

// mergeInt returns override if non-zero, otherwise base.
func mergeInt(base, override int) int {
	if override != 0 {
		return override
	}
	return base
}
