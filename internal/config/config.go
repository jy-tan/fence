// Package config defines the configuration types and loading for fence.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/tidwall/jsonc"
)

// Config is the main configuration for fence.
type Config struct {
	Extends         string           `json:"extends,omitempty" description:"Path or built-in template name to inherit base settings from (e.g. \"code\" or \"./base.json\"). Settings in this file are merged on top of the extended config."`
	Network         NetworkConfig    `json:"network" description:"Network access restrictions. Controls which domains the sandbox may connect to and how local networking is handled."`
	Filesystem      FilesystemConfig `json:"filesystem" description:"Filesystem access restrictions. Controls which paths may be read, written, or executed inside the sandbox."`
	Devices         DevicesConfig    `json:"devices,omitempty"`
	MacOS           MacOSConfig      `json:"macos,omitempty" description:"macOS-specific advanced sandbox controls. Ignored on non-macOS platforms."`
	Command         CommandConfig    `json:"command" description:"Command execution restrictions. Controls which commands are blocked or allowed at preflight and runtime."`
	SSH             SSHConfig        `json:"ssh" description:"SSH command and host restrictions. Applies only to ssh invocations; does not affect other network access."`
	AllowPty        bool             `json:"allowPty,omitempty" description:"Allow the sandboxed process to allocate a pseudo-terminal (PTY). Required for interactive programs that need terminal control (e.g. vim, less, top)."`
	ForceNewSession *bool            `json:"forceNewSession,omitempty"`
}

// NetworkConfig defines network restrictions.
type NetworkConfig struct {
	AllowedDomains      []string `json:"allowedDomains" description:"Domains the sandbox may connect to. Supports wildcards (e.g. *.example.com). Use \"*\" to allow all outbound connections. If empty, all outbound connections are blocked."`
	DeniedDomains       []string `json:"deniedDomains" description:"Domains explicitly blocked even if they match allowedDomains. Evaluated before allowedDomains."`
	AllowUnixSockets    []string `json:"allowUnixSockets,omitempty" description:"Unix socket paths the sandbox may connect to (e.g. /var/run/docker.sock)."`
	AllowAllUnixSockets bool     `json:"allowAllUnixSockets,omitempty" description:"If true, allow connections to any Unix socket path. Overrides allowUnixSockets."`
	AllowLocalBinding   bool     `json:"allowLocalBinding,omitempty" description:"Allow the sandbox to bind to local network ports. Enable this when the sandboxed process needs to run a local server."`
	AllowLocalOutbound  *bool    `json:"allowLocalOutbound,omitempty" description:"Allow outbound connections to localhost and loopback addresses. If omitted, inherits the value of allowLocalBinding."`
	// AllowLocalOutboundPorts is required on Linux for host-loopback access.
	// macOS reaches any localhost port when allowLocalOutbound is true; Linux
	// keeps --unshare-net so the sandbox's loopback is isolated from the
	// host's, and each listed port is bridged back to host 127.0.0.1:<port>.
	AllowLocalOutboundPorts []int `json:"allowLocalOutboundPorts,omitempty" description:"Linux-only. TCP ports on the host's 127.0.0.1 that the sandbox may connect to when allowLocalOutbound is true. Each listed port is forwarded from sandbox loopback to host loopback via a per-port bridge. Ignored on macOS (which allows arbitrary localhost ports when allowLocalOutbound is true)."`
	HTTPProxyPort           int   `json:"httpProxyPort,omitempty" description:"Port for the internal HTTP proxy used to enforce domain filtering. Set automatically by fence; only override for advanced configurations."`
	SOCKSProxyPort          int   `json:"socksProxyPort,omitempty" description:"Port for the internal SOCKS proxy used to enforce domain filtering. Set automatically by fence; only override for advanced configurations."`
}

// EffectiveAllowLocalOutbound returns whether outbound connections to
// localhost/loopback should be permitted. When AllowLocalOutbound is unset,
// it defaults to AllowLocalBinding (documented behavior on both macOS and
// Linux).
func (n NetworkConfig) EffectiveAllowLocalOutbound() bool {
	if n.AllowLocalOutbound != nil {
		return *n.AllowLocalOutbound
	}
	return n.AllowLocalBinding
}

// DeviceMode controls how /dev is set up inside Linux sandboxes.
type DeviceMode string

const (
	DeviceModeAuto    DeviceMode = "auto"    // Picks the safest compatible /dev layout for the current environment.
	DeviceModeMinimal DeviceMode = "minimal" // Creates a fresh minimal /dev inside the sandbox.
	DeviceModeHost    DeviceMode = "host"    // Bind-mounts the outer environment's /dev into the sandbox.
)

// DevicesConfig defines device exposure inside the sandbox.
type DevicesConfig struct {
	Mode  DeviceMode `json:"mode,omitempty" schema:"enum=auto|minimal|host"` // auto|minimal|host
	Allow []string   `json:"allow,omitempty" schema:"itemsPattern=^/dev/.+"` // Extra /dev paths to pass through when using a minimal /dev
}

// MacOSConfig defines macOS-specific sandbox controls.
type MacOSConfig struct {
	Mach MachConfig `json:"mach,omitempty" description:"Mach and XPC permissions for the macOS Seatbelt backend."`
}

// MachConfig defines additional Mach/XPC permissions for macOS sandboxes.
type MachConfig struct {
	Lookup   []string `json:"lookup,omitempty" schema:"itemsPattern=^(\\*|[^*]+\\*?)$" description:"Additional Mach/XPC services the macOS sandbox may look up. Supports exact service names, trailing-wildcard prefixes like \"org.chromium.*\", and \"*\" to allow all Mach lookups."`
	Register []string `json:"register,omitempty" schema:"itemsPattern=^(\\*|[^*]+\\*?)$" description:"Additional Mach/XPC services the macOS sandbox may register. Supports exact service names, trailing-wildcard prefixes like \"org.chromium.*\", and \"*\" to allow all Mach registrations."`
}

// FilesystemConfig defines filesystem restrictions.
type FilesystemConfig struct {
	DefaultDenyRead bool     `json:"defaultDenyRead,omitempty" description:"If true, deny all filesystem reads by default. Only paths listed in allowRead (and essential system paths) remain readable. Use for strict read isolation."`
	StrictDenyRead  bool     `json:"strictDenyRead,omitempty" description:"If true, suppress the default readable system paths that are normally added when defaultDenyRead is enabled. Only paths in allowRead will be readable. Implies defaultDenyRead."`
	WSLInterop      *bool    `json:"wslInterop,omitempty" description:"Controls access to the WSL interop binary on Windows Subsystem for Linux. If omitted, auto-detected: WSL environments allow /init, non-WSL environments do not."`
	AllowRead       []string `json:"allowRead" description:"Additional filesystem paths the sandbox may read. Accepts absolute paths and glob patterns."`
	AllowExecute    []string `json:"allowExecute" description:"Paths the sandbox may execute (grants read and execute permission, but not directory listing). Use for binaries that must be reachable but whose parent directories should not be browsable."`
	DenyRead        []string `json:"denyRead" description:"Paths explicitly blocked from reading, even if they would otherwise be permitted by allowRead or system defaults."`
	AllowWrite      []string `json:"allowWrite" description:"Filesystem paths the sandbox may write to. Accepts absolute paths and glob patterns."`
	DenyWrite       []string `json:"denyWrite" description:"Paths explicitly blocked from writing, even if they would otherwise be permitted by allowWrite."`
	AllowGitConfig  bool     `json:"allowGitConfig,omitempty" description:"If true, allow read access to ~/.gitconfig and ~/.config/git. Enable when git operations inside the sandbox need the user's identity or settings."`
}

// RuntimeExecPolicy controls how Linux runtime child-process execs are enforced.
type RuntimeExecPolicy string

const (
	RuntimeExecPolicyPath RuntimeExecPolicy = "path"
	RuntimeExecPolicyArgv RuntimeExecPolicy = "argv"
)

// CommandConfig defines command restrictions.
type CommandConfig struct {
	Deny                                []string          `json:"deny" description:"Commands or command prefixes the sandbox will refuse to run. Matched at preflight and, depending on runtimeExecPolicy, at runtime for child execs."`
	Allow                               []string          `json:"allow" description:"Commands that override a matching deny rule. Use to carve out specific exceptions from a broad deny pattern (e.g. allow \"git push origin docs\" when \"git push\" is denied)."`
	UseDefaults                         *bool             `json:"useDefaults,omitempty" description:"Whether to include the built-in default deny list (shutdown, reboot, insmod, mkfs, etc.). Defaults to true when omitted. Set to false to manage the deny list entirely yourself."`
	AcceptSharedBinaryCannotRuntimeDeny []string          `json:"acceptSharedBinaryCannotRuntimeDeny,omitempty" description:"Commands for which the shared-binary skip warning is silenced. Add a command here after investigating a collision and accepting that it cannot be blocked on this system."`
	RuntimeExecPolicy                   RuntimeExecPolicy `json:"runtimeExecPolicy,omitempty" schema:"enum=path|argv" description:"Runtime child-process exec enforcement mode. \"path\" (default) uses executable-path masking for single-token denies. \"argv\" enables Linux-only argv-aware exec interception for child processes."`
}

// SSHConfig defines SSH command restrictions.
// SSH commands are filtered using an allowlist by default for security.
type SSHConfig struct {
	AllowedHosts     []string `json:"allowedHosts" description:"Host patterns the sandbox may SSH to. Supports wildcards (e.g. *.example.com, prod-*). SSH connections to hosts not matching any pattern are blocked."`
	DeniedHosts      []string `json:"deniedHosts" description:"Host patterns explicitly blocked for SSH, even if they match allowedHosts. Evaluated before allowedHosts."`
	AllowedCommands  []string `json:"allowedCommands" description:"Commands permitted over SSH (allowlist mode). Only the listed commands may be executed on remote hosts. An empty list allows interactive sessions only."`
	DeniedCommands   []string `json:"deniedCommands" description:"Commands blocked over SSH (denylist mode). Only meaningful when allowAllCommands is true."`
	AllowAllCommands bool     `json:"allowAllCommands,omitempty" description:"If true, switch SSH command filtering to denylist mode: all remote commands are permitted except those in deniedCommands. When false (the default), allowedCommands acts as an allowlist."`
	InheritDeny      bool     `json:"inheritDeny,omitempty" description:"If true, also apply the global command.deny rules to SSH remote commands."`
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
		Devices: DevicesConfig{
			Allow: []string{},
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

// ConfigFileName is the canonical filename fence writes when creating new
// config files.
const ConfigFileName = "fence.json"

// configFileNames lists the filenames fence auto-discovers, in precedence
// order. fence.jsonc is preferred over fence.json so users can opt into
// JSONC-style comments/trailing commas by choosing the extension, mirroring
// the behavior of tools like opencode.
var configFileNames = []string{"fence.jsonc", "fence.json"}

// DefaultConfigPath returns the canonical config file path for new configs.
// Uses ~/.config/fence/fence.json as the canonical path on macOS and the OS config dir elsewhere.
func DefaultConfigPath() string {
	home, _ := os.UserHomeDir()
	configDir, _ := os.UserConfigDir()

	return defaultConfigPathFor(runtime.GOOS, home, configDir)
}

// ResolveDefaultConfigPath returns the config path fence should load by default.
// It prefers the canonical path when that file exists, but falls back to legacy
// locations while migrating older configs.
func ResolveDefaultConfigPath() string {
	home, _ := os.UserHomeDir()
	configDir, _ := os.UserConfigDir()

	return resolveDefaultConfigPathFor(runtime.GOOS, home, configDir, configFileExists)
}

// ResolveConfigPath returns the config path fence should load when --settings is
// not provided. It prefers the nearest fence.jsonc (falling back to
// fence.json) in startDir or any parent directory, and falls back to the
// user's default config path otherwise.
func ResolveConfigPath(startDir string) (string, error) {
	if startDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to determine working directory: %w", err)
		}
		startDir = cwd
	}

	home, _ := os.UserHomeDir()
	configDir, _ := os.UserConfigDir()

	return resolveConfigPathFor(runtime.GOOS, home, configDir, startDir, configFileExists)
}

func defaultConfigPathFor(goos, home, userConfigDir string) string {
	canonicalDir := canonicalConfigDir(goos, home, userConfigDir)
	if canonicalDir != "" {
		return filepath.Join(canonicalDir, ConfigFileName)
	}
	return ConfigFileName
}

func resolveDefaultConfigPathFor(goos, home, userConfigDir string, exists func(string) bool) string {
	if canonicalDir := canonicalConfigDir(goos, home, userConfigDir); canonicalDir != "" {
		for _, name := range configFileNames {
			candidate := filepath.Join(canonicalDir, name)
			if exists(candidate) {
				return candidate
			}
		}
	}

	for _, legacyPath := range legacyConfigPaths(goos, home) {
		if exists(legacyPath) {
			return legacyPath
		}
	}

	return defaultConfigPathFor(goos, home, userConfigDir)
}

func resolveConfigPathFor(goos, home, userConfigDir, startDir string, exists func(string) bool) (string, error) {
	projectPath, err := findNearestProjectConfigPath(startDir, exists)
	if err != nil {
		return "", err
	}
	if projectPath != "" {
		return projectPath, nil
	}

	return resolveDefaultConfigPathFor(goos, home, userConfigDir, exists), nil
}

// canonicalConfigDir returns the directory fence looks in for the user's
// default config, without a filename appended. Returns an empty string when
// neither a home nor OS config dir is available.
func canonicalConfigDir(goos, home, userConfigDir string) string {
	switch {
	case goos == "darwin" && home != "":
		return filepath.Join(home, ".config", "fence")
	case userConfigDir != "":
		return filepath.Join(userConfigDir, "fence")
	case home != "":
		return filepath.Join(home, ".config", "fence")
	default:
		return ""
	}
}

func legacyConfigPaths(goos, home string) []string {
	if home == "" {
		return nil
	}

	// Capacity covers the darwin "Application Support" dir plus the
	// ~/.fence dotfile, each with both .jsonc and .json variants.
	paths := make([]string, 0, 4)
	if goos == "darwin" {
		appSupport := filepath.Join(home, "Library", "Application Support", "fence")
		paths = append(paths,
			filepath.Join(appSupport, "fence.jsonc"),
			filepath.Join(appSupport, "fence.json"),
		)
	}
	return append(paths,
		filepath.Join(home, ".fence.jsonc"),
		filepath.Join(home, ".fence.json"),
	)
}

func configFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func findNearestProjectConfigPath(startDir string, exists func(string) bool) (string, error) {
	if startDir == "" {
		return "", nil
	}

	current := filepath.Clean(startDir)
	if !filepath.IsAbs(current) {
		absPath, err := filepath.Abs(current)
		if err != nil {
			return "", fmt.Errorf("failed to resolve config search path %q: %w", startDir, err)
		}
		current = absPath
	}

	for {
		for _, name := range configFileNames {
			candidate := filepath.Join(current, name)
			if exists(candidate) {
				return candidate, nil
			}
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", nil
		}
		current = parent
	}
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
	for _, port := range c.Network.AllowLocalOutboundPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid network.allowLocalOutboundPorts entry %d (expected 1-65535)", port)
		}
	}
	for _, name := range c.MacOS.Mach.Lookup {
		if err := validateMachServicePattern(name); err != nil {
			return fmt.Errorf("invalid macos.mach.lookup entry %q: %w", name, err)
		}
	}
	for _, name := range c.MacOS.Mach.Register {
		if err := validateMachServicePattern(name); err != nil {
			return fmt.Errorf("invalid macos.mach.register entry %q: %w", name, err)
		}
	}

	// strictDenyRead implies defaultDenyRead
	if c.Filesystem.StrictDenyRead {
		c.Filesystem.DefaultDenyRead = true
	}

	if slices.Contains(c.Filesystem.AllowRead, "") {
		return errors.New("filesystem.allowRead contains empty path")
	}
	if slices.Contains(c.Filesystem.AllowExecute, "") {
		return errors.New("filesystem.allowExecute contains empty path")
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

	switch c.Devices.Mode {
	case "", DeviceModeAuto, DeviceModeMinimal, DeviceModeHost:
	default:
		return fmt.Errorf("invalid devices.mode %q (expected one of: auto, minimal, host)", c.Devices.Mode)
	}
	if slices.Contains(c.Devices.Allow, "") {
		return errors.New("devices.allow contains empty path")
	}
	for _, path := range c.Devices.Allow {
		cleaned := filepath.Clean(path)
		switch {
		case cleaned == "/dev":
			return fmt.Errorf("devices.allow path %q is too broad; use devices.mode %q instead", path, DeviceModeHost)
		case !strings.HasPrefix(cleaned, "/dev/"):
			return fmt.Errorf("devices.allow path %q must be under /dev/", path)
		}
	}

	if slices.Contains(c.Command.Deny, "") {
		return errors.New("command.deny contains empty command")
	}
	if slices.Contains(c.Command.Allow, "") {
		return errors.New("command.allow contains empty command")
	}
	switch c.Command.RuntimeExecPolicy {
	case "", RuntimeExecPolicyPath, RuntimeExecPolicyArgv:
	default:
		return fmt.Errorf("invalid command.runtimeExecPolicy %q (expected one of: path, argv)", c.Command.RuntimeExecPolicy)
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

// EffectiveRuntimeExecPolicy returns the runtime exec policy, defaulting to path.
func (c *CommandConfig) EffectiveRuntimeExecPolicy() RuntimeExecPolicy {
	if c == nil || c.RuntimeExecPolicy == "" {
		return RuntimeExecPolicyPath
	}
	return c.RuntimeExecPolicy
}

func validateDomainPattern(pattern string) error {
	if pattern == "localhost" {
		return nil
	}

	if strings.Contains(pattern, "://") || strings.Contains(pattern, "/") || strings.Contains(pattern, ":") {
		return errors.New("domain pattern cannot contain protocol, path, or port")
	}

	// Handle wildcard patterns
	if pattern == "*" {
		return nil
	}

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

func validateMachServicePattern(pattern string) error {
	if pattern == "" {
		return errors.New("empty Mach service pattern")
	}
	if pattern == "*" {
		return nil
	}

	trimmed := strings.TrimSuffix(pattern, "*")
	if trimmed == "" {
		return errors.New("wildcards are only allowed as a single trailing '*'")
	}
	if strings.Contains(trimmed, "*") {
		return errors.New("wildcards are only allowed as a single trailing '*'")
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
		// Pointer field: override wins if set, otherwise base
		ForceNewSession: mergeOptionalBool(base.ForceNewSession, override.ForceNewSession),

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

			// Append int slices (base first, then override additions), deduped
			AllowLocalOutboundPorts: mergeInts(base.Network.AllowLocalOutboundPorts, override.Network.AllowLocalOutboundPorts),

			// Port fields: override wins if non-zero
			HTTPProxyPort:  mergeInt(base.Network.HTTPProxyPort, override.Network.HTTPProxyPort),
			SOCKSProxyPort: mergeInt(base.Network.SOCKSProxyPort, override.Network.SOCKSProxyPort),
		},

		Filesystem: FilesystemConfig{
			// Boolean fields: true if either enables it
			// strictDenyRead implies defaultDenyRead
			DefaultDenyRead: base.Filesystem.DefaultDenyRead || override.Filesystem.DefaultDenyRead || base.Filesystem.StrictDenyRead || override.Filesystem.StrictDenyRead,
			StrictDenyRead:  base.Filesystem.StrictDenyRead || override.Filesystem.StrictDenyRead,

			// Pointer fields: override wins if set
			WSLInterop: mergeOptionalBool(base.Filesystem.WSLInterop, override.Filesystem.WSLInterop),

			// Append slices
			AllowRead:    mergeStrings(base.Filesystem.AllowRead, override.Filesystem.AllowRead),
			AllowExecute: mergeStrings(base.Filesystem.AllowExecute, override.Filesystem.AllowExecute),
			DenyRead:     mergeStrings(base.Filesystem.DenyRead, override.Filesystem.DenyRead),
			AllowWrite:   mergeStrings(base.Filesystem.AllowWrite, override.Filesystem.AllowWrite),
			DenyWrite:    mergeStrings(base.Filesystem.DenyWrite, override.Filesystem.DenyWrite),

			// Boolean fields: override wins if set
			AllowGitConfig: base.Filesystem.AllowGitConfig || override.Filesystem.AllowGitConfig,
		},

		Devices: DevicesConfig{
			// Mode: override wins if set, otherwise base
			Mode: mergeDeviceMode(base.Devices.Mode, override.Devices.Mode),

			// Append slices
			Allow: mergeStrings(base.Devices.Allow, override.Devices.Allow),
		},

		MacOS: MacOSConfig{
			Mach: MachConfig{
				Lookup:   mergeStrings(base.MacOS.Mach.Lookup, override.MacOS.Mach.Lookup),
				Register: mergeStrings(base.MacOS.Mach.Register, override.MacOS.Mach.Register),
			},
		},

		Command: CommandConfig{
			// Append slices
			Deny:                                mergeStrings(base.Command.Deny, override.Command.Deny),
			Allow:                               mergeStrings(base.Command.Allow, override.Command.Allow),
			AcceptSharedBinaryCannotRuntimeDeny: mergeStrings(base.Command.AcceptSharedBinaryCannotRuntimeDeny, override.Command.AcceptSharedBinaryCannotRuntimeDeny),
			RuntimeExecPolicy:                   mergeRuntimeExecPolicy(base.Command.RuntimeExecPolicy, override.Command.RuntimeExecPolicy),

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

func mergeRuntimeExecPolicy(base, override RuntimeExecPolicy) RuntimeExecPolicy {
	if override != "" {
		return override
	}
	return base
}

// mergeOptionalBool returns override if non-nil, otherwise base.
func mergeOptionalBool(base, override *bool) *bool {
	if override != nil {
		return override
	}
	return base
}

// mergeDeviceMode returns override if non-empty, otherwise base.
func mergeDeviceMode(base, override DeviceMode) DeviceMode {
	if override != "" {
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

// mergeInts appends two int slices, removing duplicates while preserving order.
func mergeInts(base, override []int) []int {
	if len(base) == 0 {
		return override
	}
	if len(override) == 0 {
		return base
	}

	seen := make(map[int]bool, len(base)+len(override))
	result := make([]int, 0, len(base)+len(override))

	for _, v := range base {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	for _, v := range override {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
