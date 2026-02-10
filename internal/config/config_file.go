package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// FileWriteOptions controls config file formatting behavior.
type FileWriteOptions struct {
	// HeaderLines are written above the JSON content (one line per entry).
	// Lines are written as provided; callers can include comment prefixes.
	HeaderLines []string
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
func MarshalConfigJSON(cfg *Config) ([]byte, error) {
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

// FormatConfigForFile returns config JSON with optional header lines.
func FormatConfigForFile(cfg *Config, opts FileWriteOptions) (string, error) {
	data, err := MarshalConfigJSON(cfg)
	if err != nil {
		return "", err
	}

	var output strings.Builder
	for _, line := range opts.HeaderLines {
		output.WriteString(line)
		output.WriteByte('\n')
	}
	output.Write(data)
	output.WriteByte('\n')

	return output.String(), nil
}

// WriteConfigFile writes a fence config to a file with optional header lines.
func WriteConfigFile(cfg *Config, path string, opts FileWriteOptions) error {
	output, err := FormatConfigForFile(cfg, opts)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, []byte(output), 0o600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
