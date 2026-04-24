// Package fence provides a public API for sandboxing commands.
package fence

import (
	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/platform"
	"github.com/Use-Tusk/fence/internal/sandbox"
	"github.com/Use-Tusk/fence/internal/templates"
)

// IsSupported returns true if the current platform supports sandboxing (macOS/Linux).
func IsSupported() bool {
	return platform.IsSupported()
}

// Config is the configuration for fence.
type Config = config.Config

// NetworkConfig defines network restrictions.
type NetworkConfig = config.NetworkConfig

// FilesystemConfig defines filesystem restrictions.
type FilesystemConfig = config.FilesystemConfig

// DevicesConfig defines device exposure inside the sandbox.
type DevicesConfig = config.DevicesConfig

// DeviceMode controls how /dev is set up inside Linux sandboxes.
type DeviceMode = config.DeviceMode

const (
	DeviceModeAuto    DeviceMode = config.DeviceModeAuto
	DeviceModeMinimal DeviceMode = config.DeviceModeMinimal
	DeviceModeHost    DeviceMode = config.DeviceModeHost
)

// MacOSConfig defines macOS-specific sandbox controls.
type MacOSConfig = config.MacOSConfig

// MachConfig defines additional Mach/XPC permissions for macOS sandboxes.
type MachConfig = config.MachConfig

// CommandConfig defines command restrictions.
type CommandConfig = config.CommandConfig

// RuntimeExecPolicy controls how Linux runtime child-process execs are enforced.
type RuntimeExecPolicy = config.RuntimeExecPolicy

const (
	RuntimeExecPolicyPath RuntimeExecPolicy = config.RuntimeExecPolicyPath
	RuntimeExecPolicyArgv RuntimeExecPolicy = config.RuntimeExecPolicyArgv
)

// SSHConfig defines SSH command restrictions.
type SSHConfig = config.SSHConfig

// Manager handles sandbox initialization and command wrapping.
type Manager = sandbox.Manager

// ServiceOptions describes the sandboxed service's inbound-connectivity model.
// See Manager.SetService.
type ServiceOptions = sandbox.ServiceOptions

// ServiceExecutionModel selects the port-binding workflow fence should assume
// for the sandboxed service.
type ServiceExecutionModel = sandbox.ServiceExecutionModel

const (
	// ServiceBindsInSandbox indicates the sandboxed process itself binds
	// the exposed port inside the sandbox (default).
	ServiceBindsInSandbox ServiceExecutionModel = sandbox.ServiceBindsInSandbox

	// ServiceBindsOnHost indicates the sandboxed process delegates port
	// binding to an external daemon (docker, podman, systemctl, …) whose
	// listener lives outside the sandbox network namespace.
	ServiceBindsOnHost ServiceExecutionModel = sandbox.ServiceBindsOnHost
)

// NewManager creates a new sandbox manager.
// If debug is true, verbose logging is enabled.
// If monitor is true, only violations (blocked requests) are logged.
func NewManager(cfg *Config, debug, monitor bool) *Manager {
	return sandbox.NewManager(cfg, debug, monitor)
}

// DefaultConfig returns the default configuration with all network blocked.
func DefaultConfig() *Config {
	return config.Default()
}

// LoadConfig loads configuration from a file.
func LoadConfig(path string) (*Config, error) {
	return config.Load(path)
}

// LoadConfigResolved loads configuration from a file and resolves any extends
// entries relative to that file's parent directory.
func LoadConfigResolved(path string) (*Config, error) {
	cfg, err := config.Load(path)
	if err != nil || cfg == nil {
		return cfg, err
	}
	return templates.ResolveExtendsFromPath(cfg, path)
}

// MergeConfigs combines a base config with an override config.
func MergeConfigs(base, override *Config) *Config {
	return config.Merge(base, override)
}

// DefaultConfigPath returns the canonical config path for new configs.
func DefaultConfigPath() string {
	return config.DefaultConfigPath()
}

// ResolveDefaultConfigPath returns the config path fence should load by default.
func ResolveDefaultConfigPath() string {
	return config.ResolveDefaultConfigPath()
}

// ResolveConfigPath returns the config path fence would load when --settings is
// not provided, preferring the nearest project fence.jsonc (or fence.json)
// before the user default config path.
func ResolveConfigPath(startDir string) (string, error) {
	return config.ResolveConfigPath(startDir)
}
