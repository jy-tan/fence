//go:build !linux

package sandbox

import (
	"fmt"

	"github.com/Use-Tusk/fence/internal/config"
)

// LinuxBridge is a stub for non-Linux platforms.
type LinuxBridge struct {
	HTTPSocketPath  string
	SOCKSSocketPath string
}

// ReverseBridge is a stub for non-Linux platforms.
type ReverseBridge struct {
	Ports       []int
	SocketPaths []string
}

// LocalOutboundBridge is a stub for non-Linux platforms.
type LocalOutboundBridge struct {
	Ports       []int
	SocketPaths []string
}

// LinuxSandboxOptions is a stub for non-Linux platforms.
type LinuxSandboxOptions struct {
	UseLandlock              bool
	UseSeccomp               bool
	UseEBPF                  bool
	Monitor                  bool
	Debug                    bool
	ShellMode                string
	ShellLogin               bool
	WorkDir                  string
	LocalOutboundBridge      *LocalOutboundBridge
	ExposedHostPaths         []exposedHostPath
	UseLinuxBootstrap        bool
	ShellBasedLinuxBootstrap bool
}

// NewLinuxBridge returns an error on non-Linux platforms.
func NewLinuxBridge(httpProxyPort, socksProxyPort int, debug bool) (*LinuxBridge, error) {
	return nil, fmt.Errorf("Linux bridge not available on this platform")
}

// Cleanup is a no-op on non-Linux platforms.
func (b *LinuxBridge) Cleanup() {}

// NewReverseBridge returns an error on non-Linux platforms.
func NewReverseBridge(ports []int, debug bool) (*ReverseBridge, error) {
	return nil, fmt.Errorf("reverse bridge not available on this platform")
}

// Cleanup is a no-op on non-Linux platforms.
func (b *ReverseBridge) Cleanup() {}

// NewLocalOutboundBridge returns an error on non-Linux platforms.
// The localhost-outbound bridge exists to relay sandbox loopback to host
// loopback across --unshare-net; macOS Seatbelt handles localhost access
// declaratively and never invokes this path.
func NewLocalOutboundBridge(ports []int, debug bool) (*LocalOutboundBridge, error) {
	return nil, fmt.Errorf("local outbound bridge not available on this platform")
}

// Cleanup is a no-op on non-Linux platforms.
func (b *LocalOutboundBridge) Cleanup() {}

// WrapCommandLinux returns an error on non-Linux platforms.
func WrapCommandLinux(cfg *config.Config, command string, bridge *LinuxBridge, reverseBridge *ReverseBridge, debug bool) (string, error) {
	return "", fmt.Errorf("Linux sandbox not available on this platform")
}

// WrapCommandLinuxWithShell returns an error on non-Linux platforms.
func WrapCommandLinuxWithShell(cfg *config.Config, command string, workingDir string, bridge *LinuxBridge, reverseBridge *ReverseBridge, debug bool, shellMode string, shellLogin bool, shellBasedLinuxBootstrap bool) (string, error) {
	return "", fmt.Errorf("Linux sandbox not available on this platform")
}

// WrapCommandLinuxWithOptions returns an error on non-Linux platforms.
func WrapCommandLinuxWithOptions(cfg *config.Config, command string, bridge *LinuxBridge, reverseBridge *ReverseBridge, opts LinuxSandboxOptions) (string, error) {
	return "", fmt.Errorf("Linux sandbox not available on this platform")
}

// StartLinuxMonitor returns nil on non-Linux platforms.
func StartLinuxMonitor(pid int, opts LinuxSandboxOptions) (*LinuxMonitors, error) {
	return nil, nil
}

// LinuxMonitors is a stub for non-Linux platforms.
type LinuxMonitors struct{}

// Stop is a no-op on non-Linux platforms.
func (m *LinuxMonitors) Stop() {}

// PrintLinuxFeatures prints a message on non-Linux platforms.
func PrintLinuxFeatures() {
	fmt.Println("Linux sandbox features are only available on Linux.")
}
