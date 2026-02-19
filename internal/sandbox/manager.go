package sandbox

import (
	"fmt"
	"os"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/platform"
	"github.com/Use-Tusk/fence/internal/proxy"
)

// Manager handles sandbox initialization and command wrapping.
type Manager struct {
	config        *config.Config
	httpProxy     *proxy.HTTPProxy
	socksProxy    *proxy.SOCKSProxy
	linuxBridge   *LinuxBridge
	reverseBridge *ReverseBridge
	httpPort      int
	socksPort     int
	exposedPorts  []int
	shellMode     string
	shellLogin    bool
	debug         bool
	monitor       bool
	initialized   bool
}

// NewManager creates a new sandbox manager.
func NewManager(cfg *config.Config, debug, monitor bool) *Manager {
	return &Manager{
		config:    cfg,
		shellMode: ShellModeDefault,
		debug:     debug,
		monitor:   monitor,
	}
}

// SetExposedPorts sets the ports to expose for inbound connections.
func (m *Manager) SetExposedPorts(ports []int) {
	m.exposedPorts = ports
}

// SetShellOptions sets shell selection options for command execution.
func (m *Manager) SetShellOptions(mode string, login bool) {
	if mode == "" {
		mode = ShellModeDefault
	}
	m.shellMode = mode
	m.shellLogin = login
}

// Initialize sets up the sandbox infrastructure (proxies, etc.).
func (m *Manager) Initialize() error {
	if m.initialized {
		return nil
	}

	if !platform.IsSupported() {
		return fmt.Errorf("sandbox is not supported on platform: %s", platform.Detect())
	}

	filter := proxy.CreateDomainFilter(m.config, m.debug)

	m.httpProxy = proxy.NewHTTPProxy(filter, m.debug, m.monitor)
	httpPort, err := m.httpProxy.Start()
	if err != nil {
		return fmt.Errorf("failed to start HTTP proxy: %w", err)
	}
	m.httpPort = httpPort

	m.socksProxy = proxy.NewSOCKSProxy(filter, m.debug, m.monitor)
	socksPort, err := m.socksProxy.Start()
	if err != nil {
		_ = m.httpProxy.Stop()
		return fmt.Errorf("failed to start SOCKS proxy: %w", err)
	}
	m.socksPort = socksPort

	// On Linux, set up the socat bridges
	if platform.Detect() == platform.Linux {
		bridge, err := NewLinuxBridge(m.httpPort, m.socksPort, m.debug)
		if err != nil {
			_ = m.httpProxy.Stop()
			_ = m.socksProxy.Stop()
			return fmt.Errorf("failed to initialize Linux bridge: %w", err)
		}
		m.linuxBridge = bridge

		// Set up reverse bridge for exposed ports (inbound connections)
		// Only needed when network namespace is available - otherwise they share the network
		features := DetectLinuxFeatures()
		if len(m.exposedPorts) > 0 && features.CanUnshareNet {
			reverseBridge, err := NewReverseBridge(m.exposedPorts, m.debug)
			if err != nil {
				m.linuxBridge.Cleanup()
				_ = m.httpProxy.Stop()
				_ = m.socksProxy.Stop()
				return fmt.Errorf("failed to initialize reverse bridge: %w", err)
			}
			m.reverseBridge = reverseBridge
		} else if len(m.exposedPorts) > 0 && m.debug {
			m.logDebug("Skipping reverse bridge (no network namespace, ports accessible directly)")
		}
	}

	m.initialized = true
	m.logDebug("Sandbox manager initialized (HTTP proxy: %d, SOCKS proxy: %d)", m.httpPort, m.socksPort)
	return nil
}

// WrapCommand wraps a command with sandbox restrictions.
// Returns an error if the command is blocked by policy.
func (m *Manager) WrapCommand(command string) (string, error) {
	if !m.initialized {
		if err := m.Initialize(); err != nil {
			return "", err
		}
	}

	// Check if command is blocked by policy
	if err := CheckCommand(command, m.config); err != nil {
		return "", err
	}

	plat := platform.Detect()
	switch plat {
	case platform.MacOS:
		return WrapCommandMacOS(m.config, command, m.httpPort, m.socksPort, m.exposedPorts, m.debug, m.shellMode, m.shellLogin)
	case platform.Linux:
		return WrapCommandLinuxWithShell(m.config, command, m.linuxBridge, m.reverseBridge, m.debug, m.shellMode, m.shellLogin)
	default:
		return "", fmt.Errorf("unsupported platform: %s", plat)
	}
}

// Cleanup stops the proxies and cleans up resources.
func (m *Manager) Cleanup() {
	if m.reverseBridge != nil {
		m.reverseBridge.Cleanup()
	}
	if m.linuxBridge != nil {
		m.linuxBridge.Cleanup()
	}
	if m.httpProxy != nil {
		_ = m.httpProxy.Stop()
	}
	if m.socksProxy != nil {
		_ = m.socksProxy.Stop()
	}
	m.logDebug("Sandbox manager cleaned up")
}

func (m *Manager) logDebug(format string, args ...interface{}) {
	if m.debug {
		fmt.Fprintf(os.Stderr, "[fence] "+format+"\n", args...)
	}
}

// HTTPPort returns the HTTP proxy port.
func (m *Manager) HTTPPort() int {
	return m.httpPort
}

// SOCKSPort returns the SOCKS proxy port.
func (m *Manager) SOCKSPort() int {
	return m.socksPort
}
