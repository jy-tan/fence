package sandbox

import (
	"fmt"

	"github.com/fencesandbox/fence/internal/config"
	"github.com/fencesandbox/fence/internal/fencelog"
	"github.com/fencesandbox/fence/internal/platform"
	"github.com/fencesandbox/fence/internal/proxy"
)

// ServiceExecutionModel describes how a sandboxed service binds its host-facing
// listening port. Fence uses this to decide whether to set up a reverse bridge
// that proxies external traffic into the sandbox network namespace.
type ServiceExecutionModel int

const (
	// ServiceBindsInSandbox means the sandboxed process itself binds the
	// exposed port inside the sandbox (typical of a plain `node server.js`,
	// `python manage.py runserver`, `./bin/server`, etc.). When --unshare-net
	// is active, fence must stand up a reverse socat bridge on the host to
	// forward inbound traffic into the sandbox netns.
	ServiceBindsInSandbox ServiceExecutionModel = iota

	// ServiceBindsOnHost means the sandboxed process delegates port binding
	// to an external daemon whose listener lives outside the sandbox's
	// network namespace (e.g. `docker compose up` → dockerd, `podman run`,
	// `systemctl start …`). The daemon binds the host port directly via its
	// own network stack and routes traffic to the container — fence should
	// NOT create a reverse bridge because (a) it would collide with the
	// daemon's bind on the same port, and (b) traffic doesn't need to enter
	// the sandbox netns at all; it reaches the container via the daemon's
	// iptables / CNI plumbing.
	ServiceBindsOnHost
)

// ExposedPort is a single host-facing port exposure. BindAddress is the host
// interface the reverse-bridge listener binds on (empty defaults to 127.0.0.1);
// pass "0.0.0.0" or "::" to opt into LAN exposure. macOS has no reverse bridge
// and ignores BindAddress.
type ExposedPort struct {
	BindAddress string
	Port        int
}

// DefaultExposedBindAddress is the host interface used when an ExposedPort has
// no BindAddress. Loopback-only avoids accidental LAN exposure and matches
// WSL2's automatic localhost forwarding to Windows.
const DefaultExposedBindAddress = "127.0.0.1"

// LoopbackPort is a constructor for the common case: expose a port on the
// host loopback interface. Equivalent to ExposedPort{Port: port} since an
// empty BindAddress defaults to DefaultExposedBindAddress.
func LoopbackPort(port int) ExposedPort {
	return ExposedPort{BindAddress: DefaultExposedBindAddress, Port: port}
}

// ServiceOptions describes the sandboxed service for inbound-connection setup.
// Callers pass this via Manager.SetService before Initialize.
type ServiceOptions struct {
	// Exposures lists host-facing port bindings. Empty BindAddress fields
	// default to DefaultExposedBindAddress (127.0.0.1).
	Exposures []ExposedPort

	// ExecutionModel selects the port-binding workflow fence should assume.
	// Defaults to ServiceBindsInSandbox (the historical behavior).
	ExecutionModel ServiceExecutionModel
}

// resolvedExposures returns Exposures with empty BindAddress fields filled in.
// Duplicates are preserved.
func (s ServiceOptions) resolvedExposures() []ExposedPort {
	if len(s.Exposures) == 0 {
		return nil
	}
	out := make([]ExposedPort, len(s.Exposures))
	for i, e := range s.Exposures {
		if e.BindAddress == "" {
			e.BindAddress = DefaultExposedBindAddress
		}
		out[i] = e
	}
	return out
}

// resolvedPorts returns just the port numbers from resolvedExposures, in the
// same order. macOS uses this (no reverse bridge, bind address ignored).
func (s ServiceOptions) resolvedPorts() []int {
	if len(s.Exposures) == 0 {
		return nil
	}
	out := make([]int, len(s.Exposures))
	for i, e := range s.Exposures {
		out[i] = e.Port
	}
	return out
}

// Manager handles sandbox initialization and command wrapping.
type Manager struct {
	config              *config.Config
	httpProxy           *proxy.HTTPProxy
	socksProxy          *proxy.SOCKSProxy
	linuxBridge         *LinuxBridge
	reverseBridge       *ReverseBridge
	localOutboundBridge *LocalOutboundBridge
	httpPort            int
	socksPort           int
	service             ServiceOptions
	exposedHostPaths    []exposedHostPath
	shellMode           string
	shellLogin          bool
	debug               bool
	monitor             bool
	initialized         bool
}

// exposedHostPath records a host path that should be visible inside the
// sandbox at the same path. See Manager.ExposeHostPath.
type exposedHostPath struct {
	path     string
	writable bool
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

// SetService configures the sandboxed service's inbound-connectivity model.
// Must be called before Initialize.
func (m *Manager) SetService(opts ServiceOptions) {
	m.service = opts
}

// ExposeHostPath registers a host file or directory that must be visible
// inside the sandbox at the same path. Callers use this to hand over paths
// that the sandboxed process needs to read (or write, with writable=true)
// without having to reason about fence's internal mount plan — in particular,
// without having to know which host directories are tmpfs-overmounted by the
// sandbox (e.g. /tmp) or which cross-mount paths would otherwise be invisible.
//
// Must be called before WrapCommand. The path must exist at call time.
//
// Implementation notes:
//   - On Linux, the path is bound via bwrap's --ro-bind / --bind after all
//     tmpfs overmounts have been emitted, so a path under a fence-overmounted
//     directory (e.g. /tmp/foo) reappears inside the sandbox.
//   - On macOS, the path is added to the seatbelt profile's file-read / file-write
//     allowlist.
//   - On unsupported platforms, the call is recorded but has no effect.
func (m *Manager) ExposeHostPath(path string, writable bool) error {
	if path == "" {
		return fmt.Errorf("ExposeHostPath: empty path")
	}
	m.exposedHostPaths = append(m.exposedHostPaths, exposedHostPath{
		path:     path,
		writable: writable,
	})
	return nil
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

	route := proxy.CreateRouteFunc(m.config, m.debug)
	upstreamURL := proxy.ParseUpstreamProxyURL(m.config)
	m.httpProxy = proxy.NewHTTPProxy(route, upstreamURL, m.debug, m.monitor)
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

		// Set up reverse bridge for exposed ports (inbound connections).
		// Only needed when:
		//   (a) a network namespace is available (otherwise host & sandbox
		//       share the netns and external traffic reaches listeners directly), and
		//   (b) the service binds its port INSIDE the sandbox. For
		//       ServiceBindsOnHost (docker, podman, …), the port is bound by
		//       an external daemon outside the netns; a reverse bridge on the
		//       same port would collide with the daemon's bind.
		features := DetectLinuxFeatures()
		exposures := m.service.resolvedExposures()
		switch {
		case len(exposures) == 0:
			// nothing to do
		case m.service.ExecutionModel == ServiceBindsOnHost:
			if m.debug {
				m.logDebug("Skipping reverse bridge (ServiceBindsOnHost: external daemon binds ports %v outside sandbox netns)", m.service.resolvedPorts())
			}
		case !features.CanUnshareNet:
			if m.debug {
				m.logDebug("Skipping reverse bridge (no network namespace, ports accessible directly)")
			}
		default:
			reverseBridge, err := NewReverseBridge(exposures, m.debug)
			if err != nil {
				m.linuxBridge.Cleanup()
				_ = m.httpProxy.Stop()
				_ = m.socksProxy.Stop()
				return fmt.Errorf("failed to initialize reverse bridge: %w", err)
			}
			m.reverseBridge = reverseBridge
		}

		// Set up the localhost-outbound bridge when the user opted into
		// host-loopback access. The bridge is only meaningful when we also
		// unshare the network namespace (otherwise sandbox 127.0.0.1 already
		// is the host's 127.0.0.1 and no forwarding is needed). Wildcard
		// relaxed mode drops --unshare-net too, so skip there.
		if m.config != nil && m.config.Network.EffectiveAllowLocalOutbound() && features.CanUnshareNet && !hasWildcardAllowedDomain(m.config) {
			ports := m.config.Network.AllowLocalOutboundPorts
			if len(ports) > 0 {
				loBridge, err := NewLocalOutboundBridge(ports, m.debug)
				if err != nil {
					if m.reverseBridge != nil {
						m.reverseBridge.Cleanup()
					}
					m.linuxBridge.Cleanup()
					_ = m.httpProxy.Stop()
					_ = m.socksProxy.Stop()
					return fmt.Errorf("failed to initialize localhost-outbound bridge: %w", err)
				}
				m.localOutboundBridge = loBridge
			} else {
				// Surface the Linux-specific limitation once at startup so
				// users do not silently get the pre-fix broken behavior.
				fencelog.Printf(
					"[fence] network.allowLocalOutbound=true on Linux requires network.allowLocalOutboundPorts to list the host loopback ports to bridge (e.g. [5432, 6379]). Without it, sandbox connections to 127.0.0.1 stay isolated inside the sandbox network namespace.\n",
				)
			}
		}
	}

	m.initialized = true
	m.logDebug("Sandbox manager initialized (HTTP proxy: %d, SOCKS proxy: %d)", m.httpPort, m.socksPort)
	return nil
}

// WrapCommand wraps a command with sandbox restrictions.
// Returns an error if the command is blocked by policy.
func (m *Manager) WrapCommand(command string) (string, error) {
	return m.WrapCommandInDir(command, "")
}

// WrapCommandInDir wraps a command with sandbox restrictions using the given
// working directory as the workspace root for mandatory path protection.
func (m *Manager) WrapCommandInDir(command string, workingDir string) (string, error) {
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
	if effectiveRuntimeExecPolicy(m.config) == config.RuntimeExecPolicyArgv && plat != platform.Linux {
		return "", fmt.Errorf("command.runtimeExecPolicy=%q is only supported on Linux", config.RuntimeExecPolicyArgv)
	}

	workingDir = ResolveSandboxWorkingDir(workingDir)
	switch plat {
	case platform.MacOS:
		return WrapCommandMacOS(m.config, command, workingDir, m.httpPort, m.socksPort, m.service.resolvedPorts(), m.exposedHostPaths, m.debug, m.shellMode, m.shellLogin)
	case platform.Linux:
		return WrapCommandLinuxWithOptions(m.config, command, m.linuxBridge, m.reverseBridge, LinuxSandboxOptions{
			UseLandlock:         true,
			UseSeccomp:          true,
			UseEBPF:             true,
			Monitor:             m.monitor,
			Debug:               m.debug,
			ShellMode:           m.shellMode,
			ShellLogin:          m.shellLogin,
			WorkDir:             workingDir,
			LocalOutboundBridge: m.localOutboundBridge,
			ExposedHostPaths:    m.exposedHostPaths,
		})
	default:
		return "", fmt.Errorf("unsupported platform: %s", plat)
	}
}

// Cleanup stops the proxies and cleans up resources.
func (m *Manager) Cleanup() {
	if m.localOutboundBridge != nil {
		m.localOutboundBridge.Cleanup()
	}
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
		fencelog.Printf("[fence] "+format+"\n", args...)
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
