//go:build linux

package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/fencelog"
	"golang.org/x/term"
)

// LinuxBridge holds the socat bridge processes for Linux sandboxing (outbound).
type LinuxBridge struct {
	HTTPSocketPath  string
	SOCKSSocketPath string
	httpProcess     *exec.Cmd
	socksProcess    *exec.Cmd
	debug           bool
}

// ReverseBridge holds the socat bridge processes for inbound connections.
type ReverseBridge struct {
	Ports       []int
	SocketPaths []string // Unix socket paths for each port
	processes   []*exec.Cmd
	debug       bool
}

// LocalOutboundBridge forwards sandbox-loopback connections to host-loopback
// on a fixed list of TCP ports. It exists because Fence runs the Linux sandbox
// with --unshare-net, which isolates loopback: sandbox 127.0.0.1 is not the
// host's 127.0.0.1. This bridge lets the user opt specific host services
// (Redis, Postgres, local dev servers) into the sandbox without giving up
// external network isolation.
//
// The pattern mirrors LinuxBridge / ReverseBridge: host-side socat listens on
// a bind-mounted Unix socket and forwards to host 127.0.0.1:<port>, and the
// sandbox-side socat (started inside the sandbox bootstrap) listens on
// 127.0.0.1:<port> and forwards to the shared socket. It is only activated
// when network.allowLocalOutbound is true AND the user has listed the ports
// in network.allowLocalOutboundPorts.
type LocalOutboundBridge struct {
	Ports       []int
	SocketPaths []string
	processes   []*exec.Cmd
	debug       bool
}

// LinuxSandboxOptions contains options for the Linux sandbox.
type LinuxSandboxOptions struct {
	// Enable Landlock filesystem restrictions (requires kernel 5.13+)
	UseLandlock bool
	// Enable seccomp syscall filtering
	UseSeccomp bool
	// Enable eBPF monitoring (requires CAP_BPF or root)
	UseEBPF bool
	// Enable violation monitoring
	Monitor bool
	// Debug mode
	Debug bool
	// Shell selection mode (default|user)
	ShellMode string
	// Whether to run shell as login shell.
	ShellLogin bool
	// Working directory the sandbox policy should treat as the workspace root.
	WorkDir string
	// Optional host-side forwarder for host-loopback access when
	// network.allowLocalOutbound is true. When non-nil, the sandbox bootstrap
	// brings up matching sandbox-side socat listeners bound to 127.0.0.1
	// on each of the bridge's ports.
	LocalOutboundBridge *LocalOutboundBridge
	// ExposedHostPaths lists host files/directories the caller has explicitly
	// registered (via Manager.ExposeHostPath) to be visible inside the
	// sandbox at the same path. These bind mounts are emitted after all
	// tmpfs overmounts, so a path under a fence-overmounted directory
	// (e.g. /tmp/foo) remains visible.
	ExposedHostPaths []exposedHostPath
	// Use Go-based linux-bootstrap wrapper instead of shell script
	UseLinuxBootstrap bool
	// Development-only: force shell script bootstrap even when UseLinuxBootstrap is true
	ShellBasedLinuxBootstrap bool
}

const (
	linuxBootstrapDir       = "/tmp/fence"
	linuxBootstrapBinDir    = linuxBootstrapDir + "/bin"
	linuxBootstrapShellPath = linuxBootstrapBinDir + "/shell"
	linuxBootstrapFencePath = linuxBootstrapBinDir + "/fence"
	linuxBootstrapSocatPath = linuxBootstrapBinDir + "/socat"
	linuxBootstrapInputPath = linuxBootstrapDir + "/bootstrap.stdin"
	linuxBootstrapLogPath   = linuxBootstrapDir + "/bootstrap.log"
)

type linuxBootstrapExecutables struct {
	Shell string
	Fence string
	Socat string
}

type linuxBootstrapExecutableMount struct {
	Source      string
	Destination string
}

// linuxMinimalCoreDevicePaths are rebound from the outer environment when we
// ask Bubblewrap to create a fresh /dev. Intentionally exclude /dev/ptmx:
// Bubblewrap wires that up to the sandbox's devpts instance, and rebinding the
// host path on top breaks PTY allocation (openpty()/node-pty).
var linuxMinimalCoreDevicePaths = []string{
	"/dev/null",
	"/dev/zero",
	"/dev/full",
	"/dev/random",
	"/dev/urandom",
	"/dev/tty",
}

// linuxDefaultCrossMountReadablePaths are the default read-only locations that
// still need explicit binds when they live on separate mount points and the
// sandbox rebuilds portions of the filesystem tree (for example, `/home`) to
// expose allowlisted writable paths. Keep special mounts like /dev, /proc,
// /run, and /tmp out of this list so the sandbox's dedicated mount setup
// continues to control them.
func linuxDefaultCrossMountReadablePaths() []string {
	home, _ := os.UserHomeDir()

	paths := []string{
		"/usr/local",
		"/opt",
		"/nix",
		"/snap",
	}

	return append(paths, getDefaultUserToolingPaths(home)...)
}

// NewLinuxBridge creates Unix socket bridges to the proxy servers.
// This allows sandboxed processes to communicate with the host's proxy (outbound).
func NewLinuxBridge(httpProxyPort, socksProxyPort int, debug bool) (*LinuxBridge, error) {
	if _, err := exec.LookPath("socat"); err != nil {
		return nil, fmt.Errorf("socat is required on Linux but not found: %w", err)
	}

	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("failed to generate socket ID: %w", err)
	}
	socketID := hex.EncodeToString(id)

	tmpDir := os.TempDir()
	httpSocketPath := filepath.Join(tmpDir, fmt.Sprintf("fence-http-%s.sock", socketID))
	socksSocketPath := filepath.Join(tmpDir, fmt.Sprintf("fence-socks-%s.sock", socketID))

	bridge := &LinuxBridge{
		HTTPSocketPath:  httpSocketPath,
		SOCKSSocketPath: socksSocketPath,
		debug:           debug,
	}

	// Start HTTP bridge: Unix socket -> TCP proxy
	httpArgs := []string{
		fmt.Sprintf("UNIX-LISTEN:%s,fork,reuseaddr", httpSocketPath),
		fmt.Sprintf("TCP:localhost:%d", httpProxyPort),
	}
	bridge.httpProcess = exec.Command("socat", httpArgs...) //nolint:gosec // args constructed from trusted input
	if debug {
		fencelog.Printf("[fence:linux] Starting HTTP bridge: socat %s\n", strings.Join(httpArgs, " "))
	}
	if err := bridge.httpProcess.Start(); err != nil {
		return nil, fmt.Errorf("failed to start HTTP bridge: %w", err)
	}

	// Start SOCKS bridge: Unix socket -> TCP proxy
	socksArgs := []string{
		fmt.Sprintf("UNIX-LISTEN:%s,fork,reuseaddr", socksSocketPath),
		fmt.Sprintf("TCP:localhost:%d", socksProxyPort),
	}
	bridge.socksProcess = exec.Command("socat", socksArgs...) //nolint:gosec // args constructed from trusted input
	if debug {
		fencelog.Printf("[fence:linux] Starting SOCKS bridge: socat %s\n", strings.Join(socksArgs, " "))
	}
	if err := bridge.socksProcess.Start(); err != nil {
		bridge.Cleanup()
		return nil, fmt.Errorf("failed to start SOCKS bridge: %w", err)
	}

	// Wait for sockets to be created, up to 5 seconds
	for range 50 {
		httpExists := fileExists(httpSocketPath)
		socksExists := fileExists(socksSocketPath)
		if httpExists && socksExists {
			if debug {
				fencelog.Printf("[fence:linux] Bridges ready (HTTP: %s, SOCKS: %s)\n", httpSocketPath, socksSocketPath)
			}
			return bridge, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	bridge.Cleanup()
	return nil, fmt.Errorf("timeout waiting for bridge sockets to be created")
}

// Cleanup stops the bridge processes and removes socket files.
func (b *LinuxBridge) Cleanup() {
	if b.httpProcess != nil && b.httpProcess.Process != nil {
		_ = b.httpProcess.Process.Kill()
		_ = b.httpProcess.Wait()
	}
	if b.socksProcess != nil && b.socksProcess.Process != nil {
		_ = b.socksProcess.Process.Kill()
		_ = b.socksProcess.Wait()
	}

	// Clean up socket files
	_ = os.Remove(b.HTTPSocketPath)
	_ = os.Remove(b.SOCKSSocketPath)

	if b.debug {
		fencelog.Printf("[fence:linux] Bridges cleaned up\n")
	}
}

// NewReverseBridge creates Unix socket bridges for inbound connections.
// Host listens on ports, forwards to Unix sockets that go into the sandbox.
func NewReverseBridge(ports []int, debug bool) (*ReverseBridge, error) {
	if len(ports) == 0 {
		return nil, nil
	}

	if _, err := exec.LookPath("socat"); err != nil {
		return nil, fmt.Errorf("socat is required on Linux but not found: %w", err)
	}

	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("failed to generate socket ID: %w", err)
	}
	socketID := hex.EncodeToString(id)

	tmpDir := os.TempDir()
	bridge := &ReverseBridge{
		Ports: ports,
		debug: debug,
	}

	for _, port := range ports {
		socketPath := filepath.Join(tmpDir, fmt.Sprintf("fence-rev-%d-%s.sock", port, socketID))
		bridge.SocketPaths = append(bridge.SocketPaths, socketPath)

		// Start reverse bridge: TCP listen on host port -> Unix socket
		// The sandbox will create the Unix socket with UNIX-LISTEN
		// We use retry to wait for the socket to be created by the sandbox
		args := []string{
			fmt.Sprintf("TCP-LISTEN:%d,fork,reuseaddr", port),
			fmt.Sprintf("UNIX-CONNECT:%s,retry=50,interval=0.1", socketPath),
		}
		proc := exec.Command("socat", args...) //nolint:gosec // args constructed from trusted input
		if debug {
			fencelog.Printf("[fence:linux] Starting reverse bridge for port %d: socat %s\n", port, strings.Join(args, " "))
		}
		if err := proc.Start(); err != nil {
			bridge.Cleanup()
			return nil, fmt.Errorf("failed to start reverse bridge for port %d: %w", port, err)
		}
		bridge.processes = append(bridge.processes, proc)
	}

	if debug {
		fencelog.Printf("[fence:linux] Reverse bridges ready for ports: %v\n", ports)
	}

	return bridge, nil
}

// Cleanup stops the reverse bridge processes and removes socket files.
func (b *ReverseBridge) Cleanup() {
	for _, proc := range b.processes {
		if proc != nil && proc.Process != nil {
			_ = proc.Process.Kill()
			_ = proc.Wait()
		}
	}

	// Clean up socket files
	for _, socketPath := range b.SocketPaths {
		_ = os.Remove(socketPath)
	}

	if b.debug {
		fencelog.Printf("[fence:linux] Reverse bridges cleaned up\n")
	}
}

// NewLocalOutboundBridge starts host-side socat forwarders that relay
// connections arriving on per-port Unix sockets to host 127.0.0.1:<port>.
// The matching sandbox-side socat listeners (which bind sandbox 127.0.0.1
// and connect into these sockets) are started by the sandbox bootstrap
// script. Returns nil if the port list is empty.
func NewLocalOutboundBridge(ports []int, debug bool) (*LocalOutboundBridge, error) {
	if len(ports) == 0 {
		return nil, nil
	}

	if _, err := exec.LookPath("socat"); err != nil {
		return nil, fmt.Errorf("socat is required on Linux but not found: %w", err)
	}

	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("failed to generate socket ID: %w", err)
	}
	socketID := hex.EncodeToString(id)

	tmpDir := os.TempDir()
	bridge := &LocalOutboundBridge{
		Ports: ports,
		debug: debug,
	}

	for _, port := range ports {
		socketPath := filepath.Join(tmpDir, fmt.Sprintf("fence-lo-%d-%s.sock", port, socketID))
		// Socket must not exist yet (socat UNIX-LISTEN refuses to overwrite).
		_ = os.Remove(socketPath)
		bridge.SocketPaths = append(bridge.SocketPaths, socketPath)

		// Host side: listen on the shared Unix socket, forward to host loopback.
		// Use mode=0600 to keep the bridge restricted to the sandbox owner.
		args := []string{
			fmt.Sprintf("UNIX-LISTEN:%s,fork,reuseaddr,mode=0600", socketPath),
			fmt.Sprintf("TCP:127.0.0.1:%d", port),
		}
		proc := exec.Command("socat", args...) //nolint:gosec // args constructed from trusted input
		if debug {
			fencelog.Printf("[fence:linux] Starting localhost-outbound bridge for port %d: socat %s\n", port, strings.Join(args, " "))
		}
		if err := proc.Start(); err != nil {
			bridge.Cleanup()
			return nil, fmt.Errorf("failed to start localhost-outbound bridge for port %d: %w", port, err)
		}
		bridge.processes = append(bridge.processes, proc)
	}

	// Wait briefly for all Unix sockets to appear so the sandbox side can bind
	// into them unconditionally. Matches the LinuxBridge 5s cap.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		allReady := true
		for _, p := range bridge.SocketPaths {
			if !fileExists(p) {
				allReady = false
				break
			}
		}
		if allReady {
			if debug {
				fencelog.Printf("[fence:linux] Localhost-outbound bridges ready for ports: %v\n", ports)
			}
			return bridge, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	bridge.Cleanup()
	return nil, fmt.Errorf("timeout waiting for localhost-outbound bridge sockets to be created")
}

// Cleanup stops the local-outbound bridge processes and removes socket files.
func (b *LocalOutboundBridge) Cleanup() {
	if b == nil {
		return
	}
	for _, proc := range b.processes {
		if proc != nil && proc.Process != nil {
			_ = proc.Process.Kill()
			_ = proc.Wait()
		}
	}
	for _, socketPath := range b.SocketPaths {
		_ = os.Remove(socketPath)
	}
	if b.debug {
		fencelog.Printf("[fence:linux] Localhost-outbound bridges cleaned up\n")
	}
}

func appendLinuxDevicePassthrough(bwrapArgs []string, path string, bound map[string]bool, debug bool, reason string) []string {
	normalized := filepath.Clean(path)
	if bound[normalized] {
		return bwrapArgs
	}
	if fileExists(normalized) {
		bound[normalized] = true
		return append(bwrapArgs, "--dev-bind", normalized, normalized)
	}
	if debug {
		fencelog.Printf("[fence:linux] Skipping missing %s device passthrough: %s\n", reason, normalized)
	}
	return bwrapArgs
}

func insertLinuxArgsBeforeSpecialMounts(args []string, insert []string) []string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--dev" || args[i] == "--proc" ||
			(args[i] == "--dev-bind" && i+2 < len(args) && args[i+1] == "/dev" && args[i+2] == "/dev") {
			updated := make([]string, 0, len(args)+len(insert))
			updated = append(updated, args[:i]...)
			updated = append(updated, insert...)
			updated = append(updated, args[i:]...)
			return updated
		}
	}
	return append(args, insert...)
}

// isDirectory returns true if the path exists and is a directory.
func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// isSymlink returns true if the path is a symbolic link.
func isSymlink(path string) bool {
	info, err := os.Lstat(path) // Lstat doesn't follow symlinks
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSymlink != 0
}

// resolvePathForMount canonicalizes a path before mounting over it.
// bubblewrap can fail when destination paths include symlink components
// (common on usr-merged distros, e.g. /bin -> /usr/bin), so always prefer the
// fully-resolved path.
func resolvePathForMount(path string) (string, bool) {
	if !fileExists(path) {
		return "", false
	}
	// Resolve full path even when only an ancestor is a symlink.
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil && resolved != "" && fileExists(resolved) {
		return resolved, true
	}
	// If canonicalization fails for a symlink path, skip mounting that entry
	// instead of risking a hard bwrap startup failure.
	if isSymlink(path) {
		return "", false
	}
	// Fall back for non-symlink paths where EvalSymlinks can fail due to
	// transient lookup errors.
	return path, true
}

// sameDevice returns true if both paths reside on the same filesystem (device).
func sameDevice(path1, path2 string) bool {
	var s1, s2 syscall.Stat_t
	if syscall.Stat(path1, &s1) != nil || syscall.Stat(path2, &s2) != nil {
		return true // err on the side of caution
	}
	return s1.Dev == s2.Dev
}

// intermediaryDirs returns the chain of directories between root and targetDir,
// from shallowest to deepest. Used to create --dir entries so bwrap can set up
// mount points inside otherwise-empty mount-point stubs.
//
// Example: intermediaryDirs("/", "/run/systemd/resolve") ->
//
//	["/run", "/run/systemd", "/run/systemd/resolve"]
func intermediaryDirs(root, targetDir string) []string {
	rel, err := filepath.Rel(root, targetDir)
	if err != nil {
		return []string{targetDir}
	}
	parts := strings.Split(rel, string(filepath.Separator))
	dirs := make([]string, 0, len(parts))
	current := root
	for _, part := range parts {
		current = filepath.Join(current, part)
		dirs = append(dirs, current)
	}
	return dirs
}

// getMandatoryDenyPaths returns concrete paths (not globs) that must be protected.
// Covers dangerous files/dirs in cwd, home, and subdirectories up to
// DefaultMaxDangerousFileDepth levels deep (using a depth-limited walk).
func getMandatoryDenyPaths(cwd string, allowGitConfig bool) []string {
	var paths []string

	// Dangerous files in cwd
	for _, f := range DangerousFiles {
		paths = append(paths, filepath.Join(cwd, f))
	}

	// Dangerous directories in cwd
	for _, d := range DangerousDirectories {
		paths = append(paths, filepath.Join(cwd, d))
	}

	// Git hooks are always blocked; .git/config is optional
	paths = append(paths, filepath.Join(cwd, ".git/hooks"))
	if !allowGitConfig {
		paths = append(paths, filepath.Join(cwd, ".git/config"))
	}

	// Dangerous files in home directory
	home, err := os.UserHomeDir()
	if err == nil {
		for _, f := range DangerousFiles {
			paths = append(paths, filepath.Join(home, f))
		}
	}

	// Depth-limited walk to find dangerous files in subdirectories.
	// This catches .bashrc, .zshrc, .git/hooks, etc. in nested project dirs
	// without the cost of a full recursive glob expansion.
	dangerous := FindDangerousFiles(cwd, DefaultMaxDangerousFileDepth)
	if allowGitConfig {
		gitConfigSuffix := string(filepath.Separator) + filepath.Join(".git", "config")
		for _, p := range dangerous {
			if strings.HasSuffix(p, gitConfigSuffix) {
				continue
			}
			paths = append(paths, p)
		}
	} else {
		paths = append(paths, dangerous...)
	}

	return paths
}

// WrapCommandLinux wraps a command with Linux bubblewrap sandbox.
// It uses available security features (Landlock, seccomp) with graceful fallback.
func WrapCommandLinux(cfg *config.Config, command string, bridge *LinuxBridge, reverseBridge *ReverseBridge, debug bool) (string, error) {
	return WrapCommandLinuxWithOptions(cfg, command, bridge, reverseBridge, LinuxSandboxOptions{
		UseLandlock:       true, // Enabled by default, will fall back if not available
		UseSeccomp:        true, // Enabled by default
		UseEBPF:           true, // Enabled by default if available
		UseLinuxBootstrap: true, // Use Go-based wrapper instead of shell script
		Debug:             debug,
	})
}

// WrapCommandLinuxWithShell wraps a command with configurable shell selection.
func WrapCommandLinuxWithShell(cfg *config.Config, command string, workingDir string, bridge *LinuxBridge, reverseBridge *ReverseBridge, debug bool, shellMode string, shellLogin bool, shellBasedLinuxBootstrap bool) (string, error) {
	return WrapCommandLinuxWithOptions(cfg, command, bridge, reverseBridge, LinuxSandboxOptions{
		UseLandlock:              true,
		UseSeccomp:               true,
		UseEBPF:                  true,
		UseLinuxBootstrap:        !shellBasedLinuxBootstrap, // Use Go wrapper unless shell-based flag is set
		ShellBasedLinuxBootstrap: shellBasedLinuxBootstrap,  // Development-only: force shell script
		Debug:                    debug,
		ShellMode:                shellMode,
		ShellLogin:               shellLogin,
		WorkDir:                  workingDir,
	})
}

func linuxRuntimeEnvScript() string {
	return `
fence_runtime_dir_cleanup=

fence_dir_is_usable() {
    dir=$1
    probe=
    [ -n "$dir" ] && [ -d "$dir" ] || return 1
    probe="$dir/.fence-write-test-$$"
    (umask 077 && : > "$probe") 2>/dev/null || return 1
    rm -f "$probe" 2>/dev/null || true
    return 0
}

fence_prepare_private_runtime_dir() {
    dir=
    dir=$(mktemp -d "/tmp/fence-runtime-$(id -u)-XXXXXX" 2>/dev/null) || return 1
    chmod 700 "$dir" 2>/dev/null || true
    if ! fence_dir_is_usable "$dir"; then
        rm -rf -- "$dir" 2>/dev/null || true
        return 1
    fi
    printf '%s\n' "$dir"
}

if ! fence_dir_is_usable "${TMPDIR:-}"; then
    export TMPDIR=/tmp
fi

fence_runtime_dir=${XDG_RUNTIME_DIR:-}
if ! fence_dir_is_usable "$fence_runtime_dir"; then
    fence_runtime_dir=$(fence_prepare_private_runtime_dir 2>/dev/null || true)
    if [ -z "$fence_runtime_dir" ]; then
        fence_runtime_dir=
    else
        fence_runtime_dir_cleanup="$fence_runtime_dir"
    fi
fi

if [ -n "$fence_runtime_dir" ]; then
    export XDG_RUNTIME_DIR="$fence_runtime_dir"
else
    unset XDG_RUNTIME_DIR
fi

`
}

func planLinuxBootstrapExecutables(
	shellPath string,
	fenceExePath string,
	needsFence bool,
	needsSocat bool,
) ([]linuxBootstrapExecutableMount, linuxBootstrapExecutables, error) {
	execs := linuxBootstrapExecutables{
		Shell: linuxBootstrapShellPath,
	}
	var mounts []linuxBootstrapExecutableMount

	addMount := func(hostPath string, sandboxPath string, name string) error {
		source, ok := resolvePathForMount(hostPath)
		if !ok {
			return fmt.Errorf("failed to stage bootstrap %s executable %q", name, hostPath)
		}
		mounts = append(mounts, linuxBootstrapExecutableMount{
			Source:      source,
			Destination: sandboxPath,
		})
		return nil
	}

	if err := addMount(shellPath, execs.Shell, "shell"); err != nil {
		return nil, linuxBootstrapExecutables{}, err
	}

	if needsFence {
		execs.Fence = linuxBootstrapFencePath
		if err := addMount(fenceExePath, execs.Fence, "fence"); err != nil {
			return nil, linuxBootstrapExecutables{}, err
		}
	}

	if needsSocat {
		socatPath, err := exec.LookPath("socat")
		if err != nil {
			return nil, linuxBootstrapExecutables{}, fmt.Errorf("failed to locate socat for sandbox bootstrap: %w", err)
		}
		execs.Socat = linuxBootstrapSocatPath
		if err := addMount(socatPath, execs.Socat, "socat"); err != nil {
			return nil, linuxBootstrapExecutables{}, err
		}
	}

	return mounts, execs, nil
}

func appendLinuxBootstrapExecutableMounts(args []string, mounts []linuxBootstrapExecutableMount) []string {
	if len(mounts) == 0 {
		return args
	}

	args = append(args,
		"--dir", linuxBootstrapDir,
		"--dir", linuxBootstrapBinDir,
	)
	for _, mount := range mounts {
		args = append(args, "--ro-bind", mount.Source, mount.Destination)
	}
	return args
}

func appendLinuxBootstrapWrapperArgs(
	bwrapArgs []string,
	fenceExePath, shellPath, shellFlag, command string,
	bridge *LinuxBridge,
	reverseBridge *ReverseBridge,
	cfg *config.Config,
	debug bool,
) ([]string, error) {
	// Use staged bootstrap paths (e.g. /tmp/fence/bin/shell, /tmp/fence/bin/fence)
	// instead of binding host paths directly. This mirrors the shell-based bootstrap
	// pattern and ensures executables are accessible at known locations inside the sandbox.
	// Always mount fence (pass true) since the Go-based bootstrap always needs it
	// for the --linux-bootstrap command, regardless of whether Landlock is used.
	needsSocat := bridge != nil || (reverseBridge != nil && len(reverseBridge.Ports) > 0)
	bootstrapMounts, bootstrapExecs, err := planLinuxBootstrapExecutables(
		shellPath,
		fenceExePath,
		true,
		needsSocat,
	)
	if err != nil {
		return nil, err
	}
	bwrapArgs = appendLinuxBootstrapExecutableMounts(bwrapArgs, bootstrapMounts)

	// Build the linux-bootstrap command line using staged paths
	bootstrapCmd := []string{bootstrapExecs.Fence, "--linux-bootstrap"}
	if debug {
		bootstrapCmd = append(bootstrapCmd, "--debug")
	}
	if bridge != nil {
		bootstrapCmd = append(bootstrapCmd,
			"--http-socket", bridge.HTTPSocketPath,
			"--socks-socket", bridge.SOCKSSocketPath,
		)
	}
	if reverseBridge != nil {
		for i, port := range reverseBridge.Ports {
			bootstrapCmd = append(bootstrapCmd,
				"--reverse-bridge", fmt.Sprintf("%d:%s", port, reverseBridge.SocketPaths[i]),
			)
		}
	}
	bootstrapCmd = append(bootstrapCmd, "--", bootstrapExecs.Shell, shellFlag, command)

	// Set FENCE_SANDBOX=1 from outside the sandbox via bwrap --setenv so it is structurally
	// guaranteed to be present regardless of any in-sandbox code paths.
	bwrapArgs = append(bwrapArgs, "--setenv", "FENCE_SANDBOX", "1")

	// Pass config via environment variable
	if cfg != nil {
		configJSON, err := json.Marshal(cfg)
		if err == nil {
			bwrapArgs = append(bwrapArgs, "--setenv", "FENCE_CONFIG_JSON", string(configJSON))
		}
	}

	// Execute the bootstrap command directly (no shell wrapper needed)
	return append(bwrapArgs, bootstrapCmd...), nil
}

func buildLinuxBootstrapScript(
	cfg *config.Config,
	command string,
	bridge *LinuxBridge,
	reverseBridge *ReverseBridge,
	opts LinuxSandboxOptions,
	useLandlockWrapper bool,
	bootstrapExecs linuxBootstrapExecutables,
	shellFlag string,
) (string, error) {
	var script strings.Builder

	_, _ = fmt.Fprintf(&script, `
fence_bootstrap_dir=%s
mkdir -p "$fence_bootstrap_dir"
fence_bootstrap_input=%s
fence_bootstrap_log=%s
: >"$fence_bootstrap_input"
: >"$fence_bootstrap_log"

fence_start_helper() {
    "$@" <"$fence_bootstrap_input" >>"$fence_bootstrap_log" 2>&1 &
}

fence_wait_for_helpers() {
    attempts=100
    while [ "$attempts" -gt 0 ]; do
        all_alive=1
`, ShellQuoteSingle(linuxBootstrapDir), ShellQuoteSingle(linuxBootstrapInputPath), ShellQuoteSingle(linuxBootstrapLogPath))

	for _, pidVar := range bootstrapPIDVars(bridge, reverseBridge, opts.LocalOutboundBridge) {
		_, _ = fmt.Fprintf(&script, `        if ! kill -0 "$%s" >>"$fence_bootstrap_log" 2>&1; then
            all_alive=0
        fi
`, pidVar)
	}
	for _, socketPath := range bootstrapSocketPaths(reverseBridge) {
		_, _ = fmt.Fprintf(&script, `        if [ ! -S %s ]; then
            all_alive=0
        fi
`, ShellQuoteSingle(socketPath))
	}

	script.WriteString(`        if [ "$all_alive" -eq 1 ]; then
            return 0
        fi
        sleep 0.05
        attempts=$((attempts - 1))
    done
    echo "[fence:linux] bootstrap helpers failed to become ready; see $fence_bootstrap_log" >&2
    return 1
}

# Cleanup function
cleanup() {
    jobs -p | xargs -r kill >>"$fence_bootstrap_log" 2>&1 || true
    case "${fence_runtime_dir_cleanup:-}" in
        /tmp/fence-runtime-*)
            rm -rf -- "$fence_runtime_dir_cleanup" >>"$fence_bootstrap_log" 2>&1 || true
            ;;
    esac
}
trap cleanup EXIT
`)
	script.WriteString(linuxRuntimeEnvScript())

	// NOTE: FENCE_SANDBOX=1 is only exported inside this bridge block, meaning it is absent
	// when no network bridge is active. This is likely a bug in the shell-based bootstrap path,
	// but we leave it as-is here; the Go-based bootstrap sets it unconditionally from outside
	// the sandbox via bwrap --setenv in appendLinuxBootstrapWrapperArgs, which is structurally
	// guaranteed regardless of any in-sandbox code paths.
	if bridge != nil {
		_, _ = fmt.Fprintf(&script, `
# Start HTTP proxy listener (port 3128 -> Unix socket -> host HTTP proxy)
fence_start_helper %s
HTTP_PID=$!

# Start SOCKS proxy listener (port 1080 -> Unix socket -> host SOCKS proxy)
fence_start_helper %s
SOCKS_PID=$!

# Set proxy environment variables
export HTTP_PROXY=http://127.0.0.1:3128
export HTTPS_PROXY=http://127.0.0.1:3128
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
export ALL_PROXY=socks5h://127.0.0.1:1080
export all_proxy=socks5h://127.0.0.1:1080
export NO_PROXY=localhost,127.0.0.1
export no_proxy=localhost,127.0.0.1
export FENCE_SANDBOX=1


`,
			ShellQuote([]string{
				bootstrapExecs.Socat,
				fmt.Sprintf("TCP-LISTEN:%d,fork,reuseaddr", 3128),
				fmt.Sprintf("UNIX-CONNECT:%s", bridge.HTTPSocketPath),
			}),
			ShellQuote([]string{
				bootstrapExecs.Socat,
				fmt.Sprintf("TCP-LISTEN:%d,fork,reuseaddr", 1080),
				fmt.Sprintf("UNIX-CONNECT:%s", bridge.SOCKSSocketPath),
			}),
		)
	}

	if reverseBridge != nil && len(reverseBridge.Ports) > 0 {
		script.WriteString("\n# Start reverse bridge listeners for inbound connections\n")
		for i, port := range reverseBridge.Ports {
			socketPath := reverseBridge.SocketPaths[i]
			_, _ = fmt.Fprintf(&script, "fence_start_helper %s\n",
				ShellQuote([]string{
					bootstrapExecs.Socat,
					fmt.Sprintf("UNIX-LISTEN:%s,fork,reuseaddr", socketPath),
					fmt.Sprintf("TCP:127.0.0.1:%d", port),
				}),
			)
			_, _ = fmt.Fprintf(&script, "REV_%d_PID=$!\n", port)
		}
		script.WriteString("\n")
	}

	if opts.LocalOutboundBridge != nil && len(opts.LocalOutboundBridge.Ports) > 0 {
		script.WriteString("\n# Start localhost-outbound bridge listeners so sandbox 127.0.0.1:<port> reaches host 127.0.0.1:<port>\n")
		for i, port := range opts.LocalOutboundBridge.Ports {
			socketPath := opts.LocalOutboundBridge.SocketPaths[i]
			_, _ = fmt.Fprintf(&script, "fence_start_helper %s\n",
				ShellQuote([]string{
					bootstrapExecs.Socat,
					fmt.Sprintf("TCP-LISTEN:%d,bind=127.0.0.1,fork,reuseaddr", port),
					fmt.Sprintf("UNIX-CONNECT:%s", socketPath),
				}),
			)
			_, _ = fmt.Fprintf(&script, "LO_%d_PID=$!\n", port)
		}
		script.WriteString("\n")
	}

	if len(bootstrapPIDVars(bridge, reverseBridge, opts.LocalOutboundBridge)) > 0 {
		script.WriteString("fence_wait_for_helpers || exit 1\n\n")
	}

	if useLandlockWrapper {
		if cfg != nil {
			configJSON, err := json.Marshal(cfg)
			if err == nil {
				_, _ = fmt.Fprintf(&script, "export FENCE_CONFIG_JSON=%s\n", ShellQuoteSingle(string(configJSON)))
			}
		}

		wrapperArgs := []string{bootstrapExecs.Fence, "--landlock-apply"}
		if opts.Debug {
			wrapperArgs = append(wrapperArgs, "--debug")
		}
		wrapperArgs = append(wrapperArgs, "--", bootstrapExecs.Shell, shellFlag, command)
		_, _ = fmt.Fprintf(&script, "exec %s\n", ShellQuote(wrapperArgs))
		return script.String(), nil
	}

	script.WriteString(command)
	script.WriteString("\n")
	return script.String(), nil
}

func bootstrapPIDVars(bridge *LinuxBridge, reverseBridge *ReverseBridge, localOutboundBridge *LocalOutboundBridge) []string {
	var pidVars []string
	if bridge != nil {
		pidVars = append(pidVars, "HTTP_PID", "SOCKS_PID")
	}
	if reverseBridge != nil {
		for _, port := range reverseBridge.Ports {
			pidVars = append(pidVars, fmt.Sprintf("REV_%d_PID", port))
		}
	}
	if localOutboundBridge != nil {
		for _, port := range localOutboundBridge.Ports {
			pidVars = append(pidVars, fmt.Sprintf("LO_%d_PID", port))
		}
	}
	return pidVars
}

func bootstrapSocketPaths(reverseBridge *ReverseBridge) []string {
	if reverseBridge == nil {
		return nil
	}
	return reverseBridge.SocketPaths
}

func useLinuxInteractivePTYSession(cfg *config.Config, stdinIsTTY bool, stdoutIsTTY bool) bool {
	return cfg != nil && cfg.AllowPty && stdinIsTTY && stdoutIsTTY
}

func effectiveLinuxForceNewSession(cfg *config.Config, stdinIsTTY bool, stdoutIsTTY bool) bool {
	if cfg != nil && cfg.ForceNewSession != nil {
		return *cfg.ForceNewSession
	}
	return !useLinuxInteractivePTYSession(cfg, stdinIsTTY, stdoutIsTTY)
}

func effectiveLinuxDeviceMode(cfg *config.Config, bwrapPath string) config.DeviceMode {
	requested := config.DeviceModeAuto
	if cfg != nil && cfg.Devices.Mode != "" {
		requested = cfg.Devices.Mode
	}
	return resolveLinuxDeviceMode(requested, os.Geteuid(), isSetuidBinary(bwrapPath), isInsideContainer())
}

// resolveLinuxDeviceMode chooses the /dev mount strategy to use on Linux.
// Auto mode prefers a fresh minimal /dev unless we're relying on setuid bwrap
// compatibility outside containers.
func resolveLinuxDeviceMode(requested config.DeviceMode, euid int, bwrapSetuid, insideContainer bool) config.DeviceMode {
	switch requested {
	case config.DeviceModeHost, config.DeviceModeMinimal:
		return requested
	case "", config.DeviceModeAuto:
		if insideContainer {
			return config.DeviceModeMinimal
		}
		if euid != 0 && bwrapSetuid {
			return config.DeviceModeHost
		}
		return config.DeviceModeMinimal
	default:
		return config.DeviceModeMinimal
	}
}

func isSetuidBinary(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSetuid != 0
}

func isInsideContainer() bool {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if fileExists(marker) {
			return true
		}
	}

	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	content := string(data)
	for _, hint := range []string{"docker", "containerd", "kubepods", "libpod", "podman", "lxc"} {
		if strings.Contains(content, hint) {
			return true
		}
	}
	return false
}

// WrapCommandLinuxWithOptions wraps a command with configurable sandbox options.
func WrapCommandLinuxWithOptions(cfg *config.Config, command string, bridge *LinuxBridge, reverseBridge *ReverseBridge, opts LinuxSandboxOptions) (string, error) {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return "", fmt.Errorf("bubblewrap (bwrap) is required on Linux but not found: %w", err)
	}

	shellPath, shellFlag, err := ResolveExecutionShell(opts.ShellMode, opts.ShellLogin)
	if err != nil {
		return "", err
	}

	cwd := ResolveSandboxWorkingDir(opts.WorkDir)
	features := DetectLinuxFeatures()
	runtimeExecPolicy := effectiveRuntimeExecPolicy(cfg)
	useArgvRuntimeExecPolicy := runtimeExecPolicy == config.RuntimeExecPolicyArgv

	var deniedExecPaths []string
	if !useArgvRuntimeExecPolicy {
		var runtimeExecDenyDiagnostics []string
		deniedExecPaths, runtimeExecDenyDiagnostics = GetRuntimeDeniedExecutablePathsWithDiagnostics(cfg, opts.Debug)
		for _, msg := range runtimeExecDenyDiagnostics {
			fencelog.Printf("[fence:linux] %s\n", msg)
		}
		if resolvedShellPath, err := filepath.EvalSymlinks(shellPath); err == nil {
			deniedExecPaths = slices.DeleteFunc(deniedExecPaths, func(p string) bool {
				return p == shellPath || p == resolvedShellPath
			})
		} else {
			deniedExecPaths = slices.DeleteFunc(deniedExecPaths, func(p string) bool {
				return p == shellPath
			})
		}
	}

	if opts.Debug {
		fencelog.Printf("[fence:linux] Available features: %s\n", features.Summary())
	}

	fenceExePath, _ := os.Executable()
	executableInTmp := strings.HasPrefix(fenceExePath, "/tmp/")
	executableIsFence := strings.Contains(filepath.Base(fenceExePath), "fence")
	if useArgvRuntimeExecPolicy {
		if !features.HasSeccomp || features.SeccompLogLevel < 2 {
			return "", fmt.Errorf("command.runtimeExecPolicy=%q requires Linux seccomp user notification support (kernel 5.0+)", config.RuntimeExecPolicyArgv)
		}
		if fenceExePath == "" || !executableIsFence {
			return "", fmt.Errorf("command.runtimeExecPolicy=%q requires the fence CLI binary (current executable cannot host the runtime supervisor)", config.RuntimeExecPolicyArgv)
		}
	}

	stdinIsTTY := term.IsTerminal(int(os.Stdin.Fd()))
	stdoutIsTTY := term.IsTerminal(int(os.Stdout.Fd()))
	forceNewSession := effectiveLinuxForceNewSession(cfg, stdinIsTTY, stdoutIsTTY)

	deviceMode := effectiveLinuxDeviceMode(cfg, bwrapPath)
	if opts.Debug {
		fencelog.Printf("[fence:linux] Device mode: %s\n", deviceMode)
	}

	// In wildcard mode ("*"), skip network namespace isolation so apps that
	// don't respect HTTP_PROXY can still make direct connections.
	hasWildcardAllow := hasWildcardAllowedDomain(cfg)

	if opts.Debug && hasWildcardAllow {
		fencelog.Printf("[fence:linux] Wildcard allowedDomains detected - allowing direct network connections\n")
		fencelog.Printf("[fence:linux] Note: deniedDomains only enforced for apps that respect HTTP_PROXY\n")
	}

	// Build bwrap args with filesystem restrictions
	bwrapArgs := []string{
		"bwrap",
		"--die-with-parent",
	}
	if forceNewSession {
		bwrapArgs = append(bwrapArgs, "--new-session")
	} else if opts.Debug {
		fencelog.Printf("[fence:linux] Interactive PTY session detected - skipping --new-session and relying on seccomp TIOCSTI filtering\n")
	}

	// Only use --unshare-net if:
	// 1. The environment supports it (has CAP_NET_ADMIN)
	// 2. We're NOT in wildcard mode (need direct network access)
	// Containerized environments (Docker, CI) often lack CAP_NET_ADMIN
	if features.CanUnshareNet && !hasWildcardAllow {
		bwrapArgs = append(bwrapArgs, "--unshare-net") // Network namespace isolation
	} else if opts.Debug && !features.CanUnshareNet {
		fencelog.Printf("[fence:linux] Skipping --unshare-net (network namespace unavailable in this environment)\n")
	}

	bwrapArgs = append(bwrapArgs, "--unshare-pid") // PID namespace isolation

	// Generate seccomp filter if available and requested
	var seccompFilterPath string
	if opts.UseSeccomp && features.HasSeccomp {
		filter := NewSeccompFilter(opts.Debug)
		filterPath, err := filter.GenerateBPFFilter()
		if err != nil {
			if opts.Debug {
				fencelog.Printf("[fence:linux] Seccomp filter generation failed: %v\n", err)
			}
		} else {
			seccompFilterPath = filterPath
			if opts.Debug {
				fencelog.Printf("[fence:linux] Seccomp filter enabled (blocking dangerous syscalls and ioctl(TIOCSTI))\n")
			}
			// Add seccomp filter via fd 3 (will be set up via shell redirection)
			bwrapArgs = append(bwrapArgs, "--seccomp", "3")
		}
	}

	defaultDenyRead := cfg != nil && cfg.Filesystem.DefaultDenyRead
	strictDenyRead := cfg != nil && cfg.Filesystem.StrictDenyRead

	if defaultDenyRead {
		// In defaultDenyRead mode, we only bind essential system paths read-only
		// and user-specified allowRead paths. Everything else is inaccessible.
		if opts.Debug {
			fencelog.Printf("[fence:linux] DefaultDenyRead mode enabled - binding only essential system paths\n")
		}

		// Bind essential system paths read-only
		// Skip /dev, /proc, /tmp as they're mounted with special options below
		if !strictDenyRead {
			for _, systemPath := range GetDefaultReadablePaths() {
				if systemPath == "/dev" || systemPath == "/proc" || systemPath == "/tmp" ||
					systemPath == "/private/tmp" {
					continue
				}
				if fileExists(systemPath) {
					bwrapArgs = append(bwrapArgs, "--ro-bind", systemPath, systemPath)
				}
			}
		}

		// Track bound paths to avoid duplicate mounts across allowRead, allowExecute, and wslInterop
		boundPaths := make(map[string]bool)

		// Bind user-specified allowRead paths
		if cfg != nil && cfg.Filesystem.AllowRead != nil {
			expandedPaths := ExpandGlobPatterns(cfg.Filesystem.AllowRead)
			for _, p := range expandedPaths {
				if fileExists(p) && !strings.HasPrefix(p, "/dev/") && !strings.HasPrefix(p, "/proc/") && !boundPaths[p] {
					boundPaths[p] = true
					bwrapArgs = append(bwrapArgs, "--ro-bind", p, p)
				}
			}
			for _, p := range cfg.Filesystem.AllowRead {
				normalized := NormalizePath(p)
				if !ContainsGlobChars(normalized) && fileExists(normalized) &&
					!strings.HasPrefix(normalized, "/dev/") && !strings.HasPrefix(normalized, "/proc/") && !boundPaths[normalized] {
					boundPaths[normalized] = true
					bwrapArgs = append(bwrapArgs, "--ro-bind", normalized, normalized)
				}
			}
		}

		// Bind user-specified allowExecute paths (ro-bind so they're visible)
		if cfg != nil && cfg.Filesystem.AllowExecute != nil {
			expandedPaths := ExpandGlobPatterns(cfg.Filesystem.AllowExecute)
			for _, p := range expandedPaths {
				if fileExists(p) && !strings.HasPrefix(p, "/dev/") && !strings.HasPrefix(p, "/proc/") && !boundPaths[p] {
					boundPaths[p] = true
					bwrapArgs = append(bwrapArgs, "--ro-bind", p, p)
				}
			}
			for _, p := range cfg.Filesystem.AllowExecute {
				normalized := NormalizePath(p)
				if !ContainsGlobChars(normalized) && fileExists(normalized) &&
					!strings.HasPrefix(normalized, "/dev/") && !strings.HasPrefix(normalized, "/proc/") && !boundPaths[normalized] {
					boundPaths[normalized] = true
					bwrapArgs = append(bwrapArgs, "--ro-bind", normalized, normalized)
				}
			}
		}

		// WSL interop: bind /init when wslInterop is active
		features := DetectLinuxFeatures()
		wslInterop := features.IsWSL
		if cfg != nil && cfg.Filesystem.WSLInterop != nil {
			wslInterop = *cfg.Filesystem.WSLInterop
		}
		if wslInterop && fileExists("/init") && !boundPaths["/init"] {
			boundPaths["/init"] = true
			bwrapArgs = append(bwrapArgs, "--ro-bind", "/init", "/init")
		}
	} else {
		// Default mode: bind entire root filesystem read-only
		bwrapArgs = append(bwrapArgs, "--ro-bind", "/", "/")
	}

	switch deviceMode {
	case config.DeviceModeHost:
		// Preserve the outer /dev when we're relying on setuid-bwrap compatibility.
		bwrapArgs = append(bwrapArgs, "--dev-bind", "/dev", "/dev")
	default:
		// Prefer a fresh minimal /dev for predictable sandbox behavior.
		// Rebind core devices from the outer environment so they remain usable
		// even if the synthetic /dev tmpfs inherits restrictive mount flags.
		bwrapArgs = append(bwrapArgs, "--dev", "/dev")
		boundDevicePaths := make(map[string]bool, len(linuxMinimalCoreDevicePaths))
		for _, path := range linuxMinimalCoreDevicePaths {
			bwrapArgs = appendLinuxDevicePassthrough(bwrapArgs, path, boundDevicePaths, opts.Debug, "core")
		}
		if cfg != nil && len(cfg.Devices.Allow) > 0 {
			for _, path := range cfg.Devices.Allow {
				bwrapArgs = appendLinuxDevicePassthrough(bwrapArgs, path, boundDevicePaths, opts.Debug, "custom")
			}
		}
	}
	bwrapArgs = append(bwrapArgs, "--proc", "/proc")

	// /tmp needs to be writable for many programs
	bwrapArgs = append(bwrapArgs, "--tmpfs", "/tmp")

	// Ensure /etc/resolv.conf is readable inside the sandbox.
	// On some systems (e.g., WSL), /etc/resolv.conf is a symlink to a path
	// on a separate mount point (e.g., /mnt/wsl/resolv.conf) that isn't
	// reachable after --ro-bind / / (non-recursive bind). When the target
	// is on a different filesystem, we create intermediate directories and
	// bind the real file at its original location so the symlink resolves.
	//
	// Skipped in strictDenyRead mode: the user controls all readable paths
	// explicitly, so auto-exposing a cross-mount tree would violate the
	// strict isolation policy. Users who need DNS can add the resolv.conf
	// target to allowRead.
	if target, err := filepath.EvalSymlinks("/etc/resolv.conf"); err == nil && target != "/etc/resolv.conf" && !strictDenyRead {
		// Skip targets under specially-mounted dirs - a --tmpfs there would
		// overwrite the /dev or /proc mounts established above.
		targetUnderSpecialMount := strings.HasPrefix(target, "/dev/") ||
			strings.HasPrefix(target, "/proc/") ||
			strings.HasPrefix(target, "/tmp/")
		// Also skip if the target is under a path that fence already exposes
		// via the recursive root bind (default mode) or an explicit --ro-bind
		// (defaultDenyRead mode). Without this, a target like
		// /run/systemd/resolve/stub-resolv.conf (stock Ubuntu w/ systemd-resolved)
		// causes fence to emit --tmpfs /run, wiping /run/docker.sock and
		// anything else in /run. Targets under unbound paths like /mnt/wsl
		// still need the --tmpfs + --dir + --ro-bind fix.
		//
		// TODO: the path-prefix check here is a heuristic stand-in for the
		// real question ("will this target's mount be visible after all
		// fence-emitted mount ops?"). A more durable shape would consult
		// /proc/self/mountinfo for propagation flags on target's mount and
		// only emit the stub when the submount would NOT be reachable from
		// the sandbox's mount namespace. Deferred; this guard covers the
		// known cases (WSL /mnt/wsl needs stub; everything in
		// GetDefaultReadablePaths() does not).
		for _, p := range GetDefaultReadablePaths() {
			if strings.HasPrefix(target, p+"/") {
				targetUnderSpecialMount = true
				break
			}
		}
		if fileExists(target) && !sameDevice("/", target) && !targetUnderSpecialMount {
			// Make the symlink target reachable by creating its parent dirs.
			// Walk down from / to the target's parent: skip dirs on the root
			// device (they have real content like /mnt/c, /mnt/d on WSL),
			// apply --tmpfs at the mount boundary (first dir on a different
			// device — an empty mount-point stub safe to replace), then --dir
			// for any deeper subdirectories inside the now-writable tmpfs.
			targetDir := filepath.Dir(target)
			mountBoundaryFound := false
			for _, dir := range intermediaryDirs("/", targetDir) {
				if !mountBoundaryFound {
					if !sameDevice("/", dir) {
						bwrapArgs = append(bwrapArgs, "--tmpfs", dir)
						mountBoundaryFound = true
					}
					// skip dirs still on root device
				} else {
					bwrapArgs = append(bwrapArgs, "--dir", dir)
				}
			}
			if mountBoundaryFound {
				bwrapArgs = append(bwrapArgs, "--ro-bind", target, target)
			}
			if opts.Debug {
				fencelog.Printf("[fence:linux] Resolved /etc/resolv.conf symlink -> %s (cross-mount)\n", target)
			}
		}
	}

	writablePaths := make(map[string]bool)

	// Add default write paths (system paths needed for operation)
	for _, p := range GetDefaultWritePaths() {
		// Skip /dev paths (handled by --dev) and /tmp paths (handled by --tmpfs)
		if strings.HasPrefix(p, "/dev/") || strings.HasPrefix(p, "/tmp/") || strings.HasPrefix(p, "/private/tmp/") {
			continue
		}
		writablePaths[p] = true
	}

	// Add user-specified allowWrite paths
	if cfg != nil && cfg.Filesystem.AllowWrite != nil {
		expandedPaths := ExpandGlobPatterns(cfg.Filesystem.AllowWrite)
		for _, p := range expandedPaths {
			writablePaths[p] = true
		}

		// Add non-glob paths
		for _, p := range cfg.Filesystem.AllowWrite {
			normalized := NormalizePath(p)
			if !ContainsGlobChars(normalized) {
				writablePaths[normalized] = true
			}
		}
	}

	// Make writable paths actually writable (override read-only root)
	if writablePaths["/"] {
		delete(writablePaths, "/")
		bwrapArgs = insertLinuxArgsBeforeSpecialMounts(bwrapArgs, []string{"--bind", "/", "/"})
	}

	for p := range writablePaths {
		if fileExists(p) {
			bwrapArgs = append(bwrapArgs, "--bind", p, p)
		}
	}

	// In normal mode (not defaultDenyRead), --ro-bind / / is recursive at the
	// mount-op level, but submounts whose propagation flag is MS_PRIVATE on
	// the host (e.g. /mnt/c, /mnt/wsl on WSL's 9p/drvfs) do not propagate
	// through the recursive bind. Bind allowExecute, allowRead, and
	// allowWrite paths that live on a different device so they become
	// visible inside the sandbox.
	if !defaultDenyRead && cfg != nil {
		crossMountBound := make(map[string]bool)

		// Track which paths need writable bind (--bind vs --ro-bind)
		crossMountWritable := make(map[string]bool)

		// Collect all cross-mount paths from allowExecute, allowRead, and the
		// default readable toolchain roots that should stay visible when /home or
		// other submounts are reconstructed from allowlisted paths.
		var crossMountPaths []string
		for _, p := range cfg.Filesystem.AllowExecute {
			if !ContainsGlobChars(p) {
				crossMountPaths = append(crossMountPaths, NormalizePath(p))
			}
		}
		crossMountPaths = append(crossMountPaths, ExpandGlobPatterns(cfg.Filesystem.AllowExecute)...)
		for _, p := range cfg.Filesystem.AllowRead {
			if !ContainsGlobChars(p) {
				crossMountPaths = append(crossMountPaths, NormalizePath(p))
			}
		}
		crossMountPaths = append(crossMountPaths, ExpandGlobPatterns(cfg.Filesystem.AllowRead)...)

		// Collect allowWrite paths and mark them as writable
		for _, p := range cfg.Filesystem.AllowWrite {
			if !ContainsGlobChars(p) {
				np := NormalizePath(p)
				crossMountPaths = append(crossMountPaths, np)
				crossMountWritable[np] = true
			}
		}
		for _, p := range ExpandGlobPatterns(cfg.Filesystem.AllowWrite) {
			crossMountPaths = append(crossMountPaths, p)
			crossMountWritable[p] = true
		}
		crossMountPaths = append(crossMountPaths, linuxDefaultCrossMountReadablePaths()...)
		if cwd != "" {
			// Keep the caller's working tree reachable when it lives on a
			// separate mount (common for /home). Some tools like git need the
			// cwd path to be discoverable from /, not just inherited as an
			// already-open working directory.
			crossMountPaths = append(crossMountPaths, cwd)
		}

		for _, p := range crossMountPaths {
			if !fileExists(p) || sameDevice("/", p) || crossMountBound[p] {
				continue
			}
			crossMountBound[p] = true

			// Use the same cross-mount bind technique as the resolv.conf fix:
			// walk from / to the target, apply --tmpfs at the mount boundary,
			// --dir for deeper subdirs, then bind the target.
			targetDir := p
			if !isDirectory(p) {
				targetDir = filepath.Dir(p)
			}
			mountBoundaryFound := false
			for _, dir := range intermediaryDirs("/", targetDir) {
				if crossMountBound[dir] {
					mountBoundaryFound = true
					continue
				}
				if !mountBoundaryFound {
					if !sameDevice("/", dir) {
						bwrapArgs = append(bwrapArgs, "--tmpfs", dir)
						crossMountBound[dir] = true
						mountBoundaryFound = true
					}
				} else {
					bwrapArgs = append(bwrapArgs, "--dir", dir)
					crossMountBound[dir] = true
				}
			}
			if mountBoundaryFound {
				if crossMountWritable[p] {
					bwrapArgs = append(bwrapArgs, "--bind", p, p)
				} else {
					bwrapArgs = append(bwrapArgs, "--ro-bind", p, p)
				}
				if opts.Debug {
					fencelog.Printf("[fence:linux] Cross-mount bind: %s (writable=%v)\n", p, crossMountWritable[p])
				}
			}
		}
	}

	bwrapArgs = appendLinuxLatePolicyMounts(bwrapArgs, cfg, cwd, defaultDenyRead, deniedExecPaths, opts.Debug)

	// Apply caller-registered host path exposures. These run AFTER all tmpfs
	// overmounts above (in particular --tmpfs /tmp), so a path the caller
	// expects to pass to the sandboxed process — even one under /tmp — is
	// bound back into the sandbox at the same location. bwrap auto-creates
	// any missing intermediate directories on the destination side.
	//
	// We validate existence at wrap time (rather than at ExposeHostPath
	// registration time) to avoid a TOCTOU pitfall: a caller might register
	// a path that exists at call time but is deleted before the sandbox
	// launches, so a registration-time check would be misleading about what
	// actually ends up bound. A missing path is surfaced as a warning
	// unconditionally (not gated on opts.Debug) because ExposeHostPath is
	// an explicit caller intent - silently dropping it would cause a
	// confusing downstream failure when the sandboxed process can't find
	// the file it was told to expect.
	for _, ehp := range opts.ExposedHostPaths {
		if !fileExists(ehp.path) {
			fencelog.Printf("[fence:linux] ExposeHostPath: skipping %q (does not exist on host at sandbox-launch time)\n", ehp.path)
			continue
		}
		flag := "--ro-bind"
		if ehp.writable {
			flag = "--bind"
		}
		bwrapArgs = append(bwrapArgs, flag, ehp.path, ehp.path)
		if opts.Debug {
			fencelog.Printf("[fence:linux] ExposeHostPath: %s %s (writable=%v)\n", flag, ehp.path, ehp.writable)
		}
	}

	// Bind the outbound Unix sockets into the sandbox (need to be writable)
	if bridge != nil {
		bwrapArgs = append(bwrapArgs,
			"--bind", bridge.HTTPSocketPath, bridge.HTTPSocketPath,
			"--bind", bridge.SOCKSSocketPath, bridge.SOCKSSocketPath,
		)
	}

	// Bind reverse socket directory if needed (sockets created inside sandbox)
	if reverseBridge != nil && len(reverseBridge.SocketPaths) > 0 {
		// Get the temp directory containing the reverse sockets
		tmpDir := filepath.Dir(reverseBridge.SocketPaths[0])
		bwrapArgs = append(bwrapArgs, "--bind", tmpDir, tmpDir)
	}

	// Bind each localhost-outbound Unix socket into the sandbox so the
	// bootstrap-spawned socat listeners can connect back to the host-side
	// forwarders. Sockets are created on the host before bwrap starts.
	if opts.LocalOutboundBridge != nil {
		for _, socketPath := range opts.LocalOutboundBridge.SocketPaths {
			bwrapArgs = append(bwrapArgs, "--bind", socketPath, socketPath)
		}
	}

	// Skip Landlock wrapper if executable is in /tmp (test binaries are built there)
	// The wrapper won't work because --tmpfs /tmp hides the test binary
	// Skip Landlock wrapper if fence is being used as a library (executable is not fence)
	// The wrapper re-executes the binary with --landlock-apply, which only fence understands
	useLandlockWrapper := opts.UseLandlock && features.CanUseLandlock() && fenceExePath != "" && !executableInTmp && executableIsFence

	// Use Go-based linux-bootstrap wrapper when:
	// 1. Explicitly requested via UseLinuxBootstrap option
	// 2. Fence binary is accessible (not in /tmp, is fence binary)
	// 3. ShellBasedLinuxBootstrap is NOT set (development-only flag to force shell script)
	// This replaces the shell script bootstrap entirely
	useLinuxBootstrapWrapper := opts.UseLinuxBootstrap && fenceExePath != "" && !executableInTmp && executableIsFence && !opts.ShellBasedLinuxBootstrap

	if opts.Debug && executableInTmp {
		fencelog.Printf("[fence:linux] Skipping Landlock wrapper (executable in /tmp, likely a test)\n")
	}
	if opts.Debug && !executableIsFence {
		fencelog.Printf("[fence:linux] Skipping Landlock wrapper (running as library, not fence CLI)\n")
	}
	if useLinuxBootstrapWrapper && (useArgvRuntimeExecPolicy || (opts.LocalOutboundBridge != nil && len(opts.LocalOutboundBridge.Ports) > 0)) {
		useLinuxBootstrapWrapper = false
		if opts.Debug {
			fencelog.Printf("[fence:linux] Falling back to shell bootstrap (Go wrapper does not support argv runtime-exec or local-outbound bridging)\n")
		}
	}
	if opts.Debug && useLinuxBootstrapWrapper {
		fmt.Fprintf(os.Stderr, "[fence:linux] Using Go-based linux-bootstrap wrapper\n")
	}
	if opts.Debug && opts.ShellBasedLinuxBootstrap && opts.UseLinuxBootstrap {
		fmt.Fprintf(os.Stderr, "[fence:linux] Using shell script bootstrap (--shell-based-linux-bootstrap flag set)\n")
	}

	if useLinuxBootstrapWrapper {
		bwrapArgs, err = appendLinuxBootstrapWrapperArgs(bwrapArgs, fenceExePath, shellPath, shellFlag, command, bridge, reverseBridge, cfg, opts.Debug)
		if err != nil {
			return "", err
		}
	} else {
		bootstrapMounts, bootstrapExecs, err := planLinuxBootstrapExecutables(
			shellPath,
			fenceExePath,
			useLandlockWrapper || useArgvRuntimeExecPolicy,
			bridge != nil ||
				(reverseBridge != nil && len(reverseBridge.Ports) > 0) ||
				(opts.LocalOutboundBridge != nil && len(opts.LocalOutboundBridge.Ports) > 0),
		)
		if err != nil {
			return "", err
		}
		bwrapArgs = appendLinuxBootstrapExecutableMounts(bwrapArgs, bootstrapMounts)

		innerScript, err := buildLinuxBootstrapScript(cfg, command, bridge, reverseBridge, opts, useLandlockWrapper, bootstrapExecs, shellFlag)
		if err != nil {
			return "", err
		}

		if useArgvRuntimeExecPolicy {
			bwrapArgs = append(bwrapArgs, "--", bootstrapExecs.Fence, linuxArgvExecShimMode)
			if opts.Debug {
				bwrapArgs = append(bwrapArgs, "--debug")
			}
			bwrapArgs = append(bwrapArgs, "--", bootstrapExecs.Shell, shellFlag, innerScript)
		} else {
			bwrapArgs = append(bwrapArgs, "--", bootstrapExecs.Shell, shellFlag, innerScript)
		}
	}

	if opts.Debug {
		var featureList []string
		if features.CanUnshareNet {
			featureList = append(featureList, "bwrap(network,pid,fs)")
		} else {
			featureList = append(featureList, "bwrap(pid,fs)")
		}
		featureList = append(featureList, "dev:"+string(deviceMode))
		if features.HasSeccomp && opts.UseSeccomp && seccompFilterPath != "" {
			featureList = append(featureList, "seccomp")
		}
		featureList = append(featureList, "runtime-exec:"+string(runtimeExecPolicy))
		if useLandlockWrapper {
			featureList = append(featureList, fmt.Sprintf("landlock-v%d(wrapper)", features.LandlockABI))
		} else if features.CanUseLandlock() && opts.UseLandlock {
			featureList = append(featureList, fmt.Sprintf("landlock-v%d(unavailable)", features.LandlockABI))
		}
		if reverseBridge != nil && len(reverseBridge.Ports) > 0 {
			featureList = append(featureList, fmt.Sprintf("inbound:%v", reverseBridge.Ports))
		}
		if opts.LocalOutboundBridge != nil && len(opts.LocalOutboundBridge.Ports) > 0 {
			featureList = append(featureList, fmt.Sprintf("local-outbound:%v", opts.LocalOutboundBridge.Ports))
		}
		fencelog.Printf("[fence:linux] Sandbox: %s\n", strings.Join(featureList, ", "))
	}

	// Build the final command
	bwrapCmd := ShellQuote(bwrapArgs)
	finalCmd := bwrapCmd

	if useArgvRuntimeExecPolicy {
		return buildLinuxArgvExecRunnerCommand(fenceExePath, linuxArgvExecPlan{
			BwrapArgs:                              bwrapArgs,
			Config:                                 cfg,
			Debug:                                  opts.Debug,
			SeccompFilterPath:                      seccompFilterPath,
			AllowedMultithreadedBootstrapContinues: linuxArgvExecMultithreadedBootstrapContinueBudget(useLandlockWrapper),
		})
	}

	// If seccomp filter is enabled, wrap with fd redirection
	// bwrap --seccomp expects the filter on the specified fd
	if seccompFilterPath != "" {
		// Open filter file on fd 3, then run bwrap
		// The filter file will be cleaned up after the sandbox exits
		finalCmd = fmt.Sprintf("exec 3<%s; %s", ShellQuoteSingle(seccompFilterPath), bwrapCmd)
	}

	return finalCmd, nil
}

// StartLinuxMonitor starts violation monitoring for a Linux sandbox.
// Returns monitors that should be stopped when the sandbox exits.
func StartLinuxMonitor(pid int, opts LinuxSandboxOptions) (*LinuxMonitors, error) {
	monitors := &LinuxMonitors{}
	features := DetectLinuxFeatures()

	// Note: SeccompMonitor is disabled because our seccomp filter uses SECCOMP_RET_ERRNO
	// which silently returns EPERM without logging to dmesg/audit.
	// To enable seccomp logging, the filter would need to use SECCOMP_RET_LOG (allows syscall)
	// or SECCOMP_RET_KILL (logs but kills process) or SECCOMP_RET_USER_NOTIF (complex).
	// For now, we rely on the eBPF monitor to detect syscall failures.
	if opts.Debug && opts.Monitor && features.SeccompLogLevel >= 1 {
		fencelog.Printf("[fence:linux] Note: seccomp violations are blocked but not logged (SECCOMP_RET_ERRNO is silent)\n")
	}

	// Start eBPF monitor if available and requested
	// This monitors syscalls that return EACCES/EPERM for sandbox descendants
	if opts.Monitor && opts.UseEBPF && features.HasEBPF {
		ebpfMon := NewEBPFMonitor(pid, opts.Debug)
		if err := ebpfMon.Start(); err != nil {
			if opts.Debug {
				fencelog.Printf("[fence:linux] Failed to start eBPF monitor: %v\n", err)
			}
		} else {
			monitors.EBPFMonitor = ebpfMon
			if opts.Debug {
				fencelog.Printf("[fence:linux] eBPF monitor started for PID %d\n", pid)
			}
		}
	} else if opts.Monitor && opts.Debug {
		if !features.HasEBPF {
			fencelog.Printf("[fence:linux] eBPF monitoring not available (need CAP_BPF or root)\n")
		}
	}

	return monitors, nil
}

// LinuxMonitors holds all active monitors for a Linux sandbox.
type LinuxMonitors struct {
	EBPFMonitor *EBPFMonitor
}

// Stop stops all monitors.
func (m *LinuxMonitors) Stop() {
	if m.EBPFMonitor != nil {
		m.EBPFMonitor.Stop()
	}
}

// PrintLinuxFeatures prints available Linux sandbox features.
func PrintLinuxFeatures() {
	features := DetectLinuxFeatures()
	fmt.Printf("Linux Sandbox Features:\n")
	fmt.Printf("  Kernel: %d.%d\n", features.KernelMajor, features.KernelMinor)
	fmt.Printf("  Bubblewrap (bwrap): %v\n", features.HasBwrap)
	fmt.Printf("  Socat: %v\n", features.HasSocat)
	fmt.Printf("  Network namespace (--unshare-net): %v\n", features.CanUnshareNet)
	fmt.Printf("  Seccomp: %v (log level: %d)\n", features.HasSeccomp, features.SeccompLogLevel)
	fmt.Printf("  Landlock: %v (ABI v%d)\n", features.HasLandlock, features.LandlockABI)
	fmt.Printf("  eBPF: %v (CAP_BPF: %v, root: %v)\n", features.HasEBPF, features.HasCapBPF, features.HasCapRoot)

	fmt.Printf("\nFeature Status:\n")
	if features.MinimumViable() {
		fmt.Printf("  ✓ Minimum requirements met (bwrap + socat)\n")
	} else {
		fmt.Printf("  ✗ Missing requirements: ")
		if !features.HasBwrap {
			fmt.Printf("bwrap ")
		}
		if !features.HasSocat {
			fmt.Printf("socat ")
		}
		fmt.Println()
	}

	if features.CanUnshareNet {
		fmt.Printf("  ✓ Network namespace isolation available\n")
	} else if features.HasBwrap {
		fmt.Printf("  ⚠ Network namespace unavailable (containerized environment?)\n")
		fmt.Printf("    Sandbox will still work but with reduced network isolation.\n")
		fmt.Printf("    This is common in Docker, GitHub Actions, and other CI systems.\n")
	}

	if features.CanUseLandlock() {
		fmt.Printf("  ✓ Landlock available for enhanced filesystem control\n")
	} else {
		fmt.Printf("  ○ Landlock not available (kernel 5.13+ required)\n")
	}

	if features.CanMonitorViolations() {
		fmt.Printf("  ✓ Violation monitoring available\n")
	} else {
		fmt.Printf("  ○ Violation monitoring limited (kernel 4.14+ for seccomp logging)\n")
	}

	if features.HasEBPF {
		fmt.Printf("  ✓ eBPF monitoring available (enhanced visibility)\n")
	} else {
		fmt.Printf("  ○ eBPF monitoring not available (needs CAP_BPF or root)\n")
	}
}
