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
		fmt.Fprintf(os.Stderr, "[fence:linux] Starting HTTP bridge: socat %s\n", strings.Join(httpArgs, " "))
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
		fmt.Fprintf(os.Stderr, "[fence:linux] Starting SOCKS bridge: socat %s\n", strings.Join(socksArgs, " "))
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
				fmt.Fprintf(os.Stderr, "[fence:linux] Bridges ready (HTTP: %s, SOCKS: %s)\n", httpSocketPath, socksSocketPath)
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
		fmt.Fprintf(os.Stderr, "[fence:linux] Bridges cleaned up\n")
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
			fmt.Fprintf(os.Stderr, "[fence:linux] Starting reverse bridge for port %d: socat %s\n", port, strings.Join(args, " "))
		}
		if err := proc.Start(); err != nil {
			bridge.Cleanup()
			return nil, fmt.Errorf("failed to start reverse bridge for port %d: %w", port, err)
		}
		bridge.processes = append(bridge.processes, proc)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[fence:linux] Reverse bridges ready for ports: %v\n", ports)
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
		fmt.Fprintf(os.Stderr, "[fence:linux] Reverse bridges cleaned up\n")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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

// canMountOver returns true if bwrap can safely mount over this path.
// Returns false for symlinks (target may not exist in sandbox) and
// other special cases that could cause mount failures.
func canMountOver(path string) bool {
	if isSymlink(path) {
		return false
	}
	return fileExists(path)
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
// This expands the glob patterns from GetMandatoryDenyPatterns into real paths.
func getMandatoryDenyPaths(cwd string) []string {
	var paths []string

	// Dangerous files in cwd
	for _, f := range DangerousFiles {
		p := filepath.Join(cwd, f)
		paths = append(paths, p)
	}

	// Dangerous directories in cwd
	for _, d := range DangerousDirectories {
		p := filepath.Join(cwd, d)
		paths = append(paths, p)
	}

	// Git hooks in cwd
	paths = append(paths, filepath.Join(cwd, ".git/hooks"))

	// Git config in cwd
	paths = append(paths, filepath.Join(cwd, ".git/config"))

	// Also protect home directory dangerous files
	home, err := os.UserHomeDir()
	if err == nil {
		for _, f := range DangerousFiles {
			p := filepath.Join(home, f)
			paths = append(paths, p)
		}
	}

	return paths
}

// WrapCommandLinux wraps a command with Linux bubblewrap sandbox.
// It uses available security features (Landlock, seccomp) with graceful fallback.
func WrapCommandLinux(cfg *config.Config, command string, bridge *LinuxBridge, reverseBridge *ReverseBridge, debug bool) (string, error) {
	return WrapCommandLinuxWithOptions(cfg, command, bridge, reverseBridge, LinuxSandboxOptions{
		UseLandlock: true, // Enabled by default, will fall back if not available
		UseSeccomp:  true, // Enabled by default
		UseEBPF:     true, // Enabled by default if available
		Debug:       debug,
	})
}

// WrapCommandLinuxWithOptions wraps a command with configurable sandbox options.
func WrapCommandLinuxWithOptions(cfg *config.Config, command string, bridge *LinuxBridge, reverseBridge *ReverseBridge, opts LinuxSandboxOptions) (string, error) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		return "", fmt.Errorf("bubblewrap (bwrap) is required on Linux but not found: %w", err)
	}

	shell := "bash"
	shellPath, err := exec.LookPath(shell)
	if err != nil {
		return "", fmt.Errorf("shell %q not found: %w", shell, err)
	}

	cwd, _ := os.Getwd()
	features := DetectLinuxFeatures()

	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[fence:linux] Available features: %s\n", features.Summary())
	}

	// Check if allowedDomains contains "*" (wildcard = allow all direct network)
	// In this mode, we skip network namespace isolation so apps that don't
	// respect HTTP_PROXY can make direct connections.
	hasWildcardAllow := false
	if cfg != nil {
		hasWildcardAllow = slices.Contains(cfg.Network.AllowedDomains, "*")
	}

	if opts.Debug && hasWildcardAllow {
		fmt.Fprintf(os.Stderr, "[fence:linux] Wildcard allowedDomains detected - allowing direct network connections\n")
		fmt.Fprintf(os.Stderr, "[fence:linux] Note: deniedDomains only enforced for apps that respect HTTP_PROXY\n")
	}

	// Build bwrap args with filesystem restrictions
	bwrapArgs := []string{
		"bwrap",
		"--new-session",
		"--die-with-parent",
	}

	// Only use --unshare-net if:
	// 1. The environment supports it (has CAP_NET_ADMIN)
	// 2. We're NOT in wildcard mode (need direct network access)
	// Containerized environments (Docker, CI) often lack CAP_NET_ADMIN
	if features.CanUnshareNet && !hasWildcardAllow {
		bwrapArgs = append(bwrapArgs, "--unshare-net") // Network namespace isolation
	} else if opts.Debug && !features.CanUnshareNet {
		fmt.Fprintf(os.Stderr, "[fence:linux] Skipping --unshare-net (network namespace unavailable in this environment)\n")
	}

	bwrapArgs = append(bwrapArgs, "--unshare-pid") // PID namespace isolation

	// Generate seccomp filter if available and requested
	var seccompFilterPath string
	if opts.UseSeccomp && features.HasSeccomp {
		filter := NewSeccompFilter(opts.Debug)
		filterPath, err := filter.GenerateBPFFilter()
		if err != nil {
			if opts.Debug {
				fmt.Fprintf(os.Stderr, "[fence:linux] Seccomp filter generation failed: %v\n", err)
			}
		} else {
			seccompFilterPath = filterPath
			if opts.Debug {
				fmt.Fprintf(os.Stderr, "[fence:linux] Seccomp filter enabled (blocking %d dangerous syscalls)\n", len(DangerousSyscalls))
			}
			// Add seccomp filter via fd 3 (will be set up via shell redirection)
			bwrapArgs = append(bwrapArgs, "--seccomp", "3")
		}
	}

	defaultDenyRead := cfg != nil && cfg.Filesystem.DefaultDenyRead

	if defaultDenyRead {
		// In defaultDenyRead mode, we only bind essential system paths read-only
		// and user-specified allowRead paths. Everything else is inaccessible.
		if opts.Debug {
			fmt.Fprintf(os.Stderr, "[fence:linux] DefaultDenyRead mode enabled - binding only essential system paths\n")
		}

		// Bind essential system paths read-only
		// Skip /dev, /proc, /tmp as they're mounted with special options below
		for _, systemPath := range GetDefaultReadablePaths() {
			if systemPath == "/dev" || systemPath == "/proc" || systemPath == "/tmp" ||
				systemPath == "/private/tmp" {
				continue
			}
			if fileExists(systemPath) {
				bwrapArgs = append(bwrapArgs, "--ro-bind", systemPath, systemPath)
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

	// Mount special filesystems
	// Use --dev-bind for /dev instead of --dev to preserve host device permissions
	// (the --dev minimal devtmpfs has permission issues when bwrap is setuid)
	bwrapArgs = append(bwrapArgs, "--dev-bind", "/dev", "/dev")
	bwrapArgs = append(bwrapArgs, "--proc", "/proc")

	// /tmp needs to be writable for many programs
	bwrapArgs = append(bwrapArgs, "--tmpfs", "/tmp")

	// Ensure /etc/resolv.conf is readable inside the sandbox.
	// On some systems (e.g., WSL), /etc/resolv.conf is a symlink to a path
	// on a separate mount point (e.g., /mnt/wsl/resolv.conf) that isn't
	// reachable after --ro-bind / / (non-recursive bind). When the target
	// is on a different filesystem, we create intermediate directories and
	// bind the real file at its original location so the symlink resolves.
	if target, err := filepath.EvalSymlinks("/etc/resolv.conf"); err == nil && target != "/etc/resolv.conf" {
		// Skip targets under specially-mounted dirs — a --tmpfs there would
		// overwrite the --dev-bind or --proc mounts established above.
		targetUnderSpecialMount := strings.HasPrefix(target, "/dev/") ||
			strings.HasPrefix(target, "/proc/") ||
			strings.HasPrefix(target, "/tmp/")
		// In defaultDenyRead mode, also skip if the target is under a path
		// already individually bound (e.g., /run, /sys) — a --tmpfs would
		// overwrite that explicit bind. Targets under unbound paths like
		// /mnt/wsl still need the fix.
		if defaultDenyRead {
			for _, p := range GetDefaultReadablePaths() {
				if strings.HasPrefix(target, p+"/") {
					targetUnderSpecialMount = true
					break
				}
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
				fmt.Fprintf(os.Stderr, "[fence:linux] Resolved /etc/resolv.conf symlink -> %s (cross-mount)\n", target)
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
	for p := range writablePaths {
		if fileExists(p) {
			bwrapArgs = append(bwrapArgs, "--bind", p, p)
		}
	}

	// In normal mode (not defaultDenyRead), --ro-bind / / is non-recursive,
	// so paths on separate mount points (e.g., /mnt/c on WSL's 9p/drvfs)
	// are not captured. Bind allowExecute, allowRead, and allowWrite paths
	// that live on a different device so they become visible inside the sandbox.
	if !defaultDenyRead && cfg != nil {
		crossMountBound := make(map[string]bool)

		// Track which paths need writable bind (--bind vs --ro-bind)
		crossMountWritable := make(map[string]bool)

		// Collect all cross-mount paths from allowExecute and allowRead
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
					fmt.Fprintf(os.Stderr, "[fence:linux] Cross-mount bind: %s (writable=%v)\n", p, crossMountWritable[p])
				}
			}
		}
	}

	// Track explicit denyRead paths so they always keep precedence over
	// mandatory dangerous-path write protection.
	denyReadPaths := make(map[string]bool)

	// Handle denyRead paths - hide them
	// For directories: use --tmpfs to replace with empty tmpfs
	// For files: use --ro-bind /dev/null to mask with empty file
	// Skip symlinks: they may point outside the sandbox and cause mount errors
	if cfg != nil && cfg.Filesystem.DenyRead != nil {
		expandedDenyRead := ExpandGlobPatterns(cfg.Filesystem.DenyRead)
		for _, p := range expandedDenyRead {
			denyReadPaths[p] = true
			if canMountOver(p) {
				if isDirectory(p) {
					bwrapArgs = append(bwrapArgs, "--tmpfs", p)
				} else {
					// Mask file with /dev/null (appears as empty, unreadable)
					bwrapArgs = append(bwrapArgs, "--ro-bind", "/dev/null", p)
				}
			}
		}

		// Add non-glob paths
		for _, p := range cfg.Filesystem.DenyRead {
			normalized := NormalizePath(p)
			if !ContainsGlobChars(normalized) {
				denyReadPaths[normalized] = true
			}
			if !ContainsGlobChars(normalized) && canMountOver(normalized) {
				if isDirectory(normalized) {
					bwrapArgs = append(bwrapArgs, "--tmpfs", normalized)
				} else {
					bwrapArgs = append(bwrapArgs, "--ro-bind", "/dev/null", normalized)
				}
			}
		}
	}

	// Apply mandatory dangerous-path write protection.
	// In defaultDenyRead mode, never rebind the real path because that would
	// make hidden files readable; mask with /dev/null or empty tmpfs instead.
	//
	// Note: We only use concrete paths from getMandatoryDenyPaths(), NOT glob expansion.
	// GetMandatoryDenyPatterns() returns expensive **/pattern globs that require walking
	// the entire directory tree - this can hang on large directories (see issue #27).
	//
	// The concrete paths cover dangerous files in cwd and home directory. Files like
	// .bashrc in subdirectories are not protected, but this may be lower-risk since shell
	// rc files in project subdirectories are uncommon and not automatically sourced.
	//
	// TODO: consider depth-limited glob expansion (e.g., max 3 levels) to protect
	// subdirectory dangerous files without full tree walks that hang on large dirs.
	mandatoryDeny := getMandatoryDenyPaths(cwd)

	// Deduplicate
	seen := make(map[string]bool)
	for _, p := range mandatoryDeny {
		if denyReadPaths[p] {
			// Respect explicit denyRead precedence.
			continue
		}
		if !seen[p] && fileExists(p) {
			seen[p] = true
			if defaultDenyRead {
				if isDirectory(p) {
					bwrapArgs = append(bwrapArgs, "--tmpfs", p)
				} else {
					bwrapArgs = append(bwrapArgs, "--ro-bind", "/dev/null", p)
				}
			} else {
				bwrapArgs = append(bwrapArgs, "--ro-bind", p, p)
			}
		}
	}

	// Handle explicit denyWrite paths (make them read-only)
	if cfg != nil && cfg.Filesystem.DenyWrite != nil {
		expandedDenyWrite := ExpandGlobPatterns(cfg.Filesystem.DenyWrite)
		for _, p := range expandedDenyWrite {
			if fileExists(p) && !seen[p] {
				seen[p] = true
				bwrapArgs = append(bwrapArgs, "--ro-bind", p, p)
			}
		}
		// Add non-glob paths
		for _, p := range cfg.Filesystem.DenyWrite {
			normalized := NormalizePath(p)
			if !ContainsGlobChars(normalized) && fileExists(normalized) && !seen[normalized] {
				seen[normalized] = true
				bwrapArgs = append(bwrapArgs, "--ro-bind", normalized, normalized)
			}
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

	// Get fence executable path for Landlock wrapper
	fenceExePath, _ := os.Executable()
	// Skip Landlock wrapper if executable is in /tmp (test binaries are built there)
	// The wrapper won't work because --tmpfs /tmp hides the test binary
	executableInTmp := strings.HasPrefix(fenceExePath, "/tmp/")
	// Skip Landlock wrapper if fence is being used as a library (executable is not fence)
	// The wrapper re-executes the binary with --landlock-apply, which only fence understands
	executableIsFence := strings.Contains(filepath.Base(fenceExePath), "fence")
	useLandlockWrapper := opts.UseLandlock && features.CanUseLandlock() && fenceExePath != "" && !executableInTmp && executableIsFence

	if opts.Debug && executableInTmp {
		fmt.Fprintf(os.Stderr, "[fence:linux] Skipping Landlock wrapper (executable in /tmp, likely a test)\n")
	}
	if opts.Debug && !executableIsFence {
		fmt.Fprintf(os.Stderr, "[fence:linux] Skipping Landlock wrapper (running as library, not fence CLI)\n")
	}

	bwrapArgs = append(bwrapArgs, "--", shellPath, "-c")

	// Build the inner command that sets up socat listeners and runs the user command
	var innerScript strings.Builder

	if bridge != nil {
		// Set up outbound socat listeners inside the sandbox
		innerScript.WriteString(fmt.Sprintf(`
# Start HTTP proxy listener (port 3128 -> Unix socket -> host HTTP proxy)
socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:%s >/dev/null 2>&1 &
HTTP_PID=$!

# Start SOCKS proxy listener (port 1080 -> Unix socket -> host SOCKS proxy)
socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:%s >/dev/null 2>&1 &
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

`, bridge.HTTPSocketPath, bridge.SOCKSSocketPath))
	}

	// Set up reverse (inbound) socat listeners inside the sandbox
	if reverseBridge != nil && len(reverseBridge.Ports) > 0 {
		innerScript.WriteString("\n# Start reverse bridge listeners for inbound connections\n")
		for i, port := range reverseBridge.Ports {
			socketPath := reverseBridge.SocketPaths[i]
			// Listen on Unix socket, forward to localhost:port inside the sandbox
			innerScript.WriteString(fmt.Sprintf(
				"socat UNIX-LISTEN:%s,fork,reuseaddr TCP:127.0.0.1:%d >/dev/null 2>&1 &\n",
				socketPath, port,
			))
			innerScript.WriteString(fmt.Sprintf("REV_%d_PID=$!\n", port))
		}
		innerScript.WriteString("\n")
	}

	// Add cleanup function
	innerScript.WriteString(`
# Cleanup function
cleanup() {
    jobs -p | xargs -r kill 2>/dev/null
}
trap cleanup EXIT

# Small delay to ensure socat listeners are ready
sleep 0.1

# Run the user command
`)

	// Use Landlock wrapper if available
	if useLandlockWrapper {
		// Pass config via environment variable (serialized as JSON)
		// This ensures allowWrite/denyWrite rules are properly applied
		if cfg != nil {
			configJSON, err := json.Marshal(cfg)
			if err == nil {
				innerScript.WriteString(fmt.Sprintf("export FENCE_CONFIG_JSON=%s\n", ShellQuoteSingle(string(configJSON))))
			}
		}

		// Build wrapper command with proper quoting
		// Use bash -c to preserve shell semantics (e.g., "echo hi && ls")
		wrapperArgs := []string{fenceExePath, "--landlock-apply"}
		if opts.Debug {
			wrapperArgs = append(wrapperArgs, "--debug")
		}
		wrapperArgs = append(wrapperArgs, "--", "bash", "-c", command)

		// Use exec to replace bash with the wrapper (which will exec the command)
		innerScript.WriteString(fmt.Sprintf("exec %s\n", ShellQuote(wrapperArgs)))
	} else {
		innerScript.WriteString(command)
		innerScript.WriteString("\n")
	}

	bwrapArgs = append(bwrapArgs, innerScript.String())

	if opts.Debug {
		var featureList []string
		if features.CanUnshareNet {
			featureList = append(featureList, "bwrap(network,pid,fs)")
		} else {
			featureList = append(featureList, "bwrap(pid,fs)")
		}
		if features.HasSeccomp && opts.UseSeccomp && seccompFilterPath != "" {
			featureList = append(featureList, "seccomp")
		}
		if useLandlockWrapper {
			featureList = append(featureList, fmt.Sprintf("landlock-v%d(wrapper)", features.LandlockABI))
		} else if features.CanUseLandlock() && opts.UseLandlock {
			featureList = append(featureList, fmt.Sprintf("landlock-v%d(unavailable)", features.LandlockABI))
		}
		if reverseBridge != nil && len(reverseBridge.Ports) > 0 {
			featureList = append(featureList, fmt.Sprintf("inbound:%v", reverseBridge.Ports))
		}
		fmt.Fprintf(os.Stderr, "[fence:linux] Sandbox: %s\n", strings.Join(featureList, ", "))
	}

	// Build the final command
	bwrapCmd := ShellQuote(bwrapArgs)

	// If seccomp filter is enabled, wrap with fd redirection
	// bwrap --seccomp expects the filter on the specified fd
	if seccompFilterPath != "" {
		// Open filter file on fd 3, then run bwrap
		// The filter file will be cleaned up after the sandbox exits
		return fmt.Sprintf("exec 3<%s; %s", ShellQuoteSingle(seccompFilterPath), bwrapCmd), nil
	}

	return bwrapCmd, nil
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
		fmt.Fprintf(os.Stderr, "[fence:linux] Note: seccomp violations are blocked but not logged (SECCOMP_RET_ERRNO is silent)\n")
	}

	// Start eBPF monitor if available and requested
	// This monitors syscalls that return EACCES/EPERM for sandbox descendants
	if opts.Monitor && opts.UseEBPF && features.HasEBPF {
		ebpfMon := NewEBPFMonitor(pid, opts.Debug)
		if err := ebpfMon.Start(); err != nil {
			if opts.Debug {
				fmt.Fprintf(os.Stderr, "[fence:linux] Failed to start eBPF monitor: %v\n", err)
			}
		} else {
			monitors.EBPFMonitor = ebpfMon
			if opts.Debug {
				fmt.Fprintf(os.Stderr, "[fence:linux] eBPF monitor started for PID %d\n", pid)
			}
		}
	} else if opts.Monitor && opts.Debug {
		if !features.HasEBPF {
			fmt.Fprintf(os.Stderr, "[fence:linux] eBPF monitoring not available (need CAP_BPF or root)\n")
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
