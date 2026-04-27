//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/sandbox"
	"github.com/spf13/pflag"
)

const (
	ExitWrapperSetupFailed = 125 // Socket, landlock, or other setup failures
	ExitCommandNotFound    = 127 // User command not in PATH
)

type bootstrapOptions struct {
	httpSocket     string
	socksSocket    string
	reverseBridges []reverseBridgeSpec
	command        []string
	debug          bool
}

// exitError represents an error with an associated exit code
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	return e.err.Error()
}

func (e *exitError) ExitCode() int {
	return e.code
}

// fatalError creates an exitError and returns it
func fatalError(code int, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Error: %s\n", msg)
	return &exitError{
		code: code,
		err:  fmt.Errorf("%s", msg),
	}
}

func parseFlagsAndArgs() (bootstrapOptions, error) {
	flags := pflag.NewFlagSet("linux-bootstrap", pflag.ContinueOnError)
	httpSocket := flags.String("http-socket", "", "")
	socksSocket := flags.String("socks-socket", "", "")
	reverseBridgeSpecs := flags.StringArray("reverse-bridge", nil, "")
	debugMode := flags.Bool("debug", false, "")

	if err := flags.Parse(os.Args[2:]); err != nil {
		return bootstrapOptions{}, fatalError(ExitWrapperSetupFailed, "%v", err)
	}

	var reverseBridges []reverseBridgeSpec
	for _, s := range *reverseBridgeSpecs {
		spec, err := parseReverseBridge(s)
		if err != nil {
			return bootstrapOptions{}, fatalError(ExitWrapperSetupFailed, "%v", err)
		}
		reverseBridges = append(reverseBridges, spec)
	}

	command := flags.Args()
	if len(command) == 0 {
		return bootstrapOptions{}, fatalError(ExitWrapperSetupFailed, "no command specified")
	}

	return bootstrapOptions{
		httpSocket:     *httpSocket,
		socksSocket:    *socksSocket,
		reverseBridges: reverseBridges,
		command:        command,
		debug:          *debugMode,
	}, nil
}

type envGroup struct {
	keys  []string
	value string
}

func setEnvVars(g envGroup) error {
	for _, key := range g.keys {
		if err := os.Setenv(key, g.value); err != nil {
			return fmt.Errorf("failed to set %s: %w", key, err)
		}
	}
	return nil
}

func startTCPBridge(ctx context.Context, port int, socketPath, label string) error {
	startErrCh := make(chan struct {
		port int
		err  error
	}, 1)
	go func() {
		if _, err := bridgeTCPToUnix(ctx, port, socketPath, startErrCh); err != nil && err != context.Canceled {
			fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] %s bridge error: %v\n", label, err)
		}
	}()
	result := <-startErrCh
	return result.err
}

func startBridgesAndSetEnv(ctx context.Context, opts bootstrapOptions) ([]string, error) {
	var socketPaths []string

	if opts.httpSocket != "" {
		socketPaths = append(socketPaths, opts.httpSocket)
		if err := startTCPBridge(ctx, 3128, opts.httpSocket, "HTTP"); err != nil {
			return nil, fatalError(ExitWrapperSetupFailed, "failed to start HTTP bridge: %v", err)
		}
		if err := setEnvVars(envGroup{
			keys:  []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"},
			value: "http://127.0.0.1:3128",
		}); err != nil {
			return nil, fatalError(ExitWrapperSetupFailed, "failed to set proxy env vars: %v", err)
		}
	}

	if opts.socksSocket != "" {
		socketPaths = append(socketPaths, opts.socksSocket)
		if err := startTCPBridge(ctx, 1080, opts.socksSocket, "SOCKS"); err != nil {
			return nil, fatalError(ExitWrapperSetupFailed, "failed to start SOCKS bridge: %v", err)
		}
		if err := setEnvVars(envGroup{
			keys:  []string{"ALL_PROXY", "all_proxy"},
			value: "socks5h://127.0.0.1:1080",
		}); err != nil {
			return nil, fatalError(ExitWrapperSetupFailed, "failed to set proxy env vars: %v", err)
		}
	}

	if opts.httpSocket != "" || opts.socksSocket != "" {
		if err := setEnvVars(envGroup{
			keys:  []string{"NO_PROXY", "no_proxy"},
			value: "localhost,127.0.0.1",
		}); err != nil {
			return nil, fatalError(ExitWrapperSetupFailed, "failed to set no_proxy env vars: %v", err)
		}
	}

	for _, rb := range opts.reverseBridges {
		socketPaths = append(socketPaths, rb.socketPath)
		go func(port int, socketPath string) {
			if _, err := bridgeUnixToTCP(ctx, socketPath, port); err != nil && err != context.Canceled {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Reverse bridge error: %v\n", err)
			}
		}(rb.port, rb.socketPath)
	}

	return socketPaths, nil
}

func applyLandlock(opts bootstrapOptions, socketPaths []string) error {
	cfg, err := loadConfigFromEnv()
	if err != nil {
		return fatalError(ExitWrapperSetupFailed, "%v", err)
	}

	// Get current working directory for relative path resolution
	cwd, err := os.Getwd()
	if err != nil {
		return fatalError(ExitWrapperSetupFailed, "failed to get working directory: %v", err)
	}

	if opts.debug {
		fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Applying Landlock restrictions before command execution\n")
	}

	// Collect execute paths - we need to allow execution of the shell
	// The command[0] is the shell path (e.g., /nix/store/.../bash)
	var executePaths []string
	if len(opts.command) > 0 {
		// Resolve the command path to get the actual executable
		execPath, err := exec.LookPath(opts.command[0])
		if err == nil {
			// Add the resolved shell binary path for execution
			executePaths = append(executePaths, execPath)
			if opts.debug {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Adding execute path: %s\n", execPath)
			}
		} else if opts.debug {
			fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Warning: could not resolve command path: %v\n", err)
		}
	}

	// Apply Landlock restrictions
	err = sandbox.ApplyLandlockFromConfigWithExec(cfg, cwd, socketPaths, executePaths, opts.debug)
	if err != nil {
		if opts.debug {
			fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Warning: Landlock not applied: %v\n", err)
		}
	} else if opts.debug {
		fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Landlock restrictions applied\n")
	}

	return nil
}

func execUserCommand(opts bootstrapOptions) error {
	// Use cmd.Run() so that bridge goroutines remain alive
	// while the command executes. Landlock restrictions applied above
	// are automatically inherited by child processes.
	execPath, err := exec.LookPath(opts.command[0])
	if err != nil {
		return fatalError(ExitCommandNotFound, "command not found: %s", opts.command[0])
	}

	// Create the command
	cmd := exec.Command(execPath, opts.command[1:]...) // #nosec G204 -- execPath is resolved via exec.LookPath
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Sanitize environment (strips LD_PRELOAD, etc.)
	// FENCE_SANDBOX=1 is injected from outside the sandbox by bwrap via --setenv,
	// so it is already present in os.Environ() here.
	cmd.Env = sandbox.FilterDangerousEnv(os.Environ())

	// Run the command; keeping this process alive preserves the bridge goroutines.
	err = cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return &exitError{
				code: exitErr.ExitCode(),
				err:  exitErr,
			}
		}
		// Check if the error is "command not found"
		if cmdErr, ok := err.(*exec.Error); ok && cmdErr.Err == exec.ErrNotFound {
			return fatalError(ExitCommandNotFound, "command not found: %s", opts.command[0])
		}
		return fatalError(ExitWrapperSetupFailed, "run failed: %v", err)
	}

	return nil
}

// runLinuxBootstrapWrapper handles the --linux-bootstrap wrapper mode.
// This runs inside the sandbox and handles:
// 1. Socket bridging (TCP <-> Unix sockets for proxy support)
// 2. Waiting for sockets to be ready
// 3. Applying Landlock restrictions (if configured)
// 4. Running the user command
func runLinuxBootstrapWrapper() {
	opts, err := parseFlagsAndArgs()
	if err != nil {
		handleErrorAndExit(err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	socketPaths, err := startBridgesAndSetEnv(ctx, opts)
	if err != nil {
		handleErrorAndExit(err)
		return
	}

	if len(socketPaths) > 0 {
		if err := waitForUnixSockets(ctx, socketPaths, 5*time.Second); err != nil {
			handleErrorAndExit(fatalError(ExitWrapperSetupFailed, "%v", err))
			return
		}
	}

	// Repair runtime environment (TMPDIR, XDG_RUNTIME_DIR) if needed.
	// This mirrors the runtime env repair logic from linuxRuntimeEnvScript()
	// which is used in the shell script bootstrap path.
	// This must happen before applyLandlock since it creates directories.
	runtimeCleanup := repairRuntimeEnv()
	defer runtimeCleanup()

	if err := applyLandlock(opts, socketPaths); err != nil {
		handleErrorAndExit(err)
		return
	}

	if err := execUserCommand(opts); err != nil {
		handleErrorAndExit(err)
		return
	}
}

// handleErrorAndExit extracts the exit code from an error and calls os.Exit
func handleErrorAndExit(err error) {
	if exitErr, ok := err.(*exitError); ok {
		os.Exit(exitErr.ExitCode())
	}
	// Fallback for unexpected error types
	os.Exit(ExitWrapperSetupFailed)
}

// reverseBridgeSpec represents a reverse bridge specification (port:socketPath)
type reverseBridgeSpec struct {
	port       int
	socketPath string
}

// parseReverseBridge parses a reverse bridge spec like "3000:/tmp/fence-rev-3000.sock"
func parseReverseBridge(spec string) (reverseBridgeSpec, error) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 {
		return reverseBridgeSpec{}, fmt.Errorf("invalid reverse-bridge spec %q, expected PORT:PATH format", spec)
	}

	var port int
	if _, err := fmt.Sscanf(parts[0], "%d", &port); err != nil {
		return reverseBridgeSpec{}, fmt.Errorf("invalid port in reverse-bridge spec %q: %v", spec, err)
	}

	if port <= 0 || port > 65535 {
		return reverseBridgeSpec{}, fmt.Errorf("port %d out of range in reverse-bridge spec", port)
	}

	if parts[1] == "" {
		return reverseBridgeSpec{}, fmt.Errorf("empty socket path in reverse-bridge spec %q", spec)
	}

	return reverseBridgeSpec{
		port:       port,
		socketPath: parts[1],
	}, nil
}

// bridgeTCPToUnix bridges TCP connections on a port to a Unix socket.
// This is used for proxy support (HTTP/SOCKS proxies).
// startErrCh receives the actual port and nil once the listener is ready,
// or -1 and an error if setup fails; it is always sent to exactly once before the function returns.
func bridgeTCPToUnix(ctx context.Context, listenPort int, unixSocketPath string, startErrCh chan<- struct {
	port int
	err  error
},
) (int, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var setsockoptErr error
			err := c.Control(func(fd uintptr) {
				// Allow reuse of address to avoid "address already in use" errors
				setsockoptErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
			if err != nil {
				return err
			}
			return setsockoptErr
		},
	}

	listenAddr := fmt.Sprintf("127.0.0.1:%d", listenPort)
	ln, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		startErrCh <- struct {
			port int
			err  error
		}{-1, fmt.Errorf("failed to listen on %s: %w", listenAddr, err)}
		return -1, fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	// Get the actual port (important when listenPort is 0)
	actualPort := ln.Addr().(*net.TCPAddr).Port
	startErrCh <- struct {
		port int
		err  error
	}{actualPort, nil}

	// Close listener when context is cancelled
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return actualPort, ctx.Err()
		default:
		}

		tcpConn, err := ln.Accept()
		if err != nil {
			// Check if context was cancelled
			select {
			case <-ctx.Done():
				return actualPort, ctx.Err()
			default:
				return actualPort, fmt.Errorf("accept error: %w", err)
			}
		}

		go handleTCPToUnixConnection(tcpConn, unixSocketPath)
	}
}

// handleTCPToUnixConnection handles a single TCP to Unix socket connection
func handleTCPToUnixConnection(tcpConn net.Conn, unixPath string) {
	defer func() { _ = tcpConn.Close() }()

	unixConn, err := net.Dial("unix", unixPath)
	if err != nil {
		return
	}
	defer func() { _ = unixConn.Close() }()

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(tcpConn, unixConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(unixConn, tcpConn)
		done <- struct{}{}
	}()

	// Wait for both directions to finish
	<-done
	<-done
}

// bridgeUnixToTCP bridges a Unix socket to a TCP port (reverse bridge)
// This is used for exposing ports from inside the sandbox
func bridgeUnixToTCP(ctx context.Context, unixSocketPath string, targetPort int) (int, error) {
	// Remove socket if it already exists
	_ = os.Remove(unixSocketPath)

	// Create Unix socket listener
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", unixSocketPath)
	if err != nil {
		return -1, fmt.Errorf("failed to listen on unix socket %s: %w", unixSocketPath, err)
	}

	// Close listener when context is cancelled
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		_ = os.Remove(unixSocketPath)
	}()

	for {
		select {
		case <-ctx.Done():
			return targetPort, ctx.Err()
		default:
		}

		unixConn, err := ln.Accept()
		if err != nil {
			// Check if context was cancelled
			select {
			case <-ctx.Done():
				return targetPort, ctx.Err()
			default:
				return targetPort, fmt.Errorf("accept error: %w", err)
			}
		}

		go handleUnixToTCPConnection(unixConn, targetPort)
	}
}

// handleUnixToTCPConnection handles a single Unix to TCP socket connection
func handleUnixToTCPConnection(unixConn net.Conn, targetPort int) {
	defer func() { _ = unixConn.Close() }()

	tcpConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		return
	}
	defer func() { _ = tcpConn.Close() }()

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(unixConn, tcpConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(tcpConn, unixConn)
		done <- struct{}{}
	}()

	// Wait for one direction to finish
	<-done
}

// waitForUnixSockets waits for all Unix sockets to be ready with a timeout
func waitForUnixSockets(ctx context.Context, socketPaths []string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for _, path := range socketPaths {
		if err := waitForUnixSocket(ctx, path); err != nil {
			return fmt.Errorf("socket %s not ready: %w", path, err)
		}
	}

	return nil
}

// waitForUnixSocket waits for a single Unix socket to be ready
func waitForUnixSocket(ctx context.Context, socketPath string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Try to connect to the socket
			conn, err := net.Dial("unix", socketPath)
			if err == nil {
				_ = conn.Close()
				return nil
			}
		}
	}
}

// dirIsUsable checks if a directory exists and is writable.
func dirIsUsable(path string) bool {
	if path == "" {
		return false
	}

	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	if !info.IsDir() {
		return false
	}

	// Try to create a test file to verify write permissions
	testFile := path + "/.fence-write-test-" + fmt.Sprintf("%d", os.Getpid())
	// #nosec G304 -- testFile is intentionally created under a caller-provided directory to probe writability
	f, err := os.OpenFile(testFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(testFile)
		return false
	}
	if err := os.Remove(testFile); err != nil {
		return false
	}

	return true
}

// preparePrivateRuntimeDir creates a private runtime directory under /tmp.
func preparePrivateRuntimeDir() (dir string, cleanup func(), err error) {
	uid := os.Getuid()
	pattern := fmt.Sprintf("fence-runtime-%d-XXXXXX", uid)

	dir, err = os.MkdirTemp("/tmp", pattern)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Set permissions to 0700 (private)
	// #nosec G302 -- runtime directories must be owner-accessible and traversable
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, err
	}

	// Verify the directory is usable
	if !dirIsUsable(dir) {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("created directory is not usable")
	}

	cleanup = func() {
		_ = os.RemoveAll(dir)
	}

	return dir, cleanup, nil
}

// repairRuntimeEnv repairs TMPDIR and XDG_RUNTIME_DIR environment variables.
// Returns a cleanup function to remove any created runtime directory.
func repairRuntimeEnv() (cleanup func()) {
	cleanup = func() {} // Default no-op cleanup

	// Repair TMPDIR if not usable
	tmpdir := os.Getenv("TMPDIR")
	if !dirIsUsable(tmpdir) {
		if err := os.Setenv("TMPDIR", "/tmp"); err != nil {
			fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Warning: failed to set TMPDIR: %v\n", err)
		}
	}

	// Repair XDG_RUNTIME_DIR if not usable
	xdgRuntimeDir := os.Getenv("XDG_RUNTIME_DIR")
	var createdRuntimeDir string

	if !dirIsUsable(xdgRuntimeDir) {
		// Create a private runtime directory
		dir, dirCleanup, err := preparePrivateRuntimeDir()
		if err == nil {
			if err := os.Setenv("XDG_RUNTIME_DIR", dir); err != nil {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Warning: failed to set XDG_RUNTIME_DIR: %v\n", err)
				dirCleanup()
				return cleanup
			}
			createdRuntimeDir = dir
			cleanup = dirCleanup
		} else {
			// If we can't create a runtime dir, unset it
			if err := os.Unsetenv("XDG_RUNTIME_DIR"); err != nil {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Warning: failed to unset XDG_RUNTIME_DIR: %v\n", err)
			}
		}
	}

	// If we created a runtime dir, return a cleanup that removes it
	if createdRuntimeDir != "" {
		return cleanup
	}

	return func() {} // No cleanup needed if we didn't create a directory
}

// loadConfigFromEnv loads the config from FENCE_CONFIG_JSON environment variable,
// falling back to config.Default() if the variable is absent or invalid.
func loadConfigFromEnv() (*config.Config, error) {
	configJSON := os.Getenv("FENCE_CONFIG_JSON")
	if configJSON == "" {
		return nil, fmt.Errorf("FENCE_CONFIG_JSON is not set")
	}
	cfg := &config.Config{}
	if err := json.Unmarshal([]byte(configJSON), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse FENCE_CONFIG_JSON: %w", err)
	}
	return cfg, nil
}
