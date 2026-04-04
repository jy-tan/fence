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

func fatal(exitCode int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Error: "+format+"\n", args...)
	os.Exit(exitCode)
}

func parseFlagsAndArgs() bootstrapOptions {
	flags := pflag.NewFlagSet("linux-bootstrap", pflag.ContinueOnError)
	httpSocket := flags.String("http-socket", "", "")
	socksSocket := flags.String("socks-socket", "", "")
	reverseBridgeSpecs := flags.StringArray("reverse-bridge", nil, "")
	debugMode := flags.Bool("debug", false, "")

	if err := flags.Parse(os.Args[2:]); err != nil {
		fatal(ExitWrapperSetupFailed, "%v", err)
	}

	var reverseBridges []reverseBridgeSpec
	for _, s := range *reverseBridgeSpecs {
		spec, err := parseReverseBridge(s)
		if err != nil {
			fatal(ExitWrapperSetupFailed, "%v", err)
		}
		reverseBridges = append(reverseBridges, spec)
	}

	command := flags.Args()
	if len(command) == 0 {
		fatal(ExitWrapperSetupFailed, "no command specified")
	}

	return bootstrapOptions{
		httpSocket:     *httpSocket,
		socksSocket:    *socksSocket,
		reverseBridges: reverseBridges,
		command:        command,
		debug:          *debugMode,
	}
}

func startBridgesAndSetEnv(ctx context.Context, opts bootstrapOptions) []string {
	var socketPaths []string

	if opts.httpSocket != "" {
		socketPaths = append(socketPaths, opts.httpSocket)
		go func() {
			if err := bridgeTCPToUnix(ctx, 3128, opts.httpSocket); err != nil {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] HTTP bridge error: %v\n", err)
			}
		}()
		os.Setenv("HTTP_PROXY", "http://127.0.0.1:3128")
		os.Setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
		os.Setenv("http_proxy", "http://127.0.0.1:3128")
		os.Setenv("https_proxy", "http://127.0.0.1:3128")
	}

	if opts.socksSocket != "" {
		socketPaths = append(socketPaths, opts.socksSocket)
		go func() {
			if err := bridgeTCPToUnix(ctx, 1080, opts.socksSocket); err != nil {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] SOCKS bridge error: %v\n", err)
			}
		}()
		os.Setenv("ALL_PROXY", "socks5h://127.0.0.1:1080")
		os.Setenv("all_proxy", "socks5h://127.0.0.1:1080")
	}

	for _, rb := range opts.reverseBridges {
		socketPaths = append(socketPaths, rb.socketPath)
		go func(port int, socketPath string) {
			if err := bridgeUnixToTCP(ctx, socketPath, port); err != nil {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Reverse bridge error: %v\n", err)
			}
		}(rb.port, rb.socketPath)
	}

	return socketPaths
}

func applyLandlock(opts bootstrapOptions) {
	cfg, err := loadConfigFromEnv()
	if err != nil {
		fatal(ExitWrapperSetupFailed, "%v", err)
	}

	// Get current working directory for relative path resolution
	cwd, err := os.Getwd()
	if err != nil {
		fatal(ExitWrapperSetupFailed, "failed to get working directory: %v", err)
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
	err = sandbox.ApplyLandlockFromConfigWithExec(cfg, cwd, nil, executePaths, opts.debug)
	if err != nil {
		if opts.debug {
			fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Warning: Landlock not applied: %v\n", err)
		}
	} else if opts.debug {
		fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Landlock restrictions applied\n")
	}
}

func execUserCommand(opts bootstrapOptions) {
	// Use cmd.Run() so that bridge goroutines remain alive
	// while the command executes. Landlock restrictions applied above
	// are automatically inherited by child processes.
	execPath, err := exec.LookPath(opts.command[0])
	if err != nil {
		fatal(ExitCommandNotFound, "command not found: %s", opts.command[0])
	}

	// Create the command
	cmd := exec.Command(execPath, opts.command[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Sanitize environment (strips LD_PRELOAD, etc.)
	cmd.Env = sandbox.FilterDangerousEnv(os.Environ())

	// Run the command; keeping this process alive preserves the bridge goroutines.
	err = cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		// Check if the error is "command not found"
		if cmdErr, ok := err.(*exec.Error); ok && cmdErr.Err == exec.ErrNotFound {
			fatal(ExitCommandNotFound, "command not found: %s", opts.command[0])
		}
		fatal(ExitWrapperSetupFailed, "run failed: %v", err)
	}
}

// runLinuxBootstrapWrapper handles the --linux-bootstrap wrapper mode.
// This runs inside the sandbox and handles:
// 1. Socket bridging (TCP <-> Unix sockets for proxy support)
// 2. Waiting for sockets to be ready
// 3. Applying Landlock restrictions (if configured)
// 4. Running the user command
func runLinuxBootstrapWrapper() {
	opts := parseFlagsAndArgs()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	socketPaths := startBridgesAndSetEnv(ctx, opts)

	if len(socketPaths) > 0 {
		if err := waitForUnixSockets(ctx, socketPaths, 5*time.Second); err != nil {
			fatal(ExitWrapperSetupFailed, "%v", err)
		}
	}

	applyLandlock(opts)
	execUserCommand(opts)
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

// bridgeTCPToUnix bridges TCP connections on a port to a Unix socket
// This is used for proxy support (HTTP/SOCKS proxies)
func bridgeTCPToUnix(ctx context.Context, listenPort int, unixSocketPath string) error {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Allow reuse of address to avoid "address already in use" errors
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
		},
	}

	ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", listenPort, err)
	}

	// Close listener when context is cancelled
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		tcpConn, err := ln.Accept()
		if err != nil {
			// Check if context was cancelled
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return fmt.Errorf("accept error: %w", err)
			}
		}

		go handleTCPToUnixConnection(tcpConn, unixSocketPath)
	}
}

// handleTCPToUnixConnection handles a single TCP to Unix socket connection
func handleTCPToUnixConnection(tcpConn net.Conn, unixPath string) {
	defer tcpConn.Close()

	unixConn, err := net.Dial("unix", unixPath)
	if err != nil {
		return
	}
	defer unixConn.Close()

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(tcpConn, unixConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(unixConn, tcpConn)
		done <- struct{}{}
	}()

	// Wait for one direction to finish
	<-done
}

// bridgeUnixToTCP bridges a Unix socket to a TCP port (reverse bridge)
// This is used for exposing ports from inside the sandbox
func bridgeUnixToTCP(ctx context.Context, unixSocketPath string, targetPort int) error {
	// Remove socket if it already exists
	os.Remove(unixSocketPath)

	// Create Unix socket listener
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", unixSocketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %s: %w", unixSocketPath, err)
	}

	// Close listener when context is cancelled
	go func() {
		<-ctx.Done()
		ln.Close()
		os.Remove(unixSocketPath)
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		unixConn, err := ln.Accept()
		if err != nil {
			// Check if context was cancelled
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return fmt.Errorf("accept error: %w", err)
			}
		}

		go handleUnixToTCPConnection(unixConn, targetPort)
	}
}

// handleUnixToTCPConnection handles a single Unix to TCP socket connection
func handleUnixToTCPConnection(unixConn net.Conn, targetPort int) {
	defer unixConn.Close()

	tcpConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		return
	}
	defer tcpConn.Close()

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(unixConn, tcpConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(tcpConn, unixConn)
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
				conn.Close()
				return nil
			}
		}
	}
}
