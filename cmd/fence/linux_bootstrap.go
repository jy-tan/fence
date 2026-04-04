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
	"github.com/Use-Tusk/fence/internal/platform"
	"github.com/Use-Tusk/fence/internal/sandbox"
)

const (
	ExitWrapperSetupFailed = 125 // Socket, landlock, or other setup failures
	ExitCommandNotFound    = 127 // User command not in PATH
)

// runLinuxBootstrapWrapper handles the --linux-bootstrap wrapper mode.
// This runs inside the sandbox and handles:
// 1. Socket bridging (TCP <-> Unix sockets for proxy support)
// 2. Waiting for sockets to be ready
// 3. Applying Landlock restrictions (if configured)
// 4. Running the user command
func runLinuxBootstrapWrapper() {
	// Parse flags manually to avoid cobra dependency
	args := os.Args[2:] // Skip "fence" and "--linux-bootstrap"

	var (
		httpSocket     string
		socksSocket    string
		reverseBridges []reverseBridgeSpec
		debugMode      bool
		cmdStart       int
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--debug":
			debugMode = true
		case "--http-socket":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Error: --http-socket requires a path\n")
				os.Exit(ExitWrapperSetupFailed)
			}
			httpSocket = args[i+1]
			i++
		case "--socks-socket":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Error: --socks-socket requires a path\n")
				os.Exit(ExitWrapperSetupFailed)
			}
			socksSocket = args[i+1]
			i++
		case "--reverse-bridge":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Error: --reverse-bridge requires PORT:PATH spec\n")
				os.Exit(ExitWrapperSetupFailed)
			}
			spec, err := parseReverseBridge(args[i+1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Error: %v\n", err)
				os.Exit(ExitWrapperSetupFailed)
			}
			reverseBridges = append(reverseBridges, spec)
			i++
		case "--":
			cmdStart = i + 1
			goto parseCommand
		default:
			// Unknown flag or start of command
			if strings.HasPrefix(args[i], "--") {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Error: unknown flag: %s\n", args[i])
				os.Exit(ExitWrapperSetupFailed)
			}
			cmdStart = i
			goto parseCommand
		}
	}

parseCommand:
	if cmdStart >= len(args) {
		fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Error: no command specified\n")
		os.Exit(ExitWrapperSetupFailed)
	}

	command := args[cmdStart:]

	// Load config from FENCE_CONFIG_JSON environment variable
	// Note: We don't use cfg here, but loadConfigFromEnv() validates the JSON
	_ = loadConfigFromEnv()

	// Create context for managing goroutines
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Track all socket paths we need to wait for
	var socketPaths []string

	// Start socket bridges
	if httpSocket != "" {
		socketPaths = append(socketPaths, httpSocket)
		go func() {
			if err := bridgeTCPToUnix(ctx, 3128, httpSocket); err != nil {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] HTTP bridge error: %v\n", err)
			}
		}()
	}

	if socksSocket != "" {
		socketPaths = append(socketPaths, socksSocket)
		go func() {
			if err := bridgeTCPToUnix(ctx, 1080, socksSocket); err != nil {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] SOCKS bridge error: %v\n", err)
			}
		}()
	}

	for _, rb := range reverseBridges {
		socketPaths = append(socketPaths, rb.socketPath)
		go func(port int, socketPath string) {
			if err := bridgeUnixToTCP(ctx, socketPath, port); err != nil {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Reverse bridge error: %v\n", err)
			}
		}(rb.port, rb.socketPath)
	}

	// Wait for sockets to be ready (5 second timeout)
	if len(socketPaths) > 0 {
		if err := waitForUnixSockets(ctx, socketPaths, 5*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] %v\n", err)
			os.Exit(ExitWrapperSetupFailed)
		}
	}

	// Set proxy environment variables
	if httpSocket != "" {
		os.Setenv("HTTP_PROXY", "http://127.0.0.1:3128")
		os.Setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
		os.Setenv("http_proxy", "http://127.0.0.1:3128")
		os.Setenv("https_proxy", "http://127.0.0.1:3128")
	}

	if socksSocket != "" {
		os.Setenv("ALL_PROXY", "socks5h://127.0.0.1:1080")
		os.Setenv("all_proxy", "socks5h://127.0.0.1:1080")
	}

	// Apply Landlock restrictions before running the command.
	// Landlock restrictions are inherited by all child processes, so applying them
	// here before cmd.Run() correctly restricts the sandboxed command too.
	// We must use cmd.Run() (not syscall.Exec) so that the bridge goroutines above
	// stay alive while the command is running — syscall.Exec replaces this process
	// image entirely, killing all goroutines and leaving port 3128/1080 with no
	// listener, causing curl and other network tools to get "connection refused".

	// Check if Landlock is available and should be applied
	detectedPlatform := platform.Detect()
	applyLandlock := detectedPlatform == platform.Linux

	if debugMode {
		fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Platform detected: %v, applyLandlock: %v\n", detectedPlatform, applyLandlock)
	}
	if applyLandlock {
		// Load config from environment variable
		var cfg *config.Config
		if configJSON := os.Getenv("FENCE_CONFIG_JSON"); configJSON != "" {
			cfg = &config.Config{}
			if err := json.Unmarshal([]byte(configJSON), cfg); err != nil {
				if debugMode {
					fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Warning: failed to parse FENCE_CONFIG_JSON: %v\n", err)
				}
				cfg = nil
			}
		}
		if cfg == nil {
			cfg = config.Default()
		}

		// Get current working directory for relative path resolution
		cwd, _ := os.Getwd()

		if debugMode {
			fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Applying Landlock restrictions before command execution\n")
		}

		// Collect execute paths - we need to allow execution of the shell
		// The command[0] is the shell path (e.g., /nix/store/.../bash)
		var executePaths []string
		if len(command) > 0 {
			// Resolve the command path to get the actual executable
			execPath, err := exec.LookPath(command[0])
			if err == nil {
				// Add the resolved shell binary path for execution
				executePaths = append(executePaths, execPath)
				if debugMode {
					fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Adding execute path: %s\n", execPath)
				}
			} else if debugMode {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Warning: could not resolve command path: %v\n", err)
			}
		}

		// Apply Landlock restrictions
		err := sandbox.ApplyLandlockFromConfigWithExec(cfg, cwd, nil, executePaths, debugMode)
		if err != nil {
			if debugMode {
				fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Warning: Landlock not applied: %v\n", err)
			}
			// Continue without Landlock - bwrap still provides isolation
		} else if debugMode {
			fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Landlock restrictions applied\n")
		}

		// Find the executable
		execPath, err := exec.LookPath(command[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Error: command not found: %s\n", command[0])
			os.Exit(ExitCommandNotFound)
		}

		if debugMode {
			fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Running: %s %v\n", execPath, command[1:])
		}
	}

	// Use cmd.Run() for all platforms so that bridge goroutines remain alive
	// while the command executes. On Linux, Landlock restrictions applied above
	// are automatically inherited by child processes.
	execPath, err := exec.LookPath(command[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Error: command not found: %s\n", command[0])
		os.Exit(ExitCommandNotFound)
	}

	// Create the command
	cmd := exec.Command(execPath, command[1:]...)
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
			fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Error: command not found: %s\n", command[0])
			os.Exit(ExitCommandNotFound)
		}
		fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Run failed: %v\n", err)
		os.Exit(1)
	}
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

// loadConfigFromEnv loads the config from FENCE_CONFIG_JSON environment variable
func loadConfigFromEnv() interface{} {
	configJSON := os.Getenv("FENCE_CONFIG_JSON")
	if configJSON == "" {
		return nil
	}
	// Just validate that it's valid JSON, we don't actually use it
	var cfg interface{}
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "[fence:linux-bootstrap] Warning: failed to parse FENCE_CONFIG_JSON: %v\n", err)
		return nil
	}
	return cfg
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
