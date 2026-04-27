//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Use-Tusk/fence/internal/config"
)

func mustSetenv(t *testing.T, key, value string) {
	t.Helper()
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("failed to set %s: %v", key, err)
	}
}

func mustUnsetenv(t *testing.T, key string) {
	t.Helper()
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("failed to unset %s: %v", key, err)
	}
}

func TestBridgeTCPToUnix(t *testing.T) {
	// Create a Unix socket server that echoes data
	tmpDir := t.TempDir()
	socketPath := tmpDir + "/test.sock"

	// Start Unix socket server
	serverReady := make(chan struct{})
	go func() {
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Errorf("failed to listen on unix socket: %v", err)
			return
		}
		defer func() { _ = ln.Close() }()

		close(serverReady)

		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				_, _ = c.Write(buf[:n])
			}(conn)
		}
	}()

	// Wait for server to be ready
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	// Start TCP to Unix bridge
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErrCh := make(chan struct {
		port int
		err  error
	}, 1)
	go func() {
		if _, err := bridgeTCPToUnix(ctx, 0, socketPath, startErrCh); err != nil && err != context.Canceled {
			t.Logf("bridge error: %v", err)
		}
	}()
	result := <-startErrCh
	if result.err != nil {
		t.Fatalf("bridge failed to start: %v", result.err)
	}
	port := result.port

	// Connect via TCP and send data
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("failed to connect to bridge: %v", err)
	}
	defer func() { _ = conn.Close() }()

	testData := "hello world"
	_, err = conn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("failed to write to connection: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from connection: %v", err)
	}

	if string(buf[:n]) != testData {
		t.Errorf("expected %q, got %q", testData, string(buf[:n]))
	}
}

func TestBridgeTCPToUnix_MultipleConnections(t *testing.T) {
	// Create a Unix socket server
	tmpDir := t.TempDir()
	socketPath := tmpDir + "/test.sock"

	serverReady := make(chan struct{})
	go func() {
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Errorf("failed to listen on unix socket: %v", err)
			return
		}
		defer func() { _ = ln.Close() }()

		close(serverReady)

		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				_, _ = c.Write(buf[:n])
			}(conn)
		}
	}()

	<-serverReady
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErrCh := make(chan struct {
		port int
		err  error
	}, 1)
	go func() {
		if _, err := bridgeTCPToUnix(ctx, 0, socketPath, startErrCh); err != nil && err != context.Canceled {
			t.Logf("bridge error: %v", err)
		}
	}()
	result := <-startErrCh
	if result.err != nil {
		t.Fatalf("bridge failed to start: %v", result.err)
	}
	port := result.port

	// Test multiple concurrent connections
	done := make(chan bool, 3)
	for i := 0; i < 3; i++ {
		go func(id int) {
			conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				t.Errorf("connection %d failed: %v", id, err)
				done <- false
				return
			}
			defer func() { _ = conn.Close() }()

			msg := "test"
			_, _ = conn.Write([]byte(msg))

			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)

			if string(buf[:n]) != msg {
				t.Errorf("connection %d: expected %q, got %q", id, msg, string(buf[:n]))
			}
			done <- true
		}(i)
	}

	// Wait for all connections
	for i := 0; i < 3; i++ {
		if !<-done {
			t.Error("at least one connection failed")
		}
	}
}

func TestBridgeTCPToUnix_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := tmpDir + "/test.sock"

	serverReady := make(chan struct{})
	go func() {
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Errorf("failed to listen: %v", err)
			return
		}
		defer func() { _ = ln.Close() }()
		close(serverReady)

		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	<-serverReady
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	startErrCh := make(chan struct {
		port int
		err  error
	}, 1)
	go func() {
		if _, err := bridgeTCPToUnix(ctx, 0, socketPath, startErrCh); err != nil && err != context.Canceled {
			t.Logf("bridge error: %v", err)
		}
	}()
	result := <-startErrCh
	if result.err != nil {
		t.Fatalf("bridge failed to start: %v", result.err)
	}

	// Cancel the context
	cancel()

	// Verify bridge stops - just wait a bit since we can't easily capture the return value
	time.Sleep(100 * time.Millisecond)
}

func TestBridgeUnixToTCP(t *testing.T) {
	// Create a TCP server with dynamic port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	port := listener.Addr().(*net.TCPAddr).Port

	serverReady := make(chan struct{})
	go func() {
		close(serverReady)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				_, _ = c.Write(buf[:n])
			}(conn)
		}
	}()

	<-serverReady

	// Start Unix to TCP bridge
	tmpDir := t.TempDir()
	socketPath := tmpDir + "/reverse.sock"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if _, err := bridgeUnixToTCP(ctx, socketPath, port); err != nil && err != context.Canceled {
			t.Logf("bridge error: %v", err)
		}
	}()

	// Wait for socket to appear
	time.Sleep(100 * time.Millisecond)

	// Connect via Unix socket
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to connect to unix socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	testData := "reverse test"
	_, err = conn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	if string(buf[:n]) != testData {
		t.Errorf("expected %q, got %q", testData, string(buf[:n]))
	}
}

func TestWaitForUnixSocket_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := waitForUnixSocket(ctx, "/tmp/nonexistent-socket-xyz.sock")
	if err == nil {
		t.Error("expected timeout error for nonexistent socket")
	}
}

func TestWaitForUnixSocket_Success(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := tmpDir + "/wait.sock"

	// Start server after a delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Errorf("failed to listen: %v", err)
			return
		}
		defer func() { _ = ln.Close() }()

		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := waitForUnixSocket(ctx, socketPath)
	if err != nil {
		t.Errorf("expected socket to become ready, got error: %v", err)
	}
}

func TestWaitForUnixSockets_AllReady(t *testing.T) {
	tmpDir := t.TempDir()

	socketPaths := []string{
		tmpDir + "/sock1.sock",
		tmpDir + "/sock2.sock",
	}

	// Start servers for each socket
	for _, path := range socketPaths {
		go func(p string) {
			time.Sleep(50 * time.Millisecond)
			ln, err := net.Listen("unix", p)
			if err != nil {
				return
			}
			defer func() { _ = ln.Close() }()

			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}(path)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := waitForUnixSockets(ctx, socketPaths, 2*time.Second)
	if err != nil {
		t.Errorf("expected all sockets to become ready, got error: %v", err)
	}
}

func TestParseReverseBridge(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedPort int
		expectedPath string
		expectError  bool
	}{
		{
			name:         "valid spec",
			input:        "3000:/tmp/test.sock",
			expectedPort: 3000,
			expectedPath: "/tmp/test.sock",
			expectError:  false,
		},
		{
			name:        "missing path",
			input:       "3000:",
			expectError: true,
		},
		{
			name:        "invalid port",
			input:       "abc:/tmp/test.sock",
			expectError: true,
		},
		{
			name:        "missing colon",
			input:       "3000",
			expectError: true,
		},
		{
			name:        "port out of range",
			input:       "70000:/tmp/test.sock",
			expectError: true,
		},
		{
			name:        "negative port",
			input:       "-1:/tmp/test.sock",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := parseReverseBridge(tt.input)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if spec.port != tt.expectedPort {
				t.Errorf("expected port %d, got %d", tt.expectedPort, spec.port)
			}

			if spec.socketPath != tt.expectedPath {
				t.Errorf("expected path %q, got %q", tt.expectedPath, spec.socketPath)
			}
		})
	}
}

// TestHandleTCPToUnixConnection_WaitsForBothDirections tests that the bridge
// waits for both directions to complete before closing connections.
// This prevents data loss when one direction finishes before the other.
func TestHandleTCPToUnixConnection_WaitsForBothDirections(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := tmpDir + "/test.sock"

	// Create a Unix socket server that:
	// 1. Reads a small request
	// 2. Waits to ensure the request direction finishes first
	// 3. Sends a large response
	serverReady := make(chan struct{})
	responseSize := 100 * 1024 // 100KB response
	go func() {
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Errorf("failed to listen on unix socket: %v", err)
			return
		}
		defer func() { _ = ln.Close() }()

		close(serverReady)

		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Read the small request
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		t.Logf("Server received %d bytes: %q", n, string(buf[:n]))

		// Wait to ensure the request direction finishes first
		// This simulates a slow server response
		time.Sleep(200 * time.Millisecond)

		// Send a large response
		largeResponse := make([]byte, responseSize)
		for i := range largeResponse {
			largeResponse[i] = 'X'
		}
		written, err := conn.Write(largeResponse)
		if err != nil {
			t.Logf("Server write error: %v", err)
		} else {
			t.Logf("Server wrote %d bytes", written)
		}
	}()

	<-serverReady
	time.Sleep(50 * time.Millisecond)

	// Start TCP to Unix bridge
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErrCh := make(chan struct {
		port int
		err  error
	}, 1)
	go func() {
		if _, err := bridgeTCPToUnix(ctx, 0, socketPath, startErrCh); err != nil && err != context.Canceled {
			t.Logf("bridge error: %v", err)
		}
	}()
	result := <-startErrCh
	if result.err != nil {
		t.Fatalf("bridge failed to start: %v", result.err)
	}
	port := result.port

	// Connect via TCP
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("failed to connect to bridge: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send a small request
	request := []byte("REQUEST")
	_, err = conn.Write(request)
	if err != nil {
		t.Fatalf("failed to write request: %v", err)
	}
	t.Logf("Client sent %d bytes", len(request))

	// Close write side to signal EOF to server
	// This causes the request direction (unixConn <- tcpConn) to finish
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
		t.Log("Client closed write side")
	}

	// Read the large response
	// With the bug: connection closes early, read fails or gets partial data
	// With the fix: we get the full response
	responseBuf := make([]byte, responseSize*2)
	totalRead := 0
	deadline := time.After(5 * time.Second)

	for totalRead < responseSize {
		select {
		case <-deadline:
			t.Fatalf("timeout: only received %d of %d bytes - data was truncated", totalRead, responseSize)
		default:
		}

		n, err := conn.Read(responseBuf[totalRead:])
		if n > 0 {
			totalRead += n
			t.Logf("Client read %d bytes, total: %d", n, totalRead)
		}
		if err != nil {
			if totalRead < responseSize {
				t.Fatalf("connection closed early: got %d of %d bytes: %v", totalRead, responseSize, err)
			}
			break
		}
	}

	if totalRead < responseSize {
		t.Errorf("expected %d bytes, got %d - response was truncated", responseSize, totalRead)
	} else {
		t.Logf("SUCCESS: received full response of %d bytes", totalRead)
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Run("empty env", func(t *testing.T) {
		_ = os.Unsetenv("FENCE_CONFIG_JSON")
		_, err := loadConfigFromEnv()
		if err == nil {
			t.Error("expected error for empty env, got nil")
		}
	})

	t.Run("valid json", func(t *testing.T) {
		t.Setenv("FENCE_CONFIG_JSON", `{"allowPty": true}`)
		cfg, err := loadConfigFromEnv()
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !cfg.AllowPty {
			t.Error("expected AllowPty=true from parsed config")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		t.Setenv("FENCE_CONFIG_JSON", `{invalid}`)
		_, err := loadConfigFromEnv()
		if err == nil {
			t.Error("expected error for invalid json, got nil")
		}
	})

	t.Run("valid json with network config", func(t *testing.T) {
		cfg := &config.Config{
			Network: config.NetworkConfig{
				AllowedDomains: []string{"github.com"},
				DeniedDomains:  []string{},
			},
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("failed to marshal config: %v", err)
		}
		t.Setenv("FENCE_CONFIG_JSON", string(data))

		result, err := loadConfigFromEnv()
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(result.Network.AllowedDomains) != 1 || result.Network.AllowedDomains[0] != "github.com" {
			t.Errorf("expected AllowedDomains=[github.com], got %v", result.Network.AllowedDomains)
		}
	})
}

// TestRepairRuntimeEnv_Integration tests the runtime environment repair
// in realistic scenarios where TMPDIR or XDG_RUNTIME_DIR are problematic.
// This mirrors the shell script logic from linuxRuntimeEnvScript().
func TestRepairRuntimeEnv_Integration(t *testing.T) {
	// Save original values
	origTMPDIR := os.Getenv("TMPDIR")
	origXDG := os.Getenv("XDG_RUNTIME_DIR")
	defer func() {
		if origTMPDIR != "" {
			mustSetenv(t, "TMPDIR", origTMPDIR)
		} else {
			mustUnsetenv(t, "TMPDIR")
		}
		if origXDG != "" {
			mustSetenv(t, "XDG_RUNTIME_DIR", origXDG)
		} else {
			mustUnsetenv(t, "XDG_RUNTIME_DIR")
		}
	}()

	t.Run("repairs unset TMPDIR", func(t *testing.T) {
		mustUnsetenv(t, "TMPDIR")
		cleanup := repairRuntimeEnv()
		defer cleanup()

		tmpdir := os.Getenv("TMPDIR")
		if tmpdir != "/tmp" {
			t.Errorf("expected TMPDIR=/tmp for unset TMPDIR, got %q", tmpdir)
		}
	})

	t.Run("repairs TMPDIR pointing to nonexistent directory", func(t *testing.T) {
		mustSetenv(t, "TMPDIR", "/nonexistent/tmp/dir/xyz123")
		cleanup := repairRuntimeEnv()
		defer cleanup()

		tmpdir := os.Getenv("TMPDIR")
		if tmpdir != "/tmp" {
			t.Errorf("expected TMPDIR=/tmp for nonexistent path, got %q", tmpdir)
		}
	})

	t.Run("keeps valid TMPDIR", func(t *testing.T) {
		validTmpDir := t.TempDir()
		mustSetenv(t, "TMPDIR", validTmpDir)
		cleanup := repairRuntimeEnv()
		defer cleanup()

		tmpdir := os.Getenv("TMPDIR")
		if tmpdir != validTmpDir {
			t.Errorf("expected TMPDIR to remain %q, got %q", validTmpDir, tmpdir)
		}
	})

	t.Run("creates XDG_RUNTIME_DIR when unset", func(t *testing.T) {
		mustUnsetenv(t, "XDG_RUNTIME_DIR")
		cleanup := repairRuntimeEnv()
		defer cleanup()

		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg == "" {
			t.Fatal("expected XDG_RUNTIME_DIR to be set")
		}

		// Verify it's under /tmp with correct prefix
		if !strings.HasPrefix(xdg, "/tmp/fence-runtime-") {
			t.Errorf("expected XDG_RUNTIME_DIR under /tmp/fence-runtime-, got %q", xdg)
		}

		// Verify directory exists and is usable
		info, err := os.Stat(xdg)
		if err != nil {
			t.Fatalf("XDG_RUNTIME_DIR directory does not exist: %v", err)
		}

		// Verify permissions are 0700
		if info.Mode().Perm() != 0o700 {
			t.Errorf("expected XDG_RUNTIME_DIR permissions 0700, got %04o", info.Mode().Perm())
		}

		// Verify we can write to it
		testFile := xdg + "/test-write"
		if err := os.WriteFile(testFile, []byte("test"), 0o600); err != nil {
			t.Errorf("cannot write to XDG_RUNTIME_DIR: %v", err)
		}
		if err := os.Remove(testFile); err != nil {
			t.Errorf("failed to remove test file: %v", err)
		}
	})

	t.Run("repairs XDG_RUNTIME_DIR pointing to nonexistent directory", func(t *testing.T) {
		mustSetenv(t, "XDG_RUNTIME_DIR", "/nonexistent/runtime/dir/xyz123")
		cleanup := repairRuntimeEnv()
		defer cleanup()

		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg == "" {
			t.Fatal("expected XDG_RUNTIME_DIR to be set")
		}

		// Verify it was replaced with a new directory
		if !strings.HasPrefix(xdg, "/tmp/fence-runtime-") {
			t.Errorf("expected XDG_RUNTIME_DIR under /tmp/fence-runtime-, got %q", xdg)
		}

		// Verify the new directory exists
		if _, err := os.Stat(xdg); err != nil {
			t.Fatalf("XDG_RUNTIME_DIR directory does not exist: %v", err)
		}
	})

	t.Run("keeps valid XDG_RUNTIME_DIR", func(t *testing.T) {
		validRuntimeDir := t.TempDir()
		mustSetenv(t, "XDG_RUNTIME_DIR", validRuntimeDir)
		cleanup := repairRuntimeEnv()
		defer cleanup()

		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg != validRuntimeDir {
			t.Errorf("expected XDG_RUNTIME_DIR to remain %q, got %q", validRuntimeDir, xdg)
		}
	})

	t.Run("cleanup removes created runtime directory", func(t *testing.T) {
		mustUnsetenv(t, "XDG_RUNTIME_DIR")
		cleanup := repairRuntimeEnv()

		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg == "" {
			t.Fatal("XDG_RUNTIME_DIR was not set")
		}

		// Verify directory exists
		if _, err := os.Stat(xdg); err != nil {
			t.Fatalf("directory does not exist: %v", err)
		}

		// Call cleanup
		cleanup()

		// Verify directory is removed
		if _, err := os.Stat(xdg); !os.IsNotExist(err) {
			t.Errorf("expected directory to be removed after cleanup, got error: %v", err)
		}
	})

	t.Run("cleanup does not remove pre-existing XDG_RUNTIME_DIR", func(t *testing.T) {
		existingDir := t.TempDir()
		mustSetenv(t, "XDG_RUNTIME_DIR", existingDir)
		cleanup := repairRuntimeEnv()

		// Call cleanup
		cleanup()

		// Verify original directory still exists
		if _, err := os.Stat(existingDir); err != nil {
			t.Errorf("expected pre-existing directory to remain after cleanup: %v", err)
		}
	})

	t.Run("handles both TMPDIR and XDG_RUNTIME_DIR needing repair", func(t *testing.T) {
		mustUnsetenv(t, "TMPDIR")
		mustUnsetenv(t, "XDG_RUNTIME_DIR")
		cleanup := repairRuntimeEnv()
		defer cleanup()

		// Verify both are repaired
		tmpdir := os.Getenv("TMPDIR")
		if tmpdir != "/tmp" {
			t.Errorf("expected TMPDIR=/tmp, got %q", tmpdir)
		}

		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg == "" {
			t.Error("expected XDG_RUNTIME_DIR to be set")
		}
	})

	t.Run("handles read-only XDG_RUNTIME_DIR", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("test requires non-root user")
		}

		// Create a read-only directory
		tmpDir := t.TempDir()
		readOnlyDir := tmpDir + "/readonly"
		// #nosec G301 -- the test intentionally creates a non-writable directory
		if err := os.Mkdir(readOnlyDir, 0o500); err != nil {
			t.Fatalf("failed to create read-only dir: %v", err)
		}

		mustSetenv(t, "XDG_RUNTIME_DIR", readOnlyDir)
		cleanup := repairRuntimeEnv()
		defer cleanup()

		xdg := os.Getenv("XDG_RUNTIME_DIR")
		// Should have created a new directory since the read-only one is unusable
		if xdg == readOnlyDir {
			t.Error("expected read-only XDG_RUNTIME_DIR to be replaced")
		}

		if !strings.HasPrefix(xdg, "/tmp/fence-runtime-") {
			t.Errorf("expected new XDG_RUNTIME_DIR under /tmp/fence-runtime-, got %q", xdg)
		}
	})
}

// TestExecUserCommand tests the command execution function.
func TestExecUserCommand(t *testing.T) {
	t.Run("command not found", func(t *testing.T) {
		opts := bootstrapOptions{
			command: []string{"nonexistent-command-xyz123"},
		}

		err := execUserCommand(opts)
		if err == nil {
			t.Fatal("expected error for nonexistent command")
		}

		var exitErr *exitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected exitError, got %T", err)
		}

		if exitErr.ExitCode() != ExitCommandNotFound {
			t.Errorf("expected exit code %d, got %d", ExitCommandNotFound, exitErr.ExitCode())
		}
	})

	t.Run("successful command execution", func(t *testing.T) {
		opts := bootstrapOptions{
			command: []string{"echo", "hello"},
		}

		err := execUserCommand(opts)
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("command with exit code", func(t *testing.T) {
		opts := bootstrapOptions{
			command: []string{"sh", "-c", "exit 42"},
		}

		err := execUserCommand(opts)
		if err == nil {
			t.Fatal("expected error for non-zero exit code")
		}

		var exitErr *exitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected exitError, got %T", err)
		}

		if exitErr.ExitCode() != 42 {
			t.Errorf("expected exit code 42, got %d", exitErr.ExitCode())
		}
	})
}

// TestParseFlagsAndArgs tests flag parsing and validation.
func TestParseFlagsAndArgs(t *testing.T) {
	// Save original args
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	t.Run("no command specified", func(t *testing.T) {
		os.Args = []string{"fence", "--linux-bootstrap"}
		_, err := parseFlagsAndArgs()
		if err == nil {
			t.Error("expected error for no command")
		}

		var exitErr *exitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected exitError, got %T", err)
		}

		if exitErr.ExitCode() != ExitWrapperSetupFailed {
			t.Errorf("expected exit code %d, got %d", ExitWrapperSetupFailed, exitErr.ExitCode())
		}
	})

	t.Run("valid command", func(t *testing.T) {
		os.Args = []string{"fence", "--linux-bootstrap", "echo", "hello"}
		opts, err := parseFlagsAndArgs()
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(opts.command) != 2 {
			t.Errorf("expected 2 command args, got %d", len(opts.command))
		}
		if opts.command[0] != "echo" {
			t.Errorf("expected command[0]=echo, got %q", opts.command[0])
		}
	})

	t.Run("invalid reverse-bridge spec", func(t *testing.T) {
		os.Args = []string{"fence", "--linux-bootstrap", "--reverse-bridge", "invalid", "echo"}
		_, err := parseFlagsAndArgs()
		if err == nil {
			t.Error("expected error for invalid reverse-bridge spec")
		}

		var exitErr *exitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected exitError, got %T", err)
		}

		if exitErr.ExitCode() != ExitWrapperSetupFailed {
			t.Errorf("expected exit code %d, got %d", ExitWrapperSetupFailed, exitErr.ExitCode())
		}
	})

	t.Run("parses reverse-bridge correctly", func(t *testing.T) {
		os.Args = []string{"fence", "--linux-bootstrap", "--reverse-bridge", "3000:/tmp/test.sock", "echo"}
		opts, err := parseFlagsAndArgs()
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if len(opts.reverseBridges) != 1 {
			t.Fatalf("expected 1 reverse bridge, got %d", len(opts.reverseBridges))
		}
		if opts.reverseBridges[0].port != 3000 {
			t.Errorf("expected port 3000, got %d", opts.reverseBridges[0].port)
		}
		if opts.reverseBridges[0].socketPath != "/tmp/test.sock" {
			t.Errorf("expected socket path /tmp/test.sock, got %q", opts.reverseBridges[0].socketPath)
		}
	})
}

// TestApplyLandlock tests Landlock application.
func TestApplyLandlock(t *testing.T) {
	t.Run("missing FENCE_CONFIG_JSON", func(t *testing.T) {
		_ = os.Unsetenv("FENCE_CONFIG_JSON")
		opts := bootstrapOptions{
			command: []string{"echo"},
		}

		err := applyLandlock(opts, nil)
		if err == nil {
			t.Error("expected error for missing FENCE_CONFIG_JSON")
		}

		var exitErr *exitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected exitError, got %T", err)
		}

		if exitErr.ExitCode() != ExitWrapperSetupFailed {
			t.Errorf("expected exit code %d, got %d", ExitWrapperSetupFailed, exitErr.ExitCode())
		}
	})

	t.Run("valid config", func(t *testing.T) {
		t.Setenv("FENCE_CONFIG_JSON", `{}`)
		opts := bootstrapOptions{
			command: []string{"echo"},
		}

		err := applyLandlock(opts, nil)
		// Landlock may fail if not supported, but should not return exitError
		if err != nil {
			var exitErr *exitError
			if errors.As(err, &exitErr) {
				t.Errorf("unexpected exitError: %v", err)
			}
			// Non-exit errors are acceptable (e.g., Landlock not supported)
		}
	})
}

// TestExitError tests the exitError type.
func TestExitError(t *testing.T) {
	t.Run("Error() returns message", func(t *testing.T) {
		err := &exitError{
			code: 42,
			err:  fmt.Errorf("test error"),
		}

		if err.Error() != "test error" {
			t.Errorf("expected 'test error', got %q", err.Error())
		}
	})

	t.Run("ExitCode() returns code", func(t *testing.T) {
		err := &exitError{
			code: 42,
			err:  fmt.Errorf("test error"),
		}

		if err.ExitCode() != 42 {
			t.Errorf("expected exit code 42, got %d", err.ExitCode())
		}
	})

	t.Run("errors.As works", func(t *testing.T) {
		err := &exitError{
			code: 42,
			err:  fmt.Errorf("test error"),
		}

		var exitErr *exitError
		if !errors.As(err, &exitErr) {
			t.Error("expected errors.As to work")
		}

		if exitErr.ExitCode() != 42 {
			t.Errorf("expected exit code 42, got %d", exitErr.ExitCode())
		}
	})
}

func TestStartBridgesAndSetEnv_SetsNoProxy(t *testing.T) {
	t.Run("sets NO_PROXY and no_proxy when http socket is configured", func(t *testing.T) {
		tmpDir := t.TempDir()
		httpSocketPath := tmpDir + "/http.sock"

		httpListener, err := net.Listen("unix", httpSocketPath)
		if err != nil {
			t.Fatalf("failed to listen on http socket: %v", err)
		}
		defer func() {
			if err := httpListener.Close(); err != nil {
				t.Errorf("failed to close http listener: %v", err)
			}
		}()
		go func() {
			for {
				conn, err := httpListener.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()

		t.Setenv("NO_PROXY", "")
		t.Setenv("no_proxy", "")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		opts := bootstrapOptions{
			httpSocket: httpSocketPath,
			command:    []string{"echo", "hello"},
		}

		_, err = startBridgesAndSetEnv(ctx, opts)
		if err != nil {
			t.Fatalf("startBridgesAndSetEnv failed: %v", err)
		}

		noProxy := os.Getenv("NO_PROXY")
		if noProxy != "localhost,127.0.0.1" {
			t.Errorf("expected NO_PROXY=localhost,127.0.0.1, got %q", noProxy)
		}
		noProxyLower := os.Getenv("no_proxy")
		if noProxyLower != "localhost,127.0.0.1" {
			t.Errorf("expected no_proxy=localhost,127.0.0.1, got %q", noProxyLower)
		}
	})

	t.Run("sets NO_PROXY and no_proxy when socks socket is configured", func(t *testing.T) {
		tmpDir := t.TempDir()
		socksSocketPath := tmpDir + "/socks.sock"

		socksListener, err := net.Listen("unix", socksSocketPath)
		if err != nil {
			t.Fatalf("failed to listen on socks socket: %v", err)
		}
		defer func() {
			if err := socksListener.Close(); err != nil {
				t.Errorf("failed to close socks listener: %v", err)
			}
		}()
		go func() {
			for {
				conn, err := socksListener.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()

		t.Setenv("NO_PROXY", "")
		t.Setenv("no_proxy", "")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		opts := bootstrapOptions{
			socksSocket: socksSocketPath,
			command:     []string{"echo", "hello"},
		}

		_, err = startBridgesAndSetEnv(ctx, opts)
		if err != nil {
			t.Fatalf("startBridgesAndSetEnv failed: %v", err)
		}

		noProxy := os.Getenv("NO_PROXY")
		if noProxy != "localhost,127.0.0.1" {
			t.Errorf("expected NO_PROXY=localhost,127.0.0.1, got %q", noProxy)
		}
		noProxyLower := os.Getenv("no_proxy")
		if noProxyLower != "localhost,127.0.0.1" {
			t.Errorf("expected no_proxy=localhost,127.0.0.1, got %q", noProxyLower)
		}
	})
}
