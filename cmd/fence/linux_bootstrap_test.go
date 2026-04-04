package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Use-Tusk/fence/internal/config"
)

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
		defer ln.Close()

		close(serverReady)

		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				c.Write(buf[:n])
			}(conn)
		}
	}()

	// Wait for server to be ready
	<-serverReady
	time.Sleep(50 * time.Millisecond)

	// Start TCP to Unix bridge
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := bridgeTCPToUnix(ctx, 18080, socketPath); err != nil && err != context.Canceled {
			t.Logf("bridge error: %v", err)
		}
	}()

	// Wait for bridge to start
	time.Sleep(100 * time.Millisecond)

	// Connect via TCP and send data
	conn, err := net.Dial("tcp", "127.0.0.1:18080")
	if err != nil {
		t.Fatalf("failed to connect to bridge: %v", err)
	}
	defer conn.Close()

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
		defer ln.Close()

		close(serverReady)

		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				c.Write(buf[:n])
			}(conn)
		}
	}()

	<-serverReady
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := bridgeTCPToUnix(ctx, 18081, socketPath); err != nil && err != context.Canceled {
			t.Logf("bridge error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Test multiple concurrent connections
	done := make(chan bool, 3)
	for i := 0; i < 3; i++ {
		go func(id int) {
			conn, err := net.Dial("tcp", "127.0.0.1:18081")
			if err != nil {
				t.Errorf("connection %d failed: %v", id, err)
				done <- false
				return
			}
			defer conn.Close()

			msg := "test"
			conn.Write([]byte(msg))

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
		defer ln.Close()
		close(serverReady)

		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	<-serverReady
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- bridgeTCPToUnix(ctx, 18082, socketPath)
	}()

	time.Sleep(100 * time.Millisecond)

	// Cancel the context
	cancel()

	// Verify bridge stops
	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("bridge did not stop after context cancellation")
	}
}

func TestBridgeUnixToTCP(t *testing.T) {
	// Create a TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:18083")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	serverReady := make(chan struct{})
	go func() {
		close(serverReady)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				c.Write(buf[:n])
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
		if err := bridgeUnixToTCP(ctx, socketPath, 18083); err != nil && err != context.Canceled {
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
	defer conn.Close()

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
		defer ln.Close()

		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
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
			defer ln.Close()

			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
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

func TestLoadConfigFromEnv(t *testing.T) {
	t.Run("empty env", func(t *testing.T) {
		os.Unsetenv("FENCE_CONFIG_JSON")
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
