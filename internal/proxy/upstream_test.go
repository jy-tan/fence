package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"io"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Use-Tusk/fence/internal/config"
)

// ---------------------------------------------------------------------------
// CreateRouteFunc tests
// ---------------------------------------------------------------------------

func TestCreateRouteFunc(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		host string
		port int
		want RouteDecision
	}{
		{
			name: "nil config denies",
			cfg:  nil,
			host: "example.com", port: 443,
			want: RouteDecisionDeny,
		},
		{
			name: "allowed domain → direct",
			cfg: &config.Config{Network: config.NetworkConfig{
				AllowedDomains: []string{"example.com"},
			}},
			host: "example.com", port: 443,
			want: RouteDecisionDirect,
		},
		{
			name: "denied domain → deny (even with upstream configured)",
			cfg: &config.Config{Network: config.NetworkConfig{
				AllowedDomains: []string{"example.com"},
				DeniedDomains:  []string{"evil.com"},
				UpstreamProxy:  "http://127.0.0.1:8080",
			}},
			host: "evil.com", port: 443,
			want: RouteDecisionDeny,
		},
		{
			name: "denied overrides allowed (even with upstream)",
			cfg: &config.Config{Network: config.NetworkConfig{
				AllowedDomains: []string{"example.com"},
				DeniedDomains:  []string{"example.com"},
				UpstreamProxy:  "http://127.0.0.1:8080",
			}},
			host: "example.com", port: 443,
			want: RouteDecisionDeny,
		},
		{
			name: "unmatched host, no upstream → deny",
			cfg: &config.Config{Network: config.NetworkConfig{
				AllowedDomains: []string{"example.com"},
			}},
			host: "other.com", port: 443,
			want: RouteDecisionDeny,
		},
		{
			name: "unmatched host, upstream configured → upstream",
			cfg: &config.Config{Network: config.NetworkConfig{
				AllowedDomains: []string{"example.com"},
				UpstreamProxy:  "http://127.0.0.1:8080",
			}},
			host: "other.com", port: 443,
			want: RouteDecisionUpstream,
		},
		{
			name: "wildcard allowed domain → direct",
			cfg: &config.Config{Network: config.NetworkConfig{
				AllowedDomains: []string{"*.example.com"},
				UpstreamProxy:  "http://127.0.0.1:8080",
			}},
			host: "api.example.com", port: 443,
			want: RouteDecisionDirect,
		},
		{
			name: "star wildcard → direct",
			cfg: &config.Config{Network: config.NetworkConfig{
				AllowedDomains: []string{"*"},
			}},
			host: "anything.com", port: 443,
			want: RouteDecisionDirect,
		},
		{
			name: "empty allowed list, upstream configured → upstream",
			cfg: &config.Config{Network: config.NetworkConfig{
				AllowedDomains: []string{},
				UpstreamProxy:  "http://127.0.0.1:8080",
			}},
			host: "example.com", port: 443,
			want: RouteDecisionUpstream,
		},
		{
			name: "empty allowed list, no upstream → deny",
			cfg: &config.Config{Network: config.NetworkConfig{
				AllowedDomains: []string{},
			}},
			host: "example.com", port: 443,
			want: RouteDecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := CreateRouteFunc(tt.cfg, false)
			got := route(tt.host, tt.port)
			if got != tt.want {
				t.Errorf("CreateRouteFunc()(%q, %d) = %v, want %v", tt.host, tt.port, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Config validation tests for UpstreamProxy
// ---------------------------------------------------------------------------

func TestNetworkConfigUpstreamProxyValidation(t *testing.T) {
	tests := []struct {
		name      string
		upstream  string
		wantError bool
	}{
		{"empty string is valid (disabled)", "", false},
		{"valid http URL", "http://127.0.0.1:8080", false},
		{"valid https URL", "https://proxy.example.com:8080", false},
		{"valid http with hostname", "http://mitm.local:8080", false},
		{"missing scheme", "127.0.0.1:8080", true},
		{"unsupported scheme socks5", "socks5://127.0.0.1:1080", true},
		{"no host", "http://", true},
		{"ftp scheme", "ftp://proxy.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"example.com"},
					UpstreamProxy:  tt.upstream,
				},
			}
			err := cfg.Validate()
			if tt.wantError && err == nil {
				t.Errorf("Validate() expected error for upstreamProxy=%q, got nil", tt.upstream)
			}
			if !tt.wantError && err != nil {
				t.Errorf("Validate() unexpected error for upstreamProxy=%q: %v", tt.upstream, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseUpstreamProxyURL tests
// ---------------------------------------------------------------------------

func TestParseUpstreamProxyURL(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		wantNil  bool
		wantHost string
	}{
		{"nil config → nil", nil, true, ""},
		{"empty upstreamProxy → nil", &config.Config{}, true, ""},
		{
			"valid URL parsed",
			&config.Config{Network: config.NetworkConfig{UpstreamProxy: "http://127.0.0.1:8080"}},
			false, "127.0.0.1:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseUpstreamProxyURL(tt.cfg)
			if tt.wantNil {
				if got != nil {
					t.Errorf("ParseUpstreamProxyURL() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("ParseUpstreamProxyURL() = nil, want non-nil")
			}
			if got.Host != tt.wantHost {
				t.Errorf("ParseUpstreamProxyURL().Host = %q, want %q", got.Host, tt.wantHost)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// readProxyResponseStatus tests
// ---------------------------------------------------------------------------

func TestReadProxyResponseStatus(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		wantStatus int
		wantErr    bool
	}{
		{
			name:       "200 with headers",
			response:   "HTTP/1.1 200 Connection Established\r\nProxy-Agent: test\r\n\r\n",
			wantStatus: 200,
		},
		{
			name:       "407 proxy auth required",
			response:   "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
			wantStatus: 407,
		},
		{
			name:       "200 no extra headers",
			response:   "HTTP/1.1 200 OK\r\n\r\n",
			wantStatus: 200,
		},
		{
			// bare \n\n (no \r) — the old byte-by-byte drain loop would hang
			name:       "200 bare LF terminator",
			response:   "HTTP/1.1 200 OK\n\n",
			wantStatus: 200,
		},
		{
			name:     "malformed status line",
			response: "GARBAGE\r\n\r\n",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use a pair of connected net.Conn so we can feed bytes to the reader
			server, client := net.Pipe()
			defer func() { _ = server.Close() }()
			defer func() { _ = client.Close() }()

			go func() {
				_, _ = server.Write([]byte(tt.response))
				_ = server.Close()
			}()

			status, _, err := readProxyResponseStatus(client)
			if tt.wantErr {
				if err == nil {
					t.Errorf("readProxyResponseStatus() expected error, got status %d", status)
				}
				return
			}
			if err != nil {
				t.Fatalf("readProxyResponseStatus() unexpected error: %v", err)
			}
			if status != tt.wantStatus {
				t.Errorf("readProxyResponseStatus() = %d, want %d", status, tt.wantStatus)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HTTPProxy routing integration tests (using a fake upstream)
// ---------------------------------------------------------------------------

// skipIfCannotBind skips the test when the process cannot bind a TCP listener
// (e.g. when running inside a fence sandbox).
func skipIfCannotBind(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping: cannot bind TCP listener (likely running inside sandbox): %v", err)
	}
	_ = ln.Close()
}

// startFakeUpstreamProxy starts a minimal HTTP proxy that records the requests
// it receives and responds with the given status for CONNECT, or echoes for HTTP.
func startFakeUpstreamProxy(t *testing.T, connectStatus int) (addr string, connectRequests *[]string, cleanup func()) {
	t.Helper()
	requests := &[]string{}
	var mu sync.Mutex

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake upstream listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				mu.Lock()
				*requests = append(*requests, fmt.Sprintf("%s %s", req.Method, req.Host))
				mu.Unlock()
				if req.Method == http.MethodConnect {
					if connectStatus == http.StatusOK {
						_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
						// Keep connection open for piping (drain it)
						buf := make([]byte, 4096)
						for {
							_, err := c.Read(buf)
							if err != nil {
								return
							}
						}
					} else {
						_, _ = fmt.Fprintf(c, "HTTP/1.1 %d Denied\r\n\r\n", connectStatus)
					}
				}
			}(conn)
		}
	}()

	return ln.Addr().String(), requests, func() { _ = ln.Close() }
}

func TestHTTPProxy_RouteDecisions(t *testing.T) {
	skipIfCannotBind(t)
	upstreamAddr, connectRequests, cleanupUpstream := startFakeUpstreamProxy(t, http.StatusOK)
	defer cleanupUpstream()

	upstreamURL, _ := url.Parse("http://" + upstreamAddr)

	cfg := &config.Config{
		Network: config.NetworkConfig{
			AllowedDomains: []string{"allowed.example.com"},
			DeniedDomains:  []string{"denied.example.com"},
			UpstreamProxy:  "http://" + upstreamAddr,
		},
	}
	route := CreateRouteFunc(cfg, false)
	proxy := NewHTTPProxy(route, upstreamURL, false, false)

	port, err := proxy.Start()
	if err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Stop() //nolint:errcheck

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)

	t.Run("CONNECT to denied domain returns 403", func(t *testing.T) {
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer func() { _ = conn.Close() }()

		_, _ = fmt.Fprintf(conn, "CONNECT denied.example.com:443 HTTP/1.1\r\nHost: denied.example.com:443\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("CONNECT to unmatched domain forwarded to upstream", func(t *testing.T) {
		before := len(*connectRequests)
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer func() { _ = conn.Close() }()

		_, _ = fmt.Fprintf(conn, "CONNECT grey.example.com:443 HTTP/1.1\r\nHost: grey.example.com:443\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		after := len(*connectRequests)
		if after <= before {
			t.Errorf("upstream received no CONNECT request")
		}
	})

	t.Run("CONNECT to allowed domain does not go to upstream", func(t *testing.T) {
		before := len(*connectRequests)

		// We can't actually complete a TLS handshake in a unit test, but we
		// can verify the proxy dials the target directly (not upstream) by
		// checking that the upstream received no new request.
		// We start a local echo server to be the "allowed" target.
		targetLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("target listen: %v", err)
		}
		defer func() { _ = targetLn.Close() }()
		targetPort := targetLn.Addr().(*net.TCPAddr).Port

		go func() {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			buf := make([]byte, 256)
			n, _ := c.Read(buf)
			_, _ = c.Write(buf[:n]) // echo
		}()

		// Use a route that directs 127.0.0.1 to direct
		directRoute := func(host string, port int) RouteDecision {
			if host == "127.0.0.1" {
				return RouteDecisionDirect
			}
			return RouteDecisionDeny
		}
		directProxy := NewHTTPProxy(directRoute, upstreamURL, false, false)
		directPort, err := directProxy.Start()
		if err != nil {
			t.Fatalf("direct proxy start: %v", err)
		}
		defer directProxy.Stop() //nolint:errcheck

		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", directPort))
		if err != nil {
			t.Fatalf("dial direct proxy: %v", err)
		}
		defer func() { _ = conn.Close() }()

		_, _ = fmt.Fprintf(conn, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", targetPort, targetPort)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}

		// Upstream should NOT have received a new request
		after := len(*connectRequests)
		if after != before {
			t.Errorf("upstream received unexpected request for direct route")
		}
	})
}

func TestHTTPProxy_UpstreamDeniesConnect(t *testing.T) {
	skipIfCannotBind(t)
	upstreamAddr, _, cleanupUpstream := startFakeUpstreamProxy(t, http.StatusForbidden)
	defer cleanupUpstream()

	upstreamURL, _ := url.Parse("http://" + upstreamAddr)
	route := func(host string, port int) RouteDecision { return RouteDecisionUpstream }

	proxy := NewHTTPProxy(route, upstreamURL, false, false)
	port, err := proxy.Start()
	if err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Stop() //nolint:errcheck

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT target.example.com:443 HTTP/1.1\r\nHost: target.example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	// Upstream denied → fence should return 403 to client
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHTTPProxy_PlainHTTPViaUpstream(t *testing.T) {
	skipIfCannotBind(t)
	// Start a fake origin server
	originLn, _ := net.Listen("tcp", "127.0.0.1:0")
	originServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("hello from origin"))
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = originServer.Serve(originLn) }()
	defer func() { _ = originServer.Close() }()
	originPort := originLn.Addr().(*net.TCPAddr).Port

	// Start a minimal upstream proxy that forwards plain HTTP
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	upstreamServer := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Forward to the real origin
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d%s", originPort, r.URL.Path)) //nolint:gosec // test helper with controlled input
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			w.WriteHeader(resp.StatusCode)
			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			_, _ = w.Write(buf[:n])
		}),
	}
	go func() { _ = upstreamServer.Serve(upstreamLn) }()
	defer func() { _ = upstreamServer.Close() }()

	upstreamURL, _ := url.Parse("http://" + upstreamLn.Addr().String())

	// All traffic goes upstream
	route := func(host string, port int) RouteDecision { return RouteDecisionUpstream }
	p := NewHTTPProxy(route, upstreamURL, false, false)
	proxyPort, err := p.Start()
	if err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer p.Stop() //nolint:errcheck

	// Make request through fence proxy → upstream proxy → origin
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", originPort))
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHTTPProxy_UnreachableUpstream_Returns502(t *testing.T) {
	skipIfCannotBind(t)

	// Pick a port that is definitely not listening.
	freeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	deadPort := freeLn.Addr().(*net.TCPAddr).Port
	_ = freeLn.Close() // release it immediately — nothing will listen there

	upstreamURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", deadPort))
	route := func(host string, port int) RouteDecision { return RouteDecisionUpstream }

	proxy := NewHTTPProxy(route, upstreamURL, false, false)
	port, err := proxy.Start()
	if err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Stop() //nolint:errcheck

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT target.example.com:443 HTTP/1.1\r\nHost: target.example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Buffered-reader correctness: bytes after the header terminator must not be lost
// ---------------------------------------------------------------------------

// TestReadProxyResponseStatus_BufferedBytesPreserved verifies that any bytes
// the upstream sends immediately after the blank header line are still
// accessible via the returned *bufio.Reader and not silently discarded.
func TestReadProxyResponseStatus_BufferedBytesPreserved(t *testing.T) {
	// Simulate an upstream that writes the CONNECT response and then
	// immediately sends the first bytes of the tunnelled TLS handshake.
	earlyData := []byte("TLS-early-data")
	response := append(
		[]byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: test\r\n\r\n"),
		earlyData...,
	)

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	go func() {
		_, _ = server.Write(response)
		_ = server.Close()
	}()

	status, br, err := readProxyResponseStatus(client)
	if err != nil {
		t.Fatalf("readProxyResponseStatus() unexpected error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	// The early data must still be readable from the returned bufio.Reader.
	got := make([]byte, len(earlyData))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("reading buffered early data: %v", err)
	}
	if string(got) != string(earlyData) {
		t.Errorf("buffered bytes = %q, want %q", got, earlyData)
	}
}

// TestHTTPProxy_ConnectUpstream_EarlyDataForwarded verifies the end-to-end
// path: when an upstream proxy sends bytes immediately after
// "200 Connection Established", those bytes must reach the client through the
// pipe — not be lost in the bufio.Reader used during header parsing.
func TestHTTPProxy_ConnectUpstream_EarlyDataForwarded(t *testing.T) {
	skipIfCannotBind(t)

	earlyData := []byte("early-payload-from-upstream")

	// Fake upstream: after accepting the CONNECT it sends early data and then
	// drains the connection so the pipe goroutines can complete cleanly.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer func() { _ = upstreamLn.Close() }()

	go func() {
		c, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()

		// Consume the CONNECT request.
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}

		// Respond with 200 and flush early data in one write so it is
		// likely buffered together in the receiver's bufio.Reader.
		msg := append([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"), earlyData...)
		_, _ = c.Write(msg)

		// Keep connection open until the client side closes.
		buf := make([]byte, 256)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()

	upstreamURL, _ := url.Parse("http://" + upstreamLn.Addr().String())
	route := func(host string, port int) RouteDecision { return RouteDecisionUpstream }
	proxy := NewHTTPProxy(route, upstreamURL, false, false)

	proxyPort, err := proxy.Start()
	if err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Stop() //nolint:errcheck

	// Connect a raw client through the fence proxy.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send CONNECT and read the 200 response.
	_, _ = fmt.Fprintf(conn, "CONNECT target.example.com:443 HTTP/1.1\r\nHost: target.example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	// Read the early data that the upstream sent right after its 200.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(earlyData))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading early data from proxied conn: %v", err)
	}
	if string(got) != string(earlyData) {
		t.Errorf("early data = %q, want %q", got, earlyData)
	}
}
