// Package proxy provides HTTP and SOCKS5 proxy servers with domain filtering.
package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/fencelog"
)

// FilterFunc determines if a connection to host:port should be allowed.
type FilterFunc func(host string, port int) bool

// HTTPProxy is an HTTP/HTTPS proxy server with domain filtering.
type HTTPProxy struct {
	server   *http.Server
	listener net.Listener
	filter   FilterFunc
	debug    bool
	monitor  bool
	mu       sync.RWMutex
	running  bool
}

// NewHTTPProxy creates a new HTTP proxy with the given filter.
// If monitor is true, only blocked requests are logged.
// If debug is true, all requests and filter rules are logged.
func NewHTTPProxy(filter FilterFunc, debug, monitor bool) *HTTPProxy {
	return &HTTPProxy{
		filter:  filter,
		debug:   debug,
		monitor: monitor,
	}
}

// Start starts the HTTP proxy on a random available port.
func (p *HTTPProxy) Start() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed to listen: %w", err)
	}

	p.listener = listener
	p.server = &http.Server{
		Handler:           http.HandlerFunc(p.handleRequest),
		ReadHeaderTimeout: 10 * time.Second,
	}

	p.mu.Lock()
	p.running = true
	p.mu.Unlock()

	go func() {
		if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			p.logDebug("HTTP proxy server error: %v", err)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	p.logDebug("HTTP proxy listening on localhost:%d", addr.Port)
	return addr.Port, nil
}

// Stop stops the HTTP proxy.
func (p *HTTPProxy) Stop() error {
	p.mu.Lock()
	p.running = false
	p.mu.Unlock()

	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.server.Shutdown(ctx)
	}
	return nil
}

// Port returns the port the proxy is listening on.
func (p *HTTPProxy) Port() int {
	if p.listener == nil {
		return 0
	}
	return p.listener.Addr().(*net.TCPAddr).Port
}

func (p *HTTPProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleConnect handles HTTPS CONNECT requests (tunnel).
func (p *HTTPProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		portStr = "443"
	}

	port := 443
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	// Check if allowed
	if !p.filter(host, port) {
		p.logRequest("CONNECT", fmt.Sprintf("https://%s:%d", host, port), host, 403, "BLOCKED", time.Since(start))
		http.Error(w, "Connection blocked by network allowlist", http.StatusForbidden)
		return
	}

	p.logRequest("CONNECT", fmt.Sprintf("https://%s:%d", host, port), host, 200, "ALLOWED", time.Since(start))

	// Connect to target
	targetConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
	if err != nil {
		p.logDebug("CONNECT dial failed: %s:%d: %v", host, port, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer func() { _ = targetConn.Close() }()

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Pipe data bidirectionally
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, targetConn)
	}()

	wg.Wait()
}

// handleHTTP handles regular HTTP proxy requests.
func (p *HTTPProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	targetURL, err := url.Parse(r.RequestURI)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	host := targetURL.Hostname()
	port := 80
	if targetURL.Port() != "" {
		if p, err := strconv.Atoi(targetURL.Port()); err == nil {
			port = p
		}
	} else if targetURL.Scheme == "https" {
		port = 443
	}

	if !p.filter(host, port) {
		p.logRequest(r.Method, r.RequestURI, host, 403, "BLOCKED", time.Since(start))
		http.Error(w, "Connection blocked by network allowlist", http.StatusForbidden)
		return
	}

	// Create new request and copy headers
	proxyReq, err := http.NewRequest(r.Method, r.RequestURI, r.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}
	proxyReq.Host = targetURL.Host

	// Remove hop-by-hop headers
	proxyReq.Header.Del("Proxy-Connection")
	proxyReq.Header.Del("Proxy-Authorization")

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		p.logRequest(r.Method, r.RequestURI, host, 502, "ERROR", time.Since(start))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	p.logRequest(r.Method, r.RequestURI, host, resp.StatusCode, "ALLOWED", time.Since(start))
}

func (p *HTTPProxy) logDebug(format string, args ...interface{}) {
	if p.debug {
		fencelog.Printf("[fence:http] "+format+"\n", args...)
	}
}

// logRequest logs a detailed request entry.
// In monitor mode (-m), only blocked/error requests are logged.
// In debug mode (-d), all requests are logged.
func (p *HTTPProxy) logRequest(method, url, host string, status int, action string, duration time.Duration) {
	isBlocked := action == "BLOCKED" || action == "ERROR"

	if p.monitor && !p.debug && !isBlocked {
		return
	}

	if !p.debug && !p.monitor {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	statusIcon := "✓"
	switch action {
	case "BLOCKED":
		statusIcon = "✗"
	case "ERROR":
		statusIcon = "!"
	}
	fencelog.Printf("[fence:http] %s %s %-7s %d %s %s (%v)\n", timestamp, statusIcon, method, status, host, truncateURL(url, 60), duration.Round(time.Millisecond))
}

// truncateURL shortens a URL for display.
func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}
	return url[:maxLen-3] + "..."
}

// CreateDomainFilter creates a filter function from a config.
// When debug is true, logs filter rule matches to stderr.
func CreateDomainFilter(cfg *config.Config, debug bool) FilterFunc {
	return func(host string, port int) bool {
		if cfg == nil {
			// No config = deny all
			if debug {
				fencelog.Printf("[fence:filter] No config, denying: %s:%d\n", host, port)
			}
			return false
		}

		// Check denied domains first
		for _, denied := range cfg.Network.DeniedDomains {
			if config.MatchesDomain(host, denied) {
				if debug {
					fencelog.Printf("[fence:filter] Denied by rule: %s:%d (matched %s)\n", host, port, denied)
				}
				return false
			}
		}

		// Check allowed domains
		for _, allowed := range cfg.Network.AllowedDomains {
			if config.MatchesDomain(host, allowed) {
				if debug {
					fencelog.Printf("[fence:filter] Allowed by rule: %s:%d (matched %s)\n", host, port, allowed)
				}
				return true
			}
		}

		if debug {
			fencelog.Printf("[fence:filter] No matching rule, denying: %s:%d\n", host, port)
		}
		return false
	}
}

// GetHostFromRequest extracts the hostname from a request.
func GetHostFromRequest(r *http.Request) string {
	host := r.Host
	if h := r.URL.Hostname(); h != "" {
		host = h
	}
	// Strip port
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}
