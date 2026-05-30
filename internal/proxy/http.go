// Package proxy provides HTTP and SOCKS5 proxy servers with domain filtering.
package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fencesandbox/fence/internal/config"
	"github.com/fencesandbox/fence/internal/fencelog"
)

// FilterFunc determines if a connection to host:port should be allowed.
// Used by SOCKSProxy and legacy callers; HTTPProxy uses RouteFunc instead.
type FilterFunc func(host string, port int) bool

// RouteDecision is the tri-state routing outcome for an HTTP proxy request.
type RouteDecision int

const (
	// RouteDecisionDeny rejects the request with 403. Applied to deniedDomains
	// and to unmatched traffic when no upstream proxy is configured.
	RouteDecisionDeny RouteDecision = iota

	// RouteDecisionDirect connects to the target host directly.
	// Applied to hosts matching allowedDomains.
	RouteDecisionDirect

	// RouteDecisionUpstream forwards the request to the configured upstream
	// proxy. Applied to unmatched (grey-zone) traffic when upstreamProxy is set.
	RouteDecisionUpstream
)

// RouteFunc maps a host:port to a RouteDecision.
type RouteFunc func(host string, port int) RouteDecision

// HTTPProxy is an HTTP/HTTPS proxy server with domain filtering.
type HTTPProxy struct {
	server         *http.Server
	listener       net.Listener
	route          RouteFunc
	upstreamURL    *url.URL // nil when no upstream is configured
	directClient   *http.Client
	upstreamClient *http.Client
	debug          bool
	monitor        bool
	mu             sync.RWMutex
	running        bool
}

// NewHTTPProxy creates a new HTTP proxy with the given route function.
// upstreamURL may be nil when no upstream proxy is configured.
// If monitor is true, only blocked requests are logged.
// If debug is true, all requests and filter rules are logged.
func NewHTTPProxy(route RouteFunc, upstreamURL *url.URL, debug, monitor bool) *HTTPProxy {
	noRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	directTransport := &http.Transport{}
	directClient := &http.Client{Transport: directTransport, Timeout: 30 * time.Second, CheckRedirect: noRedirect}

	var upstreamClient *http.Client
	if upstreamURL != nil {
		upstreamTransport := &http.Transport{Proxy: http.ProxyURL(upstreamURL)}
		upstreamClient = &http.Client{Transport: upstreamTransport, Timeout: 30 * time.Second, CheckRedirect: noRedirect}
	}

	return &HTTPProxy{
		route:          route,
		upstreamURL:    upstreamURL,
		directClient:   directClient,
		upstreamClient: upstreamClient,
		debug:          debug,
		monitor:        monitor,
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

	decision := p.route(host, port)

	switch decision {
	case RouteDecisionDeny:
		p.logRequest("CONNECT", fmt.Sprintf("https://%s:%d", host, port), host, 403, "BLOCKED", time.Since(start))
		http.Error(w, "Connection blocked by network allowlist", http.StatusForbidden)
		return

	case RouteDecisionUpstream:
		if p.upstreamURL == nil {
			p.logRequest("CONNECT", fmt.Sprintf("https://%s:%d", host, port), host, 502, "UPSTREAM_ERROR", time.Since(start))
			http.Error(w, "Bad Gateway: no upstream proxy configured", http.StatusBadGateway)
			return
		}
		p.handleConnectViaUpstream(w, r, host, port, start)
		return
	}

	// RouteDecisionDirect: connect to target directly.
	p.logRequest("CONNECT", fmt.Sprintf("https://%s:%d", host, port), host, 200, "ALLOWED", time.Since(start))

	targetConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second) // #nosec G704 - validated by route() allowlist
	if err != nil {
		p.logDebug("CONNECT dial failed: %s:%d: %v", host, port, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer func() { _ = targetConn.Close() }()

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
		_ = closeWrite(targetConn)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, targetConn)
		_ = closeWrite(clientConn)
	}()

	wg.Wait()
}

// handleConnectViaUpstream tunnels a CONNECT request through the upstream proxy.
func (p *HTTPProxy) handleConnectViaUpstream(w http.ResponseWriter, r *http.Request, host string, port int, start time.Time) {
	// Open a TCP connection to the upstream proxy.
	upstreamAddr := p.upstreamURL.Host
	if p.upstreamURL.Port() == "" {
		switch strings.ToLower(p.upstreamURL.Scheme) {
		case "https":
			upstreamAddr = p.upstreamURL.Hostname() + ":443"
		default:
			upstreamAddr = p.upstreamURL.Hostname() + ":80"
		}
	}

	upstreamConn, err := net.DialTimeout("tcp", upstreamAddr, 10*time.Second)
	if err != nil {
		p.logDebug("UPSTREAM CONNECT dial failed: %s: %v", upstreamAddr, err)
		p.logRequest("CONNECT", fmt.Sprintf("https://%s:%d", host, port), host, 502, "UPSTREAM_ERROR", time.Since(start))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer func() { _ = upstreamConn.Close() }()

	// Send CONNECT to the upstream proxy.
	connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port)
	if _, err := upstreamConn.Write([]byte(connectReq)); err != nil {
		p.logDebug("UPSTREAM CONNECT write failed: %v", err)
		p.logRequest("CONNECT", fmt.Sprintf("https://%s:%d", host, port), host, 502, "UPSTREAM_ERROR", time.Since(start))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Read the upstream proxy's response line.
	upstreamStatus, upstreamReader, err := readProxyResponseStatus(upstreamConn)
	if err != nil {
		p.logDebug("UPSTREAM CONNECT response read failed: %v", err)
		p.logRequest("CONNECT", fmt.Sprintf("https://%s:%d", host, port), host, 502, "UPSTREAM_ERROR", time.Since(start))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	if upstreamStatus != http.StatusOK {
		p.logRequest("CONNECT", fmt.Sprintf("https://%s:%d", host, port), host, upstreamStatus, "UPSTREAM_DENIED", time.Since(start))
		http.Error(w, "Upstream proxy denied connection", http.StatusForbidden)
		return
	}

	p.logRequest("CONNECT", fmt.Sprintf("https://%s:%d", host, port), host, 200, "UPSTREAM_OK", time.Since(start))

	// Hijack the client connection and pipe client <-> upstream.
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

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstreamConn, clientConn)
		_ = closeWrite(upstreamConn)
	}()

	go func() {
		defer wg.Done()
		// Use upstreamReader (not the raw conn) so any bytes buffered during
		// header parsing are not lost before piping begins.
		_, _ = io.Copy(clientConn, upstreamReader)
		_ = closeWrite(clientConn)
	}()

	wg.Wait()
}

// closeWrite attempts a half-close (FIN) on the write side of conn.
// Works for *net.TCPConn and anything that implements CloseWrite.
func closeWrite(conn net.Conn) error {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// readProxyResponseStatus reads the HTTP status line from a raw connection
// (used after sending CONNECT to an upstream proxy) and returns the status code.
// It consumes headers up to and including the blank line, and returns the
// *bufio.Reader that must be used for all subsequent reads from conn — it may
// contain bytes buffered beyond the header terminator.
func readProxyResponseStatus(conn net.Conn) (int, *bufio.Reader, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	br := bufio.NewReader(conn)

	// Read and parse the status line, e.g. "HTTP/1.1 200 Connection Established".
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return 0, nil, fmt.Errorf("reading status line: %w", err)
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return 0, nil, fmt.Errorf("malformed status line: %q", statusLine)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, fmt.Errorf("invalid status code %q: %w", parts[1], err)
	}

	// Drain the response headers.
	tp := textproto.NewReader(br)
	if _, err := tp.ReadMIMEHeader(); err != nil && err.Error() != "EOF" {
		// ReadMIMEHeader returns an error on the blank terminating line only when
		// there are no headers at all; treat that as success.
		if _, ok := err.(textproto.ProtocolError); !ok {
			_ = err // non-fatal; headers are informational here
		}
	}

	return code, br, nil
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

	decision := p.route(host, port)

	if decision == RouteDecisionDeny {
		p.logRequest(r.Method, r.RequestURI, host, 403, "BLOCKED", time.Since(start))
		http.Error(w, "Connection blocked by network allowlist", http.StatusForbidden)
		return
	}

	proxyReq, err := http.NewRequest(r.Method, r.RequestURI, r.Body) // #nosec G704 - validated by route() allowlist
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	proxyReq.Host = targetURL.Host
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Remove hop-by-hop headers
	proxyReq.Header.Del("Proxy-Connection")
	proxyReq.Header.Del("Proxy-Authorization")

	client := p.directClient
	if decision == RouteDecisionUpstream {
		if p.upstreamClient == nil {
			p.logRequest(r.Method, r.RequestURI, host, 502, "UPSTREAM_ERROR", time.Since(start))
			http.Error(w, "Bad Gateway: no upstream proxy configured", http.StatusBadGateway)
			return
		}
		client = p.upstreamClient
	}

	resp, err := client.Do(proxyReq) // #nosec G704 - validated by route() allowlist
	if err != nil {
		action := "ERROR"
		if decision == RouteDecisionUpstream {
			action = "UPSTREAM_ERROR"
		}
		p.logRequest(r.Method, r.RequestURI, host, 502, action, time.Since(start))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	action := "ALLOWED"
	if decision == RouteDecisionUpstream {
		action = "UPSTREAM_OK"
	}
	p.logRequest(r.Method, r.RequestURI, host, resp.StatusCode, action, time.Since(start))
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
	isBlocked := action == "BLOCKED" || action == "ERROR" || action == "UPSTREAM_ERROR" || action == "UPSTREAM_DENIED"

	if p.monitor && !p.debug && !isBlocked {
		return
	}

	if !p.debug && !p.monitor {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	statusIcon := "✓"
	switch action {
	case "BLOCKED", "UPSTREAM_DENIED":
		statusIcon = "✗"
	case "ERROR", "UPSTREAM_ERROR":
		statusIcon = "!"
	case "UPSTREAM", "UPSTREAM_OK":
		statusIcon = "→"
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

// CreateDomainFilter creates a boolean FilterFunc from a config.
// Used by SOCKSProxy and hook-mode evaluator; HTTP proxy uses CreateRouteFunc.
// When debug is true, logs filter rule matches to stderr.
func CreateDomainFilter(cfg *config.Config, debug bool) FilterFunc {
	return func(host string, port int) bool {
		if cfg == nil {
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

// CreateRouteFunc creates a RouteFunc from a config for use by HTTPProxy.
//
// Decision logic:
//   - deniedDomains  → RouteDecisionDeny      (hard block, never forwarded upstream)
//   - allowedDomains → RouteDecisionDirect     (connect directly to target)
//   - otherwise      → RouteDecisionUpstream   (if upstreamProxy configured)
//   - otherwise      → RouteDecisionDeny       (no upstream configured)
func CreateRouteFunc(cfg *config.Config, debug bool) RouteFunc {
	return func(host string, port int) RouteDecision {
		if cfg == nil {
			if debug {
				fencelog.Printf("[fence:filter] No config, denying: %s:%d\n", host, port)
			}
			return RouteDecisionDeny
		}

		// Hard block: deniedDomains always denied, even if upstream is configured.
		for _, denied := range cfg.Network.DeniedDomains {
			if config.MatchesDomain(host, denied) {
				if debug {
					fencelog.Printf("[fence:filter] Denied by rule: %s:%d (matched %s)\n", host, port, denied)
				}
				return RouteDecisionDeny
			}
		}

		// Direct allow.
		for _, allowed := range cfg.Network.AllowedDomains {
			if config.MatchesDomain(host, allowed) {
				if debug {
					fencelog.Printf("[fence:filter] Allowed by rule: %s:%d (matched %s)\n", host, port, allowed)
				}
				return RouteDecisionDirect
			}
		}

		// Grey zone: consult DefaultAction.
		// The second condition is a backward-compatibility path: configs written
		// before DefaultAction existed set only UpstreamProxy. Validate() now
		// requires DefaultAction:"proxy" when UpstreamProxy is set, but configs
		// loaded without going through Validate() (e.g. programmatic use) must
		// still behave sensibly — presence of UpstreamProxy implies proxy intent.
		wantUpstream := cfg.Network.DefaultAction == config.DefaultActionProxy ||
			(cfg.Network.DefaultAction == "" && cfg.Network.UpstreamProxy != "")
		if wantUpstream {
			if debug {
				fencelog.Printf("[fence:filter] No matching rule, forwarding upstream: %s:%d\n", host, port)
			}
			return RouteDecisionUpstream
		}

		if debug {
			fencelog.Printf("[fence:filter] No matching rule, denying: %s:%d\n", host, port)
		}
		return RouteDecisionDeny
	}
}

// URLBlockedError is returned when a URL is blocked by network policy at the
// hook layer. Wrap-mode equivalent is the in-line filter result inside
// CreateDomainFilter; this exists so callers can `errors.As` and surface the
// matched rule.
type URLBlockedError struct {
	URL         string
	Host        string
	MatchedRule string
	Reason      string
}

func (e *URLBlockedError) Error() string {
	if e.MatchedRule == "" {
		return fmt.Sprintf("network access to %q blocked: %s", e.URL, e.Reason)
	}
	return fmt.Sprintf("network access to %q blocked: %s (matched %q)", e.URL, e.Reason, e.MatchedRule)
}

// CheckURL is the hook-time predicate paralleling CreateDomainFilter's
// wrap-mode traffic gate. Both consume cfg.Network.* identically: a URL is
// allowed iff the host matches AllowedDomains and not DeniedDomains; an
// empty AllowedDomains denies everything.
//
// Caveat: hook-time enforcement is deny-by-intent, not deny-by-traffic.
// The agent could embed an allowed host in a path
// (`?next=https://blocked.example/`) and the actual HTTP fetch would not
// be intercepted — wrap mode (with the proxy in the network path) is the
// answer for that. Hook mode catches the agent's declared intent only.
//
// Adapters that want hook-mode to be permissive when network policy is
// unconfigured should ship a template (see internal/templates/hermes.json
// for a worked example) rather than relaxing this predicate.
func CheckURL(rawURL string, cfg *config.Config) error {
	if cfg == nil {
		cfg = config.Default()
	}

	host, err := hostFromURLString(rawURL)
	if err != nil {
		return &URLBlockedError{URL: rawURL, Reason: err.Error()}
	}

	for _, denied := range cfg.Network.DeniedDomains {
		if config.MatchesDomain(host, denied) {
			return &URLBlockedError{
				URL:         rawURL,
				Host:        host,
				MatchedRule: denied,
				Reason:      "deniedDomains",
			}
		}
	}

	for _, allowed := range cfg.Network.AllowedDomains {
		if config.MatchesDomain(host, allowed) {
			return nil
		}
	}

	return &URLBlockedError{
		URL:    rawURL,
		Host:   host,
		Reason: "not in allowedDomains",
	}
}

// hostFromURLString parses rawURL and returns the lower-cased hostname,
// stripped of any port. Returns an error if the URL is unparseable, has no
// host, or uses a non-network scheme (file:, data:, etc.) we'd refuse to
// reason about.
func hostFromURLString(rawURL string) (string, error) {
	if strings.TrimSpace(rawURL) == "" {
		return "", fmt.Errorf("empty url")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "ws", "wss":
	case "":
		return "", fmt.Errorf("url has no scheme")
	default:
		return "", fmt.Errorf("unsupported url scheme %q", parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("url has no host")
	}
	return strings.ToLower(host), nil
}

// ParseUpstreamProxyURL parses the upstream proxy URL from the config.
// Returns nil when no upstream is configured or the URL is invalid.
func ParseUpstreamProxyURL(cfg *config.Config) *url.URL {
	if cfg == nil || cfg.Network.UpstreamProxy == "" {
		return nil
	}
	parsed, err := url.Parse(cfg.Network.UpstreamProxy)
	if err != nil {
		return nil
	}
	return parsed
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
