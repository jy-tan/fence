package proxy

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

func TestTruncateURL(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		maxLen int
		want   string
	}{
		{"short url", "https://example.com", 50, "https://example.com"},
		{"exact length", "https://example.com", 19, "https://example.com"},
		{"needs truncation", "https://example.com/very/long/path/to/resource", 30, "https://example.com/very/lo..."},
		{"empty url", "", 50, ""},
		{"very short max", "https://example.com", 10, "https:/..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateURL(tt.url, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateURL(%q, %d) = %q, want %q", tt.url, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestGetHostFromRequest(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		urlStr   string
		wantHost string
	}{
		{
			name:     "host header only",
			host:     "example.com",
			urlStr:   "/path",
			wantHost: "example.com",
		},
		{
			name:     "host header with port",
			host:     "example.com:8080",
			urlStr:   "/path",
			wantHost: "example.com",
		},
		{
			name:     "full URL overrides host",
			host:     "other.com",
			urlStr:   "http://example.com/path",
			wantHost: "example.com",
		},
		{
			name:     "url with port",
			host:     "other.com",
			urlStr:   "http://example.com:9000/path",
			wantHost: "example.com",
		},
		{
			name:     "ipv6 host",
			host:     "[::1]:8080",
			urlStr:   "/path",
			wantHost: "[::1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedURL, _ := url.Parse(tt.urlStr)
			req := &http.Request{
				Host: tt.host,
				URL:  parsedURL,
			}

			got := GetHostFromRequest(req)
			if got != tt.wantHost {
				t.Errorf("GetHostFromRequest() = %q, want %q", got, tt.wantHost)
			}
		})
	}
}

func TestCreateDomainFilter(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		host    string
		port    int
		allowed bool
	}{
		{
			name:    "nil config denies all",
			cfg:     nil,
			host:    "example.com",
			port:    443,
			allowed: false,
		},
		{
			name: "allowed domain",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"example.com"},
				},
			},
			host:    "example.com",
			port:    443,
			allowed: true,
		},
		{
			name: "denied domain takes precedence",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"example.com"},
					DeniedDomains:  []string{"example.com"},
				},
			},
			host:    "example.com",
			port:    443,
			allowed: false,
		},
		{
			name: "wildcard allowed",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"*.example.com"},
				},
			},
			host:    "api.example.com",
			port:    443,
			allowed: true,
		},
		{
			name: "wildcard denied",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"*.example.com"},
					DeniedDomains:  []string{"*.blocked.example.com"},
				},
			},
			host:    "api.blocked.example.com",
			port:    443,
			allowed: false,
		},
		{
			name: "unmatched domain denied",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"example.com"},
				},
			},
			host:    "other.com",
			port:    443,
			allowed: false,
		},
		{
			name: "empty allowed list denies all",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{},
				},
			},
			host:    "example.com",
			port:    443,
			allowed: false,
		},
		{
			name: "star wildcard allows all",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"*"},
				},
			},
			host:    "any-domain.example.com",
			port:    443,
			allowed: true,
		},
		{
			name: "star wildcard with deny list",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"*"},
					DeniedDomains:  []string{"blocked.com"},
				},
			},
			host:    "blocked.com",
			port:    443,
			allowed: false,
		},
		{
			name: "star wildcard allows non-denied",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"*"},
					DeniedDomains:  []string{"blocked.com"},
				},
			},
			host:    "allowed.com",
			port:    443,
			allowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := CreateDomainFilter(tt.cfg, false)
			got := filter(tt.host, tt.port)
			if got != tt.allowed {
				t.Errorf("CreateDomainFilter() filter(%q, %d) = %v, want %v", tt.host, tt.port, got, tt.allowed)
			}
		})
	}
}

func TestCreateDomainFilterCaseInsensitive(t *testing.T) {
	cfg := &config.Config{
		Network: config.NetworkConfig{
			AllowedDomains: []string{"Example.COM"},
		},
	}

	filter := CreateDomainFilter(cfg, false)

	tests := []struct {
		host    string
		allowed bool
	}{
		{"example.com", true},
		{"EXAMPLE.COM", true},
		{"Example.Com", true},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := filter(tt.host, 443)
			if got != tt.allowed {
				t.Errorf("filter(%q) = %v, want %v", tt.host, got, tt.allowed)
			}
		})
	}
}

func TestNewHTTPProxy(t *testing.T) {
	filter := func(host string, port int) RouteDecision { return RouteDecisionDirect }

	tests := []struct {
		name    string
		debug   bool
		monitor bool
	}{
		{"default", false, false},
		{"debug mode", true, false},
		{"monitor mode", false, true},
		{"both modes", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := NewHTTPProxy(filter, nil, tt.debug, tt.monitor)
			if proxy == nil {
				t.Fatal("NewHTTPProxy() returned nil")
			}
			if proxy.debug != tt.debug {
				t.Errorf("debug = %v, want %v", proxy.debug, tt.debug)
			}
			if proxy.monitor != tt.monitor {
				t.Errorf("monitor = %v, want %v", proxy.monitor, tt.monitor)
			}
		})
	}
}

func TestHTTPProxyStartStop(t *testing.T) {
	skipIfCannotBind(t)
	filter := func(host string, port int) RouteDecision { return RouteDecisionDirect }
	proxy := NewHTTPProxy(filter, nil, false, false)

	port, err := proxy.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if port <= 0 {
		t.Errorf("Start() returned invalid port: %d", port)
	}

	if proxy.Port() != port {
		t.Errorf("Port() = %d, want %d", proxy.Port(), port)
	}

	if err := proxy.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestHTTPProxyPortBeforeStart(t *testing.T) {
	filter := func(host string, port int) RouteDecision { return RouteDecisionDirect }
	proxy := NewHTTPProxy(filter, nil, false, false)

	if proxy.Port() != 0 {
		t.Errorf("Port() before Start() = %d, want 0", proxy.Port())
	}
}
