package proxy

import (
	"context"
	"net"
	"testing"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

func TestFenceRuleSetAllow(t *testing.T) {
	tests := []struct {
		name    string
		fqdn    string
		ip      net.IP
		port    int
		allowed bool
	}{
		{
			name:    "allow by FQDN",
			fqdn:    "allowed.com",
			port:    443,
			allowed: true,
		},
		{
			name:    "deny by FQDN",
			fqdn:    "blocked.com",
			port:    443,
			allowed: false,
		},
		{
			name:    "fallback to IP when FQDN empty",
			fqdn:    "",
			ip:      net.ParseIP("1.2.3.4"),
			port:    80,
			allowed: false,
		},
		{
			name:    "allow with IP fallback",
			fqdn:    "",
			ip:      net.ParseIP("127.0.0.1"),
			port:    8080,
			allowed: true,
		},
	}

	filter := func(host string, port int) bool {
		return host == "allowed.com" || host == "127.0.0.1"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := &fenceRuleSet{filter: filter, debug: false, monitor: false}
			req := &socks5.Request{
				DestAddr: &statute.AddrSpec{
					FQDN: tt.fqdn,
					IP:   tt.ip,
					Port: tt.port,
				},
			}

			_, allowed := rs.Allow(context.Background(), req)
			if allowed != tt.allowed {
				t.Errorf("Allow() = %v, want %v", allowed, tt.allowed)
			}
		})
	}
}

func TestNewSOCKSProxy(t *testing.T) {
	filter := func(host string, port int) bool { return true }

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
			proxy := NewSOCKSProxy(filter, tt.debug, tt.monitor)
			if proxy == nil {
				t.Fatal("NewSOCKSProxy() returned nil")
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

func TestSOCKSProxyStartStop(t *testing.T) {
	skipIfCannotBind(t)
	filter := func(host string, port int) bool { return true }
	proxy := NewSOCKSProxy(filter, false, false)

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

func TestSOCKSProxyPortBeforeStart(t *testing.T) {
	filter := func(host string, port int) bool { return true }
	proxy := NewSOCKSProxy(filter, false, false)

	if proxy.Port() != 0 {
		t.Errorf("Port() before Start() = %d, want 0", proxy.Port())
	}
}
