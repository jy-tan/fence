package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Use-Tusk/fence/internal/fencelog"
	"github.com/things-go/go-socks5"
)

// SOCKSProxy is a SOCKS5 proxy server with domain filtering.
type SOCKSProxy struct {
	server   *socks5.Server
	listener net.Listener
	filter   FilterFunc
	debug    bool
	monitor  bool
	port     int
}

// NewSOCKSProxy creates a new SOCKS5 proxy with the given filter.
// If monitor is true, only blocked connections are logged.
// If debug is true, all connections are logged.
func NewSOCKSProxy(filter FilterFunc, debug, monitor bool) *SOCKSProxy {
	return &SOCKSProxy{
		filter:  filter,
		debug:   debug,
		monitor: monitor,
	}
}

// fenceRuleSet implements socks5.RuleSet for domain filtering.
type fenceRuleSet struct {
	filter  FilterFunc
	debug   bool
	monitor bool
}

func (r *fenceRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	host := req.DestAddr.FQDN
	if host == "" {
		host = req.DestAddr.IP.String()
	}
	port := req.DestAddr.Port

	allowed := r.filter(host, port)

	shouldLog := r.debug || (r.monitor && !allowed)
	if shouldLog {
		timestamp := time.Now().Format("15:04:05")
		if allowed {
			fencelog.Printf("[fence:socks] %s ✓ CONNECT %s:%d ALLOWED\n", timestamp, host, port)
		} else {
			fencelog.Printf("[fence:socks] %s ✗ CONNECT %s:%d BLOCKED\n", timestamp, host, port)
		}
	}
	return ctx, allowed
}

// Start starts the SOCKS5 proxy on a random available port.
func (p *SOCKSProxy) Start() (int, error) {
	// Create listener first to get a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed to listen: %w", err)
	}
	p.listener = listener
	p.port = listener.Addr().(*net.TCPAddr).Port

	server := socks5.NewServer(
		socks5.WithRule(&fenceRuleSet{
			filter:  p.filter,
			debug:   p.debug,
			monitor: p.monitor,
		}),
	)
	p.server = server

	go func() {
		if err := p.server.Serve(p.listener); err != nil {
			if p.debug {
				fencelog.Printf("[fence:socks] Server error: %v\n", err)
			}
		}
	}()

	if p.debug {
		fencelog.Printf("[fence:socks] SOCKS5 proxy listening on localhost:%d\n", p.port)
	}
	return p.port, nil
}

// Stop stops the SOCKS5 proxy.
func (p *SOCKSProxy) Stop() error {
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// Port returns the port the proxy is listening on.
func (p *SOCKSProxy) Port() int {
	return p.port
}
