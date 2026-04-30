//go:build linux

package sandbox

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// findFreeTCPPort asks the kernel for an unused TCP port on 127.0.0.1, then
// closes the listener so the port is free for the test to claim. The port
// can theoretically be reused before we bind it, but the window is small
// enough for the rare collision to be acceptable.
func findFreeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate test port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// listenAddrFor returns the dotted address the kernel reports as bound for
// the given port, by parsing `ss -ltn`. Returns "" if no such listener is
// found within the deadline.
func listenAddrFor(t *testing.T, port int, deadline time.Time) string {
	t.Helper()
	target := ":" + strconv.Itoa(port)
	for time.Now().Before(deadline) {
		out, err := exec.Command("ss", "-ltnH").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if !strings.Contains(line, target) {
					continue
				}
				fields := strings.Fields(line)
				// `ss -ltnH` lines look like:
				// LISTEN 0 5 127.0.0.1:4096 0.0.0.0:*
				// Local Address:Port is field index 3.
				if len(fields) >= 4 {
					localAddr := fields[3]
					if strings.HasSuffix(localAddr, target) {
						return strings.TrimSuffix(localAddr, target)
					}
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return ""
}

// TestNewReverseBridge_DefaultBindIsLoopback proves the security and
// WSL2-compatibility fix: a bare port (no explicit bind address) maps to a
// host-side socat listening on 127.0.0.1 only, never on *:PORT.
//
// This is the regression test for issue #150 (fence -p PORT not reachable
// from a Windows browser through WSL2's localhost forwarding because the
// host listener was bound on all interfaces).
func TestNewReverseBridge_DefaultBindIsLoopback(t *testing.T) {
	if _, err := exec.LookPath("socat"); err != nil {
		t.Skip("socat not installed; skipping")
	}
	if _, err := exec.LookPath("ss"); err != nil {
		t.Skip("ss not installed; skipping")
	}

	port := findFreeTCPPort(t)
	bridge, err := NewReverseBridge([]ExposedPort{{Port: port}}, false)
	if err != nil {
		t.Fatalf("NewReverseBridge: %v", err)
	}
	defer bridge.Cleanup()

	got := listenAddrFor(t, port, time.Now().Add(2*time.Second))
	if got != "127.0.0.1" {
		t.Fatalf("expected reverse bridge to bind 127.0.0.1, got %q (port %d)", got, port)
	}

	if len(bridge.Exposures) != 1 || bridge.Exposures[0].BindAddress != "127.0.0.1" {
		t.Errorf("bridge.Exposures = %+v, want [{127.0.0.1 %d}]", bridge.Exposures, port)
	}
	if len(bridge.Ports) != 1 || bridge.Ports[0] != port {
		t.Errorf("bridge.Ports = %v, want [%d]", bridge.Ports, port)
	}
}

// TestNewReverseBridge_ExplicitWildcardBindOptIn confirms that 0.0.0.0 still
// works when explicitly requested. This is the escape hatch for users who
// genuinely need LAN exposure (or who are testing reachability from another
// host).
func TestNewReverseBridge_ExplicitWildcardBindOptIn(t *testing.T) {
	if _, err := exec.LookPath("socat"); err != nil {
		t.Skip("socat not installed; skipping")
	}
	if _, err := exec.LookPath("ss"); err != nil {
		t.Skip("ss not installed; skipping")
	}

	port := findFreeTCPPort(t)
	bridge, err := NewReverseBridge([]ExposedPort{{BindAddress: "0.0.0.0", Port: port}}, false)
	if err != nil {
		t.Fatalf("NewReverseBridge: %v", err)
	}
	defer bridge.Cleanup()

	got := listenAddrFor(t, port, time.Now().Add(2*time.Second))
	if got != "0.0.0.0" && got != "*" {
		t.Fatalf("expected reverse bridge to bind 0.0.0.0/*, got %q (port %d)", got, port)
	}
}

// TestNewReverseBridge_IPv6LoopbackBindOptIn verifies that an IPv6 bind
// address routes through TCP6-LISTEN and produces a working [::1]:PORT
// listener. socat 1.7.x has historically been picky about IPv6 family
// auto-detection on TCP-LISTEN; this test pins down the expected behavior
// for the fence-on-IPv6 path.
func TestNewReverseBridge_IPv6LoopbackBindOptIn(t *testing.T) {
	if _, err := exec.LookPath("socat"); err != nil {
		t.Skip("socat not installed; skipping")
	}
	if _, err := exec.LookPath("ss"); err != nil {
		t.Skip("ss not installed; skipping")
	}

	port := findFreeTCPPort(t)
	bridge, err := NewReverseBridge([]ExposedPort{{BindAddress: "::1", Port: port}}, false)
	if err != nil {
		t.Fatalf("NewReverseBridge: %v", err)
	}
	defer bridge.Cleanup()

	got := listenAddrFor(t, port, time.Now().Add(2*time.Second))
	// `ss` renders IPv6 literals with brackets in the Local Address column.
	if got != "[::1]" {
		t.Fatalf("expected reverse bridge to bind [::1], got %q (port %d)", got, port)
	}
}

// TestNewReverseBridge_EmptyExposuresIsNoop verifies the early-return path
// for callers that pass nothing to expose.
func TestNewReverseBridge_EmptyExposuresIsNoop(t *testing.T) {
	bridge, err := NewReverseBridge(nil, false)
	if err != nil {
		t.Fatalf("NewReverseBridge(nil) error: %v", err)
	}
	if bridge != nil {
		t.Errorf("NewReverseBridge(nil) = %+v, want nil", bridge)
	}
}

func TestSocatTCPListenVerb(t *testing.T) {
	cases := []struct {
		bind string
		want string
	}{
		{"127.0.0.1", "TCP4-LISTEN"},
		{"0.0.0.0", "TCP4-LISTEN"},
		{"192.168.1.10", "TCP4-LISTEN"},
		{"::1", "TCP6-LISTEN"},
		{"::", "TCP6-LISTEN"},
		{"2001:db8::1", "TCP6-LISTEN"},
		{"", "TCP4-LISTEN"},          // fallback for non-IP / empty
		{"localhost", "TCP4-LISTEN"}, // CLI rejects this earlier; defensively returns v4
	}

	for _, tc := range cases {
		t.Run(tc.bind, func(t *testing.T) {
			if got := socatTCPListenVerb(tc.bind); got != tc.want {
				t.Errorf("socatTCPListenVerb(%q) = %q, want %q", tc.bind, got, tc.want)
			}
		})
	}
}
