package proxy

import (
	"errors"
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

func TestCheckURL_HookModeDefaultAllow(t *testing.T) {
	// No allowedDomains and no deniedDomains: the user hasn't expressed
	// any network policy, so hook mode treats web fetches as out-of-scope.
	cfg := &config.Config{}
	if err := CheckURL("https://example.com/path", cfg); err != nil {
		t.Fatalf("expected allow when neither list configured, got %v", err)
	}
}

func TestCheckURL_AllowedDomain(t *testing.T) {
	cfg := &config.Config{
		Network: config.NetworkConfig{
			AllowedDomains: []string{"example.com"},
		},
	}
	if err := CheckURL("https://example.com/x", cfg); err != nil {
		t.Errorf("expected allow, got %v", err)
	}
	err := CheckURL("https://blocked.test/", cfg)
	if err == nil {
		t.Fatal("expected deny")
	}
	var blocked *URLBlockedError
	if !errors.As(err, &blocked) || blocked.Reason != "not in allowedDomains" {
		t.Fatalf("expected not-in-allowedDomains, got %v", err)
	}
}

func TestCheckURL_DeniedOverridesAllowed(t *testing.T) {
	cfg := &config.Config{
		Network: config.NetworkConfig{
			AllowedDomains: []string{"*.example.com"},
			DeniedDomains:  []string{"secrets.example.com"},
		},
	}
	if err := CheckURL("https://secrets.example.com/x", cfg); err == nil {
		t.Fatal("expected denied to win")
	}
	if err := CheckURL("https://api.example.com/x", cfg); err != nil {
		t.Errorf("expected sibling under wildcard to allow, got %v", err)
	}
}

func TestCheckURL_RejectsNonHTTPSchemes(t *testing.T) {
	cfg := &config.Config{
		Network: config.NetworkConfig{
			AllowedDomains: []string{"*"},
		},
	}
	cases := []string{
		"file:///etc/passwd",
		"data:text/plain;base64,SGVsbG8=",
		"ftp://ftp.example.com/x",
	}
	for _, raw := range cases {
		if err := CheckURL(raw, cfg); err == nil {
			t.Errorf("expected non-http scheme %q to be denied", raw)
		}
	}
}

func TestCheckURL_DeniedOnlyConfig(t *testing.T) {
	// User wants "block these specific hosts, allow everything else" —
	// when allowedDomains is empty but deniedDomains is set, we still
	// allow non-matching hosts. The proxy filter (wrap mode) would
	// block them; hook mode is intent-only.
	cfg := &config.Config{
		Network: config.NetworkConfig{
			DeniedDomains: []string{"evil.test"},
		},
	}
	if err := CheckURL("https://example.com/x", cfg); err != nil {
		t.Errorf("expected allow when only denied is set, got %v", err)
	}
	if err := CheckURL("https://evil.test/x", cfg); err == nil {
		t.Errorf("expected denied host to be blocked")
	}
}
