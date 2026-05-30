package proxy

import (
	"errors"
	"testing"

	"github.com/fencesandbox/fence/internal/config"
)

func TestCheckURL_EmptyPolicyDenies(t *testing.T) {
	// Hook-mode is deny-by-default for parity with wrap-mode's proxy
	// filter (CreateDomainFilter denies anything not in AllowedDomains).
	// The documented fix for users who want broad allowance is to extend
	// a Hermes-shaped template, not to relax this predicate.
	cfg := &config.Config{}
	err := CheckURL("https://example.com/path", cfg)
	if err == nil {
		t.Fatal("expected deny for unconfigured policy")
	}
	var blocked *URLBlockedError
	if !errors.As(err, &blocked) || blocked.Reason != "not in allowedDomains" {
		t.Fatalf("expected not-in-allowedDomains, got %v", err)
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

func TestCheckURL_DeniedWithoutAllowedDeniesAll(t *testing.T) {
	// Symmetry with CreateDomainFilter: an empty allowedDomains is a
	// total deny regardless of what's in deniedDomains. The denied list
	// is just an extra precedence layer for users who want defence in
	// depth against patterns inside an explicitly allowed wildcard.
	cfg := &config.Config{
		Network: config.NetworkConfig{
			DeniedDomains: []string{"evil.test"},
		},
	}
	if err := CheckURL("https://example.com/x", cfg); err == nil {
		t.Errorf("expected deny when allowedDomains is empty")
	}
	if err := CheckURL("https://evil.test/x", cfg); err == nil {
		t.Errorf("expected denied host to be blocked")
	}
}
