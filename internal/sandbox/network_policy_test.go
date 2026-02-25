package sandbox

import (
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

// TestWildcardAllowedDomainsSkipsUnshareNet verifies wildcard semantics
func TestWildcardAllowedDomainsSkipsUnshareNet(t *testing.T) {
	tests := []struct {
		name           string
		allowedDomains []string
		wantWildcard   bool
	}{
		{
			name:           "no domains",
			allowedDomains: []string{},
			wantWildcard:   false,
		},
		{
			name:           "specific domain",
			allowedDomains: []string{"api.openai.com"},
			wantWildcard:   false,
		},
		{
			name:           "wildcard domain",
			allowedDomains: []string{"*"},
			wantWildcard:   true,
		},
		{
			name:           "wildcard with specific domains",
			allowedDomains: []string{"api.openai.com", "*"},
			wantWildcard:   true,
		},
		{
			name:           "wildcard subdomain pattern is not full wildcard",
			allowedDomains: []string{"*.openai.com"},
			wantWildcard:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: tt.allowedDomains,
				},
				Filesystem: config.FilesystemConfig{
					AllowWrite: []string{"/tmp/test"},
				},
			}

			got := hasWildcardAllowedDomain(cfg)
			if got != tt.wantWildcard {
				t.Errorf("hasWildcardAllowedDomain() = %v, want %v", got, tt.wantWildcard)
			}
		})
	}
}

func TestWildcardDetectionLogic(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *config.Config
		expectWildcard bool
	}{
		{
			name:           "nil config",
			cfg:            nil,
			expectWildcard: false,
		},
		{
			name: "empty allowed domains",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{},
				},
			},
			expectWildcard: false,
		},
		{
			name: "specific domains only",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"example.com", "api.openai.com"},
				},
			},
			expectWildcard: false,
		},
		{
			name: "exact star wildcard",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"*"},
				},
			},
			expectWildcard: true,
		},
		{
			name: "star wildcard among others",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"example.com", "*", "api.openai.com"},
				},
			},
			expectWildcard: true,
		},
		{
			name: "prefix wildcard is not star",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"*.example.com"},
				},
			},
			expectWildcard: false,
		},
		{
			name: "star in domain name is not wildcard",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"test*domain.com"},
				},
			},
			expectWildcard: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasWildcardAllowedDomain(tt.cfg)
			if got != tt.expectWildcard {
				t.Errorf("hasWildcardAllowedDomain() = %v, want %v", got, tt.expectWildcard)
			}
		})
	}
}
