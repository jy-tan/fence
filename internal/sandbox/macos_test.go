package sandbox

import (
	"strings"
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

// TestMacOS_WildcardAllowedDomainsRelaxesNetwork verifies that when allowedDomains
// contains "*", the macOS sandbox profile allows direct network connections.
func TestMacOS_WildcardAllowedDomainsRelaxesNetwork(t *testing.T) {
	tests := []struct {
		name                     string
		allowedDomains           []string
		wantNetworkRestricted    bool
		wantAllowNetworkOutbound bool
	}{
		{
			name:                     "no domains - network restricted",
			allowedDomains:           []string{},
			wantNetworkRestricted:    true,
			wantAllowNetworkOutbound: false,
		},
		{
			name:                     "specific domain - network restricted",
			allowedDomains:           []string{"api.openai.com"},
			wantNetworkRestricted:    true,
			wantAllowNetworkOutbound: false,
		},
		{
			name:                     "wildcard domain - network unrestricted",
			allowedDomains:           []string{"*"},
			wantNetworkRestricted:    false,
			wantAllowNetworkOutbound: true,
		},
		{
			name:                     "wildcard with specific domains - network unrestricted",
			allowedDomains:           []string{"api.openai.com", "*"},
			wantNetworkRestricted:    false,
			wantAllowNetworkOutbound: true,
		},
		{
			name:                     "wildcard subdomain pattern - network restricted",
			allowedDomains:           []string{"*.openai.com"},
			wantNetworkRestricted:    true,
			wantAllowNetworkOutbound: false,
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

			// Generate the sandbox profile parameters
			params := buildMacOSParamsForTest(cfg)

			if params.NeedsNetworkRestriction != tt.wantNetworkRestricted {
				t.Errorf("NeedsNetworkRestriction = %v, want %v",
					params.NeedsNetworkRestriction, tt.wantNetworkRestricted)
			}

			// Generate the actual profile and check its contents
			profile := GenerateSandboxProfile(params)

			// When network is unrestricted, profile should allow network* (all network ops)
			if tt.wantAllowNetworkOutbound {
				if !strings.Contains(profile, "(allow network*)") {
					t.Errorf("expected unrestricted network profile to contain '(allow network*)', got:\n%s", profile)
				}
			} else {
				// When network is restricted, profile should NOT have blanket allow
				if strings.Contains(profile, "(allow network*)") {
					t.Errorf("expected restricted network profile to NOT contain blanket '(allow network*)'")
				}
			}
		})
	}
}

// buildMacOSParamsForTest is a helper to build MacOSSandboxParams from config,
// replicating the logic in WrapCommandMacOS for testing.
func buildMacOSParamsForTest(cfg *config.Config) MacOSSandboxParams {
	hasWildcardAllow := false
	for _, d := range cfg.Network.AllowedDomains {
		if d == "*" {
			hasWildcardAllow = true
			break
		}
	}

	needsNetwork := len(cfg.Network.AllowedDomains) > 0 || len(cfg.Network.DeniedDomains) > 0
	allowPaths := append(GetDefaultWritePaths(), cfg.Filesystem.AllowWrite...)
	allowLocalBinding := cfg.Network.AllowLocalBinding
	allowLocalOutbound := allowLocalBinding
	if cfg.Network.AllowLocalOutbound != nil {
		allowLocalOutbound = *cfg.Network.AllowLocalOutbound
	}

	needsNetworkRestriction := !hasWildcardAllow && (needsNetwork || len(cfg.Network.AllowedDomains) == 0)

	return MacOSSandboxParams{
		Command:                 "echo test",
		NeedsNetworkRestriction: needsNetworkRestriction,
		HTTPProxyPort:           8080,
		SOCKSProxyPort:          1080,
		AllowUnixSockets:        cfg.Network.AllowUnixSockets,
		AllowAllUnixSockets:     cfg.Network.AllowAllUnixSockets,
		AllowLocalBinding:       allowLocalBinding,
		AllowLocalOutbound:      allowLocalOutbound,
		DefaultDenyRead:         cfg.Filesystem.DefaultDenyRead,
		ReadAllowPaths:          cfg.Filesystem.AllowRead,
		ReadDenyPaths:           cfg.Filesystem.DenyRead,
		WriteAllowPaths:         allowPaths,
		WriteDenyPaths:          cfg.Filesystem.DenyWrite,
		AllowPty:                cfg.AllowPty,
		AllowGitConfig:          cfg.Filesystem.AllowGitConfig,
	}
}

// TestMacOS_ProfileNetworkSection verifies the network section of generated profiles.
func TestMacOS_ProfileNetworkSection(t *testing.T) {
	tests := []struct {
		name           string
		restricted     bool
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:       "unrestricted network allows all",
			restricted: false,
			wantContains: []string{
				"(allow network*)", // Blanket allow all network operations
			},
			wantNotContain: []string{},
		},
		{
			name:       "restricted network does not allow all",
			restricted: true,
			wantContains: []string{
				"; Network", // Should have network section
			},
			wantNotContain: []string{
				"(allow network*)", // Should NOT have blanket allow
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := MacOSSandboxParams{
				Command:                 "echo test",
				NeedsNetworkRestriction: tt.restricted,
				HTTPProxyPort:           8080,
				SOCKSProxyPort:          1080,
			}

			profile := GenerateSandboxProfile(params)

			for _, want := range tt.wantContains {
				if !strings.Contains(profile, want) {
					t.Errorf("profile should contain %q, got:\n%s", want, profile)
				}
			}

			for _, notWant := range tt.wantNotContain {
				if strings.Contains(profile, notWant) {
					t.Errorf("profile should NOT contain %q", notWant)
				}
			}
		})
	}
}

// TestMacOS_DefaultDenyRead verifies that the defaultDenyRead option properly restricts filesystem reads.
func TestMacOS_DefaultDenyRead(t *testing.T) {
	tests := []struct {
		name                      string
		defaultDenyRead           bool
		allowRead                 []string
		wantContainsBlanketAllow  bool
		wantContainsMetadataAllow bool
		wantContainsSystemAllows  bool
		wantContainsUserAllowRead bool
	}{
		{
			name:                      "default mode - blanket allow read",
			defaultDenyRead:           false,
			allowRead:                 nil,
			wantContainsBlanketAllow:  true,
			wantContainsMetadataAllow: false, // No separate metadata allow needed
			wantContainsSystemAllows:  false, // No need for explicit system allows
			wantContainsUserAllowRead: false,
		},
		{
			name:                      "defaultDenyRead enabled - metadata allow, system data allows",
			defaultDenyRead:           true,
			allowRead:                 nil,
			wantContainsBlanketAllow:  false,
			wantContainsMetadataAllow: true, // Should have file-read-metadata for traversal
			wantContainsSystemAllows:  true, // Should have explicit system path allows
			wantContainsUserAllowRead: false,
		},
		{
			name:                      "defaultDenyRead with allowRead paths",
			defaultDenyRead:           true,
			allowRead:                 []string{"/home/user/project"},
			wantContainsBlanketAllow:  false,
			wantContainsMetadataAllow: true,
			wantContainsSystemAllows:  true,
			wantContainsUserAllowRead: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := MacOSSandboxParams{
				Command:         "echo test",
				HTTPProxyPort:   8080,
				SOCKSProxyPort:  1080,
				DefaultDenyRead: tt.defaultDenyRead,
				ReadAllowPaths:  tt.allowRead,
			}

			profile := GenerateSandboxProfile(params)

			// Check for blanket "(allow file-read*)" without path restrictions
			// This appears at the start of read rules section in default mode
			hasBlanketAllow := strings.Contains(profile, "(allow file-read*)\n")
			if hasBlanketAllow != tt.wantContainsBlanketAllow {
				t.Errorf("blanket file-read allow = %v, want %v", hasBlanketAllow, tt.wantContainsBlanketAllow)
			}

			// Check for file-read-metadata allow (for directory traversal in defaultDenyRead mode)
			hasMetadataAllow := strings.Contains(profile, "(allow file-read-metadata)")
			if hasMetadataAllow != tt.wantContainsMetadataAllow {
				t.Errorf("file-read-metadata allow = %v, want %v", hasMetadataAllow, tt.wantContainsMetadataAllow)
			}

			// Check for system path allows (e.g., /usr, /bin) - should use file-read-data in strict mode
			hasSystemAllows := strings.Contains(profile, `(subpath "/usr")`) ||
				strings.Contains(profile, `(subpath "/bin")`)
			if hasSystemAllows != tt.wantContainsSystemAllows {
				t.Errorf("system path allows = %v, want %v\nProfile:\n%s", hasSystemAllows, tt.wantContainsSystemAllows, profile)
			}

			// Check for user-specified allowRead paths
			if tt.wantContainsUserAllowRead && len(tt.allowRead) > 0 {
				hasUserAllow := strings.Contains(profile, tt.allowRead[0])
				if !hasUserAllow {
					t.Errorf("user allowRead path %q not found in profile", tt.allowRead[0])
				}
			}
		})
	}
}

// TestExpandMacOSTmpPaths verifies that /tmp and /private/tmp paths are properly mirrored.
func TestExpandMacOSTmpPaths(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "mirrors /tmp to /private/tmp",
			input: []string{".", "/tmp"},
			want:  []string{".", "/tmp", "/private/tmp"},
		},
		{
			name:  "mirrors /private/tmp to /tmp",
			input: []string{".", "/private/tmp"},
			want:  []string{".", "/private/tmp", "/tmp"},
		},
		{
			name:  "no change when both present",
			input: []string{".", "/tmp", "/private/tmp"},
			want:  []string{".", "/tmp", "/private/tmp"},
		},
		{
			name:  "no change when neither present",
			input: []string{".", "~/.cache"},
			want:  []string{".", "~/.cache"},
		},
		{
			name:  "mirrors /tmp/fence to /private/tmp/fence",
			input: []string{".", "/tmp/fence"},
			want:  []string{".", "/tmp/fence", "/private/tmp/fence"},
		},
		{
			name:  "mirrors /private/tmp/fence to /tmp/fence",
			input: []string{".", "/private/tmp/fence"},
			want:  []string{".", "/private/tmp/fence", "/tmp/fence"},
		},
		{
			name:  "mirrors nested subdirectory",
			input: []string{".", "/tmp/foo/bar"},
			want:  []string{".", "/tmp/foo/bar", "/private/tmp/foo/bar"},
		},
		{
			name:  "no duplicate when mirror already present",
			input: []string{".", "/tmp/fence", "/private/tmp/fence"},
			want:  []string{".", "/tmp/fence", "/private/tmp/fence"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandMacOSTmpPaths(tt.input)

			if len(got) != len(tt.want) {
				t.Errorf("expandMacOSTmpPaths() = %v, want %v", got, tt.want)
				return
			}

			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("expandMacOSTmpPaths()[%d] = %v, want %v", i, v, tt.want[i])
				}
			}
		})
	}
}
