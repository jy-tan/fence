package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestValidateDomainPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		// Valid patterns
		{"valid domain", "example.com", false},
		{"valid subdomain", "api.example.com", false},
		{"valid wildcard", "*.example.com", false},
		{"valid wildcard subdomain", "*.api.example.com", false},
		{"localhost", "localhost", false},

		// Invalid patterns
		{"protocol included", "https://example.com", true},
		{"path included", "example.com/path", true},
		{"port included", "example.com:443", true},
		{"wildcard too broad", "*.com", true},
		{"invalid wildcard position", "example.*.com", true},
		{"trailing wildcard", "example.com.*", true},
		{"leading dot", ".example.com", true},
		{"trailing dot", "example.com.", true},
		{"no TLD", "example", true},
		{"empty wildcard domain part", "*.", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDomainPattern(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDomainPattern(%q) error = %v, wantErr %v", tt.pattern, err, tt.wantErr)
			}
		})
	}
}

func TestMatchesDomain(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		pattern  string
		want     bool
	}{
		// Exact matches
		{"exact match", "example.com", "example.com", true},
		{"exact match case insensitive", "Example.COM", "example.com", true},
		{"exact no match", "other.com", "example.com", false},

		// Wildcard matches
		{"wildcard match subdomain", "api.example.com", "*.example.com", true},
		{"wildcard match deep subdomain", "deep.api.example.com", "*.example.com", true},
		{"wildcard no match base domain", "example.com", "*.example.com", false},
		{"wildcard no match different domain", "api.other.com", "*.example.com", false},
		{"wildcard case insensitive", "API.Example.COM", "*.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesDomain(tt.hostname, tt.pattern)
			if got != tt.want {
				t.Errorf("MatchesDomain(%q, %q) = %v, want %v", tt.hostname, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "valid empty config",
			config:  Config{},
			wantErr: false,
		},
		{
			name: "valid config with domains",
			config: Config{
				Network: NetworkConfig{
					AllowedDomains: []string{"example.com", "*.github.com"},
					DeniedDomains:  []string{"blocked.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid allowed domain",
			config: Config{
				Network: NetworkConfig{
					AllowedDomains: []string{"https://example.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid denied domain",
			config: Config{
				Network: NetworkConfig{
					DeniedDomains: []string{"*.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "empty allowRead path",
			config: Config{
				Filesystem: FilesystemConfig{
					AllowRead: []string{""},
				},
			},
			wantErr: true,
		},
		{
			name: "empty denyRead path",
			config: Config{
				Filesystem: FilesystemConfig{
					DenyRead: []string{""},
				},
			},
			wantErr: true,
		},
		{
			name: "empty allowWrite path",
			config: Config{
				Filesystem: FilesystemConfig{
					AllowWrite: []string{""},
				},
			},
			wantErr: true,
		},
		{
			name: "empty denyWrite path",
			config: Config{
				Filesystem: FilesystemConfig{
					DenyWrite: []string{""},
				},
			},
			wantErr: true,
		},
		{
			name: "empty allowExecute path",
			config: Config{
				Filesystem: FilesystemConfig{
					AllowExecute: []string{""},
				},
			},
			wantErr: true,
		},
		{
			name: "valid allowExecute path",
			config: Config{
				Filesystem: FilesystemConfig{
					AllowExecute: []string{"/usr/bin/ls"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid wslInterop true",
			config: Config{
				Filesystem: FilesystemConfig{
					WSLInterop: boolPtr(true),
				},
			},
			wantErr: false,
		},
		{
			name: "valid wslInterop false",
			config: Config{
				Filesystem: FilesystemConfig{
					WSLInterop: boolPtr(false),
				},
			},
			wantErr: false,
		},
		{
			name: "valid devices minimal mode",
			config: Config{
				Devices: DevicesConfig{
					Mode:  DeviceModeMinimal,
					Allow: []string{"/dev/dri", "/dev/fuse"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid devices host mode",
			config: Config{
				Devices: DevicesConfig{
					Mode: DeviceModeHost,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid devices mode",
			config: Config{
				Devices: DevicesConfig{
					Mode: "invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "empty devices allow path",
			config: Config{
				Devices: DevicesConfig{
					Allow: []string{""},
				},
			},
			wantErr: true,
		},
		{
			name: "devices allow path outside dev",
			config: Config{
				Devices: DevicesConfig{
					Allow: []string{"/tmp/not-a-device"},
				},
			},
			wantErr: true,
		},
		{
			name: "devices allow root dev path too broad",
			config: Config{
				Devices: DevicesConfig{
					Allow: []string{"/dev"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg == nil {
		t.Fatal("Default() returned nil")
	}
	if cfg.Network.AllowedDomains == nil {
		t.Error("AllowedDomains should not be nil")
	}
	if cfg.Network.DeniedDomains == nil {
		t.Error("DeniedDomains should not be nil")
	}
	if cfg.Filesystem.DenyRead == nil {
		t.Error("DenyRead should not be nil")
	}
	if cfg.Filesystem.AllowWrite == nil {
		t.Error("AllowWrite should not be nil")
	}
	if cfg.Filesystem.DenyWrite == nil {
		t.Error("DenyWrite should not be nil")
	}
	if cfg.Devices.Allow == nil {
		t.Error("Devices.Allow should not be nil")
	}
}

func TestLoad(t *testing.T) {
	// Create temp directory for test files
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		content     string
		setup       func(string) string // returns path
		wantNil     bool
		wantErr     bool
		checkConfig func(*testing.T, *Config)
	}{
		{
			name:    "nonexistent file",
			setup:   func(dir string) string { return filepath.Join(dir, "nonexistent.json") },
			wantNil: true,
			wantErr: false,
		},
		{
			name:    "empty file",
			content: "",
			setup: func(dir string) string {
				path := filepath.Join(dir, "empty.json")
				_ = os.WriteFile(path, []byte(""), 0o600)
				return path
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name:    "whitespace only file",
			content: "   \n\t  ",
			setup: func(dir string) string {
				path := filepath.Join(dir, "whitespace.json")
				_ = os.WriteFile(path, []byte("   \n\t  "), 0o600)
				return path
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "valid config",
			setup: func(dir string) string {
				path := filepath.Join(dir, "valid.json")
				content := `{"network":{"allowedDomains":["example.com"]}}`
				_ = os.WriteFile(path, []byte(content), 0o600)
				return path
			},
			wantNil: false,
			wantErr: false,
			checkConfig: func(t *testing.T, cfg *Config) {
				if len(cfg.Network.AllowedDomains) != 1 {
					t.Errorf("expected 1 allowed domain, got %d", len(cfg.Network.AllowedDomains))
				}
				if cfg.Network.AllowedDomains[0] != "example.com" {
					t.Errorf("expected example.com, got %s", cfg.Network.AllowedDomains[0])
				}
			},
		},
		{
			name: "config with devices config",
			setup: func(dir string) string {
				path := filepath.Join(dir, "devices.json")
				content := `{"devices":{"mode":"minimal","allow":["/dev/dri","/dev/fuse"]}}`
				_ = os.WriteFile(path, []byte(content), 0o600)
				return path
			},
			wantNil: false,
			wantErr: false,
			checkConfig: func(t *testing.T, cfg *Config) {
				if cfg.Devices.Mode != DeviceModeMinimal {
					t.Fatalf("expected devices mode %q, got %q", DeviceModeMinimal, cfg.Devices.Mode)
				}
				if len(cfg.Devices.Allow) != 2 {
					t.Fatalf("expected 2 device allow paths, got %d", len(cfg.Devices.Allow))
				}
				if cfg.Devices.Allow[0] != "/dev/dri" || cfg.Devices.Allow[1] != "/dev/fuse" {
					t.Fatalf("unexpected devices allow paths: %v", cfg.Devices.Allow)
				}
			},
		},
		{
			name: "invalid JSON",
			setup: func(dir string) string {
				path := filepath.Join(dir, "invalid.json")
				_ = os.WriteFile(path, []byte("{invalid json}"), 0o600)
				return path
			},
			wantNil: false,
			wantErr: true,
		},
		{
			name: "config with allowExecute and wslInterop",
			setup: func(dir string) string {
				path := filepath.Join(dir, "wsl.json")
				content := `{"filesystem":{"wslInterop":false,"allowExecute":["/mnt/c/bin/test.exe"]}}`
				_ = os.WriteFile(path, []byte(content), 0o600)
				return path
			},
			wantNil: false,
			wantErr: false,
			checkConfig: func(t *testing.T, cfg *Config) {
				if cfg.Filesystem.WSLInterop == nil {
					t.Fatal("expected WSLInterop to be non-nil")
				}
				if *cfg.Filesystem.WSLInterop != false {
					t.Error("expected WSLInterop to be false")
				}
				if len(cfg.Filesystem.AllowExecute) != 1 {
					t.Fatalf("expected 1 allowExecute path, got %d", len(cfg.Filesystem.AllowExecute))
				}
				if cfg.Filesystem.AllowExecute[0] != "/mnt/c/bin/test.exe" {
					t.Errorf("expected /mnt/c/bin/test.exe, got %s", cfg.Filesystem.AllowExecute[0])
				}
			},
		},
		{
			name: "config with wslInterop true",
			setup: func(dir string) string {
				path := filepath.Join(dir, "wsl_true.json")
				content := `{"filesystem":{"wslInterop":true}}`
				_ = os.WriteFile(path, []byte(content), 0o600)
				return path
			},
			wantNil: false,
			wantErr: false,
			checkConfig: func(t *testing.T, cfg *Config) {
				if cfg.Filesystem.WSLInterop == nil {
					t.Fatal("expected WSLInterop to be non-nil")
				}
				if *cfg.Filesystem.WSLInterop != true {
					t.Error("expected WSLInterop to be true")
				}
			},
		},
		{
			name: "config with wslInterop omitted stays nil",
			setup: func(dir string) string {
				path := filepath.Join(dir, "wsl_omit.json")
				content := `{"filesystem":{"allowWrite":["/tmp"]}}`
				_ = os.WriteFile(path, []byte(content), 0o600)
				return path
			},
			wantNil: false,
			wantErr: false,
			checkConfig: func(t *testing.T, cfg *Config) {
				if cfg.Filesystem.WSLInterop != nil {
					t.Errorf("expected WSLInterop to be nil (auto-detect), got %v", *cfg.Filesystem.WSLInterop)
				}
			},
		},
		{
			name: "invalid allowExecute empty string via load",
			setup: func(dir string) string {
				path := filepath.Join(dir, "bad_exec.json")
				content := `{"filesystem":{"allowExecute":[""]}}`
				_ = os.WriteFile(path, []byte(content), 0o600)
				return path
			},
			wantNil: false,
			wantErr: true,
		},
		{
			name: "invalid domain in config",
			setup: func(dir string) string {
				path := filepath.Join(dir, "invalid_domain.json")
				content := `{"network":{"allowedDomains":["*.com"]}}`
				_ = os.WriteFile(path, []byte(content), 0o600)
				return path
			},
			wantNil: false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(tmpDir)
			cfg, err := Load(path)

			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantNil && cfg != nil {
				t.Error("Load() expected nil config")
				return
			}

			if !tt.wantNil && !tt.wantErr && cfg == nil {
				t.Error("Load() returned nil config unexpectedly")
				return
			}

			if tt.checkConfig != nil && cfg != nil {
				tt.checkConfig(t, cfg)
			}
		})
	}
}

func TestDefaultConfigPath(t *testing.T) {
	path := DefaultConfigPath()
	if path == "" {
		t.Error("DefaultConfigPath() returned empty string")
	}
	// Should always return the canonical destination path.
	base := filepath.Base(path)
	if base != "fence.json" {
		t.Errorf("DefaultConfigPath() = %q, expected to end with fence.json", path)
	}
}

func TestDefaultConfigPathFor(t *testing.T) {
	darwinHome := filepath.Join(string(os.PathSeparator), "Users", "alice")
	darwinCanonical := filepath.Join(darwinHome, ".config", "fence", "fence.json")

	linuxHome := filepath.Join(string(os.PathSeparator), "home", "alice")
	linuxConfigDir := filepath.Join(linuxHome, ".config")

	tests := []struct {
		name          string
		goos          string
		home          string
		userConfigDir string
		want          string
	}{
		{
			name:          "darwin uses xdg-style path",
			goos:          "darwin",
			home:          darwinHome,
			userConfigDir: filepath.Join(darwinHome, "Library", "Application Support"),
			want:          darwinCanonical,
		},
		{
			name:          "linux keeps os config dir",
			goos:          "linux",
			home:          linuxHome,
			userConfigDir: linuxConfigDir,
			want:          filepath.Join(linuxConfigDir, "fence", "fence.json"),
		},
		{
			name: "returns local fallback when home and config dir are unavailable",
			goos: "linux",
			want: "fence.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defaultConfigPathFor(tt.goos, tt.home, tt.userConfigDir)
			if got != tt.want {
				t.Fatalf("defaultConfigPathFor() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveDefaultConfigPathFor(t *testing.T) {
	darwinHome := filepath.Join(string(os.PathSeparator), "Users", "alice")
	darwinCanonical := filepath.Join(darwinHome, ".config", "fence", "fence.json")
	darwinLegacyAppSupport := filepath.Join(darwinHome, "Library", "Application Support", "fence", "fence.json")
	darwinLegacyDotfile := filepath.Join(darwinHome, ".fence.json")

	linuxHome := filepath.Join(string(os.PathSeparator), "home", "alice")
	linuxConfigDir := filepath.Join(linuxHome, ".config")
	linuxCanonical := filepath.Join(linuxConfigDir, "fence", "fence.json")
	linuxLegacyDotfile := filepath.Join(linuxHome, ".fence.json")

	tests := []struct {
		name          string
		goos          string
		home          string
		userConfigDir string
		existing      map[string]bool
		want          string
	}{
		{
			name:          "darwin prefers canonical config file",
			goos:          "darwin",
			home:          darwinHome,
			userConfigDir: filepath.Join(darwinHome, "Library", "Application Support"),
			existing: map[string]bool{
				darwinCanonical:        true,
				darwinLegacyAppSupport: true,
				darwinLegacyDotfile:    true,
			},
			want: darwinCanonical,
		},
		{
			name:          "darwin still loads legacy file when only canonical directory exists",
			goos:          "darwin",
			home:          darwinHome,
			userConfigDir: filepath.Join(darwinHome, "Library", "Application Support"),
			existing: map[string]bool{
				filepath.Dir(darwinCanonical): true,
				darwinLegacyAppSupport:        true,
			},
			want: darwinLegacyAppSupport,
		},
		{
			name:          "darwin falls back to legacy application support file",
			goos:          "darwin",
			home:          darwinHome,
			userConfigDir: filepath.Join(darwinHome, "Library", "Application Support"),
			existing: map[string]bool{
				darwinLegacyAppSupport: true,
			},
			want: darwinLegacyAppSupport,
		},
		{
			name:          "darwin falls back to legacy dotfile",
			goos:          "darwin",
			home:          darwinHome,
			userConfigDir: filepath.Join(darwinHome, "Library", "Application Support"),
			existing: map[string]bool{
				darwinLegacyDotfile: true,
			},
			want: darwinLegacyDotfile,
		},
		{
			name:          "darwin returns canonical path when no config exists yet",
			goos:          "darwin",
			home:          darwinHome,
			userConfigDir: filepath.Join(darwinHome, "Library", "Application Support"),
			existing: map[string]bool{
				filepath.Dir(darwinCanonical): true,
			},
			want: darwinCanonical,
		},
		{
			name:          "linux prefers canonical path",
			goos:          "linux",
			home:          linuxHome,
			userConfigDir: linuxConfigDir,
			existing:      map[string]bool{},
			want:          linuxCanonical,
		},
		{
			name:          "linux falls back to legacy dotfile",
			goos:          "linux",
			home:          linuxHome,
			userConfigDir: linuxConfigDir,
			existing: map[string]bool{
				linuxLegacyDotfile: true,
			},
			want: linuxLegacyDotfile,
		},
		{
			name:     "returns local fallback when home and config dir are unavailable",
			goos:     "linux",
			existing: map[string]bool{},
			want:     "fence.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveDefaultConfigPathFor(tt.goos, tt.home, tt.userConfigDir, func(path string) bool {
				return tt.existing[path]
			})
			if got != tt.want {
				t.Fatalf("resolveDefaultConfigPathFor() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMerge(t *testing.T) {
	t.Run("nil base", func(t *testing.T) {
		override := &Config{
			AllowPty: true,
			Network: NetworkConfig{
				AllowedDomains: []string{"example.com"},
			},
		}
		result := Merge(nil, override)
		if !result.AllowPty {
			t.Error("expected AllowPty to be true")
		}
		if len(result.Network.AllowedDomains) != 1 || result.Network.AllowedDomains[0] != "example.com" {
			t.Error("expected AllowedDomains to be [example.com]")
		}
		if result.Extends != "" {
			t.Error("expected Extends to be cleared")
		}
	})

	t.Run("nil override", func(t *testing.T) {
		base := &Config{
			AllowPty: true,
			Network: NetworkConfig{
				AllowedDomains: []string{"example.com"},
			},
		}
		result := Merge(base, nil)
		if !result.AllowPty {
			t.Error("expected AllowPty to be true")
		}
		if len(result.Network.AllowedDomains) != 1 {
			t.Error("expected AllowedDomains to be [example.com]")
		}
	})

	t.Run("both nil", func(t *testing.T) {
		result := Merge(nil, nil)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("merge allowed domains", func(t *testing.T) {
		base := &Config{
			Network: NetworkConfig{
				AllowedDomains: []string{"github.com", "api.github.com"},
			},
		}
		override := &Config{
			Extends: "base-template",
			Network: NetworkConfig{
				AllowedDomains: []string{"private-registry.company.com"},
			},
		}
		result := Merge(base, override)

		// Should have all three domains
		if len(result.Network.AllowedDomains) != 3 {
			t.Errorf("expected 3 allowed domains, got %d: %v", len(result.Network.AllowedDomains), result.Network.AllowedDomains)
		}

		// Extends should be cleared
		if result.Extends != "" {
			t.Errorf("expected Extends to be cleared, got %q", result.Extends)
		}
	})

	t.Run("deduplicate merged domains", func(t *testing.T) {
		base := &Config{
			Network: NetworkConfig{
				AllowedDomains: []string{"github.com", "example.com"},
			},
		}
		override := &Config{
			Network: NetworkConfig{
				AllowedDomains: []string{"github.com", "new.com"},
			},
		}
		result := Merge(base, override)

		// Should deduplicate
		if len(result.Network.AllowedDomains) != 3 {
			t.Errorf("expected 3 domains (deduped), got %d: %v", len(result.Network.AllowedDomains), result.Network.AllowedDomains)
		}
	})

	t.Run("merge boolean flags", func(t *testing.T) {
		base := &Config{
			AllowPty: false,
			Network: NetworkConfig{
				AllowLocalBinding: true,
			},
		}
		override := &Config{
			AllowPty: true,
			Network: NetworkConfig{
				AllowLocalOutbound: boolPtr(true),
			},
		}
		result := Merge(base, override)

		if !result.AllowPty {
			t.Error("expected AllowPty to be true (from override)")
		}
		if !result.Network.AllowLocalBinding {
			t.Error("expected AllowLocalBinding to be true (from base)")
		}
		if result.Network.AllowLocalOutbound == nil || !*result.Network.AllowLocalOutbound {
			t.Error("expected AllowLocalOutbound to be true (from override)")
		}
	})

	t.Run("merge forceNewSession override wins", func(t *testing.T) {
		base := &Config{
			ForceNewSession: boolPtr(true),
		}
		override := &Config{
			ForceNewSession: boolPtr(false),
		}
		result := Merge(base, override)

		if result.ForceNewSession == nil {
			t.Fatal("expected ForceNewSession to be non-nil")
		}
		if *result.ForceNewSession {
			t.Error("expected ForceNewSession to be false (override wins)")
		}
	})

	t.Run("merge command config", func(t *testing.T) {
		base := &Config{
			Command: CommandConfig{
				Deny: []string{"git push", "rm -rf"},
			},
		}
		override := &Config{
			Command: CommandConfig{
				Deny:  []string{"sudo"},
				Allow: []string{"git status"},
			},
		}
		result := Merge(base, override)

		if len(result.Command.Deny) != 3 {
			t.Errorf("expected 3 denied commands, got %d", len(result.Command.Deny))
		}
		if len(result.Command.Allow) != 1 {
			t.Errorf("expected 1 allowed command, got %d", len(result.Command.Allow))
		}
	})

	t.Run("merge filesystem config", func(t *testing.T) {
		base := &Config{
			Filesystem: FilesystemConfig{
				AllowWrite: []string{"."},
				DenyRead:   []string{"~/.ssh/**"},
			},
		}
		override := &Config{
			Filesystem: FilesystemConfig{
				AllowWrite: []string{"/tmp"},
				DenyWrite:  []string{".env"},
			},
		}
		result := Merge(base, override)

		if len(result.Filesystem.AllowWrite) != 2 {
			t.Errorf("expected 2 write paths, got %d", len(result.Filesystem.AllowWrite))
		}
		if len(result.Filesystem.DenyRead) != 1 {
			t.Errorf("expected 1 deny read path, got %d", len(result.Filesystem.DenyRead))
		}
		if len(result.Filesystem.DenyWrite) != 1 {
			t.Errorf("expected 1 deny write path, got %d", len(result.Filesystem.DenyWrite))
		}
	})

	t.Run("merge devices config", func(t *testing.T) {
		base := &Config{
			Devices: DevicesConfig{
				Mode:  DeviceModeHost,
				Allow: []string{"/dev/dri"},
			},
		}
		override := &Config{
			Devices: DevicesConfig{
				Mode:  DeviceModeMinimal,
				Allow: []string{"/dev/fuse"},
			},
		}
		result := Merge(base, override)

		if result.Devices.Mode != DeviceModeMinimal {
			t.Errorf("expected devices mode %q, got %q", DeviceModeMinimal, result.Devices.Mode)
		}
		if len(result.Devices.Allow) != 2 {
			t.Fatalf("expected 2 device allow paths, got %d: %v", len(result.Devices.Allow), result.Devices.Allow)
		}
	})

	t.Run("merge devices mode preserves base when override unset", func(t *testing.T) {
		base := &Config{
			Devices: DevicesConfig{
				Mode: DeviceModeHost,
			},
		}
		override := &Config{
			Devices: DevicesConfig{
				Allow: []string{"/dev/fuse"},
			},
		}
		result := Merge(base, override)

		if result.Devices.Mode != DeviceModeHost {
			t.Errorf("expected devices mode %q, got %q", DeviceModeHost, result.Devices.Mode)
		}
		if len(result.Devices.Allow) != 1 || result.Devices.Allow[0] != "/dev/fuse" {
			t.Errorf("unexpected devices allow paths: %v", result.Devices.Allow)
		}
	})

	t.Run("merge defaultDenyRead and allowRead", func(t *testing.T) {
		base := &Config{
			Filesystem: FilesystemConfig{
				DefaultDenyRead: true,
				AllowRead:       []string{"/home/user/project"},
			},
		}
		override := &Config{
			Filesystem: FilesystemConfig{
				AllowRead: []string{"/home/user/other"},
			},
		}
		result := Merge(base, override)

		if !result.Filesystem.DefaultDenyRead {
			t.Error("expected DefaultDenyRead to be true (from base)")
		}
		if len(result.Filesystem.AllowRead) != 2 {
			t.Errorf("expected 2 allowRead paths, got %d: %v", len(result.Filesystem.AllowRead), result.Filesystem.AllowRead)
		}
	})

	t.Run("merge defaultDenyRead from override", func(t *testing.T) {
		base := &Config{
			Filesystem: FilesystemConfig{
				DefaultDenyRead: false,
			},
		}
		override := &Config{
			Filesystem: FilesystemConfig{
				DefaultDenyRead: true,
				AllowRead:       []string{"/home/user/project"},
			},
		}
		result := Merge(base, override)

		if !result.Filesystem.DefaultDenyRead {
			t.Error("expected DefaultDenyRead to be true (from override)")
		}
		if len(result.Filesystem.AllowRead) != 1 {
			t.Errorf("expected 1 allowRead path, got %d", len(result.Filesystem.AllowRead))
		}
	})

	t.Run("merge allowExecute", func(t *testing.T) {
		base := &Config{
			Filesystem: FilesystemConfig{
				AllowExecute: []string{"/usr/bin/ls"},
			},
		}
		override := &Config{
			Filesystem: FilesystemConfig{
				AllowExecute: []string{"/usr/bin/cat"},
			},
		}
		result := Merge(base, override)

		if len(result.Filesystem.AllowExecute) != 2 {
			t.Errorf("expected 2 allowExecute paths, got %d: %v", len(result.Filesystem.AllowExecute), result.Filesystem.AllowExecute)
		}
	})

	t.Run("deduplicate merged allowExecute", func(t *testing.T) {
		base := &Config{
			Filesystem: FilesystemConfig{
				AllowExecute: []string{"/usr/bin/ls", "/usr/bin/cat"},
			},
		}
		override := &Config{
			Filesystem: FilesystemConfig{
				AllowExecute: []string{"/usr/bin/ls", "/usr/bin/grep"},
			},
		}
		result := Merge(base, override)

		if len(result.Filesystem.AllowExecute) != 3 {
			t.Errorf("expected 3 allowExecute paths (deduped), got %d: %v", len(result.Filesystem.AllowExecute), result.Filesystem.AllowExecute)
		}
	})

	t.Run("merge wslInterop override wins", func(t *testing.T) {
		base := &Config{
			Filesystem: FilesystemConfig{
				WSLInterop: boolPtr(true),
			},
		}
		override := &Config{
			Filesystem: FilesystemConfig{
				WSLInterop: boolPtr(false),
			},
		}
		result := Merge(base, override)

		if result.Filesystem.WSLInterop == nil {
			t.Fatal("expected WSLInterop to be non-nil")
		}
		if *result.Filesystem.WSLInterop != false {
			t.Error("expected WSLInterop to be false (override wins)")
		}
	})

	t.Run("merge wslInterop nil base with override", func(t *testing.T) {
		base := &Config{
			Filesystem: FilesystemConfig{},
		}
		override := &Config{
			Filesystem: FilesystemConfig{
				WSLInterop: boolPtr(true),
			},
		}
		result := Merge(base, override)

		if result.Filesystem.WSLInterop == nil {
			t.Fatal("expected WSLInterop to be non-nil")
		}
		if *result.Filesystem.WSLInterop != true {
			t.Error("expected WSLInterop to be true (from override)")
		}
	})

	t.Run("merge wslInterop nil base with false override", func(t *testing.T) {
		override := &Config{
			Filesystem: FilesystemConfig{
				WSLInterop: boolPtr(false),
			},
		}
		result := Merge(nil, override)

		if result.Filesystem.WSLInterop == nil {
			t.Fatal("expected WSLInterop to be non-nil")
		}
		if *result.Filesystem.WSLInterop != false {
			t.Error("expected WSLInterop to be false (from override)")
		}
	})

	t.Run("merge wslInterop base preserved when override nil", func(t *testing.T) {
		base := &Config{
			Filesystem: FilesystemConfig{
				WSLInterop: boolPtr(true),
			},
		}
		override := &Config{
			Filesystem: FilesystemConfig{},
		}
		result := Merge(base, override)

		if result.Filesystem.WSLInterop == nil {
			t.Fatal("expected WSLInterop to be non-nil")
		}
		if *result.Filesystem.WSLInterop != true {
			t.Error("expected WSLInterop to be true (from base)")
		}
	})

	t.Run("override ports", func(t *testing.T) {
		base := &Config{
			Network: NetworkConfig{
				HTTPProxyPort:  8080,
				SOCKSProxyPort: 1080,
			},
		}
		override := &Config{
			Network: NetworkConfig{
				HTTPProxyPort: 9090, // override
				// SOCKSProxyPort not set, should keep base
			},
		}
		result := Merge(base, override)

		if result.Network.HTTPProxyPort != 9090 {
			t.Errorf("expected HTTPProxyPort 9090, got %d", result.Network.HTTPProxyPort)
		}
		if result.Network.SOCKSProxyPort != 1080 {
			t.Errorf("expected SOCKSProxyPort 1080, got %d", result.Network.SOCKSProxyPort)
		}
	})
}

func boolPtr(b bool) *bool {
	return &b
}

func TestValidateHostPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		// Valid patterns
		{"simple hostname", "server1", false},
		{"domain", "example.com", false},
		{"subdomain", "prod.example.com", false},
		{"wildcard prefix", "*.example.com", false},
		{"wildcard middle", "prod-*.example.com", false},
		{"ip address", "192.168.1.1", false},
		{"ipv6 address", "::1", false},
		{"ipv6 full", "2001:db8::1", false},
		{"localhost", "localhost", false},

		// Invalid patterns
		{"empty", "", true},
		{"with protocol", "ssh://example.com", true},
		{"with path", "example.com/path", true},
		{"with port", "example.com:22", true},
		{"with username", "user@example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHostPattern(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateHostPattern(%q) error = %v, wantErr %v", tt.pattern, err, tt.wantErr)
			}
		})
	}
}

func TestMatchesHost(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		pattern  string
		want     bool
	}{
		// Exact matches
		{"exact match", "server1.example.com", "server1.example.com", true},
		{"exact match case insensitive", "Server1.Example.COM", "server1.example.com", true},
		{"exact no match", "server2.example.com", "server1.example.com", false},

		// Wildcard matches
		{"wildcard prefix", "api.example.com", "*.example.com", true},
		{"wildcard prefix deep", "deep.api.example.com", "*.example.com", true},
		{"wildcard no match base", "example.com", "*.example.com", false},
		{"wildcard middle", "prod-web-01.example.com", "prod-*.example.com", true},
		{"wildcard middle no match", "dev-web-01.example.com", "prod-*.example.com", false},
		{"wildcard suffix", "server1.prod", "server1.*", true},
		{"multiple wildcards", "prod-web-01.us-east.example.com", "prod-*-*.example.com", true},

		// Star matches all
		{"star matches all", "anything.example.com", "*", true},

		// IP addresses
		{"ip exact match", "192.168.1.1", "192.168.1.1", true},
		{"ip no match", "192.168.1.2", "192.168.1.1", false},
		{"ip wildcard", "192.168.1.100", "192.168.1.*", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesHost(tt.hostname, tt.pattern)
			if got != tt.want {
				t.Errorf("MatchesHost(%q, %q) = %v, want %v", tt.hostname, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestSSHConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid SSH config",
			config: Config{
				SSH: SSHConfig{
					AllowedHosts:    []string{"*.example.com", "prod-*.internal"},
					AllowedCommands: []string{"ls", "cat", "grep"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid allowed host with protocol",
			config: Config{
				SSH: SSHConfig{
					AllowedHosts: []string{"ssh://example.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid denied host with username",
			config: Config{
				SSH: SSHConfig{
					DeniedHosts: []string{"user@example.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "empty allowed command",
			config: Config{
				SSH: SSHConfig{
					AllowedHosts:    []string{"example.com"},
					AllowedCommands: []string{"ls", ""},
				},
			},
			wantErr: true,
		},
		{
			name: "empty denied command",
			config: Config{
				SSH: SSHConfig{
					AllowedHosts:   []string{"example.com"},
					DeniedCommands: []string{""},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMergeAcceptSharedBinaryCannotRuntimeDeny(t *testing.T) {
	t.Run("base and override are appended", func(t *testing.T) {
		base := &Config{Command: CommandConfig{AcceptSharedBinaryCannotRuntimeDeny: []string{"dd"}}}
		override := &Config{Command: CommandConfig{AcceptSharedBinaryCannotRuntimeDeny: []string{"curl"}}}
		result := Merge(base, override)
		if !slices.Contains(result.Command.AcceptSharedBinaryCannotRuntimeDeny, "dd") {
			t.Error("expected base entry 'dd' to be present after merge")
		}
		if !slices.Contains(result.Command.AcceptSharedBinaryCannotRuntimeDeny, "curl") {
			t.Error("expected override entry 'curl' to be present after merge")
		}
	})

	t.Run("base entries inherited when override is unset", func(t *testing.T) {
		base := &Config{Command: CommandConfig{AcceptSharedBinaryCannotRuntimeDeny: []string{"dd"}}}
		override := &Config{}
		result := Merge(base, override)
		if !slices.Contains(result.Command.AcceptSharedBinaryCannotRuntimeDeny, "dd") {
			t.Error("expected base entry 'dd' to be inherited when override is nil")
		}
	})

	t.Run("nil when both unset", func(t *testing.T) {
		result := Merge(&Config{}, &Config{})
		if len(result.Command.AcceptSharedBinaryCannotRuntimeDeny) != 0 {
			t.Errorf("expected empty AcceptSharedBinaryCannotRuntimeDeny when both unset, got %v", result.Command.AcceptSharedBinaryCannotRuntimeDeny)
		}
	})
}

func TestMergeSSHConfig(t *testing.T) {
	t.Run("merge SSH allowed hosts", func(t *testing.T) {
		base := &Config{
			SSH: SSHConfig{
				AllowedHosts: []string{"prod-*.example.com"},
			},
		}
		override := &Config{
			SSH: SSHConfig{
				AllowedHosts: []string{"dev-*.example.com"},
			},
		}
		result := Merge(base, override)

		if len(result.SSH.AllowedHosts) != 2 {
			t.Errorf("expected 2 allowed hosts, got %d: %v", len(result.SSH.AllowedHosts), result.SSH.AllowedHosts)
		}
	})

	t.Run("merge SSH commands", func(t *testing.T) {
		base := &Config{
			SSH: SSHConfig{
				AllowedCommands: []string{"ls", "cat"},
				DeniedCommands:  []string{"rm -rf"},
			},
		}
		override := &Config{
			SSH: SSHConfig{
				AllowedCommands: []string{"grep", "find"},
				DeniedCommands:  []string{"shutdown"},
			},
		}
		result := Merge(base, override)

		if len(result.SSH.AllowedCommands) != 4 {
			t.Errorf("expected 4 allowed commands, got %d", len(result.SSH.AllowedCommands))
		}
		if len(result.SSH.DeniedCommands) != 2 {
			t.Errorf("expected 2 denied commands, got %d", len(result.SSH.DeniedCommands))
		}
	})

	t.Run("merge SSH boolean flags", func(t *testing.T) {
		base := &Config{
			SSH: SSHConfig{
				AllowAllCommands: false,
				InheritDeny:      true,
			},
		}
		override := &Config{
			SSH: SSHConfig{
				AllowAllCommands: true,
				InheritDeny:      false,
			},
		}
		result := Merge(base, override)

		if !result.SSH.AllowAllCommands {
			t.Error("expected AllowAllCommands to be true (OR logic)")
		}
		if !result.SSH.InheritDeny {
			t.Error("expected InheritDeny to be true (OR logic)")
		}
	})
}
