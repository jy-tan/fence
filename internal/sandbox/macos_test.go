package sandbox

import (
	"os"
	"path/filepath"
	"regexp"
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
		MachLookup:              cfg.MacOS.Mach.Lookup,
		MachRegister:            cfg.MacOS.Mach.Register,
		DefaultDenyRead:         cfg.Filesystem.DefaultDenyRead,
		StrictDenyRead:          cfg.Filesystem.StrictDenyRead,
		ReadAllowPaths:          cfg.Filesystem.AllowRead,
		ReadDenyPaths:           cfg.Filesystem.DenyRead,
		WriteAllowPaths:         allowPaths,
		WriteDenyPaths:          cfg.Filesystem.DenyWrite,
		AllowPty:                cfg.AllowPty,
		AllowGitConfig:          cfg.Filesystem.AllowGitConfig,
	}
}

func TestMacOS_MachLookupRules(t *testing.T) {
	tests := []struct {
		name         string
		lookup       []string
		wantContains []string
	}{
		{
			name:         "exact mach lookup",
			lookup:       []string{"com.apple.CoreSimulator.CoreSimulatorService"},
			wantContains: []string{`(allow mach-lookup (global-name "com.apple.CoreSimulator.CoreSimulatorService"))`},
		},
		{
			name:         "wildcard mach lookup",
			lookup:       []string{"org.chromium.*"},
			wantContains: []string{`(allow mach-lookup (global-name-regex #"^org\.chromium\."))`},
		},
		{
			name:         "allow all mach lookup",
			lookup:       []string{"*"},
			wantContains: []string{`(allow mach-lookup)`},
		},
		{
			name:   "mixed exact and wildcard",
			lookup: []string{"com.apple.SecurityServer", "com.apple.*"},
			wantContains: []string{
				`(allow mach-lookup (global-name "com.apple.SecurityServer"))`,
				`(allow mach-lookup (global-name-regex #"^com\.apple\."))`,
			},
		},
		{
			name:         "wildcard with star takes precedence",
			lookup:       []string{"com.apple.*", "*"},
			wantContains: []string{`(allow mach-lookup)`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := MacOSSandboxParams{
				Command:    "echo test",
				MachLookup: tt.lookup,
			}

			profile := GenerateSandboxProfile(params)
			for _, want := range tt.wantContains {
				if !strings.Contains(profile, want) {
					t.Fatalf("profile should contain %q, got:\n%s", want, profile)
				}
			}
		})
	}
}

func TestMacOS_MachRegisterRules(t *testing.T) {
	tests := []struct {
		name         string
		register     []string
		wantContains []string
	}{
		{
			name:         "exact mach register",
			register:     []string{"org.chromium.Chromium.MachPortRendezvousServer"},
			wantContains: []string{`(allow mach-register (global-name "org.chromium.Chromium.MachPortRendezvousServer"))`},
		},
		{
			name:         "wildcard mach register",
			register:     []string{"org.chromium.*"},
			wantContains: []string{`(allow mach-register (global-name-regex #"^org\.chromium\."))`},
		},
		{
			name:         "allow all mach register",
			register:     []string{"*"},
			wantContains: []string{`(allow mach-register)`},
		},
		{
			name:     "mixed exact and wildcard",
			register: []string{"md.obsidian.MachPortRendezvousServer", "md.obsidian.*"},
			wantContains: []string{
				`(allow mach-register (global-name "md.obsidian.MachPortRendezvousServer"))`,
				`(allow mach-register (global-name-regex #"^md\.obsidian\."))`,
			},
		},
		{
			name:         "wildcard with star takes precedence",
			register:     []string{"md.obsidian.*", "*"},
			wantContains: []string{`(allow mach-register)`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := MacOSSandboxParams{
				Command:      "echo test",
				MachRegister: tt.register,
			}

			profile := GenerateSandboxProfile(params)
			for _, want := range tt.wantContains {
				if !strings.Contains(profile, want) {
					t.Fatalf("profile should contain %q, got:\n%s", want, profile)
				}
			}
		})
	}
}

// machRegexLineRE extracts the raw regex body from a line shaped like:
//
//	(allow mach-<op> (global-name-regex #"<pattern>"))
//
// The #"..." form in SBPL is a raw regex literal: backslashes are passed
// through verbatim to the regex engine, with the sole exception that \" is
// an escaped closing quote (so the literal can contain a double-quote).
var machRegexLineRE = regexp.MustCompile(`\(allow mach-(?:lookup|register) \(global-name-regex #"((?:[^"\\]|\\.)*)"\)\)`)

// extractMachRegexes parses a generated SBPL profile and returns the list of
// regex patterns emitted for (global-name-regex #"...") rules, in order.
// The returned patterns are the actual regex strings (with \" unescaped) that
// the regex engine would see.
func extractMachRegexes(t *testing.T, profile string) []string {
	t.Helper()
	var patterns []string
	for _, m := range machRegexLineRE.FindAllStringSubmatch(profile, -1) {
		// Only \" is an SBPL-level escape inside #"..."; every other
		// backslash is literal input to the regex engine.
		patterns = append(patterns, strings.ReplaceAll(m[1], `\"`, `"`))
	}
	return patterns
}

// TestMacOS_MachWildcardRegexSemantics verifies that wildcard mach patterns
// emit regexes that actually match intended service names and reject unrelated
// ones. This catches the class of bug where the emitted rule parses fine but
// the regex pattern is subtly wrong (e.g., double-escaped backslashes turning
// `\.` into `\\.` which means "literal-backslash + any-char" in SBPL regex).
func TestMacOS_MachWildcardRegexSemantics(t *testing.T) {
	tests := []struct {
		name           string
		lookup         []string
		register       []string
		shouldMatch    []string
		shouldNotMatch []string
	}{
		{
			name:           "com.apple wildcard lookup",
			lookup:         []string{"com.apple.*"},
			shouldMatch:    []string{"com.apple.diagnosticd", "com.apple.fonts", "com.apple."},
			shouldNotMatch: []string{"com.other.thing", "zzcom.apple.x", "comxapplex"},
		},
		{
			name:           "md.obsidian wildcard register",
			register:       []string{"md.obsidian.*"},
			shouldMatch:    []string{"md.obsidian.MachPortRendezvousServer", "md.obsidian.helper"},
			shouldNotMatch: []string{"md.other.thing", "mdxobsidianxfoo", "com.apple.foo"},
		},
		{
			name:           "multi-segment prefix",
			lookup:         []string{"com.apple.security.*"},
			shouldMatch:    []string{"com.apple.security.cryptoTokenKit", "com.apple.security.agent"},
			shouldNotMatch: []string{"com.apple.Security.Agent", "com.apple.securityd", "com.apple.other"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := GenerateSandboxProfile(MacOSSandboxParams{
				Command:      "echo test",
				MachLookup:   tt.lookup,
				MachRegister: tt.register,
			})

			patterns := extractMachRegexes(t, profile)
			if len(patterns) == 0 {
				t.Fatalf("no global-name-regex rules emitted in profile:\n%s", profile)
			}

			for _, pat := range patterns {
				re, err := regexp.Compile(pat)
				if err != nil {
					t.Fatalf("emitted regex %q does not compile: %v", pat, err)
				}

				for _, name := range tt.shouldMatch {
					if !re.MatchString(name) {
						t.Errorf("regex %q should match service name %q (profile excerpt: %s)", pat, name, pat)
					}
				}
				for _, name := range tt.shouldNotMatch {
					if re.MatchString(name) {
						t.Errorf("regex %q should NOT match service name %q", pat, name)
					}
				}
			}
		})
	}
}

// TestMacOS_MachWildcardRegexWithStrangeChars verifies that service name
// patterns containing regex metacharacters are escaped correctly in the
// emitted SBPL. This protects against user-supplied patterns like
// "com.foo+bar.*" silently over-matching.
func TestMacOS_MachWildcardRegexMetacharsEscaped(t *testing.T) {
	profile := GenerateSandboxProfile(MacOSSandboxParams{
		Command:    "echo test",
		MachLookup: []string{"com.foo+bar.*"},
	})

	patterns := extractMachRegexes(t, profile)
	if len(patterns) != 1 {
		t.Fatalf("expected exactly one regex, got %d: %v", len(patterns), patterns)
	}

	re, err := regexp.Compile(patterns[0])
	if err != nil {
		t.Fatalf("emitted regex %q does not compile: %v", patterns[0], err)
	}

	// Literal "+" must be required, not treated as "one or more of o".
	if !re.MatchString("com.foo+bar.baz") {
		t.Errorf("regex %q should match %q", patterns[0], "com.foo+bar.baz")
	}
	if re.MatchString("com.foobar.baz") {
		t.Errorf("regex %q should NOT match %q (plus was not escaped)", patterns[0], "com.foobar.baz")
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

func TestGlobToRegex_DoubleStarMatchesCurrentDirectory(t *testing.T) {
	tests := []struct {
		pattern string
		matches []string
		rejects []string
	}{
		{
			pattern: "**/*.key",
			matches: []string{"secret.key", "nested/secret.key", "nested/deeper/secret.key"},
			rejects: []string{"secret.pem"},
		},
		{
			pattern: "**/.env",
			matches: []string{".env", "nested/.env", "nested/deeper/.env"},
			rejects: []string{".env.local"},
		},
		{
			pattern: "**/.env.*",
			matches: []string{".env.local", "nested/.env.production", "nested/deeper/.env.test"},
			rejects: []string{".env"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			regex := regexp.MustCompile(GlobToRegex(tt.pattern))
			for _, path := range tt.matches {
				if !regex.MatchString(path) {
					t.Fatalf("GlobToRegex(%s) should match %q", tt.pattern, path)
				}
			}
			for _, path := range tt.rejects {
				if regex.MatchString(path) {
					t.Fatalf("GlobToRegex(%s) should not match %q", tt.pattern, path)
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

func countRuleBlockOccurrences(rules []string, want ...string) int {
	if len(want) == 0 || len(rules) < len(want) {
		return 0
	}

	count := 0
	for i := 0; i <= len(rules)-len(want); i++ {
		matched := true
		for j, line := range want {
			if rules[i+j] != line {
				matched = false
				break
			}
		}
		if matched {
			count++
		}
	}

	return count
}

func TestGenerateWriteRules_DeduplicatesSharedAncestorMoveRules(t *testing.T) {
	logTag := "test-log"
	rules := generateWriteRules(nil, []string{
		"/fence-issue-74-home/.pypirc",
		"/fence-issue-74-home/.netrc",
	}, false, "", logTag)

	tests := []struct {
		name  string
		lines []string
	}{
		{
			name: "shared ancestor literal",
			lines: []string{
				"(deny file-write-unlink",
				`  (literal "/fence-issue-74-home")`,
				`  (with message "test-log"))`,
			},
		},
		{
			name: "first denied file",
			lines: []string{
				"(deny file-write-unlink",
				`  (subpath "/fence-issue-74-home/.pypirc")`,
				`  (with message "test-log"))`,
			},
		},
		{
			name: "second denied file",
			lines: []string{
				"(deny file-write-unlink",
				`  (subpath "/fence-issue-74-home/.netrc")`,
				`  (with message "test-log"))`,
			},
		},
	}

	for _, tt := range tests {
		if got := countRuleBlockOccurrences(rules, tt.lines...); got != 1 {
			t.Fatalf("%s count = %d, want 1\nRules:\n%s", tt.name, got, strings.Join(rules, "\n"))
		}
	}
}

func TestGenerateWriteRules_DeduplicatesExactDuplicateRules(t *testing.T) {
	logTag := "test-log"
	rules := generateWriteRules(nil, []string{
		"/fence-issue-74-dup/.pypirc",
		"/fence-issue-74-dup/.pypirc",
	}, false, "", logTag)

	tests := []struct {
		name  string
		lines []string
	}{
		{
			name: "direct deny",
			lines: []string{
				"(deny file-write*",
				`  (subpath "/fence-issue-74-dup/.pypirc")`,
				`  (with message "test-log"))`,
			},
		},
		{
			name: "move deny",
			lines: []string{
				"(deny file-write-unlink",
				`  (subpath "/fence-issue-74-dup/.pypirc")`,
				`  (with message "test-log"))`,
			},
		},
		{
			name: "ancestor literal",
			lines: []string{
				"(deny file-write-unlink",
				`  (literal "/fence-issue-74-dup")`,
				`  (with message "test-log"))`,
			},
		},
	}

	for _, tt := range tests {
		if got := countRuleBlockOccurrences(rules, tt.lines...); got != 1 {
			t.Fatalf("%s count = %d, want 1\nRules:\n%s", tt.name, got, strings.Join(rules, "\n"))
		}
	}
}

func TestGenerateWriteRules_UsesWorkspaceScopedMandatoryDenyPatterns(t *testing.T) {
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	workspace := t.TempDir()
	if err := os.Chdir(workspace); err != nil {
		t.Fatalf("failed to chdir to workspace: %v", err)
	}
	defer func() {
		_ = os.Chdir(originalWD)
	}()

	rules := generateWriteRules([]string{workspace}, nil, false, workspace, "test-log")
	joinedRules := strings.Join(rules, "\n")

	scopedRegex := escapePath(GlobToRegex(filepath.Join(ResolveSandboxWorkingDir(workspace), "**", ".idea", "**")))
	if !strings.Contains(joinedRules, "(regex "+scopedRegex+")") {
		t.Fatalf("expected scoped .idea deny regex in rules, got:\n%s", joinedRules)
	}

	unscopedRegex := escapePath(GlobToRegex("**/.idea/**"))
	if strings.Contains(joinedRules, "(regex "+unscopedRegex+")") {
		t.Fatalf("unexpected unscoped .idea deny regex in rules:\n%s", joinedRules)
	}
}

// TestWrapCommandMacOS_ExposedHostPathsGrantReadAndWrite verifies that paths
// registered via Manager.ExposeHostPath appear in BOTH the read and write
// allowlists when writable=true, and read-only when writable=false. Without
// the read-side entry, a writable exposure would be open(O_RDWR)-but-
// unreadable under defaultDenyRead (the file-read-data and file-write*
// operation classes are disjoint in seatbelt).
func TestWrapCommandMacOS_ExposedHostPathsGrantReadAndWrite(t *testing.T) {
	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			DefaultDenyRead: true,
		},
	}

	tmpDir := t.TempDir()
	roPath := filepath.Join(tmpDir, "ro.yml")
	rwPath := filepath.Join(tmpDir, "rw")
	if err := os.WriteFile(roPath, []byte("x: 1\n"), 0o600); err != nil {
		t.Fatalf("write ro: %v", err)
	}
	if err := os.Mkdir(rwPath, 0o700); err != nil {
		t.Fatalf("mkdir rw: %v", err)
	}

	cmd, err := WrapCommandMacOS(cfg, "true", "", 8080, 1080, nil, []exposedHostPath{
		{path: roPath, writable: false},
		{path: rwPath, writable: true},
	}, false, ShellModeDefault, false)
	if err != nil {
		t.Fatalf("WrapCommandMacOS: %v", err)
	}

	// The rule generator passes paths through NormalizePath, which resolves
	// symlinks (/var → /private/var on macOS). Match the resolved form.
	roResolved := NormalizePath(roPath)
	rwResolved := NormalizePath(rwPath)

	readRO := "(allow file-read-data\n  (subpath " + escapePath(roResolved) + "))"
	readRW := "(allow file-read-data\n  (subpath " + escapePath(rwResolved) + "))"
	writeRW := "(allow file-write*\n  (subpath " + escapePath(rwResolved) + ")"
	writeRO := "(allow file-write*\n  (subpath " + escapePath(roResolved) + ")"

	if !strings.Contains(cmd, readRO) {
		t.Errorf("expected read-only exposure to produce file-read-data rule for %s in profile:\n%s", roResolved, cmd)
	}
	if !strings.Contains(cmd, readRW) {
		t.Errorf("expected writable exposure to ALSO produce file-read-data rule for %s (defaultDenyRead bug fix) in profile:\n%s", rwResolved, cmd)
	}
	if !strings.Contains(cmd, writeRW) {
		t.Errorf("expected writable exposure to produce file-write* rule for %s in profile:\n%s", rwResolved, cmd)
	}
	if strings.Contains(cmd, writeRO) {
		t.Errorf("read-only exposure must NOT produce a file-write* rule for %s, profile:\n%s", roResolved, cmd)
	}
}

// TestWrapCommandMacOS_ExposedHostPathsSkipsMissing verifies that a registered
// path which no longer exists at wrap time is silently dropped (with a warning
// log) rather than producing a rule for a nonexistent subpath. This protects
// against TOCTOU confusion where a path exists at ExposeHostPath registration
// but is deleted before the sandbox launches.
//
// Runs in defaultDenyRead mode because that's where exposed paths appear as
// individual subpath rules (in permissive mode reads are globally allowed and
// paths aren't enumerated).
func TestWrapCommandMacOS_ExposedHostPathsSkipsMissing(t *testing.T) {
	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			DefaultDenyRead: true,
		},
	}

	tmpDir := t.TempDir()
	good := filepath.Join(tmpDir, "ok.yml")
	if err := os.WriteFile(good, []byte("ok"), 0o600); err != nil {
		t.Fatalf("write good: %v", err)
	}
	missing := filepath.Join(tmpDir, "does-not-exist.yml")

	cmd, err := WrapCommandMacOS(cfg, "true", "", 8080, 1080, nil, []exposedHostPath{
		{path: good, writable: false},
		{path: missing, writable: false},
	}, false, ShellModeDefault, false)
	if err != nil {
		t.Fatalf("WrapCommandMacOS: %v", err)
	}

	// Rule generator resolves symlinks (/var → /private/var on macOS).
	goodResolved := NormalizePath(good)
	missingResolved := NormalizePath(missing)

	if strings.Contains(cmd, escapePath(missingResolved)) {
		t.Errorf("missing exposed host path %q should not appear in seatbelt profile, got:\n%s", missingResolved, cmd)
	}
	if !strings.Contains(cmd, escapePath(goodResolved)) {
		t.Errorf("existing exposed host path %q should appear in seatbelt profile, got:\n%s", goodResolved, cmd)
	}
}
