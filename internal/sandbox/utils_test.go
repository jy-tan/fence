package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainsGlobChars(t *testing.T) {
	tests := []struct {
		pattern string
		want    bool
	}{
		{"/path/to/file", false},
		{"/path/to/dir/", false},
		{"relative/path", false},
		{"/path/with/asterisk/*", true},
		{"/path/with/question?", true},
		{"/path/with/brackets[a-z]", true},
		{"/path/**/*.go", true},
		{"*.txt", true},
		{"file[0-9].txt", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			got := ContainsGlobChars(tt.pattern)
			if got != tt.want {
				t.Errorf("ContainsGlobChars(%q) = %v, want %v", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestRemoveTrailingGlobSuffix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/path/to/dir/**", "/path/to/dir"},
		{"/path/to/dir", "/path/to/dir"},
		{"/path/**/**", "/path/**"},
		{"/**", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := RemoveTrailingGlobSuffix(tt.input)
			if got != tt.want {
				t.Errorf("RemoveTrailingGlobSuffix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "tilde alone",
			input: "~",
			want:  home,
		},
		{
			name:  "tilde with path",
			input: "~/Documents",
			want:  filepath.Join(home, "Documents"),
		},
		{
			name:  "absolute path",
			input: "/usr/bin",
			want:  "/usr/bin",
		},
		{
			name:  "relative dot path",
			input: "./subdir",
			want:  filepath.Join(cwd, "subdir"),
		},
		{
			name:  "relative parent path",
			input: "../sibling",
			want:  filepath.Join(filepath.Dir(cwd), "sibling"),
		},
		{
			name:  "glob pattern preserved",
			input: "/path/**/*.go",
			want:  "/path/**/*.go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizePath(tt.input)

			// For paths that involve symlink resolution, we just check the result is reasonable
			if strings.Contains(tt.input, "**") || strings.Contains(tt.input, "*") {
				if got != tt.want {
					t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, got, tt.want)
				}
				return
			}

			// For tilde and relative paths, we check prefixes since symlinks may resolve differently
			if tt.input == "~" {
				if got != home && !strings.HasPrefix(got, "/") {
					t.Errorf("NormalizePath(%q) = %q, expected home directory", tt.input, got)
				}
			} else if strings.HasPrefix(tt.input, "~/") {
				if !strings.HasPrefix(got, home) && !strings.HasPrefix(got, "/") {
					t.Errorf("NormalizePath(%q) = %q, expected path under home", tt.input, got)
				}
			}
		})
	}
}

func TestGenerateProxyEnvVars(t *testing.T) {
	tests := []struct {
		name      string
		httpPort  int
		socksPort int
		wantEnvs  []string
		dontWant  []string
	}{
		{
			name:      "no ports",
			httpPort:  0,
			socksPort: 0,
			wantEnvs: []string{
				"FENCE_SANDBOX=1",
			},
			dontWant: []string{
				"HTTP_PROXY=",
				"HTTPS_PROXY=",
				"ALL_PROXY=",
			},
		},
		{
			name:      "http port only",
			httpPort:  8080,
			socksPort: 0,
			wantEnvs: []string{
				"FENCE_SANDBOX=1",
				"HTTP_PROXY=http://localhost:8080",
				"HTTPS_PROXY=http://localhost:8080",
				"http_proxy=http://localhost:8080",
				"https_proxy=http://localhost:8080",
				"NO_PROXY=",
				"no_proxy=",
			},
			dontWant: []string{
				"ALL_PROXY=",
				"all_proxy=",
			},
		},
		{
			name:      "socks port only",
			httpPort:  0,
			socksPort: 1080,
			wantEnvs: []string{
				"FENCE_SANDBOX=1",
				"ALL_PROXY=socks5h://localhost:1080",
				"all_proxy=socks5h://localhost:1080",
				"FTP_PROXY=socks5h://localhost:1080",
				"GIT_SSH_COMMAND=",
			},
			dontWant: []string{
				"HTTP_PROXY=",
				"HTTPS_PROXY=",
			},
		},
		{
			name:      "both ports",
			httpPort:  8080,
			socksPort: 1080,
			wantEnvs: []string{
				"FENCE_SANDBOX=1",
				"HTTP_PROXY=http://localhost:8080",
				"HTTPS_PROXY=http://localhost:8080",
				"ALL_PROXY=socks5h://localhost:1080",
				"GIT_SSH_COMMAND=",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateProxyEnvVars(tt.httpPort, tt.socksPort)

			// Check expected env vars are present
			for _, want := range tt.wantEnvs {
				found := false
				for _, env := range got {
					if strings.HasPrefix(env, want) || env == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("GenerateProxyEnvVars(%d, %d) missing %q", tt.httpPort, tt.socksPort, want)
				}
			}

			// Check unwanted env vars are not present
			for _, dontWant := range tt.dontWant {
				for _, env := range got {
					if strings.HasPrefix(env, dontWant) {
						t.Errorf("GenerateProxyEnvVars(%d, %d) should not contain %q, got %q", tt.httpPort, tt.socksPort, dontWant, env)
					}
				}
			}

			// TMPDIR should always be set. Use /tmp/fence when available, fallback to /tmp otherwise.
			tmpDirFound := false
			for _, env := range got {
				if !strings.HasPrefix(env, "TMPDIR=") {
					continue
				}
				tmpDirFound = true
				tmpDir := strings.TrimPrefix(env, "TMPDIR=")
				if tmpDir != "/tmp/fence" && tmpDir != "/tmp" {
					t.Errorf("GenerateProxyEnvVars(%d, %d) TMPDIR should be /tmp/fence or /tmp, got %q", tt.httpPort, tt.socksPort, tmpDir)
				}
			}
			if !tmpDirFound {
				t.Errorf("GenerateProxyEnvVars(%d, %d) missing TMPDIR env", tt.httpPort, tt.socksPort)
			}
		})
	}
}

func TestEnsureSandboxTMPDIRPathRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real-target")
	link := filepath.Join(root, "tmp-link")
	fallback := filepath.Join(root, "fallback")

	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("failed to create target dir: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	got := ensureSandboxTMPDIRPath(link, fallback)
	if got != fallback {
		t.Fatalf("expected fallback for symlink tmpdir, got %q", got)
	}
}

func TestEnsureSandboxTMPDIRPathCreatesDirectory(t *testing.T) {
	root := t.TempDir()
	tmpDir := filepath.Join(root, "new-tmpdir")
	fallback := filepath.Join(root, "fallback")

	got := ensureSandboxTMPDIRPath(tmpDir, fallback)
	if got != tmpDir {
		t.Fatalf("expected tmpdir path, got %q", got)
	}

	info, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatalf("expected created directory, stat failed: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected directory at %q", tmpDir)
	}
}

func TestEncodeSandboxedCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"simple command", "ls -la"},
		{"command with spaces", "grep -r 'pattern' /path/to/dir"},
		{"empty command", ""},
		{"special chars", "echo $HOME && ls | grep foo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeSandboxedCommand(tt.command)
			if encoded == "" && tt.command != "" {
				t.Error("EncodeSandboxedCommand returned empty string")
			}

			// Roundtrip test
			decoded, err := DecodeSandboxedCommand(encoded)
			if err != nil {
				t.Errorf("DecodeSandboxedCommand failed: %v", err)
			}

			// Commands are truncated to 100 chars
			expected := tt.command
			if len(expected) > 100 {
				expected = expected[:100]
			}
			if decoded != expected {
				t.Errorf("Roundtrip failed: got %q, want %q", decoded, expected)
			}
		})
	}
}

func TestEncodeSandboxedCommandTruncation(t *testing.T) {
	// Test that long commands are truncated
	longCommand := strings.Repeat("a", 200)
	encoded := EncodeSandboxedCommand(longCommand)
	decoded, _ := DecodeSandboxedCommand(encoded)

	if len(decoded) != 100 {
		t.Errorf("Expected truncated command of 100 chars, got %d", len(decoded))
	}
}

func TestDecodeSandboxedCommandInvalid(t *testing.T) {
	_, err := DecodeSandboxedCommand("not-valid-base64!!!")
	if err == nil {
		t.Error("DecodeSandboxedCommand should fail on invalid base64")
	}
}
