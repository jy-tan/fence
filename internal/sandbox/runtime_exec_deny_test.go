package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

func TestRuntimeExecutableToken(t *testing.T) {
	tests := []struct {
		rule string
		want string
		ok   bool
	}{
		{"python3", "python3", true},
		{" /usr/bin/python3 ", "/usr/bin/python3", true},
		{"git push", "", false},
		{"dd if=", "", false},
		{"python*", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		got, ok := runtimeExecutableToken(tt.rule)
		if ok != tt.ok || got != tt.want {
			t.Fatalf("runtimeExecutableToken(%q) = (%q,%v), want (%q,%v)", tt.rule, got, ok, tt.want, tt.ok)
		}
	}
}

func TestGetRuntimeDeniedExecutablePaths_SingleTokenOnly(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny: []string{"python3", "git push", "dd if=", "bash -c"},
		},
	}

	got := GetRuntimeDeniedExecutablePaths(cfg)
	if len(resolveExecutablePaths("python3")) == 0 {
		t.Skip("python3 not available on this system")
	}
	if len(got) == 0 {
		t.Fatalf("expected at least one resolved path for single-token deny entry")
	}

	for _, p := range got {
		base := filepath.Base(p)
		if slices.Contains([]string{"git", "dd", "bash"}, base) {
			t.Fatalf("unexpected direct binary path in results: %s", p)
		}
	}
}

func TestResolveExecutablePaths_CanonicalizesSymlinkAliases(t *testing.T) {
	info, err := os.Lstat("/bin")
	if err != nil {
		t.Skip("/bin not present")
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Skip("/bin is not a symlink on this system")
	}

	paths := resolveExecutablePaths("true")
	if len(paths) == 0 {
		t.Skip("true not available on this system")
	}
	for _, p := range paths {
		if strings.HasPrefix(p, "/bin/") {
			t.Fatalf("expected canonical (non-/bin) path, got: %s", p)
		}
	}
}

func TestGetRuntimeDeniedExecutablePaths_DedupesCanonicalAliasInputs(t *testing.T) {
	info, err := os.Lstat("/bin")
	if err != nil {
		t.Skip("/bin not present")
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Skip("/bin is not a symlink on this system")
	}

	useDefaults := false
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"/bin/true", "/usr/bin/true"},
			UseDefaults: &useDefaults,
		},
	}

	got := GetRuntimeDeniedExecutablePaths(cfg)
	if len(got) == 0 {
		t.Skip("true binary paths were not resolved on this system")
	}
	if len(got) != 1 {
		t.Fatalf("expected canonical alias paths to dedupe to one entry, got: %v", got)
	}
}

func TestResolveExecutablePaths_ReturnsOriginalAbsolutePathWhenNotSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	exePath := filepath.Join(tmpDir, "fake-exe")
	if err := os.WriteFile(exePath, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatalf("failed to create fake executable: %v", err)
	}

	got := resolveExecutablePaths(exePath)
	if len(got) != 1 {
		t.Fatalf("expected exactly one resolved path, got: %v", got)
	}
	want := exePath
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil && resolved != "" {
		want = resolved
	}
	if got[0] != want {
		t.Fatalf("expected resolved path %q, got %q", want, got[0])
	}
}

func TestGetRuntimeDeniedExecutablePaths_IncludesChrootFromDefaults(t *testing.T) {
	chrootPaths := resolveExecutablePaths("chroot")
	if len(chrootPaths) == 0 {
		t.Skip("chroot not available on this system")
	}

	cfg := &config.Config{
		Command: config.CommandConfig{
			// nil means "use defaults"
			UseDefaults: nil,
		},
	}
	got := GetRuntimeDeniedExecutablePaths(cfg)

	for _, want := range chrootPaths {
		if !slices.Contains(got, want) {
			t.Fatalf("expected chroot path %q in runtime denied paths, got: %v", want, got)
		}
	}
}
