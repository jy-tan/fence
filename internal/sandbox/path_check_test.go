package sandbox

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

func TestCheckWritePath_HookModeDefaultAllow(t *testing.T) {
	// When neither allowWrite nor denyWrite is configured, hook-mode
	// treats writes as out-of-scope so users opting in to command policy
	// don't accidentally block every write_file call.
	cfg := &config.Config{}
	if err := CheckWritePath("/tmp/anywhere.txt", "", cfg); err != nil {
		t.Fatalf("expected nil for unconfigured policy, got %v", err)
	}
}

func TestCheckWritePath_AllowWriteSubtreeMatch(t *testing.T) {
	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			AllowWrite: []string{"/workspace/proj"},
		},
	}

	cases := map[string]bool{
		"/workspace/proj":          true,
		"/workspace/proj/file.txt": true,
		"/workspace/proj/sub/x.go": true,
		"/workspace/projector":     false,
		"/workspace/other":         false,
		"/workspace":               false,
	}
	for path, wantAllow := range cases {
		err := CheckWritePath(path, "", cfg)
		gotAllow := err == nil
		if gotAllow != wantAllow {
			t.Errorf("CheckWritePath(%q) = %v, want allow=%v", path, err, wantAllow)
		}
	}
}

func TestCheckWritePath_DenyWriteOverridesAllow(t *testing.T) {
	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			AllowWrite: []string{"/workspace"},
			DenyWrite:  []string{"/workspace/secrets"},
		},
	}

	if err := CheckWritePath("/workspace/secrets/db.json", "", cfg); err == nil {
		t.Fatal("expected denyWrite to win over allowWrite")
	} else {
		var blocked *PathWriteBlockedError
		if !errors.As(err, &blocked) || blocked.Reason != "denyWrite" {
			t.Fatalf("expected denyWrite reason, got %#v", err)
		}
	}

	// Sibling under allowWrite still allowed.
	if err := CheckWritePath("/workspace/code/x.go", "", cfg); err != nil {
		t.Fatalf("expected sibling under allowWrite to pass, got %v", err)
	}
}

func TestCheckWritePath_DangerousPathsAlwaysDenied(t *testing.T) {
	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			AllowWrite: []string{"/"},
		},
	}
	for _, path := range []string{
		"/home/user/.zshrc",
		"/home/user/proj/.bashrc",
		"/home/user/proj/.git/hooks/pre-commit",
		"/home/user/proj/.git/config",
		"/home/user/proj/.vscode/settings.json",
		"/home/user/proj/.claude/commands/x.md",
	} {
		err := CheckWritePath(path, "", cfg)
		if err == nil {
			t.Errorf("expected dangerous path %q to be denied even with allowWrite=/", path)
		}
	}
}

func TestCheckWritePath_GitInternalsButNotGitDir(t *testing.T) {
	// Writes to .git itself (e.g. refs, objects, HEAD) must remain
	// permitted under allowWrite=/ — git operations need it. Only
	// hooks/* and config are sentinel-protected.
	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			AllowWrite: []string{"/"},
		},
	}
	if err := CheckWritePath("/repo/.git/refs/heads/main", "", cfg); err != nil {
		t.Errorf("expected .git refs to remain writable, got %v", err)
	}
	if err := CheckWritePath("/repo/.git/HEAD", "", cfg); err != nil {
		t.Errorf("expected .git/HEAD to remain writable, got %v", err)
	}
}

func TestCheckWritePath_RelativePathResolvedAgainstCWD(t *testing.T) {
	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			AllowWrite: []string{"/workspace/proj"},
		},
	}
	if err := CheckWritePath("./file.txt", "/workspace/proj", cfg); err != nil {
		t.Errorf("expected relative path under cwd to allow, got %v", err)
	}
	// "../" escape: /workspace/proj/../outside.txt = /workspace/outside.txt
	if err := CheckWritePath("../outside.txt", "/workspace/proj", cfg); err == nil {
		t.Errorf("expected escape path to be denied")
	}
}

func TestCheckWritePath_GlobSupport(t *testing.T) {
	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			AllowWrite: []string{"/workspace/**/*.log"},
		},
	}
	if err := CheckWritePath("/workspace/app/run.log", "", cfg); err != nil {
		t.Errorf("expected glob-matched path to allow, got %v", err)
	}
	if err := CheckWritePath("/workspace/app/run.txt", "", cfg); err == nil {
		t.Errorf("expected non-matching path to be denied")
	}
}

func TestCheckWritePath_RelativePathWithoutCWD(t *testing.T) {
	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			AllowWrite: []string{"/workspace"},
		},
	}
	err := CheckWritePath("file.txt", "", cfg)
	if err == nil {
		t.Fatal("expected relative path without cwd to be denied")
	}
	// Confirm we surface the structured error shape.
	var blocked *PathWriteBlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected *PathWriteBlockedError, got %T", err)
	}
}

func TestCheckWritePath_DenyWriteOnly(t *testing.T) {
	// User-set denyWrite without allowWrite means "block these specific
	// paths, allow everything else" — useful for "deny ~/.config but
	// otherwise unconstrained". We exit the default-allow short-circuit
	// when *either* allowWrite or denyWrite is non-empty.
	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{
			DenyWrite: []string{"/home/user/.config"},
		},
	}
	if err := CheckWritePath("/tmp/x", "", cfg); err == nil {
		// Once any policy is set, default-deny applies for unmatched
		// paths.
	} else {
		var blocked *PathWriteBlockedError
		if !errors.As(err, &blocked) || blocked.Reason != "not in allowWrite" {
			t.Fatalf("expected default-deny when policy is configured, got %v", err)
		}
	}
	if err := CheckWritePath("/home/user/.config/x", "", cfg); err == nil {
		t.Errorf("expected denyWrite hit")
	}
}

func TestPathInDangerousDir(t *testing.T) {
	cases := []struct {
		path string
		dir  string
		want bool
	}{
		{"/home/u/.vscode/settings.json", ".vscode", true},
		{"/home/u/proj/.vscode", ".vscode", false}, // exact match shouldn't trigger; only descendants
		{"/home/u/proj/notvscode/x", ".vscode", false},
		{"/repo/.claude/commands/x.md", ".claude/commands", true},
		{"/repo/.claude/agents/x.md", ".claude/commands", false},
	}
	for _, tc := range cases {
		path := filepath.FromSlash(tc.path)
		got := pathInDangerousDir(path, tc.dir)
		if got != tc.want {
			t.Errorf("pathInDangerousDir(%q, %q) = %v, want %v", tc.path, tc.dir, got, tc.want)
		}
	}
}
