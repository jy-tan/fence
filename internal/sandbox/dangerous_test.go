package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestGetDefaultWritePaths(t *testing.T) {
	paths := GetDefaultWritePaths()

	if len(paths) == 0 {
		t.Error("GetDefaultWritePaths() returned empty slice")
	}

	essentialPaths := []string{"/dev/stdout", "/dev/stderr", "/dev/null", "/tmp/fence"}
	for _, essential := range essentialPaths {
		found := slices.Contains(paths, essential)
		if !found {
			t.Errorf("GetDefaultWritePaths() missing essential path %q", essential)
		}
	}
}

func TestGetMandatoryDenyPatterns(t *testing.T) {
	cwd := "/home/user/project"

	tests := []struct {
		name             string
		cwd              string
		allowGitConfig   bool
		shouldContain    []string
		shouldNotContain []string
	}{
		{
			name:           "with git config denied",
			cwd:            cwd,
			allowGitConfig: false,
			shouldContain: []string{
				filepath.Join(cwd, ".gitconfig"),
				filepath.Join(cwd, ".bashrc"),
				filepath.Join(cwd, ".zshrc"),
				filepath.Join(cwd, ".git/hooks"),
				filepath.Join(cwd, ".git/config"),
				"**/.gitconfig",
				"**/.bashrc",
				"**/.git/hooks/**",
				"**/.git/config",
			},
		},
		{
			name:           "with git config allowed",
			cwd:            cwd,
			allowGitConfig: true,
			shouldContain: []string{
				filepath.Join(cwd, ".gitconfig"),
				filepath.Join(cwd, ".git/hooks"),
				"**/.git/hooks/**",
			},
			shouldNotContain: []string{
				filepath.Join(cwd, ".git/config"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := GetMandatoryDenyPatterns(tt.cwd, tt.allowGitConfig)

			for _, expected := range tt.shouldContain {
				found := slices.Contains(patterns, expected)
				if !found {
					t.Errorf("GetMandatoryDenyPatterns() missing pattern %q", expected)
				}
			}

			for _, notExpected := range tt.shouldNotContain {
				found := slices.Contains(patterns, notExpected)
				if found {
					t.Errorf("GetMandatoryDenyPatterns() should not contain %q when allowGitConfig=%v", notExpected, tt.allowGitConfig)
				}
			}
		})
	}
}

func TestGetMandatoryDenyPatternsContainsDangerousFiles(t *testing.T) {
	cwd := "/test/project"
	patterns := GetMandatoryDenyPatterns(cwd, false)

	// Each dangerous file should appear both as a cwd-relative path and as a glob pattern
	for _, file := range DangerousFiles {
		cwdPath := filepath.Join(cwd, file)
		globPattern := "**/" + file

		foundCwd := false
		foundGlob := false

		for _, p := range patterns {
			if p == cwdPath {
				foundCwd = true
			}
			if p == globPattern {
				foundGlob = true
			}
		}

		if !foundCwd {
			t.Errorf("Missing cwd-relative pattern for dangerous file %q", file)
		}
		if !foundGlob {
			t.Errorf("Missing glob pattern for dangerous file %q", file)
		}
	}
}

func TestGetMandatoryDenyPatternsContainsDangerousDirectories(t *testing.T) {
	cwd := "/test/project"
	patterns := GetMandatoryDenyPatterns(cwd, false)

	for _, dir := range DangerousDirectories {
		cwdPath := filepath.Join(cwd, dir)
		globPattern := "**/" + dir + "/**"

		foundCwd := false
		foundGlob := false

		for _, p := range patterns {
			if p == cwdPath {
				foundCwd = true
			}
			if p == globPattern {
				foundGlob = true
			}
		}

		if !foundCwd {
			t.Errorf("Missing cwd-relative pattern for dangerous directory %q", dir)
		}
		if !foundGlob {
			t.Errorf("Missing glob pattern for dangerous directory %q", dir)
		}
	}
}

func TestGetMandatoryDenyPatternsGitHooksAlwaysBlocked(t *testing.T) {
	cwd := "/test/project"

	// Git hooks should be blocked regardless of allowGitConfig
	for _, allowGitConfig := range []bool{true, false} {
		patterns := GetMandatoryDenyPatterns(cwd, allowGitConfig)

		foundHooksPath := false
		foundHooksGlob := false

		for _, p := range patterns {
			if p == filepath.Join(cwd, ".git/hooks") {
				foundHooksPath = true
			}
			if strings.Contains(p, ".git/hooks") && strings.HasPrefix(p, "**") {
				foundHooksGlob = true
			}
		}

		if !foundHooksPath || !foundHooksGlob {
			t.Errorf("Git hooks should always be blocked (allowGitConfig=%v)", allowGitConfig)
		}
	}
}

func TestFindDangerousFiles(t *testing.T) {
	// Create a temp directory tree with dangerous files at various depths:
	//   cwd/.bashrc               (depth 0 - directly in cwd)
	//   cwd/subdir/.zshrc         (depth 1 - one level deep)
	//   cwd/a/b/.bashrc           (depth 2 - two levels deep)
	//   cwd/a/b/c/.profile        (depth 3 - three levels deep, at limit)
	//   cwd/a/b/c/d/.bashrc       (depth 4 - beyond default limit)
	//   cwd/subdir/.vscode/       (dangerous directory at depth 1)
	//   cwd/a/.git/hooks/         (git hooks at depth 1)
	//   cwd/a/.git/config         (git config at depth 1)
	//   cwd/node_modules/pkg/.bashrc  (should be excluded)

	tmpDir := t.TempDir()

	// Helper to create files/dirs
	mkfile := func(rel string) {
		abs := filepath.Join(tmpDir, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mkdir := func(rel string) {
		abs := filepath.Join(tmpDir, rel)
		if err := os.MkdirAll(abs, 0o750); err != nil {
			t.Fatal(err)
		}
	}

	// Dangerous files at various depths
	mkfile(".bashrc")         // depth 0
	mkfile("subdir/.zshrc")   // depth 1
	mkfile("a/b/.bashrc")     // depth 2
	mkfile("a/b/c/.profile")  // depth 3
	mkfile("a/b/c/d/.bashrc") // depth 4 — beyond limit

	// Dangerous directories
	mkdir("subdir/.vscode") // depth 1

	// Git hooks and config in nested repo
	mkdir("a/.git/hooks")   // depth 1
	mkfile("a/.git/config") // depth 1

	// File in node_modules — should be excluded
	mkfile("node_modules/pkg/.bashrc")

	// Directory with name that is a suffix-match for a dangerous dir but not
	// on a path boundary (e.g. "not.claude/commands" should NOT match ".claude/commands")
	mkdir("sub/not.claude/commands")

	// Safe file — should not appear
	mkfile("subdir/safe.txt")

	t.Run("depth 3 finds nested dangerous files but not beyond limit", func(t *testing.T) {
		results := FindDangerousFiles(tmpDir, 3)

		shouldFind := []string{
			filepath.Join(tmpDir, "subdir/.zshrc"),
			filepath.Join(tmpDir, "a/b/.bashrc"),
			filepath.Join(tmpDir, "a/b/c/.profile"),
			filepath.Join(tmpDir, "subdir/.vscode"),
			filepath.Join(tmpDir, "a/.git/hooks"),
			filepath.Join(tmpDir, "a/.git/config"),
		}

		shouldNotFind := []string{
			// depth 0 files are not returned (cwd-level files are added separately)
			filepath.Join(tmpDir, ".bashrc"),
			// depth 4 is beyond limit
			filepath.Join(tmpDir, "a/b/c/d/.bashrc"),
			// node_modules should be excluded
			filepath.Join(tmpDir, "node_modules/pkg/.bashrc"),
			// suffix false-positive: "not.claude/commands" should not match ".claude/commands"
			filepath.Join(tmpDir, "sub/not.claude/commands"),
			// safe files should never appear
			filepath.Join(tmpDir, "subdir/safe.txt"),
		}

		for _, want := range shouldFind {
			if !slices.Contains(results, want) {
				t.Errorf("FindDangerousFiles() should find %q but didn't.\nGot: %v", want, results)
			}
		}

		for _, notWant := range shouldNotFind {
			if slices.Contains(results, notWant) {
				t.Errorf("FindDangerousFiles() should NOT find %q but did", notWant)
			}
		}
	})

	t.Run("depth 1 only finds immediate subdirectory files", func(t *testing.T) {
		results := FindDangerousFiles(tmpDir, 1)

		shouldFind := []string{
			filepath.Join(tmpDir, "subdir/.zshrc"),
			filepath.Join(tmpDir, "subdir/.vscode"),
			filepath.Join(tmpDir, "a/.git/hooks"),
			filepath.Join(tmpDir, "a/.git/config"),
		}

		shouldNotFind := []string{
			filepath.Join(tmpDir, "a/b/.bashrc"),
			filepath.Join(tmpDir, "a/b/c/.profile"),
		}

		for _, want := range shouldFind {
			if !slices.Contains(results, want) {
				t.Errorf("FindDangerousFiles(depth=1) should find %q but didn't.\nGot: %v", want, results)
			}
		}

		for _, notWant := range shouldNotFind {
			if slices.Contains(results, notWant) {
				t.Errorf("FindDangerousFiles(depth=1) should NOT find %q", notWant)
			}
		}
	})

	t.Run("depth 0 returns nothing", func(t *testing.T) {
		results := FindDangerousFiles(tmpDir, 0)
		if len(results) != 0 {
			t.Errorf("FindDangerousFiles(depth=0) should return empty, got %v", results)
		}
	})
}
