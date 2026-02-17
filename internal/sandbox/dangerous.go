package sandbox

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DangerousFiles lists files that should be protected from writes.
// These files can be used for code execution or data exfiltration.
var DangerousFiles = []string{
	".gitconfig",
	".gitmodules",
	".bashrc",
	".bash_profile",
	".zshrc",
	".zprofile",
	".profile",
	".ripgreprc",
	".mcp.json",
}

// DangerousDirectories lists directories that should be protected from writes.
// Excludes .git since we need it writable for git operations.
var DangerousDirectories = []string{
	".vscode",
	".idea",
	".claude/commands",
	".claude/agents",
}

// GetDefaultWritePaths returns system paths that should be writable for commands to work.
func GetDefaultWritePaths() []string {
	home, _ := os.UserHomeDir()

	paths := []string{
		"/dev/stdout",
		"/dev/stderr",
		"/dev/null",
		"/dev/tty",
		"/dev/dtracehelper",
		"/dev/autofs_nowait",
		"/tmp/fence",
		"/private/tmp/fence",
	}

	if home != "" {
		paths = append(paths,
			filepath.Join(home, ".npm/_logs"),
			filepath.Join(home, ".fence/debug"),
		)
	}

	return paths
}

// GetDefaultReadablePaths returns paths that should remain readable when defaultDenyRead is enabled.
// These are essential system paths needed for most programs to run.
//
// Note on user tooling paths: Version managers like nvm, pyenv, etc. require read access to their
// entire installation directories (not just bin/) because runtimes need to load libraries and
// modules from these paths. For example, Node.js needs to read ~/.nvm/versions/.../lib/ to load
// globally installed packages. This is a trade-off between functionality and strict isolation.
// Users who need tighter control can use denyRead to block specific subpaths within these directories.
func GetDefaultReadablePaths() []string {
	home, _ := os.UserHomeDir()

	paths := []string{
		// Core system paths
		"/bin",
		"/sbin",
		"/usr",
		"/lib",
		"/lib64",

		// System configuration (needed for DNS, SSL, locale, etc.)
		"/etc",

		// Proc filesystem (needed for process info)
		"/proc",

		// Sys filesystem (needed for system info)
		"/sys",

		// Device nodes
		"/dev",

		// macOS specific
		"/System",
		"/Library",
		"/Applications",
		"/private/etc",
		"/private/var/db",
		"/private/var/run",

		// Linux distributions may have these
		"/opt",
		"/run",

		// Temp directories (needed for many operations)
		"/tmp",
		"/private/tmp",

		// Common package manager paths
		"/usr/local",
		"/opt/homebrew",
		"/nix",
		"/snap",
	}

	// User-installed tooling paths. These version managers and language runtimes need
	// read access to their full directories (not just bin/) to function properly.
	// Runtimes load libraries, modules, and configs from within these directories.
	if home != "" {
		paths = append(paths,
			// Node.js version managers (need lib/ for global packages)
			filepath.Join(home, ".nvm"),
			filepath.Join(home, ".fnm"),
			filepath.Join(home, ".volta"),
			filepath.Join(home, ".n"),

			// Python version managers (need lib/ for installed packages)
			filepath.Join(home, ".pyenv"),
			filepath.Join(home, ".local/pipx"),

			// Ruby version managers (need lib/ for gems)
			filepath.Join(home, ".rbenv"),
			filepath.Join(home, ".rvm"),

			// Rust (bin only - cargo doesn't need full .cargo for execution)
			filepath.Join(home, ".cargo/bin"),
			filepath.Join(home, ".rustup"),

			// Go (bin only)
			filepath.Join(home, "go/bin"),
			filepath.Join(home, ".go"),

			// User local binaries (bin only)
			filepath.Join(home, ".local/bin"),
			filepath.Join(home, "bin"),

			// Bun (bin only)
			filepath.Join(home, ".bun/bin"),

			// Deno (bin only)
			filepath.Join(home, ".deno/bin"),
		)
	}

	return paths
}

// DefaultMaxDangerousFileDepth is the default depth limit for FindDangerousFiles.
const DefaultMaxDangerousFileDepth = 3

// FindDangerousFiles walks the directory tree under root up to maxDepth levels
// of subdirectories and returns absolute paths to dangerous files, directories,
// and git hooks/config found in those subdirectories.
//
// maxDepth controls how many levels of project subdirectories to search:
//   - maxDepth=0: returns nothing (no subdirectory search)
//   - maxDepth=1: searches immediate subdirectories only (root/sub/*.dangerous)
//   - maxDepth=3: searches up to root/a/b/c/*.dangerous
//
// Items directly in root are not returned - the caller adds those separately.
// node_modules directories are skipped for performance.
// .git internals (hooks/, config) are handled specially: when a .git dir is found
// within the depth range, we peek inside for hooks/ and config without counting
// .git's internal structure against the depth limit.
func FindDangerousFiles(root string, maxDepth int) []string {
	if maxDepth <= 0 {
		return nil
	}

	// Build lookup sets for O(1) matching
	dangerousFileSet := make(map[string]bool, len(DangerousFiles))
	for _, f := range DangerousFiles {
		dangerousFileSet[f] = true
	}
	dangerousDirSet := make(map[string]bool, len(DangerousDirectories))
	for _, d := range DangerousDirectories {
		dangerousDirSet[d] = true
	}
	// For multi-component dangerous dirs like ".claude/commands", track the
	// first component so we enter it during the walk, then match the full path.
	multiCompFirstComponent := make(map[string]bool)
	for _, d := range DangerousDirectories {
		if strings.Contains(d, string(filepath.Separator)) {
			first := strings.SplitN(d, string(filepath.Separator), 2)[0]
			multiCompFirstComponent[first] = true
		}
	}

	rootClean := filepath.Clean(root)
	rootPrefix := rootClean + string(filepath.Separator)

	var results []string

	_ = filepath.WalkDir(rootClean, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return filepath.SkipDir
		}
		if path == rootClean {
			return nil
		}

		rel := strings.TrimPrefix(path, rootPrefix)
		components := strings.Split(rel, string(filepath.Separator))
		nComp := len(components)
		name := d.Name()

		// Skip node_modules entirely for performance
		if d.IsDir() && name == "node_modules" {
			return filepath.SkipDir
		}

		// subdirLevel: how many user-facing subdirectory levels from root.
		// root/sub/.bashrc -> nComp=2 -> subdirLevel=1
		// root/a/b/.bashrc -> nComp=3 -> subdirLevel=2
		subdirLevel := nComp - 1

		// Handle .git directories specially: peek inside for hooks/ and config
		// without counting .git internals against the depth limit.
		// The depth that matters is where .git sits in the subdirectory tree.
		// root/.git (subdirLevel=0) -> skip (caller handles cwd-level .git)
		// root/a/.git (subdirLevel=1) -> peek inside if maxDepth >= 1
		if d.IsDir() && name == ".git" {
			if subdirLevel >= 1 && subdirLevel <= maxDepth {
				hooksPath := filepath.Join(path, "hooks")
				if info, e := os.Stat(hooksPath); e == nil && info.IsDir() {
					results = append(results, hooksPath)
				}
				configPath := filepath.Join(path, "config")
				if info, e := os.Stat(configPath); e == nil && !info.IsDir() {
					results = append(results, configPath)
				}
			}
			return filepath.SkipDir
		}

		// Items with 1 component are direct children of root - skip them
		// (the caller already adds cwd-level dangerous files/dirs).
		// For directories, we still need to descend into them.
		if nComp == 1 {
			return nil
		}

		// Prune directories beyond our search depth.
		// We need to descend up to maxDepth+1 components to find dangerous
		// files/dirs at the maxDepth level (nComp = maxDepth+1).
		if d.IsDir() && subdirLevel > maxDepth {
			return filepath.SkipDir
		}

		// Check dangerous files
		if !d.IsDir() && dangerousFileSet[name] && subdirLevel <= maxDepth {
			results = append(results, path)
			return nil
		}

		// Check dangerous directories (single-component like ".vscode")
		if d.IsDir() && dangerousDirSet[name] && subdirLevel <= maxDepth {
			results = append(results, path)
			return filepath.SkipDir
		}

		// Check multi-component dangerous dirs like ".claude/commands":
		// match when the relative path ends with the full pattern on a
		// path-component boundary (so "not.claude/commands" won't match).
		if d.IsDir() {
			for _, dd := range DangerousDirectories {
				if strings.Contains(dd, string(filepath.Separator)) &&
					subdirLevel <= maxDepth &&
					strings.HasSuffix(rel, dd) &&
					(rel == dd || rel[len(rel)-len(dd)-1] == filepath.Separator) {
					results = append(results, path)
					return filepath.SkipDir
				}
			}
		}

		return nil
	})

	return results
}

// GetMandatoryDenyPatterns returns glob patterns for paths that must always be protected.
func GetMandatoryDenyPatterns(cwd string, allowGitConfig bool) []string {
	var patterns []string

	// Dangerous files - in CWD and all subdirectories
	for _, f := range DangerousFiles {
		patterns = append(patterns, filepath.Join(cwd, f))
		patterns = append(patterns, "**/"+f)
	}

	// Dangerous directories
	for _, d := range DangerousDirectories {
		patterns = append(patterns, filepath.Join(cwd, d))
		patterns = append(patterns, "**/"+d+"/**")
	}

	// Git hooks are always blocked
	patterns = append(patterns, filepath.Join(cwd, ".git/hooks"))
	patterns = append(patterns, "**/.git/hooks/**")

	// Git config is conditionally blocked
	if !allowGitConfig {
		patterns = append(patterns, filepath.Join(cwd, ".git/config"))
		patterns = append(patterns, "**/.git/config")
	}

	return patterns
}
