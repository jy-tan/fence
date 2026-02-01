package sandbox

import (
	"os"
	"path/filepath"
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
		"/var",

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

	// Add user-installed tooling paths (these contain executables/runtimes, not user data)
	if home != "" {
		paths = append(paths,
			// Node.js version managers
			filepath.Join(home, ".nvm"),
			filepath.Join(home, ".fnm"),
			filepath.Join(home, ".volta"),
			filepath.Join(home, ".n"),

			// Python version managers
			filepath.Join(home, ".pyenv"),
			filepath.Join(home, ".local/pipx"),

			// Ruby version managers
			filepath.Join(home, ".rbenv"),
			filepath.Join(home, ".rvm"),

			// Rust
			filepath.Join(home, ".cargo/bin"),
			filepath.Join(home, ".rustup"),

			// Go
			filepath.Join(home, "go/bin"),
			filepath.Join(home, ".go"),

			// User local binaries
			filepath.Join(home, ".local/bin"),
			filepath.Join(home, "bin"),

			// Bun
			filepath.Join(home, ".bun/bin"),

			// Deno
			filepath.Join(home, ".deno/bin"),
		)
	}

	return paths
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
