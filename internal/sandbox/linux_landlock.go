//go:build linux

package sandbox

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/bmatcuk/doublestar/v4"
	"golang.org/x/sys/unix"
)

// ApplyLandlockFromConfig creates and applies Landlock restrictions based on config.
// This should be called before exec'ing the sandboxed command.
// Returns nil if Landlock is not available (graceful fallback).
func ApplyLandlockFromConfig(cfg *config.Config, cwd string, socketPaths []string, debug bool) error {
	features := DetectLinuxFeatures()
	if !features.CanUseLandlock() {
		if debug {
			fmt.Fprintf(os.Stderr, "[fence:landlock] Not available (kernel %d.%d < 5.13), skipping\n",
				features.KernelMajor, features.KernelMinor)
		}
		return nil // Graceful fallback - Landlock not available
	}

	ruleset, err := NewLandlockRuleset(debug)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "[fence:landlock] Failed to create ruleset: %v\n", err)
		}
		return nil // Graceful fallback
	}
	defer func() { _ = ruleset.Close() }()

	if err := ruleset.Initialize(); err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "[fence:landlock] Failed to initialize: %v\n", err)
		}
		return nil // Graceful fallback
	}

	// Essential system paths - allow read+execute
	// Note: /dev is handled separately with read+write for /dev/null, /dev/zero, etc.
	systemReadPaths := []string{
		"/usr",
		"/lib",
		"/lib64",
		"/lib32",
		"/bin",
		"/sbin",
		"/etc",
		"/proc",
		"/sys",
		"/run",
		"/var/lib",
		"/var/cache",
		"/opt",
	}

	for _, p := range systemReadPaths {
		if err := ruleset.AllowRead(p); err != nil && debug {
			// Ignore errors for paths that don't exist
			if !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "[fence:landlock] Warning: failed to add read path %s: %v\n", p, err)
			}
		}
	}

	// If /etc/resolv.conf is a cross-mount symlink (e.g., -> /mnt/wsl/resolv.conf
	// on WSL), Landlock needs a read rule for the resolved target's parent dir,
	// otherwise following the symlink hits EACCES.
	if target, err := filepath.EvalSymlinks("/etc/resolv.conf"); err == nil && target != "/etc/resolv.conf" {
		targetDir := filepath.Dir(target)
		if err := ruleset.AllowRead(targetDir); err != nil && debug {
			fmt.Fprintf(os.Stderr, "[fence:landlock] Warning: failed to add resolv.conf target dir %s: %v\n", targetDir, err)
		}
	}

	// Current working directory - read access (may be upgraded to write below)
	if cwd != "" {
		if err := ruleset.AllowRead(cwd); err != nil && debug {
			fmt.Fprintf(os.Stderr, "[fence:landlock] Warning: failed to add cwd read path: %v\n", err)
		}
	}

	// Home directory - read access
	if home, err := os.UserHomeDir(); err == nil {
		if err := ruleset.AllowRead(home); err != nil && debug {
			fmt.Fprintf(os.Stderr, "[fence:landlock] Warning: failed to add home read path: %v\n", err)
		}
	}

	// /tmp - allow read+write (many programs need this)
	if err := ruleset.AllowReadWrite("/tmp"); err != nil && debug {
		fmt.Fprintf(os.Stderr, "[fence:landlock] Warning: failed to add /tmp write path: %v\n", err)
	}

	// /dev needs read+write for /dev/null, /dev/zero, /dev/tty, etc.
	// Landlock doesn't support rules on device files directly, so we allow the whole /dev
	if err := ruleset.AllowReadWrite("/dev"); err != nil && debug {
		fmt.Fprintf(os.Stderr, "[fence:landlock] Warning: failed to add /dev write path: %v\n", err)
	}

	// Socket paths for proxy communication
	for _, p := range socketPaths {
		dir := filepath.Dir(p)
		if err := ruleset.AllowReadWrite(dir); err != nil && debug {
			fmt.Fprintf(os.Stderr, "[fence:landlock] Warning: failed to add socket path %s: %v\n", dir, err)
		}
	}

	// User-configured allowWrite paths
	if cfg != nil && cfg.Filesystem.AllowWrite != nil {
		expandedPaths := ExpandGlobPatterns(cfg.Filesystem.AllowWrite)
		for _, p := range expandedPaths {
			if err := ruleset.AllowReadWrite(p); err != nil && debug {
				fmt.Fprintf(os.Stderr, "[fence:landlock] Warning: failed to add write path %s: %v\n", p, err)
			}
		}
		// Also add non-glob paths directly
		for _, p := range cfg.Filesystem.AllowWrite {
			if !ContainsGlobChars(p) {
				normalized := NormalizePath(p)
				if err := ruleset.AllowReadWrite(normalized); err != nil && debug {
					fmt.Fprintf(os.Stderr, "[fence:landlock] Warning: failed to add write path %s: %v\n", normalized, err)
				}
			}
		}
	}

	// Apply the ruleset
	if err := ruleset.Apply(); err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "[fence:landlock] Failed to apply: %v\n", err)
		}
		return nil // Graceful fallback
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[fence:landlock] Applied restrictions (ABI v%d)\n", features.LandlockABI)
	}

	return nil
}

// LandlockRuleset manages Landlock filesystem restrictions.
type LandlockRuleset struct {
	rulesetFd   int
	abiVersion  int
	debug       bool
	initialized bool
	readPaths   map[string]bool
	writePaths  map[string]bool
	denyPaths   map[string]bool
}

// NewLandlockRuleset creates a new Landlock ruleset.
func NewLandlockRuleset(debug bool) (*LandlockRuleset, error) {
	features := DetectLinuxFeatures()
	if !features.CanUseLandlock() {
		return nil, fmt.Errorf("Landlock not available (kernel %d.%d, need 5.13+)",
			features.KernelMajor, features.KernelMinor)
	}

	return &LandlockRuleset{
		rulesetFd:  -1,
		abiVersion: features.LandlockABI,
		debug:      debug,
		readPaths:  make(map[string]bool),
		writePaths: make(map[string]bool),
		denyPaths:  make(map[string]bool),
	}, nil
}

// Initialize creates the Landlock ruleset.
func (l *LandlockRuleset) Initialize() error {
	if l.initialized {
		return nil
	}

	// Determine which access rights to handle based on ABI version
	fsAccess := l.getHandledAccessFS()

	attr := landlockRulesetAttr{
		handledAccessFS: fsAccess,
	}

	// Note: We do NOT enable Landlock network restrictions (handledAccessNet)
	// because:
	// 1. Network isolation is already handled by bwrap's network namespace
	// 2. Enabling network restrictions without proper allow rules would break
	//    the sandbox's proxy connections
	// 3. The proxy architecture requires localhost connections which would
	//    need complex rule management

	fd, _, err := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), //nolint:gosec // required for syscall
		unsafe.Sizeof(attr),
		0,
	)
	if err != 0 {
		return fmt.Errorf("failed to create Landlock ruleset: %w", err)
	}

	l.rulesetFd = int(fd)
	l.initialized = true

	if l.debug {
		fmt.Fprintf(os.Stderr, "[fence:landlock] Created ruleset (ABI v%d, fd=%d)\n", l.abiVersion, l.rulesetFd)
	}

	return nil
}

// getHandledAccessFS returns the filesystem access rights to handle.
func (l *LandlockRuleset) getHandledAccessFS() uint64 {
	// Base access rights (ABI v1)
	access := uint64(
		LANDLOCK_ACCESS_FS_EXECUTE |
			LANDLOCK_ACCESS_FS_WRITE_FILE |
			LANDLOCK_ACCESS_FS_READ_FILE |
			LANDLOCK_ACCESS_FS_READ_DIR |
			LANDLOCK_ACCESS_FS_REMOVE_DIR |
			LANDLOCK_ACCESS_FS_REMOVE_FILE |
			LANDLOCK_ACCESS_FS_MAKE_CHAR |
			LANDLOCK_ACCESS_FS_MAKE_DIR |
			LANDLOCK_ACCESS_FS_MAKE_REG |
			LANDLOCK_ACCESS_FS_MAKE_SOCK |
			LANDLOCK_ACCESS_FS_MAKE_FIFO |
			LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			LANDLOCK_ACCESS_FS_MAKE_SYM,
	)

	// ABI v2: add REFER (cross-directory renames)
	if l.abiVersion >= 2 {
		access |= LANDLOCK_ACCESS_FS_REFER
	}

	// ABI v3: add TRUNCATE
	if l.abiVersion >= 3 {
		access |= LANDLOCK_ACCESS_FS_TRUNCATE
	}

	// ABI v5: add IOCTL_DEV
	if l.abiVersion >= 5 {
		access |= LANDLOCK_ACCESS_FS_IOCTL_DEV
	}

	return access
}

// AllowRead adds read access to a path.
func (l *LandlockRuleset) AllowRead(path string) error {
	return l.addPathRule(path, LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR|LANDLOCK_ACCESS_FS_EXECUTE)
}

// AllowWrite adds write access to a path.
func (l *LandlockRuleset) AllowWrite(path string) error {
	access := uint64(
		LANDLOCK_ACCESS_FS_WRITE_FILE |
			LANDLOCK_ACCESS_FS_REMOVE_DIR |
			LANDLOCK_ACCESS_FS_REMOVE_FILE |
			LANDLOCK_ACCESS_FS_MAKE_CHAR |
			LANDLOCK_ACCESS_FS_MAKE_DIR |
			LANDLOCK_ACCESS_FS_MAKE_REG |
			LANDLOCK_ACCESS_FS_MAKE_SOCK |
			LANDLOCK_ACCESS_FS_MAKE_FIFO |
			LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			LANDLOCK_ACCESS_FS_MAKE_SYM,
	)

	// Add REFER for ABI v2+
	if l.abiVersion >= 2 {
		access |= LANDLOCK_ACCESS_FS_REFER
	}

	// Add TRUNCATE for ABI v3+
	if l.abiVersion >= 3 {
		access |= LANDLOCK_ACCESS_FS_TRUNCATE
	}

	return l.addPathRule(path, access)
}

// AllowReadWrite adds full read/write access to a path.
func (l *LandlockRuleset) AllowReadWrite(path string) error {
	if err := l.AllowRead(path); err != nil {
		return err
	}
	return l.AllowWrite(path)
}

// addPathRule adds a rule for a specific path.
func (l *LandlockRuleset) addPathRule(path string, access uint64) error {
	if !l.initialized {
		if err := l.Initialize(); err != nil {
			return err
		}
	}

	// Resolve symlinks and get absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for %s: %w", path, err)
	}

	// Try to resolve symlinks, but don't fail if the path doesn't exist
	if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = resolved
	}

	// Check if path exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		if l.debug {
			fmt.Fprintf(os.Stderr, "[fence:landlock] Skipping non-existent path: %s\n", absPath)
		}
		return nil
	}

	// Open the path with O_PATH
	fd, err := unix.Open(absPath, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		if l.debug {
			fmt.Fprintf(os.Stderr, "[fence:landlock] Failed to open path %s: %v\n", absPath, err)
		}
		return nil // Don't fail on paths we can't access
	}
	defer func() { _ = unix.Close(fd) }()

	// Use fstat on the fd to avoid TOCTOU race between stat and open
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		if l.debug {
			fmt.Fprintf(os.Stderr, "[fence:landlock] Failed to fstat path %s: %v\n", absPath, err)
		}
		return nil
	}
	isDir := (stat.Mode & unix.S_IFMT) == unix.S_IFDIR

	// Intersect with handled access to avoid invalid combinations
	access &= l.getHandledAccessFS()

	// Filter out directory-only access rights for non-directory paths (files, sockets, devices, etc.).
	// Landlock returns EINVAL if you try to add MAKE_*, REMOVE_*, READ_DIR, or REFER rights to a non-directory.
	// See: https://docs.kernel.org/userspace-api/landlock.html
	// File-compatible rights: EXECUTE, WRITE_FILE, READ_FILE, TRUNCATE
	// Directory-only rights: READ_DIR, REMOVE_*, MAKE_*, REFER
	if !isDir {
		dirOnlyRights := uint64(
			LANDLOCK_ACCESS_FS_READ_DIR |
				LANDLOCK_ACCESS_FS_REMOVE_DIR |
				LANDLOCK_ACCESS_FS_REMOVE_FILE |
				LANDLOCK_ACCESS_FS_MAKE_CHAR |
				LANDLOCK_ACCESS_FS_MAKE_DIR |
				LANDLOCK_ACCESS_FS_MAKE_REG |
				LANDLOCK_ACCESS_FS_MAKE_SOCK |
				LANDLOCK_ACCESS_FS_MAKE_FIFO |
				LANDLOCK_ACCESS_FS_MAKE_BLOCK |
				LANDLOCK_ACCESS_FS_MAKE_SYM |
				LANDLOCK_ACCESS_FS_REFER,
		)
		access &^= dirOnlyRights
	}

	if access == 0 {
		if l.debug {
			fmt.Fprintf(os.Stderr, "[fence:landlock] Skipping %s: no applicable access rights\n", absPath)
		}
		return nil
	}

	attr := landlockPathBeneathAttr{
		allowedAccess: access,
		parentFd:      int32(fd), //nolint:gosec // fd from unix.Open fits in int32
	}

	_, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(l.rulesetFd),
		LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&attr)), //nolint:gosec // required for syscall
	)
	if errno != 0 {
		return fmt.Errorf("failed to add Landlock rule for %s: %w", absPath, errno)
	}

	if l.debug {
		fmt.Fprintf(os.Stderr, "[fence:landlock] Added rule: %s (access=0x%x)\n", absPath, access)
	}

	return nil
}

// Apply applies the Landlock ruleset to the current process.
func (l *LandlockRuleset) Apply() error {
	if !l.initialized {
		return fmt.Errorf("Landlock ruleset not initialized")
	}

	// Set NO_NEW_PRIVS first (required for Landlock)
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to set NO_NEW_PRIVS: %w", err)
	}

	// Apply the ruleset
	_, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_RESTRICT_SELF,
		uintptr(l.rulesetFd),
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("failed to apply Landlock ruleset: %w", errno)
	}

	if l.debug {
		fmt.Fprintf(os.Stderr, "[fence:landlock] Ruleset applied to process\n")
	}

	return nil
}

// Close closes the ruleset file descriptor.
func (l *LandlockRuleset) Close() error {
	if l.rulesetFd >= 0 {
		err := unix.Close(l.rulesetFd)
		l.rulesetFd = -1
		return err
	}
	return nil
}

// ExpandGlobPatterns expands glob patterns to actual paths for Landlock rules.
// Optimized for Landlock's PATH_BENEATH semantics:
//   - "dir/**" → returns just "dir" (Landlock covers descendants automatically)
//   - "**/pattern" → scoped to cwd only, skips already-covered directories
//   - "**/dir/**" → finds dirs in cwd, returns them (PATH_BENEATH covers contents)
func ExpandGlobPatterns(patterns []string) []string {
	var expanded []string
	seen := make(map[string]bool)

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	// First pass: collect directories covered by "dir/**" patterns
	// These will be skipped when walking for "**/pattern" patterns
	coveredDirs := make(map[string]bool)
	for _, pattern := range patterns {
		if !ContainsGlobChars(pattern) {
			continue
		}
		pattern = NormalizePath(pattern)
		if strings.HasSuffix(pattern, "/**") && !strings.Contains(strings.TrimSuffix(pattern, "/**"), "**") {
			dir := strings.TrimSuffix(pattern, "/**")
			if !strings.HasPrefix(dir, "/") {
				dir = filepath.Join(cwd, dir)
			}
			// Store relative path for matching during walk
			relDir, err := filepath.Rel(cwd, dir)
			if err == nil {
				coveredDirs[relDir] = true
			}
		}
	}

	for _, pattern := range patterns {
		if !ContainsGlobChars(pattern) {
			// Not a glob, use as-is
			normalized := NormalizePath(pattern)
			if !seen[normalized] {
				seen[normalized] = true
				expanded = append(expanded, normalized)
			}
			continue
		}

		// Normalize pattern
		pattern = NormalizePath(pattern)

		// Case 1: "dir/**" - just return the dir (PATH_BENEATH handles descendants)
		// This avoids walking the directory entirely
		if strings.HasSuffix(pattern, "/**") && !strings.Contains(strings.TrimSuffix(pattern, "/**"), "**") {
			dir := strings.TrimSuffix(pattern, "/**")
			if !strings.HasPrefix(dir, "/") {
				dir = filepath.Join(cwd, dir)
			}
			if !seen[dir] {
				seen[dir] = true
				expanded = append(expanded, dir)
			}
			continue
		}

		// Case 2: "**/pattern" or "**/dir/**" - scope to cwd only
		// Skip directories already covered by dir/** patterns
		if strings.HasPrefix(pattern, "**/") {
			// Extract what we're looking for after the **/
			suffix := strings.TrimPrefix(pattern, "**/")

			// If it ends with /**, we're looking for directories
			isDir := strings.HasSuffix(suffix, "/**")
			if isDir {
				suffix = strings.TrimSuffix(suffix, "/**")
			}

			// Walk cwd looking for matches, skipping covered directories
			fsys := os.DirFS(cwd)
			searchPattern := "**/" + suffix

			err := doublestar.GlobWalk(fsys, searchPattern, func(path string, d fs.DirEntry) error {
				// Skip directories that are already covered by dir/** patterns
				// Check each parent directory of the current path
				pathParts := strings.Split(path, string(filepath.Separator))
				for i := 1; i <= len(pathParts); i++ {
					parentPath := strings.Join(pathParts[:i], string(filepath.Separator))
					if coveredDirs[parentPath] {
						if d.IsDir() {
							return fs.SkipDir
						}
						return nil // Skip this file, it's under a covered dir
					}
				}

				absPath := filepath.Join(cwd, path)
				if !seen[absPath] {
					seen[absPath] = true
					expanded = append(expanded, absPath)
				}
				return nil
			})
			if err != nil {
				continue
			}
			continue
		}

		// Case 3: Other patterns with * but not ** - use standard glob scoped to cwd
		if !strings.Contains(pattern, "**") {
			var searchBase string
			var searchPattern string

			if strings.HasPrefix(pattern, "/") {
				// Absolute pattern - find the non-glob prefix
				parts := strings.Split(pattern, "/")
				var baseparts []string
				for _, p := range parts {
					if ContainsGlobChars(p) {
						break
					}
					baseparts = append(baseparts, p)
				}
				searchBase = strings.Join(baseparts, "/")
				if searchBase == "" {
					searchBase = "/"
				}
				searchPattern = strings.TrimPrefix(pattern, searchBase+"/")
			} else {
				searchBase = cwd
				searchPattern = pattern
			}

			fsys := os.DirFS(searchBase)
			matches, err := doublestar.Glob(fsys, searchPattern)
			if err != nil {
				continue
			}

			for _, match := range matches {
				absPath := filepath.Join(searchBase, match)
				if !seen[absPath] {
					seen[absPath] = true
					expanded = append(expanded, absPath)
				}
			}
		}
	}

	return expanded
}
