package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/Use-Tusk/fence/internal/config"
)

// criticalCommands is the hardcoded list of commands whose collateral blocking
// would break basic shell scripting or interactive use. Only commands that no
// reasonable sandbox policy would intentionally block are included here.
// Plausible block targets (rm, kill, chmod, chown, ln, stat, dd, etc.) are
// deliberately excluded.
//
// Ordering is intentional: the truncated non-debug warning shows only the
// first 3 collisions, so the list is sorted by how alarming the collateral
// damage is for agent pipelines.
//
// Tier 1 — present in GNU coreutils, uutils-coreutils AND busybox, ordered
// by agent pipeline frequency. These appear first because they are the most
// likely collateral victims when a coreutils/busybox multicall binary is blocked.
//
// Tier 2 — present in busybox but NOT in GNU coreutils (grep, sed, awk,
// find, xargs live in separate packages on most distros). These only collide
// when busybox is the shared binary, so they sit at the end.
var criticalCommands = []string{
	// Tier 1: in coreutils + busybox, by agent frequency.
	"cat",
	"head",
	"tail",
	"echo",
	"sort",
	"wc",
	"cut",
	"tr",
	"uniq",
	// Tier 1 remainder: alphabetical.
	"[",
	"basename",
	"cp",
	"date",
	"dirname",
	"env",
	"false",
	"id",
	"ls",
	"mkdir",
	"mktemp",
	"mv",
	"printf",
	"pwd",
	"readlink",
	"realpath",
	"rmdir",
	"tee",
	"test",
	"touch",
	"true",
	"uname",
	"whoami",
	// Tier 2: busybox only, by agent frequency.
	"grep",
	"sed",
	"awk",
	"find",
	"xargs",
}

var commonExecutableDirs = []string{
	"/usr/bin",
	"/bin",
	"/usr/local/bin",
	"/opt/homebrew/bin",
	"/opt/local/bin",
}

// GetRuntimeDeniedExecutablePaths returns absolute executable paths that should
// be blocked at exec-time for this config.
//
// Runtime exec enforcement is intentionally conservative:
// - Only deny entries that are a single executable token are included.
// - Prefix rules with arguments (e.g. "git push", "dd if=") remain preflight-only.
func GetRuntimeDeniedExecutablePaths(cfg *config.Config) []string {
	paths, _ := GetRuntimeDeniedExecutablePathsWithDiagnostics(cfg, false)
	return paths
}

// GetRuntimeDeniedExecutablePathsWithDiagnostics returns the list of executable paths to deny at
// runtime, along with a diagnostics slice. Each diagnostic is formatted for the given debug
// level: non-debug messages truncate the collision list to the first 3 items and hint at
// --debug for the full list; debug messages show all collisions.
func GetRuntimeDeniedExecutablePathsWithDiagnostics(cfg *config.Config, debug bool) ([]string, []string) {
	if cfg == nil {
		return nil, nil
	}

	var denyRules []string
	denyRules = append(denyRules, cfg.Command.Deny...)
	if cfg.Command.UseDefaultDeniedCommands() {
		denyRules = append(denyRules, config.DefaultDeniedCommands...)
	}

	// Pre-compute the full set of deny tokens so shouldSkipRuntimeExecDenyPath
	// can exclude them from the critical-collision check. A shared name that is
	// itself being denied is not collateral damage — the user explicitly wants
	// it blocked — and must not trigger the skip-with-warning path.
	// Index by both the raw token and its basename. findSharedExecutableNames
	// always returns bare filenames (entry.Name()), so an absolute-path deny
	// entry like "/tmp/ls" must also be reachable as "ls" in the collision check.
	denyTokens := make(map[string]bool, len(denyRules)*2)
	for _, rule := range denyRules {
		if t, ok := runtimeExecutableToken(rule); ok {
			denyTokens[t] = true
			denyTokens[filepath.Base(t)] = true
		}
	}

	var paths []string
	var diagnostics []string
	seen := make(map[string]bool)
	sharedCache := make(map[string]sharedExecutableInfo)

	for _, rule := range denyRules {
		token, ok := runtimeExecutableToken(rule)
		if !ok {
			continue
		}

		for _, resolved := range resolveExecutablePaths(token) {
			if seen[resolved] {
				continue
			}
			skip, reason := shouldSkipRuntimeExecDenyPath(
				resolved, token,
				cfg.Command.AcceptSharedBinaryCannotRuntimeDeny,
				denyTokens,
				sharedCache,
				debug,
			)
			seen[resolved] = true
			if reason != "" {
				diagnostics = append(diagnostics, reason)
			}
			if skip {
				continue
			}
			paths = append(paths, resolved)
		}
	}

	slices.Sort(paths)
	slices.Sort(diagnostics)
	return paths, diagnostics
}

func runtimeExecutableToken(rule string) (string, bool) {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return "", false
	}

	tokens := tokenizeCommand(rule)
	if len(tokens) != 1 {
		return "", false
	}

	token := strings.TrimSpace(tokens[0])
	if token == "" {
		return "", false
	}

	// Runtime exec enforcement is path/name-based; skip entries that clearly
	// encode shell-level matching syntax.
	if strings.ContainsAny(token, "*?[]|&;()<>$`=") {
		return "", false
	}

	return token, true
}

func resolveExecutablePaths(token string) []string {
	var paths []string
	seen := make(map[string]bool)
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		paths = append(paths, p)
	}

	addCanonicalPath := func(p string) {
		if p == "" {
			return
		}
		resolved := p
		if r, err := filepath.EvalSymlinks(p); err == nil && r != "" {
			resolved = r
		}
		// Prefer the real (symlink-resolved) path to avoid generating deny entries
		// like /bin/* on usr-merged distros where /bin is a symlink to /usr/bin.
		//
		// Bubblewrap is strict about mounting over paths with symlink components;
		// attempting to bind-mask /bin/foo can fail even when /usr/bin/foo exists.
		if resolved != p {
			add(resolved)
			return
		}
		add(p)
	}

	if strings.ContainsRune(token, filepath.Separator) {
		abs := token
		if !filepath.IsAbs(abs) {
			if cwd, err := os.Getwd(); err == nil {
				abs = filepath.Join(cwd, abs)
			}
		}
		if executablePathExists(abs) {
			addCanonicalPath(abs)
		}
		return paths
	}

	if resolved, err := exec.LookPath(token); err == nil {
		addCanonicalPath(resolved)
	}

	for _, dir := range commonExecutableDirs {
		candidate := filepath.Join(dir, token)
		if executablePathExists(candidate) {
			addCanonicalPath(candidate)
		}
	}

	return paths
}

type sharedExecutableInfo struct {
	checked bool
	shared  bool
	names   []string
}

func shouldSkipRuntimeExecDenyPath(
	path string,
	token string,
	acceptSharedBinaryCannotRuntimeDeny []string,
	denyTokens map[string]bool,
	sharedCache map[string]sharedExecutableInfo,
	debug bool,
) (bool, string) {
	info := getSharedExecutableInfo(path, sharedCache)
	if !info.shared {
		return false, ""
	}

	// Collect which of the shared names are critical commands, excluding:
	//   • the token itself — the user explicitly asked to block it, so it is
	//     not collateral damage to itself, and
	//   • any name that is also in the deny list — if the user is blocking
	//     both "dd" and "ls" on a shared binary, "ls" is intentional, not
	//     collateral damage; all shared names being denied means the binary
	//     should be blocked normally.
	var criticalCollisions []string
	for _, name := range info.names {
		if name != filepath.Base(token) && !denyTokens[name] && slices.Contains(criticalCommands, name) {
			criticalCollisions = append(criticalCollisions, name)
		}
	}
	// Sort by priority index in criticalCommands so the truncated non-debug
	// warning surfaces the most impactful collateral commands first.
	slices.SortFunc(criticalCollisions, func(a, b string) int {
		return slices.Index(criticalCommands, a) - slices.Index(criticalCommands, b)
	})

	// No critical command would be collaterally blocked — safe to block normally.
	if len(criticalCollisions) == 0 {
		return false, ""
	}

	// User has explicitly accepted that this command cannot be runtime-blocked.
	// Skip silently — no diagnostic. Normalize both sides to basename so that
	// "dd" and "/usr/bin/dd" are treated as equivalent.
	tokenBase := filepath.Base(token)
	for _, accepted := range acceptSharedBinaryCannotRuntimeDeny {
		if accepted == token || filepath.Base(accepted) == tokenBase {
			return true, ""
		}
	}

	// Format the collision list.
	// Non-debug: show the first maxShort critical names (highest priority first);
	// the "+N more" count covers all remaining inode-sharers — not just critical
	// ones — so the user sees the true blast radius.
	// Debug: critical names first (priority order), then all other shared names
	// appended alphabetically, with no repetitions.
	const maxShort = 3
	var collisionSummary string
	if debug {
		criticalSet := make(map[string]bool, len(criticalCollisions))
		for _, name := range criticalCollisions {
			criticalSet[name] = true
		}
		var nonCritical []string
		for _, name := range info.names {
			if name == tokenBase || denyTokens[name] || criticalSet[name] {
				continue
			}
			nonCritical = append(nonCritical, name)
		}
		slices.Sort(nonCritical)
		all := make([]string, 0, len(criticalCollisions)+len(nonCritical))
		all = append(all, criticalCollisions...)
		all = append(all, nonCritical...)
		collisionSummary = strings.Join(all, " ")
	} else {
		shown := criticalCollisions
		if len(shown) > maxShort {
			shown = shown[:maxShort]
		}
		// remaining covers all other names sharing the inode minus the token
		// itself and the names already shown in the excerpt.
		remaining := len(info.names) - 1 - len(shown)
		collisionSummary = strings.Join(shown, " ")
		if remaining > 0 {
			collisionSummary = fmt.Sprintf("%s +%d more, use --debug for full list",
				collisionSummary, remaining)
		}
	}

	return false, fmt.Sprintf(
		"runtime exec deny warning for %s (requested: %s): shared binary also implements "+
			"critical commands [%s], which will be collaterally blocked. To skip runtime "+
			"blocking of %q and silence this warning, add it to \"acceptSharedBinaryCannotRuntimeDeny\" "+
			"in your command config.",
		path,
		token,
		collisionSummary,
		filepath.Base(token),
	)
}

func getSharedExecutableInfo(path string, sharedCache map[string]sharedExecutableInfo) sharedExecutableInfo {
	if cached, ok := sharedCache[path]; ok && cached.checked {
		return cached
	}

	shared, names := findSharedExecutableNames(path)
	info := sharedExecutableInfo{checked: true, shared: shared, names: names}
	sharedCache[path] = info
	return info
}

type fileIdentity struct {
	dev uint64
	ino uint64
}

func statFileIdentity(path string) (fileIdentity, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return fileIdentity{}, false
	}
	return fileIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
}

func executableSearchDirs(path string) []string {
	var dirs []string
	seen := make(map[string]bool)
	add := func(dir string) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return
		}
		if seen[dir] {
			return
		}
		if !directoryExists(dir) {
			return
		}
		seen[dir] = true
		dirs = append(dirs, dir)
	}

	add(filepath.Dir(path))
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		add(dir)
	}
	for _, dir := range commonExecutableDirs {
		add(dir)
	}
	return dirs
}

func findSharedExecutableNames(path string) (bool, []string) {
	targetIdentity, ok := statFileIdentity(path)
	if !ok {
		return false, nil
	}

	nameSet := make(map[string]bool)
	for _, dir := range executableSearchDirs(path) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			candidate := filepath.Join(dir, entry.Name())
			candidateIdentity, ok := statFileIdentity(candidate)
			if !ok {
				continue
			}
			if candidateIdentity != targetIdentity {
				continue
			}
			nameSet[entry.Name()] = true
		}
	}

	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	slices.Sort(names)
	return len(names) > 1, names
}

func directoryExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func executablePathExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
