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
// level: non-debug messages truncate the collision list to the first 3 critical commands and
// hint at --debug for expanded details; debug messages show all detected relevant aliases.
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
	// always returns bare filenames, so an absolute-path deny entry like
	// "/tmp/ls" must also be reachable as "ls" in the collision check.
	denyTokens := make(map[string]bool, len(denyRules)*2)
	for _, rule := range denyRules {
		if t, ok := runtimeExecutableToken(rule); ok {
			denyTokens[t] = true
			denyTokens[filepath.Base(t)] = true
		}
	}

	type runtimeDeniedTarget struct {
		token string
		path  string
	}

	var targets []runtimeDeniedTarget
	for _, rule := range denyRules {
		token, ok := runtimeExecutableToken(rule)
		if !ok {
			continue
		}
		for _, resolved := range resolveExecutablePaths(token) {
			targets = append(targets, runtimeDeniedTarget{token: token, path: resolved})
		}
	}

	var resolvedPaths []string
	for _, target := range targets {
		resolvedPaths = append(resolvedPaths, target.path)
	}
	sharedSearch := newSharedExecutableSearch(resolvedPaths, runtimeExecSharedProbeNames(denyTokens))

	var paths []string
	var diagnostics []string
	seen := make(map[string]bool)
	sharedCache := make(map[string]sharedExecutableInfo)

	for _, target := range targets {
		if seen[target.path] {
			continue
		}
		skip, reason := shouldSkipRuntimeExecDenyPathWithSearch(
			target.path,
			target.token,
			cfg.Command.AcceptSharedBinaryCannotRuntimeDeny,
			denyTokens,
			sharedCache,
			sharedSearch,
			debug,
		)
		seen[target.path] = true
		if reason != "" {
			diagnostics = append(diagnostics, reason)
		}
		if skip {
			continue
		}
		paths = append(paths, target.path)
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

func runtimeExecSharedProbeNames(denyTokens map[string]bool) []string {
	probeNames := make([]string, 0, len(criticalCommands)+len(denyTokens))
	probeNames = append(probeNames, criticalCommands...)
	for token := range denyTokens {
		probeNames = append(probeNames, token)
	}
	return sharedExecutableProbeNames(nil, probeNames)
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
	return shouldSkipRuntimeExecDenyPathWithSearch(
		path,
		token,
		acceptSharedBinaryCannotRuntimeDeny,
		denyTokens,
		sharedCache,
		sharedExecutableSearch{},
		debug,
	)
}

func shouldSkipRuntimeExecDenyPathWithSearch(
	path string,
	token string,
	acceptSharedBinaryCannotRuntimeDeny []string,
	denyTokens map[string]bool,
	sharedCache map[string]sharedExecutableInfo,
	sharedSearch sharedExecutableSearch,
	debug bool,
) (bool, string) {
	info := getSharedExecutableInfoWithSearch(path, sharedCache, sharedSearch)
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
	// Non-debug: show the first maxShort critical names (highest priority first)
	// and note if we detected additional aliases sharing the same binary.
	// Debug: critical names first (priority order), then any other detected
	// relevant aliases appended alphabetically, with no repetitions.
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
		// remaining covers all other detected aliases sharing the inode minus the
		// token itself and the names already shown in the excerpt.
		remaining := len(info.names) - 1 - len(shown)
		collisionSummary = strings.Join(shown, " ")
		if remaining > 0 {
			collisionSummary = fmt.Sprintf("%s +%d more detected aliases, use --debug for expanded details",
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

func getSharedExecutableInfoWithSearch(
	path string,
	sharedCache map[string]sharedExecutableInfo,
	sharedSearch sharedExecutableSearch,
) sharedExecutableInfo {
	if cached, ok := sharedCache[path]; ok && cached.checked {
		return cached
	}

	shared, names := findSharedExecutableNamesWithSearch(path, sharedSearch)
	info := sharedExecutableInfo{checked: true, shared: shared, names: names}
	sharedCache[path] = info
	return info
}

func executableSearchDirs(paths ...string) []string {
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

	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		add(filepath.Dir(path))
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		add(dir)
	}
	for _, dir := range commonExecutableDirs {
		add(dir)
	}
	return dirs
}

type sharedExecutableCandidate struct {
	name string
	info os.FileInfo
}

type sharedExecutableSearch struct {
	candidatesByDevice map[uint64][]sharedExecutableCandidate
	candidatesFallback []sharedExecutableCandidate
}

func sharedExecutableProbeNames(paths []string, probeNames []string) []string {
	seen := make(map[string]bool, len(paths)+len(probeNames))
	var names []string
	add := func(name string) {
		name = strings.TrimSpace(filepath.Base(name))
		if name == "" || name == "." || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}
	for _, path := range paths {
		add(path)
	}
	for _, name := range probeNames {
		add(name)
	}
	slices.Sort(names)
	return names
}

func fileInfoDeviceID(info os.FileInfo) (uint64, bool) {
	if info == nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, false
	}
	switch dev := any(stat.Dev).(type) {
	case int:
		if dev < 0 {
			return 0, false
		}
		return uint64(dev), true
	case int8:
		if dev < 0 {
			return 0, false
		}
		return uint64(dev), true
	case int16:
		if dev < 0 {
			return 0, false
		}
		return uint64(dev), true
	case int32:
		if dev < 0 {
			return 0, false
		}
		return uint64(dev), true
	case int64:
		if dev < 0 {
			return 0, false
		}
		return uint64(dev), true
	case uint:
		return uint64(dev), true
	case uint8:
		return uint64(dev), true
	case uint16:
		return uint64(dev), true
	case uint32:
		return uint64(dev), true
	case uint64:
		return dev, true
	case uintptr:
		return uint64(dev), true
	default:
		return 0, false
	}
}

func addSharedExecutableCandidate(search *sharedExecutableSearch, candidate sharedExecutableCandidate) {
	if dev, ok := fileInfoDeviceID(candidate.info); ok {
		if search.candidatesByDevice == nil {
			search.candidatesByDevice = make(map[uint64][]sharedExecutableCandidate)
		}
		search.candidatesByDevice[dev] = append(search.candidatesByDevice[dev], candidate)
		return
	}
	search.candidatesFallback = append(search.candidatesFallback, candidate)
}

func sharedExecutableTargetDevices(paths []string) map[uint64]bool {
	targetDevices := make(map[uint64]bool)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		if dev, ok := fileInfoDeviceID(info); ok {
			targetDevices[dev] = true
		}
	}
	return targetDevices
}

func shouldFullyProbeSearchDir(dir string, targetDevices map[uint64]bool) bool {
	if len(targetDevices) == 0 {
		return true
	}
	info, err := os.Stat(dir)
	if err != nil {
		return true
	}
	dev, ok := fileInfoDeviceID(info)
	if !ok {
		return true
	}
	return targetDevices[dev]
}

func probeSharedExecutableCandidate(candidatePath string, fullProbe bool, targetDevices map[uint64]bool) (os.FileInfo, bool) {
	if fullProbe {
		info, err := os.Stat(candidatePath)
		if err != nil || info.IsDir() {
			return nil, false
		}
		return info, true
	}

	info, err := os.Lstat(candidatePath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return nil, false
	}

	resolvedInfo, err := os.Stat(candidatePath)
	if err != nil || resolvedInfo.IsDir() {
		return nil, false
	}
	if dev, ok := fileInfoDeviceID(resolvedInfo); ok && len(targetDevices) > 0 && !targetDevices[dev] {
		return nil, false
	}
	return resolvedInfo, true
}

func (s sharedExecutableSearch) candidatesForTarget(targetInfo os.FileInfo) []sharedExecutableCandidate {
	if dev, ok := fileInfoDeviceID(targetInfo); ok {
		bucket := s.candidatesByDevice[dev]
		if len(s.candidatesFallback) == 0 {
			return bucket
		}
		candidates := make([]sharedExecutableCandidate, 0, len(bucket)+len(s.candidatesFallback))
		candidates = append(candidates, bucket...)
		candidates = append(candidates, s.candidatesFallback...)
		return candidates
	}

	total := len(s.candidatesFallback)
	for _, bucket := range s.candidatesByDevice {
		total += len(bucket)
	}
	candidates := make([]sharedExecutableCandidate, 0, total)
	for _, bucket := range s.candidatesByDevice {
		candidates = append(candidates, bucket...)
	}
	candidates = append(candidates, s.candidatesFallback...)
	return candidates
}

func newSharedExecutableSearch(paths []string, probeNames []string) sharedExecutableSearch {
	candidateNames := sharedExecutableProbeNames(paths, probeNames)
	if len(candidateNames) == 0 {
		return sharedExecutableSearch{}
	}

	targetDevices := sharedExecutableTargetDevices(paths)
	search := sharedExecutableSearch{}
	seenPaths := make(map[string]bool)
	for _, dir := range executableSearchDirs(paths...) {
		fullProbe := shouldFullyProbeSearchDir(dir, targetDevices)
		for _, name := range candidateNames {
			candidatePath := filepath.Join(dir, name)
			if seenPaths[candidatePath] {
				continue
			}
			seenPaths[candidatePath] = true

			info, ok := probeSharedExecutableCandidate(candidatePath, fullProbe, targetDevices)
			if !ok {
				continue
			}
			addSharedExecutableCandidate(&search, sharedExecutableCandidate{name: name, info: info})
		}
	}
	return search
}

func findSharedExecutableNames(path string, probeNames ...string) (bool, []string) {
	return findSharedExecutableNamesWithSearch(path, newSharedExecutableSearch([]string{path}, probeNames))
}

func findSharedExecutableNamesWithSearch(path string, sharedSearch sharedExecutableSearch) (bool, []string) {
	targetInfo, err := os.Stat(path)
	if err != nil {
		return false, nil
	}

	nameSet := make(map[string]bool)
	for _, candidate := range sharedSearch.candidatesForTarget(targetInfo) {
		if !os.SameFile(targetInfo, candidate.info) {
			continue
		}
		nameSet[candidate.name] = true
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
	info, err := os.Stat(path) // #nosec G703 - helper to check if directory exists, no execution
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
