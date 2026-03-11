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
	got, diagnostics := GetRuntimeDeniedExecutablePathsWithDiagnostics(cfg, false)

	// On most systems chroot is a standalone binary and lands directly in the
	// deny list. On Nix, however, chroot resolves to the coreutils multicall
	// binary (which also implements ls, cat, etc.), so it will be skipped with
	// a diagnostic instead. Both outcomes are correct behaviour — accept either.
	for _, want := range chrootPaths {
		if slices.Contains(got, want) {
			continue
		}
		matched := false
		for _, msg := range diagnostics {
			if strings.Contains(msg, want) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("expected chroot path %q in runtime denied paths or diagnostics, got paths=%v diagnostics=%v", want, got, diagnostics)
		}
	}
}

func TestFindSharedExecutableNames_DetectsSharedBinary(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "tool-a")
	alias := filepath.Join(tmpDir, "tool-b")

	// #nosec G306 -- test fixture requires executable permissions
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("failed to create executable: %v", err)
	}
	if err := os.Link(target, alias); err != nil {
		t.Fatalf("failed to create hardlink alias: %v", err)
	}

	shared, names := findSharedExecutableNames(target)
	if !shared {
		t.Fatalf("expected shared executable to be detected, got names=%v", names)
	}
	if !slices.Contains(names, "tool-a") || !slices.Contains(names, "tool-b") {
		t.Fatalf("expected both aliases in result, got: %v", names)
	}
}

func TestFindSharedExecutableNames_UniqueBinary(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "tool-single")

	// #nosec G306 -- test fixture requires executable permissions
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("failed to create executable: %v", err)
	}

	shared, names := findSharedExecutableNames(target)
	if shared {
		t.Fatalf("expected unique executable to not be shared, got names=%v", names)
	}
	if len(names) != 1 || names[0] != "tool-single" {
		t.Fatalf("expected only tool-single in result, got: %v", names)
	}
}

func TestShouldSkipRuntimeExecDenyPath_UniqueDoesNotSkip(t *testing.T) {
	path := "/usr/bin/true"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  false,
			names:   []string{"true"},
		},
	}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "true", false, nil, map[string]bool{"true": true}, sharedCache, false)
	if skip {
		t.Fatalf("expected unique executable target to not be skipped, reason=%q", reason)
	}
	if reason != "" {
		t.Fatalf("expected empty reason for non-skip, got %q", reason)
	}
}

func TestShouldSkipRuntimeExecDenyPath_SharedSkipsWithReason(t *testing.T) {
	path := "/shared/bin/dd"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"cat", "dd", "ls"},
		},
	}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "dd", false, nil, map[string]bool{"dd": true}, sharedCache, true)
	if !skip {
		t.Fatalf("expected shared binary with critical collision to be skipped")
	}
	if !strings.Contains(reason, "critical commands") {
		t.Fatalf("expected reason to mention critical commands, got %q", reason)
	}
	if !strings.Contains(reason, "cat") || !strings.Contains(reason, "ls") {
		t.Fatalf("expected reason to name the colliding critical commands, got %q", reason)
	}
	if !strings.Contains(reason, "allowBlockingCritical") {
		t.Fatalf("expected reason to mention allowBlockingCritical, got %q", reason)
	}
	if !strings.Contains(reason, "silenceSharedBinaryWarning") {
		t.Fatalf("expected reason to mention silenceSharedBinaryWarning, got %q", reason)
	}
}

func TestShouldSkipRuntimeExecDenyPath_SharedNonCriticalDoesNotSkip(t *testing.T) {
	// python3, python3.11, python3-config are all non-critical — blocking any
	// one of them should be allowed even though they share a binary.
	path := "/usr/bin/python3.11"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"python3", "python3.11", "python3-config"},
		},
	}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "python3", false, nil, map[string]bool{"python3": true}, sharedCache, false)
	if skip {
		t.Fatalf("expected shared binary with only non-critical names to not be skipped, reason=%q", reason)
	}
	if reason != "" {
		t.Fatalf("expected empty reason for non-skip, got %q", reason)
	}
}

func TestShouldSkipRuntimeExecDenyPath_AllowBlockingCriticalForcesBlock(t *testing.T) {
	path := "/shared/bin/dd"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"cat", "dd", "ls"},
		},
	}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "dd", true, nil, map[string]bool{"dd": true}, sharedCache, false)
	if skip {
		t.Fatalf("expected allowBlockingCritical to force block despite critical collision, reason=%q", reason)
	}
	if reason != "" {
		t.Fatalf("expected empty reason when allowBlockingCritical is set, got %q", reason)
	}
}

func TestShouldSkipRuntimeExecDenyPath_silenceSharedBinaryWarningSilencesWarning(t *testing.T) {
	path := "/shared/bin/dd"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"cat", "dd", "ls"},
		},
	}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "dd", false, []string{"dd"}, map[string]bool{"dd": true}, sharedCache, false)
	if !skip {
		t.Fatalf("expected shared binary to be skipped when token is in silenceSharedBinaryWarning")
	}
	if reason != "" {
		t.Fatalf("expected empty reason (silenced) when token is in silenceSharedBinaryWarning, got %q", reason)
	}
}

func TestShouldSkipRuntimeExecDenyPath_silenceSharedBinaryWarningMatchesAcrossForms(t *testing.T) {
	// The user denies "/shared/bin/dd" (absolute path token) but writes "dd"
	// (bare name) in silenceSharedBinaryWarning, or vice versa.  Both forms
	// must silence the warning — mismatched forms must not silently fail.
	path := "/shared/bin/dd"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"cat", "dd", "ls"},
		},
	}

	cases := []struct {
		token   string
		silence string
	}{
		// absolute-path deny rule, bare-name silence entry
		{token: "/shared/bin/dd", silence: "dd"},
		// bare-name deny rule, absolute-path silence entry
		{token: "dd", silence: "/shared/bin/dd"},
	}

	for _, c := range cases {
		denyTokens := map[string]bool{c.token: true, filepath.Base(c.token): true}
		skip, reason := shouldSkipRuntimeExecDenyPath(path, c.token, false, []string{c.silence}, denyTokens, sharedCache, false)
		if !skip {
			t.Errorf("token=%q silence=%q: expected skip (silenced), but was not skipped", c.token, c.silence)
		}
		if reason != "" {
			t.Errorf("token=%q silence=%q: expected empty reason (silenced), got %q", c.token, c.silence, reason)
		}
	}
}

func TestShouldSkipRuntimeExecDenyPath_CriticalTokenWithNoCriticalCollateral(t *testing.T) {
	// User explicitly blocks "ls" (a critical command). The shared binary also
	// implements "dd" and "rm" — neither of which is critical. There is no
	// collateral damage to other critical commands, so the block should proceed.
	path := "/shared/bin/coreutils"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"dd", "ls", "rm"},
		},
	}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "ls", false, nil, map[string]bool{"ls": true}, sharedCache, false)
	if skip {
		t.Fatalf("expected explicit block of critical token with no critical collateral to proceed, reason=%q", reason)
	}
	if reason != "" {
		t.Fatalf("expected empty reason for non-skip, got %q", reason)
	}
}

func TestShouldSkipRuntimeExecDenyPath_CriticalTokenNotListedInOwnCollision(t *testing.T) {
	// User explicitly blocks "ls" (a critical command). The shared binary also
	// implements "cat" and "head" — both critical. The block should be skipped,
	// but the diagnostic must not list "ls" itself as a colliding command.
	path := "/shared/bin/coreutils"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"cat", "head", "ls"},
		},
	}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "ls", false, nil, map[string]bool{"ls": true}, sharedCache, true)
	if !skip {
		t.Fatalf("expected block to be skipped due to critical collateral (cat, head)")
	}
	// The bracketed collision list is part of the verbose diagnostic. "ls" will
	// appear elsewhere in the verbose message (e.g. in the silenceSharedBinaryWarning
	// suggestion), so check specifically that it is absent from the bracketed
	// collision list rather than the full message string.
	start := strings.Index(reason, "[")
	end := strings.Index(reason, "]")
	if start == -1 || end == -1 || end <= start {
		t.Fatalf("expected bracketed collision list in diagnostic, got %q", reason)
	}
	collisionList := reason[start+1 : end]
	if strings.Contains(collisionList, "ls") {
		t.Fatalf("expected collision list to not include the token itself, got collision list %q in %q", collisionList, reason)
	}
	if !strings.Contains(collisionList, "cat") || !strings.Contains(collisionList, "head") {
		t.Fatalf("expected collision list to name collateral critical commands, got collision list %q in %q", collisionList, reason)
	}
}

func TestGetRuntimeDeniedExecutablePaths_AllSharedNamesDeniedShouldBlock(t *testing.T) {
	// Shared binary (one inode) implements three commands: dd, ls, cat.
	// The user denies all three by full path.
	//
	// ls and cat are critical commands, so the current collision check would
	// normally skip the block with a warning. But since ls and cat are
	// themselves in the deny list they are intentional targets — not collateral
	// damage — and the binary must be blocked.
	tmpDir := t.TempDir()
	ddPath := filepath.Join(tmpDir, "dd")
	lsPath := filepath.Join(tmpDir, "ls")
	catPath := filepath.Join(tmpDir, "cat")

	// #nosec G306 -- test fixture requires executable permissions
	if err := os.WriteFile(ddPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("failed to create executable: %v", err)
	}
	if err := os.Link(ddPath, lsPath); err != nil {
		t.Fatalf("failed to hardlink ls: %v", err)
	}
	if err := os.Link(ddPath, catPath); err != nil {
		t.Fatalf("failed to hardlink cat: %v", err)
	}

	useDefaults := false
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{ddPath, lsPath, catPath},
			UseDefaults: &useDefaults,
		},
	}

	got, diagnostics := GetRuntimeDeniedExecutablePathsWithDiagnostics(cfg, false)

	// All three tokens resolve to the same inode and deduplicate to one path.
	// Because every critical co-inhabitant is also explicitly denied, the
	// binary must appear in the blocked list — not be silently dropped.
	//
	// resolveExecutablePaths calls filepath.EvalSymlinks, which on macOS
	// expands /var/folders/... → /private/var/folders/..., so compare against
	// the canonical form of the path.
	wantPath := ddPath
	if resolved, err := filepath.EvalSymlinks(ddPath); err == nil {
		wantPath = resolved
	}
	if !slices.Contains(got, wantPath) {
		t.Fatalf("expected shared binary to be blocked when all shared names are denied, got paths=%v diagnostics=%v", got, diagnostics)
	}
}

func TestGetRuntimeDeniedExecutablePaths_PartialDenyStillSkipsForUninstructedCritical(t *testing.T) {
	// Shared binary (one inode) implements four commands: dd, ls, cat, head.
	// The user denies dd and ls — but NOT cat or head.
	//
	// ls is excluded from the collision check because it is also being denied
	// (intentional target, not collateral damage). But cat and head are critical
	// commands that the user never asked to block, so they ARE collateral damage.
	// The binary must still be skipped with a warning even though ls is denied.
	tmpDir := t.TempDir()
	ddPath := filepath.Join(tmpDir, "dd")
	lsPath := filepath.Join(tmpDir, "ls")
	catPath := filepath.Join(tmpDir, "cat")
	headPath := filepath.Join(tmpDir, "head")

	// #nosec G306 -- test fixture requires executable permissions
	if err := os.WriteFile(ddPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("failed to create executable: %v", err)
	}
	for _, p := range []string{lsPath, catPath, headPath} {
		if err := os.Link(ddPath, p); err != nil {
			t.Fatalf("failed to hardlink %s: %v", p, err)
		}
	}

	useDefaults := false
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{ddPath, lsPath},
			UseDefaults: &useDefaults,
		},
	}

	got, diagnostics := GetRuntimeDeniedExecutablePathsWithDiagnostics(cfg, true)

	// The binary must NOT appear in the blocked list: cat and head are
	// uninstructed critical co-inhabitants and would be collaterally blocked.
	wantPath := ddPath
	if resolved, err := filepath.EvalSymlinks(ddPath); err == nil {
		wantPath = resolved
	}
	if slices.Contains(got, wantPath) {
		t.Fatalf("expected shared binary to be skipped when uninstructed critical co-inhabitants remain, got paths=%v", got)
	}

	// There must be at least one diagnostic explaining the collision.
	if len(diagnostics) == 0 {
		t.Fatalf("expected diagnostics for skipped shared binary, got none")
	}

	// The diagnostic must mention the uninstructed critical collaterals (cat,
	// head) and must NOT mention ls (which is itself being denied).
	combined := strings.Join(diagnostics, "\n")
	start := strings.Index(combined, "[")
	end := strings.Index(combined, "]")
	if start == -1 || end == -1 || end <= start {
		t.Fatalf("expected bracketed collision list in diagnostic, got %q", combined)
	}
	collisionList := combined[start+1 : end]
	if strings.Contains(collisionList, "ls") {
		t.Fatalf("collision list must not include ls (it is also being denied), got collision list %q", collisionList)
	}
	if !strings.Contains(collisionList, "cat") || !strings.Contains(collisionList, "head") {
		t.Fatalf("collision list must name uninstructed critical collaterals cat and head, got collision list %q", collisionList)
	}
}

// 3a: when the token is an absolute path, the token's own basename must be
// excluded from the critical-collision list even when denyTokens only contains
// the absolute form (not the bare name).
func TestShouldSkipRuntimeExecDenyPath_AbsolutePathTokenExcludedFromOwnCollision(t *testing.T) {
	path := "/shared/bin/ls"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"cat", "head", "ls"},
		},
	}
	// denyTokens has only the absolute form — simulates calling the function
	// directly without the basename pre-population that the outer loop does.
	denyTokens := map[string]bool{"/shared/bin/ls": true}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "/shared/bin/ls", false, nil, denyTokens, sharedCache, true)
	if !skip {
		t.Fatal("expected block to be skipped due to critical collateral (cat, head)")
	}
	start := strings.Index(reason, "[")
	end := strings.Index(reason, "]")
	if start == -1 || end == -1 || end <= start {
		t.Fatalf("expected bracketed collision list in diagnostic, got %q", reason)
	}
	collisionList := reason[start+1 : end]
	if strings.Contains(collisionList, "ls") {
		t.Fatalf("token basename 'ls' must not appear in its own collision list, got %q", collisionList)
	}
	if !strings.Contains(collisionList, "cat") || !strings.Contains(collisionList, "head") {
		t.Fatalf("expected cat and head in collision list, got %q", collisionList)
	}
}

// 3b: two deny rules that resolve to the same canonical path should produce
// exactly one diagnostic, not one per token.
func TestGetRuntimeDeniedExecutablePathsWithDiagnostics_NoDuplicateDiagnostics(t *testing.T) {
	tmpDir := t.TempDir()
	ddPath := filepath.Join(tmpDir, "dd")
	catPath := filepath.Join(tmpDir, "cat")
	lsPath := filepath.Join(tmpDir, "ls")
	symlinkPath := filepath.Join(tmpDir, "dd-link")

	// #nosec G306 -- test fixture requires executable permissions
	if err := os.WriteFile(ddPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{catPath, lsPath} {
		if err := os.Link(ddPath, p); err != nil {
			t.Fatalf("failed to hardlink %s: %v", p, err)
		}
	}
	if err := os.Symlink(ddPath, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	useDefaults := false
	cfg := &config.Config{
		Command: config.CommandConfig{
			// ddPath and symlinkPath both canonicalize to the same real path.
			Deny:        []string{ddPath, symlinkPath},
			UseDefaults: &useDefaults,
		},
	}

	_, diagnostics := GetRuntimeDeniedExecutablePathsWithDiagnostics(cfg, false)

	if len(diagnostics) > 1 {
		t.Fatalf("expected at most 1 diagnostic for two tokens resolving to the same skipped path, got %d: %v", len(diagnostics), diagnostics)
	}
}

// 3f: when the token is an absolute path, the silenceSharedBinaryWarning hint
// in the diagnostic must name the bare basename, not the full path.
func TestShouldSkipRuntimeExecDenyPath_DiagnosticSuggestsBasenameInSilenceHint(t *testing.T) {
	path := "/shared/bin/dd"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"cat", "dd", "ls"},
		},
	}
	denyTokens := map[string]bool{"/shared/bin/dd": true, "dd": true}

	_, reason := shouldSkipRuntimeExecDenyPath(path, "/shared/bin/dd", false, nil, denyTokens, sharedCache, true)
	if reason == "" {
		t.Fatal("expected a diagnostic reason")
	}
	if !strings.Contains(reason, `"dd"`) {
		t.Fatalf(`expected diagnostic to suggest bare name "dd" in hint, got %q`, reason)
	}
	if strings.Contains(reason, `"/shared/bin/dd"`) {
		t.Fatalf(`diagnostic must not suggest full path "/shared/bin/dd" in hint, got %q`, reason)
	}
}
