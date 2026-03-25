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
	got, _ := GetRuntimeDeniedExecutablePathsWithDiagnostics(cfg, false)

	// With the new security model fence always blocks even when the binary
	// shares an inode with critical commands — blocking is the default and the
	// user must explicitly opt out via acceptSharedBinaryCannotRuntimeDeny. chroot must
	// therefore always appear in the blocked paths list regardless of whether
	// it is a standalone binary (most distros) or part of a coreutils multicall
	// binary (Nix/nix-darwin).
	for _, want := range chrootPaths {
		if !slices.Contains(got, want) {
			t.Fatalf("expected chroot path %q in runtime denied paths, got: %v", want, got)
		}
	}
}

func TestFindSharedExecutableNames_DetectsSharedBinary(t *testing.T) {
	tmpDir := t.TempDir()
	aPath := filepath.Join(tmpDir, "aaa")
	bPath := filepath.Join(tmpDir, "bbb")

	// #nosec G306 -- test fixture requires executable permissions
	if err := os.WriteFile(aPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("failed to create executable: %v", err)
	}
	if err := os.Link(aPath, bPath); err != nil {
		t.Fatalf("failed to create hard link: %v", err)
	}

	shared, names := findSharedExecutableNames(aPath)
	if !shared {
		t.Fatalf("expected file sharing an inode to be detected as shared, got names=%v", names)
	}
	if !slices.Contains(names, "aaa") || !slices.Contains(names, "bbb") {
		t.Fatalf("expected both names in shared list, got %v", names)
	}
}

func TestFindSharedExecutableNames_UniqueBinary(t *testing.T) {
	tmpDir := t.TempDir()
	aPath := filepath.Join(tmpDir, "unique-binary")

	// #nosec G306 -- test fixture requires executable permissions
	if err := os.WriteFile(aPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("failed to create executable: %v", err)
	}

	shared, names := findSharedExecutableNames(aPath)
	if shared {
		t.Fatalf("expected unique file to not be detected as shared, got names=%v", names)
	}
}

// Unique binary: no shared-inode detection fires → block with no diagnostic.
func TestShouldSkipRuntimeExecDenyPath_UniqueDoesNotSkip(t *testing.T) {
	path := "/usr/bin/true"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  false,
			names:   []string{"true"},
		},
	}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "true", nil, map[string]bool{"true": true}, sharedCache, false)
	if skip {
		t.Fatalf("expected unique executable target to not be skipped, reason=%q", reason)
	}
	if reason != "" {
		t.Fatalf("expected empty reason for non-skip, got %q", reason)
	}
}

// Shared binary with critical collision: the new default is to BLOCK, but emit
// a diagnostic warning naming the collateral critical commands and telling the
// user how to opt out via acceptSharedBinaryCannotRuntimeDeny.
func TestShouldSkipRuntimeExecDenyPath_SharedBlocksWithWarning(t *testing.T) {
	path := "/shared/bin/dd"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"cat", "dd", "ls"},
		},
	}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "dd", nil, map[string]bool{"dd": true}, sharedCache, true)
	if skip {
		t.Fatalf("expected shared binary with critical collision to be blocked (not skipped) by default")
	}
	if reason == "" {
		t.Fatalf("expected a diagnostic warning reason when critical collision is detected")
	}
	if !strings.Contains(reason, "critical commands") {
		t.Fatalf("expected reason to mention critical commands, got %q", reason)
	}
	if !strings.Contains(reason, "cat") || !strings.Contains(reason, "ls") {
		t.Fatalf("expected reason to name the colliding critical commands, got %q", reason)
	}
	if !strings.Contains(reason, "acceptSharedBinaryCannotRuntimeDeny") {
		t.Fatalf("expected reason to mention acceptSharedBinaryCannotRuntimeDeny, got %q", reason)
	}
	// The removed option must never appear in any diagnostic.
	if strings.Contains(reason, "allowBlockingCritical") {
		t.Fatalf("removed option allowBlockingCritical must not appear in diagnostic, got %q", reason)
	}
}

// Shared binary where all shared names are non-critical (python variants):
// blocking proceeds with no diagnostic — no collateral damage to critical commands.
func TestShouldSkipRuntimeExecDenyPath_SharedNonCriticalDoesNotSkip(t *testing.T) {
	path := "/usr/bin/python3.11"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"python3", "python3.11", "python3-config"},
		},
	}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "python3", nil, map[string]bool{"python3": true}, sharedCache, false)
	if skip {
		t.Fatalf("expected shared binary with only non-critical names to not be skipped, reason=%q", reason)
	}
	if reason != "" {
		t.Fatalf("expected empty reason for non-critical shared binary, got %q", reason)
	}
}

// acceptSharedBinaryCannotRuntimeDeny: when the token is in the list the path is skipped
// silently — no diagnostic is emitted.
func TestShouldSkipRuntimeExecDenyPath_AcceptSharedBinaryCannotRuntimeDenySkipsSilently(t *testing.T) {
	path := "/shared/bin/dd"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"cat", "dd", "ls"},
		},
	}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "dd", []string{"dd"}, map[string]bool{"dd": true}, sharedCache, false)
	if !skip {
		t.Fatalf("expected shared binary to be skipped when token is in acceptSharedBinaryCannotRuntimeDeny")
	}
	if reason != "" {
		t.Fatalf("expected empty reason (silenced) when token is in acceptSharedBinaryCannotRuntimeDeny, got %q", reason)
	}
}

// acceptSharedBinaryCannotRuntimeDeny matches regardless of whether the entry uses a bare
// name or an absolute path, so the user does not have to guess which form to write.
func TestShouldSkipRuntimeExecDenyPath_AcceptSharedBinaryCannotRuntimeDenyMatchesAcrossForms(t *testing.T) {
	path := "/shared/bin/dd"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"cat", "dd", "ls"},
		},
	}

	cases := []struct {
		token  string
		accept string
	}{
		// absolute-path deny rule, bare-name accept entry
		{token: "/shared/bin/dd", accept: "dd"},
		// bare-name deny rule, absolute-path accept entry
		{token: "dd", accept: "/shared/bin/dd"},
	}

	for _, c := range cases {
		denyTokens := map[string]bool{c.token: true, filepath.Base(c.token): true}
		skip, reason := shouldSkipRuntimeExecDenyPath(path, c.token, []string{c.accept}, denyTokens, sharedCache, false)
		if !skip {
			t.Errorf("token=%q accept=%q: expected skip (accepted), but was not skipped", c.token, c.accept)
		}
		if reason != "" {
			t.Errorf("token=%q accept=%q: expected empty reason (silenced), got %q", c.token, c.accept, reason)
		}
	}
}

// User explicitly blocks a critical command (ls). The shared binary only
// co-inhabits with non-critical commands (dd, rm) — no collateral damage to
// other critical commands → block proceeds with no diagnostic.
func TestShouldSkipRuntimeExecDenyPath_CriticalTokenWithNoCriticalCollateral(t *testing.T) {
	path := "/shared/bin/coreutils"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"dd", "ls", "rm"},
		},
	}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "ls", nil, map[string]bool{"ls": true}, sharedCache, false)
	if skip {
		t.Fatalf("expected explicit block of critical token with no critical collateral to proceed, reason=%q", reason)
	}
	if reason != "" {
		t.Fatalf("expected empty reason for non-skip, got %q", reason)
	}
}

// User explicitly blocks "ls". The shared binary also implements cat and head
// (both critical). Block proceeds with a diagnostic warning, but "ls" itself
// must NOT appear in the collision list — it was the intentional target, not
// collateral damage.
func TestShouldSkipRuntimeExecDenyPath_CriticalTokenNotListedInOwnCollision(t *testing.T) {
	path := "/shared/bin/coreutils"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"cat", "head", "ls"},
		},
	}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "ls", nil, map[string]bool{"ls": true}, sharedCache, true)
	if skip {
		t.Fatalf("expected block to proceed (not skip) despite critical collateral (cat, head)")
	}
	if reason == "" {
		t.Fatalf("expected a diagnostic warning when critical collateral would be blocked")
	}
	// The bracketed collision list must include cat and head but not ls.
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

// All shared names are in the deny list — every co-inhabitant is an
// intentional target. No collateral damage → binary blocked with no diagnostic.
func TestGetRuntimeDeniedExecutablePaths_AllSharedNamesDeniedShouldBlock(t *testing.T) {
	tmpDir := t.TempDir()
	ddPath := filepath.Join(tmpDir, "dd")
	lsPath := filepath.Join(tmpDir, "ls")
	catPath := filepath.Join(tmpDir, "cat")

	// #nosec G306 -- test fixture requires executable permissions
	if err := os.WriteFile(ddPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("failed to create executable: %v", err)
	}
	if err := os.Link(ddPath, lsPath); err != nil {
		t.Fatalf("failed to create hard link ls: %v", err)
	}
	if err := os.Link(ddPath, catPath); err != nil {
		t.Fatalf("failed to create hard link cat: %v", err)
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
	// binary must appear in the blocked list with no diagnostic warning.
	wantPath := ddPath
	if resolved, err := filepath.EvalSymlinks(ddPath); err == nil {
		wantPath = resolved
	}
	if !slices.Contains(got, wantPath) {
		t.Fatalf("expected shared binary to be blocked when all shared names are denied, got paths=%v diagnostics=%v", got, diagnostics)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics when all shared names are explicitly denied, got %v", diagnostics)
	}
}

// Shared binary implements dd, ls, cat, head. User denies dd and ls but NOT
// cat or head. ls is excluded from the collision check (intentional target),
// but cat and head are uninstructed critical co-inhabitants.
//
// New default: the binary is still BLOCKED, but a diagnostic warning is emitted
// naming cat and head. ls must not appear in the collision list.
func TestGetRuntimeDeniedExecutablePaths_PartialDenyBlocksWithWarningForUninstructedCritical(t *testing.T) {
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
			t.Fatalf("failed to create hard link %s: %v", p, err)
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

	// The binary MUST appear in the blocked list: the new security model blocks
	// by default even when uninstructed critical co-inhabitants are present.
	wantPath := ddPath
	if resolved, err := filepath.EvalSymlinks(ddPath); err == nil {
		wantPath = resolved
	}
	if !slices.Contains(got, wantPath) {
		t.Fatalf("expected shared binary to be blocked (new default) even with uninstructed critical co-inhabitants, got paths=%v", got)
	}

	// There must be at least one diagnostic warning about the collision.
	if len(diagnostics) == 0 {
		t.Fatalf("expected diagnostics warning about uninstructed critical co-inhabitants, got none")
	}

	// The diagnostic must mention cat and head but NOT ls (ls is also being denied).
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

// When the token is an absolute path, the token's own basename must be
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

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "/shared/bin/ls", nil, denyTokens, sharedCache, true)
	if skip {
		t.Fatal("expected block to proceed (not skip) despite critical collateral (cat, head)")
	}
	if reason == "" {
		t.Fatal("expected a diagnostic warning when critical collateral would be blocked")
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

// Two deny rules resolving to the same canonical path must produce exactly one
// diagnostic warning, not one per token.
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
			t.Fatalf("failed to create hard link %s: %v", p, err)
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

	got, diagnostics := GetRuntimeDeniedExecutablePathsWithDiagnostics(cfg, false)

	// The binary is blocked (new default). The two tokens resolve to the same
	// canonical path, so there must be exactly one entry in the blocked list
	// and at most one diagnostic warning.
	wantPath := ddPath
	if resolved, err := filepath.EvalSymlinks(ddPath); err == nil {
		wantPath = resolved
	}
	if !slices.Contains(got, wantPath) {
		t.Fatalf("expected shared binary to appear in blocked paths, got %v", got)
	}
	if len(diagnostics) > 1 {
		t.Fatalf("expected at most 1 diagnostic for two tokens resolving to the same path, got %d: %v", len(diagnostics), diagnostics)
	}
}

// When the token is an absolute path, the acceptSharedBinaryCannotRuntimeDeny hint in the
// diagnostic must name the bare basename, not the full path — so the user
// writes a short, obvious entry in their config.
func TestShouldSkipRuntimeExecDenyPath_DiagnosticSuggestsBasenameInAcceptHint(t *testing.T) {
	path := "/shared/bin/dd"
	sharedCache := map[string]sharedExecutableInfo{
		path: {
			checked: true,
			shared:  true,
			names:   []string{"cat", "dd", "ls"},
		},
	}
	denyTokens := map[string]bool{"/shared/bin/dd": true, "dd": true}

	skip, reason := shouldSkipRuntimeExecDenyPath(path, "/shared/bin/dd", nil, denyTokens, sharedCache, true)
	if skip {
		t.Fatal("expected block to proceed (not skip) despite critical collision")
	}
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
