package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/bmatcuk/doublestar/v4"
)

// PathWriteBlockedError is returned when a write to a path is blocked.
// Callers can `errors.As` to inspect MatchedRule.
type PathWriteBlockedError struct {
	Path        string
	MatchedRule string // empty when default-deny ("not in allowWrite")
	Reason      string // "denyWrite", "dangerous path", "not in allowWrite", ...
}

func (e *PathWriteBlockedError) Error() string {
	if e.MatchedRule == "" {
		return fmt.Sprintf("write to %q blocked by sandbox filesystem policy: %s", e.Path, e.Reason)
	}
	return fmt.Sprintf("write to %q blocked by sandbox filesystem policy: %s (matched %q)", e.Path, e.Reason, e.MatchedRule)
}

// CheckWritePath is the hook-time predicate paralleling the wrap-mode profile
// generators (macOS seatbelt, Linux landlock). Both consume cfg.Filesystem.*
// plus DangerousFiles / DangerousDirectories, so a single fence.json behaves
// the same in both modes — with two intentional differences:
//
//   - Hook-mode default-allow: when neither allowWrite nor denyWrite is
//     configured, returns nil. Wrap mode locks down the FS by default
//     because the OS sandbox is the only protection; hook mode treats
//     absence of policy as out-of-scope so users opting in to command
//     policy don't accidentally deny every write.
//   - allowWrite is exact-or-subtree match (mirrors seatbelt's
//     `(allow file-write* (subpath ...))`). Glob patterns use doublestar.
//
// denyWrite, dangerous files, and git internals always win over allowWrite.
// `cwd` is required when path is relative; pass "" to require absolute paths.
func CheckWritePath(path string, cwd string, cfg *config.Config) error {
	if cfg == nil {
		cfg = config.Default()
	}
	clean, err := absoluteCleanPath(path, cwd)
	if err != nil {
		return &PathWriteBlockedError{Path: path, Reason: err.Error()}
	}

	if rule, ok := matchesDangerousPath(clean); ok {
		return &PathWriteBlockedError{Path: clean, MatchedRule: rule, Reason: "dangerous path"}
	}

	if rule, ok := matchPathRule(clean, cfg.Filesystem.DenyWrite); ok {
		return &PathWriteBlockedError{Path: clean, MatchedRule: rule, Reason: "denyWrite"}
	}

	// Hook-mode default-allow when no write policy is configured. See doc.
	if len(cfg.Filesystem.AllowWrite) == 0 && len(cfg.Filesystem.DenyWrite) == 0 {
		return nil
	}

	if _, ok := matchPathRule(clean, cfg.Filesystem.AllowWrite); ok {
		return nil
	}

	return &PathWriteBlockedError{Path: clean, Reason: "not in allowWrite"}
}

// absoluteCleanPath resolves path against cwd when relative. "../" escapes
// are allowed — the policy rules decide if the resolved location is reachable.
func absoluteCleanPath(path, cwd string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	if cwd == "" {
		return "", fmt.Errorf("relative path %q without cwd", path)
	}
	if !filepath.IsAbs(cwd) {
		return "", fmt.Errorf("cwd %q is not absolute", cwd)
	}
	return filepath.Clean(filepath.Join(cwd, path)), nil
}

// matchPathRule returns (rule, true) when path matches:
//   - a glob (rule contains *, ?, [, {): via doublestar
//   - an absolute path: exact or subtree (path == rule, or path starts
//     with rule + "/")
//
// Relative rules are skipped — Fence config has always been absolute or
// globs, and silently joining against cwd would shadow user mistakes.
func matchPathRule(path string, rules []string) (string, bool) {
	for _, rule := range rules {
		if rule == "" {
			continue
		}
		if hasGlobMeta(rule) {
			if matched, err := doublestar.Match(rule, path); err == nil && matched {
				return rule, true
			}
			continue
		}
		clean := filepath.Clean(rule)
		if !filepath.IsAbs(clean) {
			continue
		}
		if path == clean {
			return rule, true
		}
		// Anchor subtree match at a component boundary; "/" is already
		// its own separator suffix.
		prefix := clean
		if !strings.HasSuffix(prefix, string(filepath.Separator)) {
			prefix += string(filepath.Separator)
		}
		if strings.HasPrefix(path, prefix) {
			return rule, true
		}
	}
	return "", false
}

func hasGlobMeta(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '*', '?', '[', '{':
			return true
		}
	}
	return false
}

// matchesDangerousPath returns (rule, true) when path is a dangerous file
// (basename match against DangerousFiles), inside a dangerous directory, or
// inside .git/hooks / .git/config. Always wins over allowWrite, mirroring
// the wrap-mode profile generators.
func matchesDangerousPath(path string) (string, bool) {
	base := filepath.Base(path)
	for _, name := range DangerousFiles {
		if base == name {
			return name, true
		}
	}

	// .git internals: hooks/* and config only. The rest of .git stays
	// writable so git itself can update HEAD/refs/objects.
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] != ".git" {
			continue
		}
		next := parts[i+1]
		if next == "hooks" {
			return ".git/hooks", true
		}
		if next == "config" && i == len(parts)-2 {
			return ".git/config", true
		}
	}

	for _, dir := range DangerousDirectories {
		if pathInDangerousDir(path, dir) {
			return dir, true
		}
	}
	return "", false
}

// pathInDangerousDir matches single-component (".vscode") and multi-component
// (".claude/commands") entries at any path-component boundary, so
// "notvscode" won't match ".vscode".
func pathInDangerousDir(path, dir string) bool {
	dirParts := strings.Split(filepath.ToSlash(dir), "/")
	pathParts := strings.Split(filepath.ToSlash(path), "/")

	if len(pathParts) <= len(dirParts) {
		return false
	}

	for start := 0; start <= len(pathParts)-len(dirParts)-1; start++ {
		match := true
		for i, want := range dirParts {
			if pathParts[start+i] != want {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
