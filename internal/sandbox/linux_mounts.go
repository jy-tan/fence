//go:build linux

package sandbox

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
)

const mountInfoPath = "/proc/self/mountinfo"

// getExtraReadableMountPaths returns Linux mount paths requested via
// filesystem.extraReadableMounts, expanded with descendant submounts from
// /proc/self/mountinfo and normalized for safe bind usage.
func getExtraReadableMountPaths(cfg *config.Config, debug bool) []string {
	if cfg == nil || len(cfg.Filesystem.ExtraReadableMounts) == 0 {
		return nil
	}

	roots := normalizeExtraReadableMountRoots(cfg.Filesystem.ExtraReadableMounts)
	if len(roots) == 0 {
		return nil
	}

	candidates := append([]string(nil), roots...)
	mountPoints, err := readMountInfoMountPoints()
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "[fence:linux] Failed reading %s for extraReadableMounts (%v), using roots only\n", mountInfoPath, err)
		}
	} else {
		candidates = expandRootsWithDescendantMounts(roots, mountPoints)
	}

	seen := make(map[string]bool)
	var out []string
	for _, p := range candidates {
		if isSpecialSandboxMountPath(p) {
			continue
		}
		mountPath, ok := resolvePathForMount(p)
		if !ok || isSpecialSandboxMountPath(mountPath) || seen[mountPath] {
			continue
		}
		seen[mountPath] = true
		out = append(out, mountPath)
	}
	return out
}

func normalizeExtraReadableMountRoots(paths []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range paths {
		if raw == "" {
			continue
		}
		if ContainsGlobChars(raw) {
			continue
		}
		p := filepath.Clean(NormalizePath(raw))
		if p == "." || p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

func readMountInfoMountPoints() ([]string, error) {
	f, err := os.Open(mountInfoPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	var mountPoints []string
	for scanner.Scan() {
		mountPoint, ok := parseMountInfoLineMountPoint(scanner.Text())
		if ok {
			mountPoints = append(mountPoints, mountPoint)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return mountPoints, nil
}

func parseMountInfoLineMountPoint(line string) (string, bool) {
	parts := strings.SplitN(line, " - ", 2)
	if len(parts) != 2 {
		return "", false
	}
	pre := strings.Fields(parts[0])
	// mount point is field #5 in mountinfo, zero-indexed 4.
	if len(pre) < 5 {
		return "", false
	}
	return unescapeMountInfoPath(pre[4]), true
}

func unescapeMountInfoPath(path string) string {
	if !strings.Contains(path, "\\") {
		return path
	}
	var b strings.Builder
	for i := 0; i < len(path); i++ {
		if path[i] == '\\' && i+3 < len(path) {
			if n, err := strconv.ParseInt(path[i+1:i+4], 8, 32); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(path[i])
	}
	return b.String()
}

func expandRootsWithDescendantMounts(roots, mountPoints []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, root := range roots {
		cleanRoot := filepath.Clean(root)
		if !seen[cleanRoot] {
			seen[cleanRoot] = true
			out = append(out, cleanRoot)
		}
	}
	for _, mp := range mountPoints {
		cleanMP := filepath.Clean(mp)
		for _, root := range roots {
			cleanRoot := filepath.Clean(root)
			if cleanMP == cleanRoot || strings.HasPrefix(cleanMP, cleanRoot+"/") {
				if !seen[cleanMP] {
					seen[cleanMP] = true
					out = append(out, cleanMP)
				}
				break
			}
		}
	}
	slices.Sort(out)
	return out
}

func isSpecialSandboxMountPath(path string) bool {
	p := filepath.Clean(path)
	return p == "/dev" || strings.HasPrefix(p, "/dev/") ||
		p == "/proc" || strings.HasPrefix(p, "/proc/") ||
		p == "/tmp" || strings.HasPrefix(p, "/tmp/") ||
		p == "/private/tmp" || strings.HasPrefix(p, "/private/tmp/")
}
