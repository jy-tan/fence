//go:build linux

package sandbox

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/fencelog"
)

type linuxLateMountKind int

const (
	linuxLateMountReadOnly linuxLateMountKind = iota
	linuxLateMountMaskFile
	linuxLateMountMaskDir
)

type linuxLateMount struct {
	Path string
	Kind linuxLateMountKind
}

type linuxLateMountPlanner struct {
	mounts []linuxLateMount
}

func newLinuxLateMountPlanner() *linuxLateMountPlanner {
	return &linuxLateMountPlanner{}
}

func (p *linuxLateMountPlanner) Add(path string, kind linuxLateMountKind) {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return
	}

	if p.hasStrictAncestor(path, linuxLateMountMaskDir) {
		return
	}

	for i, existing := range p.mounts {
		if existing.Path != path {
			continue
		}
		if linuxLateMountPriority(existing.Kind) >= linuxLateMountPriority(kind) {
			return
		}

		p.mounts[i].Kind = kind
		switch kind {
		case linuxLateMountMaskDir:
			p.removeDescendants(path, func(mount linuxLateMount) bool {
				return true
			})
		case linuxLateMountReadOnly:
			p.removeDescendants(path, func(mount linuxLateMount) bool {
				return mount.Kind == linuxLateMountReadOnly
			})
		}
		return
	}

	if kind == linuxLateMountReadOnly && p.hasStrictAncestor(path, linuxLateMountReadOnly) {
		return
	}

	switch kind {
	case linuxLateMountMaskDir:
		p.removeDescendants(path, func(mount linuxLateMount) bool {
			return true
		})
	case linuxLateMountReadOnly:
		p.removeDescendants(path, func(mount linuxLateMount) bool {
			return mount.Kind == linuxLateMountReadOnly
		})
	}

	p.mounts = append(p.mounts, linuxLateMount{Path: path, Kind: kind})
}

func (p *linuxLateMountPlanner) hasStrictAncestor(path string, kind linuxLateMountKind) bool {
	for _, mount := range p.mounts {
		if mount.Kind != kind || mount.Path == path {
			continue
		}
		if linuxPathContains(mount.Path, path) {
			return true
		}
	}
	return false
}

func (p *linuxLateMountPlanner) removeDescendants(path string, shouldRemove func(linuxLateMount) bool) {
	filtered := p.mounts[:0]
	for _, mount := range p.mounts {
		if mount.Path != path && linuxPathContains(path, mount.Path) && shouldRemove(mount) {
			continue
		}
		filtered = append(filtered, mount)
	}
	p.mounts = filtered
}

func (p *linuxLateMountPlanner) Mounts() []linuxLateMount {
	mounts := slices.Clone(p.mounts)
	slices.SortFunc(mounts, func(a, b linuxLateMount) int {
		depthA := linuxLateMountDepth(a.Path)
		depthB := linuxLateMountDepth(b.Path)
		if depthA != depthB {
			return depthA - depthB
		}
		return strings.Compare(a.Path, b.Path)
	})
	return mounts
}

func appendLinuxLateMounts(args []string, mounts []linuxLateMount) []string {
	for _, mount := range mounts {
		switch mount.Kind {
		case linuxLateMountMaskDir:
			args = append(args, "--tmpfs", mount.Path)
		case linuxLateMountMaskFile:
			args = append(args, "--ro-bind", "/dev/null", mount.Path)
		case linuxLateMountReadOnly:
			args = append(args, "--ro-bind", mount.Path, mount.Path)
		}
	}
	return args
}

func linuxLateMountPriority(kind linuxLateMountKind) int {
	switch kind {
	case linuxLateMountMaskDir:
		return 3
	case linuxLateMountMaskFile:
		return 2
	case linuxLateMountReadOnly:
		return 1
	default:
		return 0
	}
}

func linuxLateMountDepth(path string) int {
	path = filepath.Clean(path)
	trimmed := strings.Trim(path, string(filepath.Separator))
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, string(filepath.Separator)) + 1
}

func linuxPathContains(ancestor, path string) bool {
	ancestor = filepath.Clean(ancestor)
	path = filepath.Clean(path)

	if ancestor == path {
		return true
	}
	if ancestor == string(filepath.Separator) {
		return strings.HasPrefix(path, string(filepath.Separator))
	}
	return strings.HasPrefix(path, ancestor+string(filepath.Separator))
}

func collectResolvedLinuxLateMountPaths(patterns []string) []string {
	if len(patterns) == 0 {
		return nil
	}

	var paths []string
	seen := make(map[string]bool)
	for _, path := range ExpandGlobPatterns(patterns) {
		mountPath, ok := resolvePathForMount(path)
		if !ok {
			continue
		}
		mountPath = filepath.Clean(mountPath)
		if seen[mountPath] {
			continue
		}
		seen[mountPath] = true
		paths = append(paths, mountPath)
	}
	return paths
}

// appendLinuxLatePolicyMounts plans the final policy overlays with subtree-aware
// precedence so masked directories cannot be punctured by later self-binds.
func appendLinuxLatePolicyMounts(
	bwrapArgs []string,
	cfg *config.Config,
	cwd string,
	defaultDenyRead bool,
	deniedExecPaths []string,
	debug bool,
) []string {
	planner := newLinuxLateMountPlanner()

	if cfg != nil {
		for _, mountPath := range collectResolvedLinuxLateMountPaths(cfg.Filesystem.DenyRead) {
			if isDirectory(mountPath) {
				planner.Add(mountPath, linuxLateMountMaskDir)
			} else {
				planner.Add(mountPath, linuxLateMountMaskFile)
			}
		}
	}

	allowGitConfig := cfg != nil && cfg.Filesystem.AllowGitConfig
	for _, path := range getMandatoryDenyPaths(cwd, allowGitConfig) {
		mountPath, ok := resolvePathForMount(path)
		if !ok {
			continue
		}
		if defaultDenyRead {
			if isDirectory(mountPath) {
				planner.Add(mountPath, linuxLateMountMaskDir)
			} else {
				planner.Add(mountPath, linuxLateMountMaskFile)
			}
			continue
		}
		planner.Add(mountPath, linuxLateMountReadOnly)
	}

	if cfg != nil {
		for _, mountPath := range collectResolvedLinuxLateMountPaths(cfg.Filesystem.DenyWrite) {
			planner.Add(mountPath, linuxLateMountReadOnly)
		}
	}

	for _, path := range deniedExecPaths {
		mountPath, ok := resolvePathForMount(path)
		if !ok {
			if debug {
				fencelog.Printf("[fence:linux] Skipping runtime exec deny mount for %s (unmountable)\n", path)
			}
			continue
		}
		planner.Add(mountPath, linuxLateMountMaskFile)
	}

	return appendLinuxLateMounts(bwrapArgs, planner.Mounts())
}
