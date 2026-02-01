// Package templates provides embedded configuration templates for fence.
package templates

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/tidwall/jsonc"
)

// maxExtendsDepth limits inheritance chain depth to prevent infinite loops.
const maxExtendsDepth = 10

// isPath returns true if the extends value looks like a file path rather than a template name.
// A value is considered a path if it contains a path separator or starts with ".".
func isPath(s string) bool {
	return strings.ContainsAny(s, "/\\") || strings.HasPrefix(s, ".")
}

//go:embed *.json
var templatesFS embed.FS

// Template represents a named configuration template.
type Template struct {
	Name        string
	Description string
}

// AvailableTemplates lists all embedded templates with descriptions.
var templateDescriptions = map[string]string{
	"default-deny":      "No network allowlist; no write access (most restrictive)",
	"disable-telemetry": "Block analytics/error reporting (Sentry, Posthog, Statsig, etc.)",
	"workspace-write":   "Allow writes in the current directory",
	"npm-install":       "Allow npm registry; allow writes to workspace/node_modules/tmp",
	"pip-install":       "Allow PyPI; allow writes to workspace/tmp",
	"local-dev-server":  "Allow binding and localhost outbound; allow writes to workspace/tmp",
	"git-readonly":      "Blocks destructive commands like git push, rm -rf, etc.",
	"code":              "Production-ready config for AI coding agents (Claude Code, Codex, Copilot, etc.)",
	"code-relaxed":      "Like 'code' but allows direct network for apps that ignore HTTP_PROXY (cursor-agent, opencode)",
	"code-strict":       "Like 'code' but denies reads by default; only allows reading the current project directory and essential system paths",
}

// List returns all available template names sorted alphabetically.
func List() []Template {
	entries, err := templatesFS.ReadDir(".")
	if err != nil {
		return nil
	}

	var templates []Template
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		desc := templateDescriptions[name]
		if desc == "" {
			desc = "No description available"
		}
		templates = append(templates, Template{Name: name, Description: desc})
	}

	sort.Slice(templates, func(i, j int) bool {
		return templates[i].Name < templates[j].Name
	})

	return templates
}

// Load loads a template by name and returns the parsed config.
// If the template uses "extends", the inheritance chain is resolved.
func Load(name string) (*config.Config, error) {
	return loadWithDepth(name, 0, nil)
}

// loadWithDepth loads a template with cycle and depth tracking.
func loadWithDepth(name string, depth int, seen map[string]bool) (*config.Config, error) {
	if depth > maxExtendsDepth {
		return nil, fmt.Errorf("extends chain too deep (max %d)", maxExtendsDepth)
	}

	// Normalize name (remove .json if present)
	name = strings.TrimSuffix(name, ".json")

	// Check for cycles
	if seen == nil {
		seen = make(map[string]bool)
	}
	if seen[name] {
		return nil, fmt.Errorf("circular extends detected: %q", name)
	}
	seen[name] = true

	filename := name + ".json"
	data, err := templatesFS.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("template %q not found", name)
	}

	var cfg config.Config
	if err := json.Unmarshal(jsonc.ToJSON(data), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse template %q: %w", name, err)
	}

	// If this template extends another, resolve the chain
	if cfg.Extends != "" {
		baseCfg, err := loadWithDepth(cfg.Extends, depth+1, seen)
		if err != nil {
			return nil, fmt.Errorf("failed to load base template %q: %w", cfg.Extends, err)
		}
		return config.Merge(baseCfg, &cfg), nil
	}

	return &cfg, nil
}

// Exists checks if a template with the given name exists.
func Exists(name string) bool {
	name = strings.TrimSuffix(name, ".json")
	filename := name + ".json"

	_, err := templatesFS.ReadFile(filename)
	return err == nil
}

// GetPath returns the embedded path for a template (for display purposes).
func GetPath(name string) string {
	name = strings.TrimSuffix(name, ".json")
	return filepath.Join("internal/templates", name+".json")
}

// ResolveExtends resolves the extends field in a config by loading and merging
// the base template or config file. If the config has no extends field, it is returned as-is.
// Relative paths are resolved relative to the current working directory.
// Use ResolveExtendsWithBaseDir if you need to resolve relative to a specific directory.
func ResolveExtends(cfg *config.Config) (*config.Config, error) {
	return ResolveExtendsWithBaseDir(cfg, "")
}

// ResolveExtendsWithBaseDir resolves the extends field in a config.
// The baseDir is used to resolve relative paths in the extends field.
// If baseDir is empty, relative paths will be resolved relative to the current working directory.
//
// The extends field can be:
//   - A template name (e.g., "code", "npm-install")
//   - An absolute path (e.g., "/path/to/base.json")
//   - A relative path (e.g., "./base.json", "../shared/base.json")
//
// Paths are detected by the presence of "/" or "\" or a leading ".".
func ResolveExtendsWithBaseDir(cfg *config.Config, baseDir string) (*config.Config, error) {
	if cfg == nil || cfg.Extends == "" {
		return cfg, nil
	}

	return resolveExtendsWithDepth(cfg, baseDir, 0, nil)
}

// resolveExtendsWithDepth resolves extends with cycle and depth tracking.
func resolveExtendsWithDepth(cfg *config.Config, baseDir string, depth int, seen map[string]bool) (*config.Config, error) {
	if cfg == nil || cfg.Extends == "" {
		return cfg, nil
	}

	if depth > maxExtendsDepth {
		return nil, fmt.Errorf("extends chain too deep (max %d)", maxExtendsDepth)
	}

	if seen == nil {
		seen = make(map[string]bool)
	}

	var baseCfg *config.Config
	var newBaseDir string
	var err error

	// Handle file path or template name extends
	if isPath(cfg.Extends) {
		baseCfg, newBaseDir, err = loadConfigFile(cfg.Extends, baseDir, seen)
	} else {
		baseCfg, err = loadWithDepth(cfg.Extends, depth+1, seen)
		newBaseDir = ""
	}

	if err != nil {
		return nil, err
	}

	// If the base config also has extends, resolve it recursively
	if baseCfg.Extends != "" {
		baseCfg, err = resolveExtendsWithDepth(baseCfg, newBaseDir, depth+1, seen)
		if err != nil {
			return nil, err
		}
	}

	return config.Merge(baseCfg, cfg), nil
}

// loadConfigFile loads a config from a file path with cycle detection.
// Returns the loaded config, the directory of the loaded file (for resolving nested extends), and any error.
func loadConfigFile(path, baseDir string, seen map[string]bool) (*config.Config, string, error) {
	var resolvedPath string
	switch {
	case filepath.IsAbs(path):
		resolvedPath = path
	case baseDir != "":
		resolvedPath = filepath.Join(baseDir, path)
	default:
		var err error
		resolvedPath, err = filepath.Abs(path)
		if err != nil {
			return nil, "", fmt.Errorf("failed to resolve path %q: %w", path, err)
		}
	}

	// Clean and normalize the path for cycle detection
	resolvedPath = filepath.Clean(resolvedPath)

	if seen[resolvedPath] {
		return nil, "", fmt.Errorf("circular extends detected: %q", path)
	}
	seen[resolvedPath] = true

	data, err := os.ReadFile(resolvedPath) //nolint:gosec // user-provided config path - intentional
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", fmt.Errorf("extends file not found: %q", path)
		}
		return nil, "", fmt.Errorf("failed to read extends file %q: %w", path, err)
	}

	// Handle empty file
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, "", fmt.Errorf("extends file is empty: %q", path)
	}

	var cfg config.Config
	if err := json.Unmarshal(jsonc.ToJSON(data), &cfg); err != nil {
		return nil, "", fmt.Errorf("invalid JSON in extends file %q: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, "", fmt.Errorf("invalid configuration in extends file %q: %w", path, err)
	}

	return &cfg, filepath.Dir(resolvedPath), nil
}
