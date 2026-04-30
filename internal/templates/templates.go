// Package templates provides embedded configuration templates for fence.
package templates

import (
	"embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/tidwall/jsonc"
)

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
	"hermes":            "Extends 'code' with messaging-platform domains and ~/.hermes writes for Hermes Agent (gateway + CLI)",
	"openclaw":          "Extends 'code' with messaging-platform domains and ~/.openclaw writes for OpenClaw (gateway + agents)",
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
	trace, err := LoadTrace(name)
	if err != nil {
		return nil, err
	}
	return trace.Config, nil
}

// LoadTrace loads a template by name, resolves its extends chain, and records
// each inheritance step.
func LoadTrace(name string) (*config.ResolutionTrace, error) {
	cfg, err := loadRaw(name)
	if err != nil {
		return nil, err
	}
	return config.ResolveExtendsTrace(cfg, loadRaw)
}

func loadRaw(name string) (*config.Config, error) {
	name = strings.TrimSuffix(name, ".json")
	filename := name + ".json"
	data, err := templatesFS.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("template %q not found", name)
	}

	var cfg config.Config
	if err := json.Unmarshal(jsonc.ToJSON(data), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse template %q: %w", name, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config in template %q: %w", name, err)
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
	return config.ResolveExtends(cfg, loadRaw)
}

// ResolveExtendsWithBaseDir resolves the extends field in a config using
// baseDir for relative file references.
func ResolveExtendsWithBaseDir(cfg *config.Config, baseDir string) (*config.Config, error) {
	return config.ResolveExtendsWithBaseDir(cfg, baseDir, loadRaw)
}

// ResolveExtendsFromPath resolves the extends field in a config loaded from
// sourcePath, using the path itself in cycle detection.
func ResolveExtendsFromPath(cfg *config.Config, sourcePath string) (*config.Config, error) {
	trace, err := ResolveExtendsFromPathTrace(cfg, sourcePath)
	if err != nil {
		return nil, err
	}
	return trace.Config, nil
}

// ResolveExtendsFromPathTrace resolves the extends field in a config loaded
// from sourcePath and records each inheritance step.
func ResolveExtendsFromPathTrace(cfg *config.Config, sourcePath string) (*config.ResolutionTrace, error) {
	return config.ResolveExtendsFromPathTrace(cfg, sourcePath, loadRaw)
}
