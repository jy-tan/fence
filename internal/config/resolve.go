package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tidwall/jsonc"
)

const (
	// maxExtendsDepth limits inheritance chain depth to prevent infinite loops.
	maxExtendsDepth = 10
	// baseExtendsToken is a reserved extends value for the user's default config.
	baseExtendsToken = "@base"
)

// TemplateLoader loads a template config without resolving its extends chain.
type TemplateLoader func(name string) (*Config, error)

// ResolveExtends resolves the extends chain for a config.
func ResolveExtends(cfg *Config, loadTemplate TemplateLoader) (*Config, error) {
	return resolveExtends(cfg, resolveOptions{loadTemplate: loadTemplate})
}

// ResolveExtendsWithBaseDir resolves the extends chain for a config, using
// baseDir to resolve relative file paths.
func ResolveExtendsWithBaseDir(cfg *Config, baseDir string, loadTemplate TemplateLoader) (*Config, error) {
	return resolveExtends(cfg, resolveOptions{
		baseDir:      baseDir,
		loadTemplate: loadTemplate,
	})
}

// ResolveExtendsFromPath resolves the extends chain for a config loaded from
// sourcePath. The source path is recorded in cycle detection so symlink aliases
// and direct references back to the original file are caught reliably.
func ResolveExtendsFromPath(cfg *Config, sourcePath string, loadTemplate TemplateLoader) (*Config, error) {
	return resolveExtends(cfg, resolveOptions{
		sourcePath:   sourcePath,
		loadTemplate: loadTemplate,
	})
}

type resolveOptions struct {
	baseDir      string
	sourcePath   string
	loadTemplate TemplateLoader
}

type resolvedExtendsTarget struct {
	cfg     *Config
	baseDir string
	ids     []string
}

func resolveExtends(cfg *Config, opts resolveOptions) (*Config, error) {
	if cfg == nil || cfg.Extends == "" {
		return cfg, nil
	}

	currentBaseDir := opts.baseDir
	if currentBaseDir == "" && opts.sourcePath != "" {
		currentBaseDir = filepath.Dir(opts.sourcePath)
	}

	seen := make(map[string]struct{})
	if opts.sourcePath != "" {
		sourceID, err := fileTargetID(opts.sourcePath, "")
		if err != nil {
			return nil, fmt.Errorf("failed to resolve source config path %q: %w", opts.sourcePath, err)
		}
		seen[sourceID] = struct{}{}
	}

	chain := []*Config{cfg}
	current := cfg
	for depth := 0; current.Extends != ""; depth++ {
		if depth >= maxExtendsDepth {
			return nil, fmt.Errorf("extends chain too deep (max %d)", maxExtendsDepth)
		}

		target, err := resolveExtendsTarget(current.Extends, currentBaseDir, opts.loadTemplate)
		if err != nil {
			return nil, err
		}
		if err := recordSeenTargetIDs(seen, target.ids, current.Extends); err != nil {
			return nil, err
		}

		chain = append(chain, target.cfg)
		current = target.cfg
		currentBaseDir = target.baseDir
	}

	result := chain[len(chain)-1]
	for i := len(chain) - 2; i >= 0; i-- {
		result = Merge(result, chain[i])
	}
	return result, nil
}

func resolveExtendsTarget(extends, baseDir string, loadTemplate TemplateLoader) (*resolvedExtendsTarget, error) {
	switch {
	case extends == baseExtendsToken:
		return loadBaseExtendsTarget()
	case isExtendsPath(extends):
		return loadFileExtendsTarget(extends, baseDir)
	default:
		if loadTemplate == nil {
			return nil, fmt.Errorf("cannot resolve template %q without a template loader", extends)
		}

		cfg, err := loadTemplate(normalizeTemplateName(extends))
		if err != nil {
			return nil, err
		}

		return &resolvedExtendsTarget{
			cfg: cfg,
			ids: []string{templateTargetID(extends)},
		}, nil
	}
}

func loadBaseExtendsTarget() (*resolvedExtendsTarget, error) {
	defaultConfigPath := ResolveDefaultConfigPath()
	cfg, err := Load(defaultConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s config %q: %w", baseExtendsToken, defaultConfigPath, err)
	}

	target := &resolvedExtendsTarget{
		cfg: Default(),
		ids: []string{specialTargetID(baseExtendsToken)},
	}
	if cfg == nil {
		return target, nil
	}

	fileID, err := fileTargetID(defaultConfigPath, "")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s config path %q: %w", baseExtendsToken, defaultConfigPath, err)
	}

	target.cfg = cfg
	target.baseDir = filepath.Dir(defaultConfigPath)
	target.ids = append(target.ids, fileID)
	return target, nil
}

func loadFileExtendsTarget(path, baseDir string) (*resolvedExtendsTarget, error) {
	resolvedPath, err := resolveExtendsFilePath(path, baseDir)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(resolvedPath) //nolint:gosec // user-provided config path - intentional
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("extends file not found: %q", path)
		}
		return nil, fmt.Errorf("failed to read extends file %q: %w", path, err)
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("extends file is empty: %q", path)
	}

	var cfg Config
	if err := json.Unmarshal(jsonc.ToJSON(data), &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON in extends file %q: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration in extends file %q: %w", path, err)
	}

	fileID, err := fileTargetID(path, baseDir)
	if err != nil {
		return nil, err
	}

	return &resolvedExtendsTarget{
		cfg:     &cfg,
		baseDir: filepath.Dir(resolvedPath),
		ids:     []string{fileID},
	}, nil
}

func recordSeenTargetIDs(seen map[string]struct{}, ids []string, extends string) error {
	for _, id := range ids {
		if _, exists := seen[id]; exists {
			return fmt.Errorf("circular extends detected: %q", extends)
		}
	}
	for _, id := range ids {
		seen[id] = struct{}{}
	}
	return nil
}

func isExtendsPath(value string) bool {
	return strings.ContainsAny(value, `/\`) || strings.HasPrefix(value, ".")
}

func normalizeTemplateName(name string) string {
	return strings.TrimSuffix(name, ".json")
}

func templateTargetID(name string) string {
	return "template:" + normalizeTemplateName(name)
}

func specialTargetID(name string) string {
	return "special:" + name
}

func fileTargetID(path, baseDir string) (string, error) {
	resolvedPath, err := resolveExtendsFilePath(path, baseDir)
	if err != nil {
		return "", err
	}

	canonicalPath, err := canonicalExtendsFilePath(resolvedPath)
	if err != nil {
		return "", err
	}

	return "file:" + canonicalPath, nil
}

func resolveExtendsFilePath(path, baseDir string) (string, error) {
	var resolvedPath string
	switch {
	case filepath.IsAbs(path):
		resolvedPath = path
	case baseDir != "":
		resolvedPath = filepath.Join(baseDir, path)
	default:
		resolvedPath = path
	}

	if !filepath.IsAbs(resolvedPath) {
		absPath, err := filepath.Abs(resolvedPath)
		if err != nil {
			return "", fmt.Errorf("failed to resolve path %q: %w", path, err)
		}
		resolvedPath = absPath
	}

	return filepath.Clean(resolvedPath), nil
}

func canonicalExtendsFilePath(path string) (string, error) {
	canonicalPath, err := filepath.EvalSymlinks(path)
	if err == nil {
		if !filepath.IsAbs(canonicalPath) {
			canonicalPath, err = filepath.Abs(canonicalPath)
			if err != nil {
				return "", err
			}
		}
		return filepath.Clean(canonicalPath), nil
	}
	if os.IsNotExist(err) {
		return path, nil
	}
	return "", fmt.Errorf("failed to resolve path %q: %w", path, err)
}
