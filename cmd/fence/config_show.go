package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/templates"
	"github.com/spf13/cobra"
)

type activeConfigAudit struct {
	Root       config.ResolutionStep
	RootSource activeConfigRootSource
	Steps      []config.ResolutionStep
	Config     *config.Config
}

type activeConfigRootSource string

const (
	activeConfigRootSourceProject  activeConfigRootSource = "project"
	activeConfigRootSourceUser     activeConfigRootSource = "user"
	activeConfigRootSourceSettings activeConfigRootSource = "settings"
)

func newConfigShowCmd() *cobra.Command {
	var (
		settingsPath string
		templateName string
	)

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the active fence config",
		Long: `Show the active Fence config chain and fully resolved JSON.

This command does not run a sandboxed command. By default it auto-discovers
the nearest fence.jsonc or fence.json in the current directory tree and
resolves inheritance.

Examples:
  fence config show
  fence config show --settings ./custom.json
  fence config show --template code`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			audit, err := loadActiveConfigAudit("", settingsPath, templateName)
			if err != nil {
				return err
			}
			return writeConfigShowOutput(cmd.OutOrStdout(), cmd.ErrOrStderr(), audit)
		},
	}

	cmd.Flags().StringVarP(&settingsPath, "settings", "s", "", "Path to settings file (default: nearest project fence.jsonc/fence.json or OS config path)")
	cmd.Flags().StringVarP(&templateName, "template", "t", "", "Show built-in template config (e.g., code)")
	cmd.MarkFlagsMutuallyExclusive("settings", "template")

	return cmd
}

func loadActiveConfigAudit(startDir, settingsPath, templateName string) (*activeConfigAudit, error) {
	switch {
	case templateName != "":
		trace, err := templates.LoadTrace(templateName)
		if err != nil {
			return nil, fmt.Errorf("failed to load template: %w\nUse --list-templates to see available templates", err)
		}
		return &activeConfigAudit{
			Root: config.ResolutionStep{
				Kind: config.ResolutionStepKindTemplate,
				Name: strings.TrimSuffix(templateName, ".json"),
			},
			Steps:  trace.Steps,
			Config: trace.Config,
		}, nil
	case settingsPath != "":
		resolvedPath, err := resolveCLIPath(settingsPath, startDir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve settings path: %w", err)
		}
		return loadSettingsConfigAudit(resolvedPath)
	default:
		configPath, err := config.ResolveConfigPath(startDir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve config path: %w", err)
		}
		rootSource := activeConfigRootSourceProject
		if isUserConfigPath(configPath) {
			rootSource = activeConfigRootSourceUser
		}
		return loadFileConfigAudit(configPath, rootSource)
	}
}

func loadSettingsConfigAudit(path string) (*activeConfigAudit, error) {
	if info, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("settings file not found: %s", path)
		}
		return nil, fmt.Errorf("failed to stat settings file %q: %w", path, err)
	} else if info.IsDir() {
		return nil, fmt.Errorf("settings path is a directory: %s", path)
	}

	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	if cfg == nil {
		return &activeConfigAudit{
			Root: config.ResolutionStep{
				Kind: config.ResolutionStepKindFile,
				Path: path,
			},
			RootSource: activeConfigRootSourceSettings,
			Config:     config.Default(),
		}, nil
	}

	return loadedFileConfigAudit(path, activeConfigRootSourceSettings, cfg)
}

func loadFileConfigAudit(path string, rootSource activeConfigRootSource) (*activeConfigAudit, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	if cfg == nil {
		return &activeConfigAudit{
			Root: config.ResolutionStep{
				Kind: config.ResolutionStepKindDefault,
				Path: path,
			},
			RootSource: rootSource,
			Config:     config.Default(),
		}, nil
	}

	return loadedFileConfigAudit(path, rootSource, cfg)
}

func loadedFileConfigAudit(path string, rootSource activeConfigRootSource, cfg *config.Config) (*activeConfigAudit, error) {
	trace, err := templates.ResolveExtendsFromPathTrace(cfg, path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve extends: %w", err)
	}

	return &activeConfigAudit{
		Root: config.ResolutionStep{
			Kind: config.ResolutionStepKindFile,
			Path: path,
		},
		RootSource: rootSource,
		Steps:      trace.Steps,
		Config:     trace.Config,
	}, nil
}

func resolveCLIPath(path, startDir string) (string, error) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	if startDir != "" {
		return filepath.Clean(filepath.Join(startDir, path)), nil
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absPath), nil
}

func writeConfigShowOutput(stdout, stderr io.Writer, audit *activeConfigAudit) error {
	cfg := audit.Config
	if cfg == nil {
		cfg = config.Default()
	}

	data, err := config.MarshalConfigJSON(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if _, err := io.WriteString(stderr, formatConfigChain(audit)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stderr); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, string(data))
	return err
}

func formatConfigChain(audit *activeConfigAudit) string {
	var output strings.Builder
	output.WriteString("Active config chain:\n")
	output.WriteString(describeResolutionRoot(audit))
	output.WriteByte('\n')

	for i, depth := 0, 0; i < len(audit.Steps); depth++ {
		label := describeResolutionStep(audit.Steps[i])
		if audit.Steps[i].Kind == config.ResolutionStepKindSpecial && i+1 < len(audit.Steps) {
			label = fmt.Sprintf("%s %s", audit.Steps[i].Name, describeResolutionStep(audit.Steps[i+1]))
			i += 2
		} else {
			i++
		}

		output.WriteString(strings.Repeat("    ", depth))
		output.WriteString("└── ")
		output.WriteString(label)
		output.WriteByte('\n')
	}

	return output.String()
}

func describeResolutionRoot(audit *activeConfigAudit) string {
	step := audit.Root
	switch step.Kind {
	case config.ResolutionStepKindTemplate:
		return fmt.Sprintf("builtin template: %s", step.Name)
	case config.ResolutionStepKindFile:
		return fmt.Sprintf("%s: %s", describeRootFileLabel(audit.RootSource), step.Path)
	case config.ResolutionStepKindDefault:
		return describeDefaultSource("builtin default", step.Path)
	default:
		return describeResolutionStep(step)
	}
}

func describeResolutionStep(step config.ResolutionStep) string {
	switch step.Kind {
	case config.ResolutionStepKindTemplate:
		return fmt.Sprintf("builtin template: %s", step.Name)
	case config.ResolutionStepKindFile:
		if isUserConfigPath(step.Path) {
			return fmt.Sprintf("user config: %s", step.Path)
		}
		return fmt.Sprintf("file: %s", step.Path)
	case config.ResolutionStepKindSpecial:
		return step.Name
	case config.ResolutionStepKindDefault:
		return describeDefaultSource("builtin default", step.Path)
	default:
		return "unknown"
	}
}

func describeRootFileLabel(source activeConfigRootSource) string {
	switch source {
	case activeConfigRootSourceSettings:
		return "settings file"
	case activeConfigRootSourceUser:
		return "user config"
	default:
		return "project config"
	}
}

func describeDefaultSource(prefix, path string) string {
	if path == "" {
		return prefix
	}
	return fmt.Sprintf("%s (no config loaded from %s)", prefix, path)
}

func isUserConfigPath(path string) bool {
	if path == "" {
		return false
	}
	return filepath.Clean(path) == filepath.Clean(config.ResolveDefaultConfigPath())
}
