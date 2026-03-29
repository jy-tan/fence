package main

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/templates"
)

type activeConfigAudit struct {
	Root   config.ResolutionStep
	Steps  []config.ResolutionStep
	Config *config.Config
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
		return loadFileConfigAudit(resolvedPath)
	default:
		configPath, err := config.ResolveConfigPath(startDir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve config path: %w", err)
		}
		return loadFileConfigAudit(configPath)
	}
}

func loadFileConfigAudit(path string) (*activeConfigAudit, error) {
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
			Config: config.Default(),
		}, nil
	}

	trace, err := templates.ResolveExtendsFromPathTrace(cfg, path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve extends: %w", err)
	}

	return &activeConfigAudit{
		Root: config.ResolutionStep{
			Kind: config.ResolutionStepKindFile,
			Path: path,
		},
		Steps:  trace.Steps,
		Config: trace.Config,
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

func writeShowOutput(stdout, stderr io.Writer, audit *activeConfigAudit) error {
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
	_, err = fmt.Fprintln(stdout, string(data))
	return err
}

func formatConfigChain(audit *activeConfigAudit) string {
	var output strings.Builder
	output.WriteString("Active config chain:\n")
	output.WriteString(describeResolutionStep(audit.Root))
	output.WriteByte('\n')

	for i, step := range audit.Steps {
		output.WriteString(strings.Repeat("    ", i))
		output.WriteString("└── ")
		output.WriteString(describeResolutionStep(step))
		output.WriteByte('\n')
	}

	return output.String()
}

func describeResolutionStep(step config.ResolutionStep) string {
	switch step.Kind {
	case config.ResolutionStepKindTemplate:
		return fmt.Sprintf("template: %s", step.Name)
	case config.ResolutionStepKindFile:
		return fmt.Sprintf("file: %s", step.Path)
	case config.ResolutionStepKindSpecial:
		return step.Name
	case config.ResolutionStepKindDefault:
		if step.Path == "" {
			return "built-in default"
		}
		return fmt.Sprintf("built-in default (no config loaded from %s)", step.Path)
	default:
		return "unknown"
	}
}
