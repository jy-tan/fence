package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/templates"
	"github.com/spf13/cobra"
)

// newConfigInitCmd creates the config init subcommand.
func newConfigInitCmd() *cobra.Command {
	var (
		templateFlag string
		outputPath   string
		forceFlag    bool
		minimalFlag  bool
		printFlag    bool
		scaffoldFlag bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a starter fence config",
		Long: `Create a starter fence config file.

By default, this writes a config that extends the built-in "code" template:
{
  "extends": "code"
}

This makes fence immediately useful for common coding workflows while letting
you add project-specific overrides.

Examples:
  # Write default config to OS config directory
  fence config init

  # Use a different template
  fence config init --template local-dev-server

  # Create a minimal config with no template inheritance
  fence config init --minimal

  # Write to a specific path
  fence config init -o ./fence.json

  # Print config to stdout instead of writing a file
  fence config init --print

  # Include scaffold arrays as editable hints
  fence config init --scaffold`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := buildInitConfig(templateFlag, minimalFlag)
			if err != nil {
				return err
			}

			data, err := renderInitConfigJSON(cfg, scaffoldFlag)
			if err != nil {
				return fmt.Errorf("failed to marshal config: %w", err)
			}

			if printFlag {
				fmt.Println(string(data))
				return nil
			}

			destPath := outputPath
			if destPath == "" {
				destPath = config.DefaultConfigPath()
			}

			if !forceFlag {
				if _, err := os.Stat(destPath); err == nil {
					fmt.Printf("File %q already exists. Overwrite? [y/N] ", destPath)
					reader := bufio.NewReader(os.Stdin)
					response, _ := reader.ReadString('\n')
					response = strings.TrimSpace(strings.ToLower(response))
					if response != "y" && response != "yes" {
						fmt.Println("Aborted.")
						return nil
					}
				}
			}

			if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil {
				return fmt.Errorf("failed to create config directory: %w", err)
			}

			if scaffoldFlag {
				output := formatInitConfigWithComment(data, cfg)
				if err := os.WriteFile(destPath, []byte(output), 0o600); err != nil {
					return fmt.Errorf("failed to write config: %w", err)
				}
			} else {
				if err := config.WriteConfigFile(cfg, destPath, config.FileWriteOptions{
					HeaderLines: initHeaderLines(cfg),
				}); err != nil {
					return err
				}
			}

			if cfg.Extends != "" {
				fmt.Printf("Created config extending %q\n", cfg.Extends)
			} else {
				fmt.Printf("Created minimal config\n")
			}
			fmt.Printf("Written to %q\n", destPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&templateFlag, "template", "", "Template to extend (default: code)")
	cmd.Flags().BoolVar(&minimalFlag, "minimal", false, "Create a minimal config without template inheritance")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: OS config path)")
	cmd.Flags().BoolVarP(&forceFlag, "force", "y", false, "Overwrite existing file without prompting")
	cmd.Flags().BoolVar(&printFlag, "print", false, "Print config to stdout instead of writing a file")
	cmd.Flags().BoolVar(&scaffoldFlag, "scaffold", false, "Include empty arrays as editable hints in generated JSON")
	cmd.MarkFlagsMutuallyExclusive("minimal", "template")
	cmd.MarkFlagsMutuallyExclusive("print", "output")
	cmd.MarkFlagsMutuallyExclusive("print", "force")

	return cmd
}

func buildInitConfig(templateName string, minimal bool) (*config.Config, error) {
	cfg := config.Default()

	if minimal {
		return cfg, nil
	}

	if templateName == "" {
		templateName = "code"
	}

	if !templates.Exists(templateName) {
		return nil, fmt.Errorf("template %q not found\nUse --list-templates to see available templates", templateName)
	}

	cfg.Extends = templateName
	return cfg, nil
}

func renderInitConfigJSON(cfg *config.Config, scaffold bool) ([]byte, error) {
	if !scaffold {
		return config.MarshalConfigJSON(cfg)
	}

	type scaffoldNetworkConfig struct {
		AllowedDomains []string `json:"allowedDomains"`
		DeniedDomains  []string `json:"deniedDomains"`
	}
	type scaffoldFilesystemConfig struct {
		AllowRead    []string `json:"allowRead"`
		AllowExecute []string `json:"allowExecute"`
		DenyRead     []string `json:"denyRead"`
		AllowWrite   []string `json:"allowWrite"`
		DenyWrite    []string `json:"denyWrite"`
	}
	type scaffoldCommandConfig struct {
		Deny  []string `json:"deny"`
		Allow []string `json:"allow"`
	}
	type scaffoldSSHConfig struct {
		AllowedHosts    []string `json:"allowedHosts"`
		DeniedHosts     []string `json:"deniedHosts"`
		AllowedCommands []string `json:"allowedCommands"`
		DeniedCommands  []string `json:"deniedCommands"`
	}
	type scaffoldConfig struct {
		Extends    string                   `json:"extends,omitempty"`
		Network    scaffoldNetworkConfig    `json:"network"`
		Filesystem scaffoldFilesystemConfig `json:"filesystem"`
		Command    scaffoldCommandConfig    `json:"command"`
		SSH        scaffoldSSHConfig        `json:"ssh"`
	}

	scaffoldCfg := scaffoldConfig{
		Extends: cfg.Extends,
		Network: scaffoldNetworkConfig{
			AllowedDomains: []string{},
			DeniedDomains:  []string{},
		},
		Filesystem: scaffoldFilesystemConfig{
			AllowRead:    []string{},
			AllowExecute: []string{},
			DenyRead:     []string{},
			AllowWrite:   []string{},
			DenyWrite:    []string{},
		},
		Command: scaffoldCommandConfig{
			Deny:  []string{},
			Allow: []string{},
		},
		SSH: scaffoldSSHConfig{
			AllowedHosts:    []string{},
			DeniedHosts:     []string{},
			AllowedCommands: []string{},
			DeniedCommands:  []string{},
		},
	}

	return json.MarshalIndent(scaffoldCfg, "", "  ")
}

func initHeaderLines(cfg *config.Config) []string {
	if cfg.Extends == "" {
		return []string{
			"// Starter config generated by `fence config init`.",
			"// Add rules below to customize network, filesystem, command, and SSH behavior.",
			"// Configuration reference: https://github.com/Use-Tusk/fence/blob/main/docs/configuration.md",
		}
	}

	return []string{
		fmt.Sprintf("// Starter config generated by `fence config init`; this file extends %q.", cfg.Extends),
		fmt.Sprintf("// Rules from %q are inherited and not shown below.", cfg.Extends),
		"// Add your project-specific overrides in this file.",
		"// Run `fence --list-templates` to see available templates.",
		"// Configuration reference: https://github.com/Use-Tusk/fence/blob/main/docs/configuration.md",
	}
}

func formatInitConfigWithComment(data []byte, cfg *config.Config) string {
	output := strings.Join(initHeaderLines(cfg), "\n")
	if output != "" {
		output += "\n"
	}
	output += string(data)
	output += "\n"
	return output
}
