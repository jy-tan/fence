package main

import (
	"fmt"

	"github.com/Use-Tusk/fence/internal/importer"
	"github.com/spf13/cobra"
)

func newHooksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hooks",
		Short: "Print and manage editor/agent hook integrations",
	}

	cmd.AddCommand(newHooksPrintCmd())
	cmd.AddCommand(newHooksInstallCmd())
	cmd.AddCommand(newHooksUninstallCmd())
	return cmd
}

func newHooksPrintCmd() *cobra.Command {
	var (
		claude      bool
		cursor      bool
		hookOptions hookFenceOptions
	)

	cmd := &cobra.Command{
		Use:   "print",
		Short: "Print hook config for supported integrations",
		Long: `Print hook configuration snippets for supported integrations.

Examples:
  fence hooks print --claude
  fence hooks print --claude --settings ./fence.json
  fence hooks print --cursor --template code`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedHookOptions, err := hookOptions.normalized()
			if err != nil {
				return fmt.Errorf("failed to resolve hook policy options: %w", err)
			}

			switch {
			case claude:
				return writeClaudeHooksConfigWithOptions(cmd.OutOrStdout(), resolvedHookOptions)
			case cursor:
				return writeCursorHooksConfigWithOptions(cmd.OutOrStdout(), resolvedHookOptions)
			default:
				return fmt.Errorf("no hook target specified. Use --claude or --cursor")
			}
		},
	}

	cmd.Flags().BoolVar(&claude, "claude", false, "Print Claude Code hook config")
	cmd.Flags().BoolVar(&cursor, "cursor", false, "Print Cursor hook config")
	addHookPolicyFlags(cmd, &hookOptions)
	cmd.MarkFlagsMutuallyExclusive("claude", "cursor")
	return cmd
}

func newHooksInstallCmd() *cobra.Command {
	var (
		claude      bool
		cursor      bool
		path        string
		hookOptions hookFenceOptions
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install hook config into supported integrations",
		Long: `Install hook configuration into supported integrations.

Examples:
  fence hooks install --claude
  fence hooks install --claude --file ./.claude/settings.json
  fence hooks install --claude --settings ./fence.json
  fence hooks install --cursor --template code --file ./.cursor/hooks.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedHookOptions, err := hookOptions.normalized()
			if err != nil {
				return fmt.Errorf("failed to resolve hook policy options: %w", err)
			}

			switch {
			case claude:
				targetPath := path
				if targetPath == "" {
					targetPath = importer.DefaultClaudeSettingsPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Claude settings path")
				}
				changed, err := installClaudeHookWithOptions(targetPath, resolvedHookOptions)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed Claude hook in %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Claude hook already installed in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case cursor:
				targetPath := path
				if targetPath == "" {
					targetPath = defaultCursorHooksPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Cursor hooks path")
				}
				changed, err := installCursorHookWithOptions(targetPath, resolvedHookOptions)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed Cursor hook in %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Cursor hook already installed in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			default:
				return fmt.Errorf("no hook target specified. Use --claude or --cursor")
			}
		},
	}

	cmd.Flags().BoolVar(&claude, "claude", false, "Install Claude Code hook config")
	cmd.Flags().BoolVar(&cursor, "cursor", false, "Install Cursor hook config")
	cmd.Flags().StringVarP(&path, "file", "f", "", "Path to the settings file to modify (default: ~/.claude/settings.json for --claude, ~/.cursor/hooks.json for --cursor)")
	addHookPolicyFlags(cmd, &hookOptions)
	cmd.MarkFlagsMutuallyExclusive("claude", "cursor")
	return cmd
}

func newHooksUninstallCmd() *cobra.Command {
	var (
		claude bool
		cursor bool
		path   string
	)

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove hook config from supported integrations",
		Long: `Remove hook configuration from supported integrations.

Examples:
  fence hooks uninstall --claude
  fence hooks uninstall --claude --file ./.claude/settings.json
  fence hooks uninstall --cursor --file ./.cursor/hooks.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case claude:
				targetPath := path
				if targetPath == "" {
					targetPath = importer.DefaultClaudeSettingsPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Claude settings path")
				}
				changed, err := uninstallClaudeHook(targetPath)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Removed Claude hook from %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Claude hook not present in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case cursor:
				targetPath := path
				if targetPath == "" {
					targetPath = defaultCursorHooksPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Cursor hooks path")
				}
				changed, err := uninstallCursorHook(targetPath)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Removed Cursor hook from %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Cursor hook not present in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			default:
				return fmt.Errorf("no hook target specified. Use --claude or --cursor")
			}
		},
	}

	cmd.Flags().BoolVar(&claude, "claude", false, "Remove Claude Code hook config")
	cmd.Flags().BoolVar(&cursor, "cursor", false, "Remove Cursor hook config")
	cmd.Flags().StringVarP(&path, "file", "f", "", "Path to the settings file to modify (default: ~/.claude/settings.json for --claude, ~/.cursor/hooks.json for --cursor)")
	cmd.MarkFlagsMutuallyExclusive("claude", "cursor")
	return cmd
}

func addHookPolicyFlags(cmd *cobra.Command, hookOptions *hookFenceOptions) {
	cmd.Flags().StringVar(&hookOptions.SettingsPath, "settings", "", "Pin wrapped shell commands to this Fence settings file")
	cmd.Flags().StringVar(&hookOptions.TemplateName, "template", "", "Pin wrapped shell commands to this Fence template")
	cmd.MarkFlagsMutuallyExclusive("settings", "template")
}
