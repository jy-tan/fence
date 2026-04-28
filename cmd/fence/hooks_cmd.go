package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"

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
		opencode    bool
		hookOptions hookFenceOptions
	)

	cmd := &cobra.Command{
		Use:   "print",
		Short: "Print hook config for supported integrations",
		Long: `Print hook configuration snippets for supported integrations.

Examples:
  fence hooks print --claude
  fence hooks print --claude --settings ./fence.json
  fence hooks print --cursor --template code
  fence hooks print --opencode`,
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
			case opencode:
				if resolvedHookOptions.SettingsPath != "" || resolvedHookOptions.TemplateName != "" {
					return fmt.Errorf("--settings/--template are not supported with --opencode (OpenCode plugins do not accept options through the plugin array; use a local plugin shim instead, see https://github.com/Use-Tusk/opencode-fence)")
				}
				return writeOpencodeHooksConfig(cmd.OutOrStdout())
			default:
				return fmt.Errorf("no hook target specified. Use --claude, --cursor, or --opencode")
			}
		},
	}

	cmd.Flags().BoolVar(&claude, "claude", false, "Print Claude Code hook config")
	cmd.Flags().BoolVar(&cursor, "cursor", false, "Print Cursor hook config")
	cmd.Flags().BoolVar(&opencode, "opencode", false, "Print OpenCode plugin config")
	addHookPolicyFlags(cmd, &hookOptions)
	cmd.MarkFlagsMutuallyExclusive("claude", "cursor", "opencode")
	return cmd
}

func newHooksInstallCmd() *cobra.Command {
	var (
		claude      bool
		cursor      bool
		opencode    bool
		path        string
		force       bool
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
  fence hooks install --cursor --template code --file ./.cursor/hooks.json
  fence hooks install --opencode
  fence hooks install --opencode --file ./opencode.json
  fence hooks install --opencode --force                          # skip prompt`,
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
			case opencode:
				if resolvedHookOptions.SettingsPath != "" || resolvedHookOptions.TemplateName != "" {
					return fmt.Errorf("--settings/--template are not supported with --opencode (OpenCode plugins do not accept options through the plugin array; use a local plugin shim instead, see https://github.com/Use-Tusk/opencode-fence)")
				}
				targetPath := path
				if targetPath == "" {
					targetPath = resolveOpencodeConfigPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine OpenCode config path")
				}
				if !confirmJSONCCommentLossOrAbort(cmd.InOrStdin(), cmd.ErrOrStderr(), targetPath, force) {
					return nil
				}
				changed, err := installOpencodePlugin(targetPath)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed OpenCode plugin in %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "OpenCode plugin already installed in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			default:
				return fmt.Errorf("no hook target specified. Use --claude, --cursor, or --opencode")
			}
		},
	}

	cmd.Flags().BoolVar(&claude, "claude", false, "Install Claude Code hook config")
	cmd.Flags().BoolVar(&cursor, "cursor", false, "Install Cursor hook config")
	cmd.Flags().BoolVar(&opencode, "opencode", false, "Install OpenCode plugin config")
	cmd.Flags().StringVarP(&path, "file", "f", "", "Path to the settings file to modify (default: ~/.claude/settings.json for --claude, ~/.cursor/hooks.json for --cursor, existing ~/.config/opencode/opencode.{jsonc,json} for --opencode)")
	cmd.Flags().BoolVarP(&force, "force", "y", false, "Skip the confirmation prompt when comments would be stripped")
	addHookPolicyFlags(cmd, &hookOptions)
	cmd.MarkFlagsMutuallyExclusive("claude", "cursor", "opencode")
	return cmd
}

func newHooksUninstallCmd() *cobra.Command {
	var (
		claude   bool
		cursor   bool
		opencode bool
		path     string
		force    bool
	)

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove hook config from supported integrations",
		Long: `Remove hook configuration from supported integrations.

Examples:
  fence hooks uninstall --claude
  fence hooks uninstall --claude --file ./.claude/settings.json
  fence hooks uninstall --cursor --file ./.cursor/hooks.json
  fence hooks uninstall --opencode
  fence hooks uninstall --opencode --force                          # skip prompt`,
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
			case opencode:
				targetPath := path
				if targetPath == "" {
					targetPath = resolveOpencodeConfigPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine OpenCode config path")
				}
				if !confirmJSONCCommentLossOrAbort(cmd.InOrStdin(), cmd.ErrOrStderr(), targetPath, force) {
					return nil
				}
				changed, err := uninstallOpencodePlugin(targetPath)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Removed OpenCode plugin from %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "OpenCode plugin not present in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			default:
				return fmt.Errorf("no hook target specified. Use --claude, --cursor, or --opencode")
			}
		},
	}

	cmd.Flags().BoolVar(&claude, "claude", false, "Remove Claude Code hook config")
	cmd.Flags().BoolVar(&cursor, "cursor", false, "Remove Cursor hook config")
	cmd.Flags().BoolVar(&opencode, "opencode", false, "Remove OpenCode plugin config")
	cmd.Flags().StringVarP(&path, "file", "f", "", "Path to the settings file to modify (default: ~/.claude/settings.json for --claude, ~/.cursor/hooks.json for --cursor, existing ~/.config/opencode/opencode.{jsonc,json} for --opencode)")
	cmd.Flags().BoolVarP(&force, "force", "y", false, "Skip the confirmation prompt when comments would be stripped")
	cmd.MarkFlagsMutuallyExclusive("claude", "cursor", "opencode")
	return cmd
}

func addHookPolicyFlags(cmd *cobra.Command, hookOptions *hookFenceOptions) {
	cmd.Flags().StringVar(&hookOptions.SettingsPath, "settings", "", "Pin wrapped shell commands to this Fence settings file")
	cmd.Flags().StringVar(&hookOptions.TemplateName, "template", "", "Pin wrapped shell commands to this Fence template")
	cmd.MarkFlagsMutuallyExclusive("settings", "template")
}

// confirmJSONCCommentLossOrAbort warns and prompts when the pending OpenCode
// install/uninstall would strip JSONC comments. Returns proceed=true when the
// operation should continue (no comments at risk, byte-edit will preserve
// them, force=true, or user answered yes); proceed=false when the user
// declined. Read errors during the checks are intentionally swallowed — any
// real failure will resurface in the install/uninstall step itself.
func confirmJSONCCommentLossOrAbort(in io.Reader, errOut io.Writer, path string, force bool) (proceed bool) {
	hadComments, err := hookConfigHasJSONCComments(path)
	if err != nil || !hadComments {
		return true
	}
	preserves, err := opencodeWillPreserveComments(path)
	if err == nil && preserves {
		return true
	}

	_, _ = fmt.Fprintf(errOut, "warning: %q contains comments, which will be removed when Fence rewrites the file.\nConsider backing up the file first.\n", path)

	if force {
		return true
	}

	_, _ = fmt.Fprint(errOut, "Continue and strip comments? [y/N] ")
	reader := bufio.NewReader(in)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	if response != "y" && response != "yes" {
		_, _ = fmt.Fprintln(errOut, "Aborted.")
		return false
	}
	return true
}
