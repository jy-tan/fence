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
		hermes      bool
		openclaw    bool
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
  fence hooks print --opencode
  fence hooks print --hermes
  fence hooks print --openclaw`,
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
			case hermes:
				return writeHermesHooksConfig(cmd.OutOrStdout(), resolvedHookOptions)
			case openclaw:
				return writeOpenclawHooksGuidance(cmd.OutOrStdout(), resolvedHookOptions)
			default:
				return fmt.Errorf("no hook target specified. Use --claude, --cursor, --opencode, --hermes, or --openclaw")
			}
		},
	}

	cmd.Flags().BoolVar(&claude, "claude", false, "Print Claude Code hook config")
	cmd.Flags().BoolVar(&cursor, "cursor", false, "Print Cursor hook config")
	cmd.Flags().BoolVar(&opencode, "opencode", false, "Print OpenCode plugin config")
	cmd.Flags().BoolVar(&hermes, "hermes", false, "Print Hermes shell-hook config (~/.hermes/config.yaml)")
	cmd.Flags().BoolVar(&openclaw, "openclaw", false, "Print install instructions for the OpenClaw plugin (@use-tusk/openclaw-fence)")
	addHookPolicyFlags(cmd, &hookOptions)
	cmd.MarkFlagsMutuallyExclusive("claude", "cursor", "opencode", "hermes", "openclaw")
	return cmd
}

func newHooksInstallCmd() *cobra.Command {
	var (
		claude      bool
		cursor      bool
		opencode    bool
		hermes      bool
		openclaw    bool
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
  fence hooks install --opencode --force                          # skip prompt
  fence hooks install --hermes
  fence hooks install --hermes --settings ./fence.json
  fence hooks install --hermes --file ./project-hermes-config.yaml

Note: --openclaw is not supported because OpenClaw uses an imperative
plugin manager. Run 'openclaw plugins install @use-tusk/openclaw-fence'
instead. See 'fence hooks print --openclaw' for the full instructions.`,
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
			case hermes:
				targetPath := path
				if targetPath == "" {
					targetPath = defaultHermesConfigPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Hermes config path")
				}
				changed, err := installHermesHook(targetPath, resolvedHookOptions)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed Hermes hooks in %q\n", targetPath); err != nil {
						return err
					}
					if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "Note: Hermes prompts on first use of each hook. For non-TTY runs (gateway, cron) set HERMES_ACCEPT_HOOKS=1 or hooks_auto_accept: true."); err != nil {
						return err
					}
					for _, line := range hermesEmptyPolicyAdvice(resolvedHookOptions) {
						if _, err := fmt.Fprintln(cmd.ErrOrStderr(), line); err != nil {
							return err
						}
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Hermes hooks already installed in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case openclaw:
				return errOpenclawUseImperativeInstall
			default:
				return fmt.Errorf("no hook target specified. Use --claude, --cursor, --opencode, --hermes, or --openclaw")
			}
		},
	}

	cmd.Flags().BoolVar(&claude, "claude", false, "Install Claude Code hook config")
	cmd.Flags().BoolVar(&cursor, "cursor", false, "Install Cursor hook config")
	cmd.Flags().BoolVar(&opencode, "opencode", false, "Install OpenCode plugin config")
	cmd.Flags().BoolVar(&hermes, "hermes", false, "Install Hermes shell-hook config")
	cmd.Flags().BoolVar(&openclaw, "openclaw", false, "Not supported (run `openclaw plugins install @use-tusk/openclaw-fence` instead)")
	cmd.Flags().StringVarP(&path, "file", "f", "", "Path to the settings file to modify (default: ~/.claude/settings.json for --claude, ~/.cursor/hooks.json for --cursor, existing ~/.config/opencode/opencode.{jsonc,json} for --opencode, ~/.hermes/config.yaml for --hermes)")
	cmd.Flags().BoolVarP(&force, "force", "y", false, "Skip the confirmation prompt when comments would be stripped")
	addHookPolicyFlags(cmd, &hookOptions)
	cmd.MarkFlagsMutuallyExclusive("claude", "cursor", "opencode", "hermes", "openclaw")
	return cmd
}

func newHooksUninstallCmd() *cobra.Command {
	var (
		claude   bool
		cursor   bool
		opencode bool
		hermes   bool
		openclaw bool
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
  fence hooks uninstall --opencode --force                          # skip prompt
  fence hooks uninstall --hermes

Note: --openclaw is not supported. Run 'openclaw plugins uninstall
openclaw-fence' instead.`,
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
			case hermes:
				targetPath := path
				if targetPath == "" {
					targetPath = defaultHermesConfigPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Hermes config path")
				}
				changed, err := uninstallHermesHook(targetPath)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Removed Hermes hooks from %q\n", targetPath); err != nil {
						return err
					}
					if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "Tip: revoke Hermes' shell-hook consent with `hermes hooks revoke 'fence "+hermesPreToolUseMode+"'`."); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Hermes hooks not present in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case openclaw:
				return errOpenclawUseImperativeUninstall
			default:
				return fmt.Errorf("no hook target specified. Use --claude, --cursor, --opencode, --hermes, or --openclaw")
			}
		},
	}

	cmd.Flags().BoolVar(&claude, "claude", false, "Remove Claude Code hook config")
	cmd.Flags().BoolVar(&cursor, "cursor", false, "Remove Cursor hook config")
	cmd.Flags().BoolVar(&opencode, "opencode", false, "Remove OpenCode plugin config")
	cmd.Flags().BoolVar(&hermes, "hermes", false, "Remove Hermes shell-hook config")
	cmd.Flags().BoolVar(&openclaw, "openclaw", false, "Not supported (run `openclaw plugins uninstall openclaw-fence` instead)")
	cmd.Flags().StringVarP(&path, "file", "f", "", "Path to the settings file to modify (default: ~/.claude/settings.json for --claude, ~/.cursor/hooks.json for --cursor, existing ~/.config/opencode/opencode.{jsonc,json} for --opencode, ~/.hermes/config.yaml for --hermes)")
	cmd.Flags().BoolVarP(&force, "force", "y", false, "Skip the confirmation prompt when comments would be stripped")
	cmd.MarkFlagsMutuallyExclusive("claude", "cursor", "opencode", "hermes", "openclaw")
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
