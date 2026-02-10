// Package main implements the fence CLI.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/Use-Tusk/fence/internal/importer"
	"github.com/Use-Tusk/fence/internal/platform"
	"github.com/Use-Tusk/fence/internal/sandbox"
	"github.com/Use-Tusk/fence/internal/templates"
	"github.com/spf13/cobra"
)

// Build-time variables (set via -ldflags)
var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

var (
	debug         bool
	monitor       bool
	settingsPath  string
	templateName  string
	listTemplates bool
	cmdString     string
	exposePorts   []string
	exitCode      int
	showVersion   bool
	linuxFeatures bool
)

func main() {
	// Check for internal --landlock-apply mode (used inside sandbox)
	// This must be checked before cobra to avoid flag conflicts
	if len(os.Args) >= 2 && os.Args[1] == "--landlock-apply" {
		runLandlockWrapper()
		return
	}

	rootCmd := &cobra.Command{
		Use:   "fence [flags] -- [command...]",
		Short: "Run commands in a sandbox with network and filesystem restrictions",
		Long: `fence is a command-line tool that runs commands in a sandboxed environment
with network and filesystem restrictions.

By default, all network access is blocked. Configure allowed domains in
~/.config/fence/fence.json (or ~/Library/Application Support/fence/fence.json on macOS)
or pass a settings file with --settings, or use a built-in template with --template.

Examples:
  fence curl https://example.com          # Will be blocked (no domains allowed)
  fence -- curl -s https://example.com    # Use -- to separate fence flags from command
  fence -c "echo hello && ls"             # Run with shell expansion
  fence --settings config.json npm install
  fence -t npm-install npm install        # Use built-in npm-install template
  fence -t ai-coding-agents -- agent-cmd  # Use AI coding agents template
  fence -p 3000 -c "npm run dev"          # Expose port 3000 for inbound connections
  fence --list-templates                  # Show available built-in templates

Configuration file format:
{
  "network": {
    "allowedDomains": ["github.com", "*.npmjs.org"],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": [],
    "allowWrite": ["."],
    "denyWrite": []
  },
  "command": {
    "deny": ["git push", "npm publish"]
  }
}`,
		RunE:          runCommand,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
	}

	rootCmd.Flags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	rootCmd.Flags().BoolVarP(&monitor, "monitor", "m", false, "Monitor and log sandbox violations (macOS: log stream, all: proxy denials)")
	rootCmd.Flags().StringVarP(&settingsPath, "settings", "s", "", "Path to settings file (default: OS config directory)")
	rootCmd.Flags().StringVarP(&templateName, "template", "t", "", "Use built-in template (e.g., ai-coding-agents, npm-install)")
	rootCmd.Flags().BoolVar(&listTemplates, "list-templates", false, "List available templates")
	rootCmd.Flags().StringVarP(&cmdString, "c", "c", "", "Run command string directly (like sh -c)")
	rootCmd.Flags().StringArrayVarP(&exposePorts, "port", "p", nil, "Expose port for inbound connections (can be used multiple times)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Show version information")
	rootCmd.Flags().BoolVar(&linuxFeatures, "linux-features", false, "Show available Linux security features and exit")

	rootCmd.Flags().SetInterspersed(true)

	rootCmd.AddCommand(newImportCmd())
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newCompletionCmd(rootCmd))

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		exitCode = 1
	}
	os.Exit(exitCode)
}

func runCommand(cmd *cobra.Command, args []string) error {
	if showVersion {
		fmt.Printf("fence - lightweight, container-free sandbox for running untrusted commands\n")
		fmt.Printf("  Version: %s\n", version)
		fmt.Printf("  Built:   %s\n", buildTime)
		fmt.Printf("  Commit:  %s\n", gitCommit)
		return nil
	}

	if linuxFeatures {
		sandbox.PrintLinuxFeatures()
		return nil
	}

	if listTemplates {
		printTemplates()
		return nil
	}

	var command string
	switch {
	case cmdString != "":
		command = cmdString
	case len(args) > 0:
		command = sandbox.ShellQuote(args)
	default:
		return fmt.Errorf("no command specified. Use -c <command> or provide command arguments")
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[fence] Command: %s\n", command)
	}

	var ports []int
	for _, p := range exposePorts {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port: %s", p)
		}
		ports = append(ports, port)
	}

	if debug && len(ports) > 0 {
		fmt.Fprintf(os.Stderr, "[fence] Exposing ports: %v\n", ports)
	}

	// Load config: template > settings file > default path
	var cfg *config.Config
	var err error

	switch {
	case templateName != "":
		cfg, err = templates.Load(templateName)
		if err != nil {
			return fmt.Errorf("failed to load template: %w\nUse --list-templates to see available templates", err)
		}
		if debug {
			fmt.Fprintf(os.Stderr, "[fence] Using template: %s\n", templateName)
		}
	case settingsPath != "":
		cfg, err = config.Load(settingsPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		absPath, _ := filepath.Abs(settingsPath)
		cfg, err = templates.ResolveExtendsWithBaseDir(cfg, filepath.Dir(absPath))
		if err != nil {
			return fmt.Errorf("failed to resolve extends: %w", err)
		}
	default:
		configPath := config.DefaultConfigPath()
		cfg, err = config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		if cfg == nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[fence] No config found at %s, using default (block all network)\n", configPath)
			}
			cfg = config.Default()
		} else {
			cfg, err = templates.ResolveExtendsWithBaseDir(cfg, filepath.Dir(configPath))
			if err != nil {
				return fmt.Errorf("failed to resolve extends: %w", err)
			}
		}
	}

	manager := sandbox.NewManager(cfg, debug, monitor)
	manager.SetExposedPorts(ports)
	defer manager.Cleanup()

	if err := manager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize sandbox: %w", err)
	}

	var logMonitor *sandbox.LogMonitor
	if monitor {
		logMonitor = sandbox.NewLogMonitor(sandbox.GetSessionSuffix())
		if logMonitor != nil {
			if err := logMonitor.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "[fence] Warning: failed to start log monitor: %v\n", err)
			} else {
				defer logMonitor.Stop()
			}
		}
	}

	sandboxedCommand, err := manager.WrapCommand(command)
	if err != nil {
		return fmt.Errorf("failed to wrap command: %w", err)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[fence] Sandboxed command: %s\n", sandboxedCommand)
	}

	hardenedEnv := sandbox.GetHardenedEnv()
	if debug {
		if stripped := sandbox.GetStrippedEnvVars(os.Environ()); len(stripped) > 0 {
			fmt.Fprintf(os.Stderr, "[fence] Stripped dangerous env vars: %v\n", stripped)
		}
	}

	execCmd := exec.Command("sh", "-c", sandboxedCommand) //nolint:gosec // sandboxedCommand is constructed from user input - intentional
	execCmd.Env = hardenedEnv
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the command (non-blocking) so we can get the PID
	if err := execCmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	// Start Linux monitors (eBPF tracing for filesystem violations)
	var linuxMonitors *sandbox.LinuxMonitors
	if monitor && execCmd.Process != nil {
		linuxMonitors, _ = sandbox.StartLinuxMonitor(execCmd.Process.Pid, sandbox.LinuxSandboxOptions{
			Monitor: true,
			Debug:   debug,
			UseEBPF: true,
		})
		if linuxMonitors != nil {
			defer linuxMonitors.Stop()
		}
	}

	// Note: Landlock is NOT applied here because:
	// 1. The sandboxed command is already running (Landlock only affects future children)
	// 2. Proper Landlock integration requires applying restrictions inside the sandbox
	// For now, filesystem isolation relies on bwrap mount namespaces.
	// Landlock code exists for future integration (e.g., via a wrapper binary).

	go func() {
		sigCount := 0
		for sig := range sigChan {
			sigCount++
			if execCmd.Process == nil {
				continue
			}
			// First signal: graceful termination; second signal: force kill
			if sigCount >= 2 {
				_ = execCmd.Process.Kill()
			} else {
				_ = execCmd.Process.Signal(sig)
			}
		}
	}()

	// Wait for command to finish
	if err := execCmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Set exit code but don't os.Exit() here - let deferred cleanup run
			exitCode = exitErr.ExitCode()
			return nil
		}
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

// newImportCmd creates the import subcommand.
func newImportCmd() *cobra.Command {
	var (
		claudeMode bool
		inputFile  string
		outputFile string
		saveFlag   bool
		forceFlag  bool
		extendTmpl string
		noExtend   bool
	)

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import settings from other tools",
		Long: `Import permission settings from other tools and convert them to fence config.

Currently supported sources:
  --claude    Import from Claude Code settings

By default, imports extend the "code" template which provides sensible defaults
for network access (npm, GitHub, LLM providers) and filesystem protections.
Use --no-extend for a minimal config, or --extend to choose a different template.

Examples:
  # Preview import (prints JSON to stdout)
  fence import --claude

  # Save to the default config path
  #   Linux: ~/.config/fence/fence.json
  #   macOS: ~/Library/Application Support/fence/fence.json
  fence import --claude --save

  # Save to a specific output file
  fence import --claude -o ./fence.json

  # Import from a specific Claude Code settings file
  fence import --claude -f ~/.claude/settings.json --save

  # Import without extending any template (minimal config)
  fence import --claude --no-extend --save

  # Import and extend a different template
  fence import --claude --extend local-dev-server --save`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !claudeMode {
				return fmt.Errorf("no import source specified. Use --claude to import from Claude Code")
			}

			opts := importer.DefaultImportOptions()
			if noExtend {
				opts.Extends = ""
			} else if extendTmpl != "" {
				opts.Extends = extendTmpl
			}

			result, err := importer.ImportFromClaude(inputFile, opts)
			if err != nil {
				return fmt.Errorf("failed to import Claude settings: %w", err)
			}

			for _, warning := range result.Warnings {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", warning)
			}
			if len(result.Warnings) > 0 {
				fmt.Fprintln(os.Stderr)
			}

			// Determine output destination
			var destPath string
			if saveFlag {
				destPath = config.DefaultConfigPath()
			} else if outputFile != "" {
				destPath = outputFile
			}

			if destPath != "" {
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

				if err := importer.WriteConfig(result.Config, destPath); err != nil {
					return err
				}
				fmt.Printf("Imported %d rules from %s\n", result.RulesImported, result.SourcePath)
				fmt.Printf("Written to %q\n", destPath)
			} else {
				// Print clean JSON to stdout, helpful info to stderr (don't interfere with piping)
				data, err := importer.MarshalConfigJSON(result.Config)
				if err != nil {
					return fmt.Errorf("failed to marshal config: %w", err)
				}
				fmt.Println(string(data))
				if result.Config.Extends != "" {
					fmt.Fprintf(os.Stderr, "\n# Extends %q - inherited rules not shown\n", result.Config.Extends)
				}
				fmt.Fprintf(os.Stderr, "# Imported %d rules from %s\n", result.RulesImported, result.SourcePath)
				fmt.Fprintf(os.Stderr, "# Use --save to write to the default config path\n")
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&claudeMode, "claude", false, "Import from Claude Code settings")
	cmd.Flags().StringVarP(&inputFile, "file", "f", "", "Path to settings file (default: ~/.claude/settings.json for --claude)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	cmd.Flags().BoolVar(&saveFlag, "save", false, "Save to the default config path")
	cmd.Flags().BoolVarP(&forceFlag, "force", "y", false, "Overwrite existing file without prompting")
	cmd.Flags().StringVar(&extendTmpl, "extend", "", "Template to extend (default: code)")
	cmd.Flags().BoolVar(&noExtend, "no-extend", false, "Don't extend any template (minimal config)")
	cmd.MarkFlagsMutuallyExclusive("extend", "no-extend")
	cmd.MarkFlagsMutuallyExclusive("save", "output")

	return cmd
}

// newConfigCmd creates config-related subcommands.
func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage fence configuration",
	}
	cmd.AddCommand(newConfigInitCmd())
	return cmd
}

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

// newCompletionCmd creates the completion subcommand for shell completions.
func newCompletionCmd(rootCmd *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for fence.

Examples:
  # Bash (load in current session)
  source <(fence completion bash)

  # Zsh (load in current session)
  source <(fence completion zsh)

  # Fish (load in current session)
  fence completion fish | source

  # PowerShell (load in current session)
  fence completion powershell | Out-String | Invoke-Expression

To persist completions, redirect output to the appropriate completions
directory for your shell (e.g., /etc/bash_completion.d/ for bash,
${fpath[1]}/_fence for zsh, ~/.config/fish/completions/fence.fish for fish).
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return rootCmd.GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return rootCmd.GenZshCompletion(os.Stdout)
			case "fish":
				return rootCmd.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}
	return cmd
}

// printTemplates prints all available templates to stdout.
func printTemplates() {
	fmt.Println("Available templates:")
	fmt.Println()
	for _, t := range templates.List() {
		fmt.Printf("  %-20s %s\n", t.Name, t.Description)
	}
	fmt.Println()
	fmt.Println("Usage: fence -t <template> <command>")
	fmt.Println("Example: fence -t code -- code")
}

// runLandlockWrapper runs in "wrapper mode" inside the sandbox.
// It applies Landlock restrictions and then execs the user command.
// Usage: fence --landlock-apply [--debug] -- <command...>
// Config is passed via FENCE_CONFIG_JSON environment variable.
func runLandlockWrapper() {
	// Parse arguments: --landlock-apply [--debug] -- <command...>
	args := os.Args[2:] // Skip "fence" and "--landlock-apply"

	var debugMode bool
	var cmdStart int

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--debug":
			debugMode = true
		case "--":
			cmdStart = i + 1
			goto parseCommand
		default:
			// Assume rest is the command
			cmdStart = i
			goto parseCommand
		}
	}

parseCommand:
	if cmdStart >= len(args) {
		fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Error: no command specified\n")
		os.Exit(1)
	}

	command := args[cmdStart:]

	if debugMode {
		fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Applying Landlock restrictions\n")
	}

	// Only apply Landlock on Linux
	if platform.Detect() == platform.Linux {
		// Load config from environment variable (passed by parent fence process)
		var cfg *config.Config
		if configJSON := os.Getenv("FENCE_CONFIG_JSON"); configJSON != "" {
			cfg = &config.Config{}
			if err := json.Unmarshal([]byte(configJSON), cfg); err != nil {
				if debugMode {
					fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Warning: failed to parse config: %v\n", err)
				}
				cfg = nil
			}
		}
		if cfg == nil {
			cfg = config.Default()
		}

		// Get current working directory for relative path resolution
		cwd, _ := os.Getwd()

		// Apply Landlock restrictions
		err := sandbox.ApplyLandlockFromConfig(cfg, cwd, nil, debugMode)
		if err != nil {
			if debugMode {
				fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Warning: Landlock not applied: %v\n", err)
			}
			// Continue without Landlock - bwrap still provides isolation
		} else if debugMode {
			fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Landlock restrictions applied\n")
		}
	}

	// Find the executable
	execPath, err := exec.LookPath(command[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Error: command not found: %s\n", command[0])
		os.Exit(127)
	}

	if debugMode {
		fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Exec: %s %v\n", execPath, command[1:])
	}

	// Sanitize environment (strips LD_PRELOAD, etc.)
	hardenedEnv := sandbox.FilterDangerousEnv(os.Environ())

	// Exec the command (replaces this process)
	err = syscall.Exec(execPath, command, hardenedEnv) //nolint:gosec
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fence:landlock-wrapper] Exec failed: %v\n", err)
		os.Exit(1)
	}
}
