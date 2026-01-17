package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
)

// CommandBlockedError is returned when a command is blocked by policy.
type CommandBlockedError struct {
	Command       string
	BlockedPrefix string
	IsDefault     bool
}

func (e *CommandBlockedError) Error() string {
	if e.IsDefault {
		return fmt.Sprintf("command blocked by default sandbox command policy: %q matches %q", e.Command, e.BlockedPrefix)
	}
	return fmt.Sprintf("command blocked by sandbox command policy: %q matches %q", e.Command, e.BlockedPrefix)
}

// CheckCommand checks if a command is allowed by the configuration.
// It parses shell command strings and checks each sub-command in pipelines/chains.
// Returns nil if allowed, or CommandBlockedError if blocked.
func CheckCommand(command string, cfg *config.Config) error {
	if cfg == nil {
		cfg = config.Default()
	}

	subCommands := parseShellCommand(command)

	for _, subCmd := range subCommands {
		if err := checkSingleCommand(subCmd, cfg); err != nil {
			return err
		}
	}

	return nil
}

// checkSingleCommand checks a single command (not a chain) against the policy.
func checkSingleCommand(command string, cfg *config.Config) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}

	// Normalize the command for matching
	normalized := normalizeCommand(command)

	// Check if explicitly allowed (takes precedence over deny)
	for _, allow := range cfg.Command.Allow {
		if matchesPrefix(normalized, allow) {
			return nil
		}
	}

	// Check user-defined deny list
	for _, deny := range cfg.Command.Deny {
		if matchesPrefix(normalized, deny) {
			return &CommandBlockedError{
				Command:       command,
				BlockedPrefix: deny,
				IsDefault:     false,
			}
		}
	}

	// Check default deny list (if enabled)
	if cfg.Command.UseDefaultDeniedCommands() {
		for _, deny := range config.DefaultDeniedCommands {
			if matchesPrefix(normalized, deny) {
				return &CommandBlockedError{
					Command:       command,
					BlockedPrefix: deny,
					IsDefault:     true,
				}
			}
		}
	}

	// Check SSH-specific policies if this is an SSH command
	if err := CheckSSHCommand(command, cfg); err != nil {
		return err
	}

	return nil
}

// parseShellCommand splits a shell command string into individual commands.
// Handles: pipes (|), logical operators (&&, ||), semicolons (;), and subshells.
func parseShellCommand(command string) []string {
	var commands []string
	var current strings.Builder
	var inSingleQuote, inDoubleQuote bool
	var parenDepth int

	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		c := runes[i]

		// Handle quotes
		if c == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			current.WriteRune(c)
			continue
		}
		if c == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			current.WriteRune(c)
			continue
		}

		// Skip splitting inside quotes
		if inSingleQuote || inDoubleQuote {
			current.WriteRune(c)
			continue
		}

		// Handle parentheses (subshells)
		if c == '(' {
			parenDepth++
			current.WriteRune(c)
			continue
		}
		if c == ')' {
			parenDepth--
			current.WriteRune(c)
			continue
		}

		// Skip splitting inside subshells
		if parenDepth > 0 {
			current.WriteRune(c)
			continue
		}

		// Handle shell operators
		switch c {
		case '|':
			// Check for || (or just |)
			if i+1 < len(runes) && runes[i+1] == '|' {
				// ||
				if s := strings.TrimSpace(current.String()); s != "" {
					commands = append(commands, s)
				}
				current.Reset()
				i++ // Skip second |
			} else {
				// Just a pipe
				if s := strings.TrimSpace(current.String()); s != "" {
					commands = append(commands, s)
				}
				current.Reset()
			}
		case '&':
			// Check for &&
			if i+1 < len(runes) && runes[i+1] == '&' {
				if s := strings.TrimSpace(current.String()); s != "" {
					commands = append(commands, s)
				}
				current.Reset()
				i++ // Skip second &
			} else {
				// Background operator - keep in current command
				current.WriteRune(c)
			}
		case ';':
			if s := strings.TrimSpace(current.String()); s != "" {
				commands = append(commands, s)
			}
			current.Reset()
		default:
			current.WriteRune(c)
		}
	}

	// Add remaining command
	if s := strings.TrimSpace(current.String()); s != "" {
		commands = append(commands, s)
	}

	// Handle nested shell invocations like "bash -c 'git push'"
	var expanded []string
	for _, cmd := range commands {
		expanded = append(expanded, expandShellInvocation(cmd)...)
	}

	return expanded
}

// expandShellInvocation detects patterns like "bash -c 'cmd'" or "sh -c 'cmd'"
// and extracts the inner command for checking.
func expandShellInvocation(command string) []string {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}

	tokens := tokenizeCommand(command)
	if len(tokens) < 3 {
		return []string{command}
	}

	// Check for shell -c pattern
	shell := filepath.Base(tokens[0])
	isShell := shell == "sh" || shell == "bash" || shell == "zsh" ||
		shell == "ksh" || shell == "dash" || shell == "fish"

	if !isShell {
		return []string{command}
	}

	// Look for -c flag (could be combined with other flags like -lc, -ic, etc.)
	for i := 1; i < len(tokens)-1; i++ {
		flag := tokens[i]
		// Check for -c, -lc, -ic, -ilc, etc. (any flag containing 'c')
		if strings.HasPrefix(flag, "-") && strings.Contains(flag, "c") {
			// Next token is the command string
			innerCmd := tokens[i+1]
			// Recursively parse the inner command
			innerCommands := parseShellCommand(innerCmd)
			// Return both the outer command and inner commands
			// (we check both for safety)
			result := []string{command}
			result = append(result, innerCommands...)
			return result
		}
	}

	return []string{command}
}

// tokenizeCommand splits a command string into tokens, respecting quotes.
func tokenizeCommand(command string) []string {
	var tokens []string
	var current strings.Builder
	var inSingleQuote, inDoubleQuote bool

	for _, c := range command {
		switch {
		case c == '\'' && !inDoubleQuote:
			inSingleQuote = !inSingleQuote
		case c == '"' && !inSingleQuote:
			inDoubleQuote = !inDoubleQuote
		case (c == ' ' || c == '\t') && !inSingleQuote && !inDoubleQuote:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(c)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// normalizeCommand normalizes a command for matching.
// - Strips leading path from the command (e.g., /usr/bin/git -> git)
// - Collapses multiple spaces
func normalizeCommand(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}

	tokens := tokenizeCommand(command)
	if len(tokens) == 0 {
		return command
	}

	tokens[0] = filepath.Base(tokens[0])

	return strings.Join(tokens, " ")
}

// matchesPrefix checks if a command matches a blocked prefix.
// The prefix matches if the command starts with the prefix followed by
// end of string, a space, or other argument.
func matchesPrefix(command, prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return false
	}

	prefix = normalizeCommand(prefix)

	if command == prefix {
		return true
	}

	if strings.HasPrefix(command, prefix+" ") {
		return true
	}

	return false
}

// SSHBlockedError is returned when an SSH command is blocked by policy.
type SSHBlockedError struct {
	Host          string
	RemoteCommand string
	Reason        string
}

func (e *SSHBlockedError) Error() string {
	if e.RemoteCommand != "" {
		return fmt.Sprintf("SSH command blocked: %s (host: %s, command: %s)", e.Reason, e.Host, e.RemoteCommand)
	}
	return fmt.Sprintf("SSH blocked: %s (host: %s)", e.Reason, e.Host)
}

// CheckSSHCommand checks if an SSH command is allowed by the configuration.
// Returns nil if allowed, or SSHBlockedError if blocked.
func CheckSSHCommand(command string, cfg *config.Config) error {
	if cfg == nil {
		cfg = config.Default()
	}

	// Check if SSH config is active (has any hosts configured)
	// If no SSH policy is configured, allow by default
	if len(cfg.SSH.AllowedHosts) == 0 && len(cfg.SSH.DeniedHosts) == 0 {
		return nil
	}

	host, remoteCmd, isSSH := parseSSHCommand(command)
	if !isSSH {
		return nil
	}

	// Check host policy (denied then allowed)
	for _, pattern := range cfg.SSH.DeniedHosts {
		if config.MatchesHost(host, pattern) {
			return &SSHBlockedError{
				Host:          host,
				RemoteCommand: remoteCmd,
				Reason:        fmt.Sprintf("host matches denied pattern %q", pattern),
			}
		}
	}

	hostAllowed := false
	for _, pattern := range cfg.SSH.AllowedHosts {
		if config.MatchesHost(host, pattern) {
			hostAllowed = true
			break
		}
	}

	if len(cfg.SSH.AllowedHosts) > 0 && !hostAllowed {
		return &SSHBlockedError{
			Host:          host,
			RemoteCommand: remoteCmd,
			Reason:        "host not in allowedHosts",
		}
	}

	// If no remote command (interactive session), allow if host is allowed
	if remoteCmd == "" {
		return nil
	}

	return checkSSHRemoteCommand(remoteCmd, cfg)
}

// checkSSHRemoteCommand checks if a remote command is allowed by SSH policy.
// It parses the remote command into subcommands (handling &&, ||, ;, |) and validates each.
func checkSSHRemoteCommand(remoteCmd string, cfg *config.Config) error {
	// Parse into subcommands just like local commands to prevent bypass via chaining
	// e.g., "git status && rm -rf /" should check both "git status" and "rm -rf /"
	subCommands := parseShellCommand(remoteCmd)

	for _, subCmd := range subCommands {
		if err := checkSSHSingleCommand(subCmd, remoteCmd, cfg); err != nil {
			return err
		}
	}

	return nil
}

// checkSSHSingleCommand checks a single SSH remote command against policy.
func checkSSHSingleCommand(subCmd, fullRemoteCmd string, cfg *config.Config) error {
	normalized := normalizeCommand(subCmd)
	if normalized == "" {
		return nil
	}

	// Check inherited global deny list first (if enabled)
	// User-defined global then default deny list
	if cfg.SSH.InheritDeny {
		for _, deny := range cfg.Command.Deny {
			if matchesPrefix(normalized, deny) {
				return &SSHBlockedError{
					RemoteCommand: fullRemoteCmd,
					Reason:        fmt.Sprintf("command %q matches inherited global deny %q", subCmd, deny),
				}
			}
		}

		if cfg.Command.UseDefaultDeniedCommands() {
			for _, deny := range config.DefaultDeniedCommands {
				if matchesPrefix(normalized, deny) {
					return &SSHBlockedError{
						RemoteCommand: fullRemoteCmd,
						Reason:        fmt.Sprintf("command %q matches inherited default deny %q", subCmd, deny),
					}
				}
			}
		}
	}

	// Check SSH-specific denied commands
	for _, deny := range cfg.SSH.DeniedCommands {
		if matchesPrefix(normalized, deny) {
			return &SSHBlockedError{
				RemoteCommand: fullRemoteCmd,
				Reason:        fmt.Sprintf("command %q matches ssh.deniedCommands %q", subCmd, deny),
			}
		}
	}

	// If allowAllCommands is true, we're in denylist mode - allow anything not denied
	if cfg.SSH.AllowAllCommands {
		return nil
	}

	// Allowlist mode: check if command is in allowedCommands
	if len(cfg.SSH.AllowedCommands) > 0 {
		for _, allow := range cfg.SSH.AllowedCommands {
			if matchesPrefix(normalized, allow) {
				return nil
			}
		}
		// Not in allowlist
		return &SSHBlockedError{
			RemoteCommand: fullRemoteCmd,
			Reason:        fmt.Sprintf("command %q not in ssh.allowedCommands", subCmd),
		}
	}

	// No allowedCommands configured and not in denylist mode = deny all remote commands
	return &SSHBlockedError{
		RemoteCommand: fullRemoteCmd,
		Reason:        "no ssh.allowedCommands configured (allowlist mode requires explicit commands)",
	}
}

// parseSSHCommand parses an SSH command and extracts the host and remote command.
// Returns (host, remoteCommand, isSSH).
func parseSSHCommand(command string) (string, string, bool) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", "", false
	}

	tokens := tokenizeCommand(command)
	if len(tokens) == 0 {
		return "", "", false
	}

	cmdName := filepath.Base(tokens[0])
	if cmdName != "ssh" {
		return "", "", false
	}

	// Parse SSH arguments to find host and command
	// SSH syntax: ssh [options] [user@]hostname [command]
	var host string
	var remoteCmd string
	skipNext := false

	for i := 1; i < len(tokens); i++ {
		if skipNext {
			skipNext = false
			continue
		}

		arg := tokens[i]

		// Skip options that take arguments
		if arg == "-p" || arg == "-l" || arg == "-i" || arg == "-o" ||
			arg == "-F" || arg == "-J" || arg == "-W" || arg == "-b" ||
			arg == "-c" || arg == "-D" || arg == "-E" || arg == "-e" ||
			arg == "-I" || arg == "-L" || arg == "-m" || arg == "-O" ||
			arg == "-Q" || arg == "-R" || arg == "-S" || arg == "-w" {
			skipNext = true
			continue
		}

		// Skip single-char options (like -v, -t, -n, etc.)
		if strings.HasPrefix(arg, "-") {
			continue
		}

		// First non-option argument is the host
		if host == "" {
			host = arg
			// Extract the hostname from user@host format
			if atIdx := strings.LastIndex(host, "@"); atIdx >= 0 {
				host = host[atIdx+1:]
			}
			continue
		}

		// Remaining arguments form the remote command
		remoteCmd = strings.Join(tokens[i:], " ")
		break
	}

	if host == "" {
		return "", "", false
	}

	return host, remoteCmd, true
}
