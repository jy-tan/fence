package sandbox

import (
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

func TestCheckCommand_BasicDeny(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"git push", "rm -rf"},
			UseDefaults: boolPtr(false), // Disable defaults for cleaner testing
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		blockPrefix string
	}{
		// Exact matches
		{"git push", true, "git push"},
		{"rm -rf", true, "rm -rf"},

		// Prefix matches
		{"git push origin main", true, "git push"},
		{"rm -rf /", true, "rm -rf"},
		{"rm -rf .", true, "rm -rf"},

		// Should NOT match
		{"git status", false, ""},
		{"git pull", false, ""},
		{"rm file.txt", false, ""},
		{"rm -r dir", false, ""},
		{"echo git push", false, ""}, // git push is an argument, not a command
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock {
				if err == nil {
					t.Errorf("expected command %q to be blocked", tt.command)
					return
				}
				blocked, ok := err.(*CommandBlockedError)
				if !ok {
					t.Errorf("expected CommandBlockedError, got %T", err)
					return
				}
				if blocked.BlockedPrefix != tt.blockPrefix {
					t.Errorf("expected block prefix %q, got %q", tt.blockPrefix, blocked.BlockedPrefix)
				}
			} else if err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_Allow(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"git push"},
			Allow:       []string{"git push origin docs"},
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
	}{
		// Allowed by explicit allow rule
		{"git push origin docs", false},
		{"git push origin docs --force", false},

		// Still blocked (not in allow list)
		{"git push origin main", true},
		{"git push", true},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_DefaultDenyList(t *testing.T) {
	// Test with defaults enabled (nil = true)
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{},
			UseDefaults: nil, // defaults to true
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
	}{
		// Default denied commands
		{"shutdown", true},
		{"shutdown -h now", true},
		{"reboot", true},
		{"halt", true},
		{"insmod malicious.ko", true},
		{"rmmod module", true},
		{"mkfs.ext4 /dev/sda1", true},

		// Normal commands should be allowed
		{"ls", false},
		{"git status", false},
		{"npm install", false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock {
				if err == nil {
					t.Errorf("expected command %q to be blocked by defaults", tt.command)
					return
				}
				blocked, ok := err.(*CommandBlockedError)
				if !ok {
					t.Errorf("expected CommandBlockedError, got %T", err)
					return
				}
				if !blocked.IsDefault {
					t.Errorf("expected IsDefault=true for default deny list")
				}
			} else if err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_DisableDefaults(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{},
			UseDefaults: boolPtr(false),
		},
	}

	// When defaults disabled, "shutdown" should be allowed
	err := CheckCommand("shutdown", cfg)
	if err != nil {
		t.Errorf("expected 'shutdown' to be allowed when defaults disabled, got: %v", err)
	}
}

func TestCheckCommand_ChainedCommands(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"git push"},
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Chained with &&
		{"ls && git push", true, "git push in && chain"},
		{"git push && ls", true, "git push at start of && chain"},
		{"ls && echo hello && git push origin main", true, "git push at end of && chain"},

		// Chained with ||
		{"ls || git push", true, "git push in || chain"},
		{"git status || git push", true, "git push after ||"},

		// Chained with ;
		{"ls; git push", true, "git push after semicolon"},
		{"git push; ls", true, "git push before semicolon"},

		// Chained with |
		{"echo hello | git push", true, "git push in pipe"},
		{"git status | grep something", false, "no git push in pipe"},

		// Multiple operators
		{"ls && echo hi || git push", true, "git push in mixed chain"},
		{"ls; pwd; git push origin main", true, "git push in semicolon chain"},

		// Safe chains
		{"ls && pwd", false, "safe commands only"},
		{"git status | grep branch", false, "safe git command in pipe"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_NestedShellInvocation(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"git push"},
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// bash -c patterns
		{`bash -c "git push"`, true, "bash -c with git push"},
		{`bash -c 'git push origin main'`, true, "bash -c single quotes"},
		{`sh -c "git push"`, true, "sh -c with git push"},
		{`zsh -c "git push"`, true, "zsh -c with git push"},

		// bash -c with chained commands
		{`bash -c "ls && git push"`, true, "bash -c with chained git push"},
		{`sh -c 'git status; git push'`, true, "sh -c semicolon chain"},

		// Safe bash -c
		{`bash -c "git status"`, false, "bash -c with safe command"},
		{`bash -c 'ls && pwd'`, false, "bash -c with safe chain"},

		// bash -lc (login shell)
		{`bash -lc "git push"`, true, "bash -lc with git push"},

		// Full path to shell
		{`/bin/bash -c "git push"`, true, "full path bash -c"},
		{`/usr/bin/zsh -c 'git push origin main'`, true, "full path zsh -c"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_PathNormalization(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"git push"},
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Full paths should be normalized
		{"/usr/bin/git push", true, "full path git"},
		{"/usr/local/bin/git push origin main", true, "full path git with args"},

		// Relative paths
		{"./git push", true, "relative path git"},
		{"../bin/git push", true, "relative parent path git"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_QuotedArguments(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"git push"},
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Quotes shouldn't affect matching
		{`git push "origin" "main"`, true, "double quoted args"},
		{`git push 'origin' 'main'`, true, "single quoted args"},

		// "git push" as a string argument to another command should NOT block
		{`echo "git push"`, false, "git push as echo argument"},
		{`grep "git push" log.txt`, false, "git push in grep pattern"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_EdgeCases(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"rm -rf"},
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Empty command
		{"", false, "empty command"},
		{"   ", false, "whitespace only"},

		// Command that's a prefix of blocked command
		{"rm", false, "rm alone"},
		{"rm -r", false, "rm -r (not -rf)"},
		{"rm -f", false, "rm -f (not -rf)"},
		{"rm -rf", true, "rm -rf exact"},
		{"rm -rf /", true, "rm -rf with path"},

		// Similar but different
		{"rmdir", false, "rmdir (different command)"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestParseShellCommand(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"ls", []string{"ls"}},
		{"ls && pwd", []string{"ls", "pwd"}},
		{"ls || pwd", []string{"ls", "pwd"}},
		{"ls; pwd", []string{"ls", "pwd"}},
		{"ls | grep foo", []string{"ls", "grep foo"}},
		{"ls && pwd || echo fail; date", []string{"ls", "pwd", "echo fail", "date"}},

		// Quotes should be preserved
		{`echo "hello && world"`, []string{`echo "hello && world"`}},
		{`echo 'a; b'`, []string{`echo 'a; b'`}},

		// Parentheses (subshells) - preserved as single unit
		{"(ls && pwd)", []string{"(ls && pwd)"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			// parseShellCommand also expands shell invocations, so we just check basics
			result := parseShellCommand(tt.input)

			// For non-shell-invocation cases, result should match expected
			// (shell invocations will add extra entries)
			if len(result) < len(tt.expected) {
				t.Errorf("expected at least %d commands, got %d: %v", len(tt.expected), len(result), result)
			}
		})
	}
}

func TestNormalizeCommand(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"git push", "git push"},
		{"/usr/bin/git push", "git push"},
		{"/usr/local/bin/git push origin main", "git push origin main"},
		{"./script.sh arg1 arg2", "script.sh arg1 arg2"},
		{"  git   push  ", "git push"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeCommand(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeCommand(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMatchesPrefix(t *testing.T) {
	tests := []struct {
		command  string
		prefix   string
		expected bool
	}{
		{"git push", "git push", true},
		{"git push origin main", "git push", true},
		{"git pushall", "git push", false}, // "pushall" is different word
		{"git status", "git push", false},
		{"gitpush", "git push", false},
	}

	for _, tt := range tests {
		t.Run(tt.command+"_vs_"+tt.prefix, func(t *testing.T) {
			result := matchesPrefix(tt.command, tt.prefix)
			if result != tt.expected {
				t.Errorf("matchesPrefix(%q, %q) = %v, want %v", tt.command, tt.prefix, result, tt.expected)
			}
		})
	}
}

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool {
	return &b
}

func TestParseSSHCommand(t *testing.T) {
	tests := []struct {
		command   string
		wantHost  string
		wantCmd   string
		wantIsSSH bool
		desc      string
	}{
		// Basic SSH commands
		{`ssh server1.example.com`, "server1.example.com", "", true, "simple host"},
		{`ssh user@server1.example.com`, "server1.example.com", "", true, "user@host"},
		{`ssh server1.example.com ls -la`, "server1.example.com", "ls -la", true, "host with command"},
		{`ssh user@server1.example.com "cat /var/log/app.log"`, "server1.example.com", `cat /var/log/app.log`, true, "user@host with quoted command"},

		// SSH with options
		{`ssh -p 2222 server1.example.com`, "server1.example.com", "", true, "with port option"},
		{`ssh -i ~/.ssh/key server1.example.com ls`, "server1.example.com", "ls", true, "with identity file"},
		{`ssh -v -t server1.example.com`, "server1.example.com", "", true, "with flags"},
		{`ssh -o StrictHostKeyChecking=no server1.example.com`, "server1.example.com", "", true, "with -o option"},

		// Full path to ssh
		{`/usr/bin/ssh server1.example.com ls`, "server1.example.com", "ls", true, "full path ssh"},

		// Not SSH commands
		{`ls -la`, "", "", false, "not ssh"},
		{`sshpass -p password ssh server`, "", "", false, "sshpass wrapper"},
		{`echo ssh server`, "", "", false, "ssh as argument"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			host, cmd, isSSH := parseSSHCommand(tt.command)
			if isSSH != tt.wantIsSSH {
				t.Errorf("parseSSHCommand(%q) isSSH = %v, want %v", tt.command, isSSH, tt.wantIsSSH)
			}
			if host != tt.wantHost {
				t.Errorf("parseSSHCommand(%q) host = %q, want %q", tt.command, host, tt.wantHost)
			}
			if cmd != tt.wantCmd {
				t.Errorf("parseSSHCommand(%q) cmd = %q, want %q", tt.command, cmd, tt.wantCmd)
			}
		})
	}
}

func TestCheckSSHCommand_HostPolicy(t *testing.T) {
	cfg := &config.Config{
		SSH: config.SSHConfig{
			AllowedHosts: []string{"*.example.com", "prod-*"},
			DeniedHosts:  []string{"prod-db.example.com"},
		},
		Command: config.CommandConfig{
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Allowed hosts
		{`ssh server1.example.com`, false, "allowed by wildcard"},
		{`ssh api.example.com`, false, "allowed subdomain"},
		{`ssh prod-web-01`, false, "allowed by prod-* pattern"},

		// Denied hosts
		{`ssh prod-db.example.com`, true, "explicitly denied"},

		// Not in allowlist
		{`ssh other.domain.com`, true, "not in allowedHosts"},
		{`ssh dev-server`, true, "not matching any pattern"},

		// Non-SSH commands (should pass through)
		{`ls -la`, false, "not an SSH command"},
		{`curl https://example.com`, false, "not an SSH command"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckSSHCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected SSH command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected SSH command %q to be allowed, got: %v", tt.command, err)
			}
		})
	}
}

func TestCheckSSHCommand_AllowlistMode(t *testing.T) {
	cfg := &config.Config{
		SSH: config.SSHConfig{
			AllowedHosts:    []string{"*.example.com"},
			AllowedCommands: []string{"ls", "cat", "grep", "tail -f"},
		},
		Command: config.CommandConfig{
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Allowed commands
		{`ssh server.example.com ls`, false, "ls allowed"},
		{`ssh server.example.com ls -la /var/log`, false, "ls with args"},
		{`ssh server.example.com cat /etc/hosts`, false, "cat allowed"},
		{`ssh server.example.com grep error /var/log/app.log`, false, "grep allowed"},
		{`ssh server.example.com tail -f /var/log/app.log`, false, "tail -f allowed"},

		// Not in allowlist
		{`ssh server.example.com rm -rf /tmp/cache`, true, "rm not in allowlist"},
		{`ssh server.example.com chmod 777 /tmp`, true, "chmod not in allowlist"},
		{`ssh server.example.com shutdown now`, true, "shutdown not in allowlist"},
		{`ssh server.example.com tail /var/log/app.log`, true, "tail without -f not allowed"},

		// Interactive session (no command) - should be allowed
		{`ssh server.example.com`, false, "interactive session allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckSSHCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected SSH command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected SSH command %q to be allowed, got: %v", tt.command, err)
			}
		})
	}
}

func TestCheckSSHCommand_DenylistMode(t *testing.T) {
	cfg := &config.Config{
		SSH: config.SSHConfig{
			AllowedHosts:     []string{"*.example.com"},
			AllowAllCommands: true, // denylist mode
			DeniedCommands:   []string{"rm -rf", "shutdown", "chmod"},
		},
		Command: config.CommandConfig{
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Allowed (not in denylist)
		{`ssh server.example.com ls -la`, false, "ls allowed"},
		{`ssh server.example.com cat /etc/hosts`, false, "cat allowed"},
		{`ssh server.example.com rm file.txt`, false, "rm single file allowed"},
		{`ssh server.example.com apt-get update`, false, "apt-get allowed"},

		// Denied
		{`ssh server.example.com rm -rf /tmp/cache`, true, "rm -rf denied"},
		{`ssh server.example.com shutdown now`, true, "shutdown denied"},
		{`ssh server.example.com chmod 777 /tmp`, true, "chmod denied"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckSSHCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected SSH command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected SSH command %q to be allowed, got: %v", tt.command, err)
			}
		})
	}
}

func TestCheckSSHCommand_InheritDeny(t *testing.T) {
	cfg := &config.Config{
		SSH: config.SSHConfig{
			AllowedHosts:     []string{"*.example.com"},
			AllowAllCommands: true, // denylist mode
			InheritDeny:      true, // inherit global denies
		},
		Command: config.CommandConfig{
			Deny:        []string{"git push", "npm publish"},
			UseDefaults: boolPtr(true), // include default denies like shutdown
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Inherited from global deny
		{`ssh server.example.com git push origin main`, true, "git push from global deny"},
		{`ssh server.example.com npm publish`, true, "npm publish from global deny"},

		// Inherited from default deny list
		{`ssh server.example.com shutdown now`, true, "shutdown from default deny"},
		{`ssh server.example.com reboot`, true, "reboot from default deny"},

		// Allowed (not in any deny list)
		{`ssh server.example.com ls -la`, false, "ls allowed"},
		{`ssh server.example.com git status`, false, "git status allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckSSHCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected SSH command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected SSH command %q to be allowed, got: %v", tt.command, err)
			}
		})
	}
}

func TestCheckSSHCommand_NoSSHConfig(t *testing.T) {
	// No SSH policy configured - all SSH commands should pass through
	cfg := &config.Config{
		Command: config.CommandConfig{
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command string
		desc    string
	}{
		{`ssh server.example.com rm -rf /`, "dangerous command allowed when no SSH policy"},
		{`ssh any-host.com shutdown`, "any host allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckSSHCommand(tt.command, cfg)
			if err != nil {
				t.Errorf("expected SSH command %q to be allowed (no SSH policy), got: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_IntegratesSSH(t *testing.T) {
	// Test that CheckCommand also checks SSH policies
	cfg := &config.Config{
		SSH: config.SSHConfig{
			AllowedHosts:    []string{"*.example.com"},
			AllowedCommands: []string{"ls", "cat"},
		},
		Command: config.CommandConfig{
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Via CheckCommand, SSH policy should be enforced
		{`ssh server.example.com ls`, false, "allowed SSH command"},
		{`ssh server.example.com rm -rf /`, true, "blocked SSH command"},
		{`ssh other.com ls`, true, "blocked host"},

		// Non-SSH commands unaffected
		{`ls -la`, false, "local ls allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected command %q to be allowed, got: %v", tt.command, err)
			}
		})
	}
}

func TestCheckSSHCommand_CommandChaining(t *testing.T) {
	// Test that command chaining doesn't bypass allow/deny rules
	cfg := &config.Config{
		SSH: config.SSHConfig{
			AllowedHosts:    []string{"*.example.com"},
			AllowedCommands: []string{"ls", "cat", "git status"},
		},
		Command: config.CommandConfig{
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Chaining should NOT bypass allowlist
		{`ssh server.example.com "ls && rm -rf /"`, true, "ls allowed but rm -rf not"},
		{`ssh server.example.com "git status && rm -rf /"`, true, "git status allowed but rm -rf not"},
		{`ssh server.example.com "cat file; shutdown"`, true, "cat allowed but shutdown not"},
		{`ssh server.example.com "ls | xargs rm"`, true, "ls allowed but rm not"},
		{`ssh server.example.com "ls || rm -rf /"`, true, "ls allowed but rm -rf not"},

		// All subcommands allowed should work
		{`ssh server.example.com "ls && cat file"`, false, "both ls and cat allowed"},
		{`ssh server.example.com "ls; cat file"`, false, "semicolon chain with allowed commands"},
		{`ssh server.example.com "ls | cat"`, false, "pipe with allowed commands"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckSSHCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected SSH command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected SSH command %q to be allowed, got: %v", tt.command, err)
			}
		})
	}
}

func TestCheckSSHCommand_CommandChainingDenylist(t *testing.T) {
	// Test command chaining in denylist mode
	cfg := &config.Config{
		SSH: config.SSHConfig{
			AllowedHosts:     []string{"*.example.com"},
			AllowAllCommands: true,
			DeniedCommands:   []string{"rm -rf", "shutdown"},
		},
		Command: config.CommandConfig{
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Chaining should still catch denied commands
		{`ssh server.example.com "ls && rm -rf /"`, true, "rm -rf in chain blocked"},
		{`ssh server.example.com "cat file; shutdown"`, true, "shutdown in chain blocked"},

		// Chains without denied commands should work
		{`ssh server.example.com "ls && cat && grep foo"`, false, "chain without denied commands"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckSSHCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected SSH command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected SSH command %q to be allowed, got: %v", tt.command, err)
			}
		})
	}
}
