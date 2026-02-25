package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
)

// sessionSuffix is a unique identifier for this process session.
var sessionSuffix = generateSessionSuffix()

func generateSessionSuffix() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		panic("failed to generate session suffix: " + err.Error())
	}
	return "_" + hex.EncodeToString(bytes)[:9] + "_SBX"
}

// MacOSSandboxParams contains parameters for macOS sandbox wrapping.
type MacOSSandboxParams struct {
	Command                 string
	NeedsNetworkRestriction bool
	HTTPProxyPort           int
	SOCKSProxyPort          int
	AllowUnixSockets        []string
	AllowAllUnixSockets     bool
	AllowLocalBinding       bool
	AllowLocalOutbound      bool
	DefaultDenyRead         bool
	ReadAllowPaths          []string
	ReadDenyPaths           []string
	WriteAllowPaths         []string
	WriteDenyPaths          []string
	DeniedExecPaths         []string
	AllowPty                bool
	AllowGitConfig          bool
}

// GlobToRegex converts a glob pattern to a regex for macOS sandbox profiles.
func GlobToRegex(glob string) string {
	result := "^"

	// Escape regex special characters (except glob chars)
	escaped := regexp.QuoteMeta(glob)

	// Restore glob patterns and convert them
	// Order matters: ** before *
	escaped = strings.ReplaceAll(escaped, `\*\*/`, "(.*/)?")
	escaped = strings.ReplaceAll(escaped, `\*\*`, ".*")
	escaped = strings.ReplaceAll(escaped, `\*`, "[^/]*")
	escaped = strings.ReplaceAll(escaped, `\?`, "[^/]")

	result += escaped + "$"
	return result
}

// escapePath escapes a path for sandbox profile using JSON encoding.
func escapePath(path string) string {
	// Use Go's string quoting which handles escaping
	return fmt.Sprintf("%q", path)
}

// getAncestorDirectories returns all ancestor directories of a path.
func getAncestorDirectories(pathStr string) []string {
	var ancestors []string
	current := filepath.Dir(pathStr)

	for current != "/" && current != "." {
		ancestors = append(ancestors, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return ancestors
}

// expandMacOSTmpPaths mirrors /tmp paths to /private/tmp equivalents and vice versa.
// On macOS, /tmp is a symlink to /private/tmp, and symlink resolution can fail if paths
// don't exist yet. Adding both variants ensures sandbox rules match kernel-resolved paths.
func expandMacOSTmpPaths(paths []string) []string {
	seen := make(map[string]bool)
	for _, p := range paths {
		seen[p] = true
	}

	var additions []string
	for _, p := range paths {
		var mirror string
		switch {
		case p == "/tmp":
			mirror = "/private/tmp"
		case p == "/private/tmp":
			mirror = "/tmp"
		case strings.HasPrefix(p, "/tmp/"):
			mirror = "/private" + p
		case strings.HasPrefix(p, "/private/tmp/"):
			mirror = strings.TrimPrefix(p, "/private")
		}

		if mirror != "" && !seen[mirror] {
			seen[mirror] = true
			additions = append(additions, mirror)
		}
	}

	return append(paths, additions...)
}

// getTmpdirParent gets the TMPDIR parent if it matches macOS pattern.
func getTmpdirParent() []string {
	tmpdir := os.Getenv("TMPDIR")
	if tmpdir == "" {
		return nil
	}

	// Match /var/folders/XX/YYY/T/
	pattern := regexp.MustCompile(`^/(private/)?var/folders/[^/]{2}/[^/]+/T/?$`)
	if !pattern.MatchString(tmpdir) {
		return nil
	}

	parent := strings.TrimSuffix(tmpdir, "/")
	parent = strings.TrimSuffix(parent, "/T")

	// Return both /var/ and /private/var/ versions
	if strings.HasPrefix(parent, "/private/var/") {
		return []string{parent, strings.Replace(parent, "/private", "", 1)}
	} else if strings.HasPrefix(parent, "/var/") {
		return []string{parent, "/private" + parent}
	}

	return []string{parent}
}

// generateReadRules generates filesystem read rules for the sandbox profile.
func generateReadRules(defaultDenyRead bool, allowPaths, denyPaths []string, logTag string) []string {
	var rules []string

	if defaultDenyRead {
		// When defaultDenyRead is enabled:
		// 1. Allow file-read-metadata globally (needed for directory traversal, stat, etc.)
		// 2. Allow file-read-data only for system paths + user-specified allowRead paths
		// This lets programs see what files exist but not read their contents.

		// Allow metadata operations globally (stat, readdir, etc.) and root dir (for path resolution)
		rules = append(rules, "(allow file-read-metadata)")
		rules = append(rules, `(allow file-read-data (literal "/"))`)

		// Allow reading data from essential system paths
		for _, systemPath := range GetDefaultReadablePaths() {
			rules = append(rules,
				"(allow file-read-data",
				fmt.Sprintf("  (subpath %s))", escapePath(systemPath)),
			)
		}

		// Allow reading data from user-specified paths
		for _, pathPattern := range allowPaths {
			normalized := NormalizePath(pathPattern)

			if ContainsGlobChars(normalized) {
				regex := GlobToRegex(normalized)
				rules = append(rules,
					"(allow file-read-data",
					fmt.Sprintf("  (regex %s))", escapePath(regex)),
				)
			} else {
				rules = append(rules,
					"(allow file-read-data",
					fmt.Sprintf("  (subpath %s))", escapePath(normalized)),
				)
			}
		}
	} else {
		// Allow all reads by default
		rules = append(rules, "(allow file-read*)")
	}

	// In both modes, deny specific paths (denyRead takes precedence).
	// Note: We use file-read* (not file-read-data) so denied paths are fully hidden.
	// In defaultDenyRead mode, this overrides the global file-read-metadata allow,
	// meaning denied paths can't even be listed or stat'd - more restrictive than
	// default mode where denied paths are still visible but unreadable.
	for _, pathPattern := range denyPaths {
		normalized := NormalizePath(pathPattern)

		if ContainsGlobChars(normalized) {
			regex := GlobToRegex(normalized)
			rules = append(rules,
				"(deny file-read*",
				fmt.Sprintf("  (regex %s)", escapePath(regex)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		} else {
			rules = append(rules,
				"(deny file-read*",
				fmt.Sprintf("  (subpath %s)", escapePath(normalized)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		}
	}

	// Block file movement to prevent bypass
	rules = append(rules, generateMoveBlockingRules(denyPaths, logTag)...)

	return rules
}

// generateWriteRules generates filesystem write rules for the sandbox profile.
func generateWriteRules(allowPaths, denyPaths []string, allowGitConfig bool, logTag string) []string {
	var rules []string

	// Allow TMPDIR parent on macOS
	for _, tmpdirParent := range getTmpdirParent() {
		normalized := NormalizePath(tmpdirParent)
		rules = append(rules,
			"(allow file-write*",
			fmt.Sprintf("  (subpath %s)", escapePath(normalized)),
			fmt.Sprintf("  (with message %q))", logTag),
		)
	}

	// Generate allow rules
	for _, pathPattern := range allowPaths {
		normalized := NormalizePath(pathPattern)

		if ContainsGlobChars(normalized) {
			regex := GlobToRegex(normalized)
			rules = append(rules,
				"(allow file-write*",
				fmt.Sprintf("  (regex %s)", escapePath(regex)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		} else {
			rules = append(rules,
				"(allow file-write*",
				fmt.Sprintf("  (subpath %s)", escapePath(normalized)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		}
	}

	// Combine user-specified and mandatory deny patterns
	cwd, _ := os.Getwd()
	mandatoryDeny := GetMandatoryDenyPatterns(cwd, allowGitConfig)
	allDenyPaths := make([]string, 0, len(denyPaths)+len(mandatoryDeny))
	allDenyPaths = append(allDenyPaths, denyPaths...)
	allDenyPaths = append(allDenyPaths, mandatoryDeny...)

	for _, pathPattern := range allDenyPaths {
		normalized := NormalizePath(pathPattern)

		if ContainsGlobChars(normalized) {
			regex := GlobToRegex(normalized)
			rules = append(rules,
				"(deny file-write*",
				fmt.Sprintf("  (regex %s)", escapePath(regex)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		} else {
			rules = append(rules,
				"(deny file-write*",
				fmt.Sprintf("  (subpath %s)", escapePath(normalized)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		}
	}

	// Block file movement
	rules = append(rules, generateMoveBlockingRules(allDenyPaths, logTag)...)

	return rules
}

// generateMoveBlockingRules generates rules to prevent file movement bypasses.
func generateMoveBlockingRules(pathPatterns []string, logTag string) []string {
	var rules []string

	for _, pathPattern := range pathPatterns {
		normalized := NormalizePath(pathPattern)

		if ContainsGlobChars(normalized) {
			regex := GlobToRegex(normalized)
			rules = append(rules,
				"(deny file-write-unlink",
				fmt.Sprintf("  (regex %s)", escapePath(regex)),
				fmt.Sprintf("  (with message %q))", logTag),
			)

			// For globs, extract static prefix and block ancestor moves
			staticPrefix := strings.Split(normalized, "*")[0]
			if staticPrefix != "" && staticPrefix != "/" {
				baseDir := staticPrefix
				if strings.HasSuffix(baseDir, "/") {
					baseDir = baseDir[:len(baseDir)-1]
				} else {
					baseDir = filepath.Dir(staticPrefix)
				}

				rules = append(rules,
					"(deny file-write-unlink",
					fmt.Sprintf("  (literal %s)", escapePath(baseDir)),
					fmt.Sprintf("  (with message %q))", logTag),
				)

				for _, ancestor := range getAncestorDirectories(baseDir) {
					rules = append(rules,
						"(deny file-write-unlink",
						fmt.Sprintf("  (literal %s)", escapePath(ancestor)),
						fmt.Sprintf("  (with message %q))", logTag),
					)
				}
			}
		} else {
			rules = append(rules,
				"(deny file-write-unlink",
				fmt.Sprintf("  (subpath %s)", escapePath(normalized)),
				fmt.Sprintf("  (with message %q))", logTag),
			)

			for _, ancestor := range getAncestorDirectories(normalized) {
				rules = append(rules,
					"(deny file-write-unlink",
					fmt.Sprintf("  (literal %s)", escapePath(ancestor)),
					fmt.Sprintf("  (with message %q))", logTag),
				)
			}
		}
	}

	return rules
}

// GenerateSandboxProfile generates a complete macOS sandbox profile.
func GenerateSandboxProfile(params MacOSSandboxParams) string {
	logTag := "CMD64_" + EncodeSandboxedCommand(params.Command) + "_END" + sessionSuffix

	var profile strings.Builder

	// Header
	profile.WriteString("(version 1)\n")
	profile.WriteString(fmt.Sprintf("(deny default (with message %q))\n\n", logTag))
	profile.WriteString(fmt.Sprintf("; LogTag: %s\n\n", logTag))

	// Essential permissions - based on Chrome sandbox policy
	profile.WriteString(`; Essential permissions - based on Chrome sandbox policy
; Process permissions
(allow process-exec)
(allow process-fork)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
(allow mach-priv-task-port (target same-sandbox))

; User preferences
(allow user-preference-read)

; Mach IPC - specific services only
(allow mach-lookup
  (global-name "com.apple.audio.systemsoundserver")
  (global-name "com.apple.distributed_notifications@Uv3")
  (global-name "com.apple.FontObjectsServer")
  (global-name "com.apple.fonts")
  (global-name "com.apple.logd")
  (global-name "com.apple.lsd.mapdb")
  (global-name "com.apple.PowerManagement.control")
  (global-name "com.apple.system.logger")
  (global-name "com.apple.system.notification_center")
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.bsd.dirhelper")
  (global-name "com.apple.securityd.xpc")
  (global-name "com.apple.coreservices.launchservicesd")
  (global-name "com.apple.FSEvents")
  (global-name "com.apple.fseventsd")
  (global-name "com.apple.SystemConfiguration.configd")
)

; POSIX IPC
(allow ipc-posix-shm)
(allow ipc-posix-sem)

; IOKit
(allow iokit-open
  (iokit-registry-entry-class "IOSurfaceRootUserClient")
  (iokit-registry-entry-class "RootDomainUserClient")
  (iokit-user-client-class "IOSurfaceSendRight")
)
(allow iokit-get-properties)

; System socket for network info
(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))

; sysctl reads
(allow sysctl-read
  (sysctl-name "hw.activecpu")
  (sysctl-name "hw.busfrequency_compat")
  (sysctl-name "hw.byteorder")
  (sysctl-name "hw.cacheconfig")
  (sysctl-name "hw.cachelinesize_compat")
  (sysctl-name "hw.cpufamily")
  (sysctl-name "hw.cpufrequency")
  (sysctl-name "hw.cpufrequency_compat")
  (sysctl-name "hw.cputype")
  (sysctl-name "hw.l1dcachesize_compat")
  (sysctl-name "hw.l1icachesize_compat")
  (sysctl-name "hw.l2cachesize_compat")
  (sysctl-name "hw.l3cachesize_compat")
  (sysctl-name "hw.logicalcpu")
  (sysctl-name "hw.logicalcpu_max")
  (sysctl-name "hw.machine")
  (sysctl-name "hw.memsize")
  (sysctl-name "hw.ncpu")
  (sysctl-name "hw.nperflevels")
  (sysctl-name "hw.packages")
  (sysctl-name "hw.pagesize_compat")
  (sysctl-name "hw.pagesize")
  (sysctl-name "hw.physicalcpu")
  (sysctl-name "hw.physicalcpu_max")
  (sysctl-name "hw.tbfrequency_compat")
  (sysctl-name "hw.vectorunit")
  (sysctl-name "kern.argmax")
  (sysctl-name "kern.bootargs")
  (sysctl-name "kern.hostname")
  (sysctl-name "kern.maxfiles")
  (sysctl-name "kern.maxfilesperproc")
  (sysctl-name "kern.maxproc")
  (sysctl-name "kern.ngroups")
  (sysctl-name "kern.osproductversion")
  (sysctl-name "kern.osrelease")
  (sysctl-name "kern.ostype")
  (sysctl-name "kern.osvariant_status")
  (sysctl-name "kern.osversion")
  (sysctl-name "kern.secure_kernel")
  (sysctl-name "kern.tcsm_available")
  (sysctl-name "kern.tcsm_enable")
  (sysctl-name "kern.usrstack64")
  (sysctl-name "kern.version")
  (sysctl-name "kern.willshutdown")
  (sysctl-name "machdep.cpu.brand_string")
  (sysctl-name "machdep.ptrauth_enabled")
  (sysctl-name "security.mac.lockdown_mode_state")
  (sysctl-name "sysctl.proc_cputype")
  (sysctl-name "vm.loadavg")
  (sysctl-name-prefix "hw.optional.arm")
  (sysctl-name-prefix "hw.optional.arm.")
  (sysctl-name-prefix "hw.optional.armv8_")
  (sysctl-name-prefix "hw.perflevel")
  (sysctl-name-prefix "kern.proc.all")
  (sysctl-name-prefix "kern.proc.pgrp.")
  (sysctl-name-prefix "kern.proc.pid.")
  (sysctl-name-prefix "machdep.cpu.")
  (sysctl-name-prefix "net.routetable.")
)

; V8 thread calculations
(allow sysctl-write
  (sysctl-name "kern.tcsm_enable")
)

; Distributed notifications
(allow distributed-notification-post)

; Security server
(allow mach-lookup (global-name "com.apple.SecurityServer"))

; Device I/O
(allow file-ioctl (literal "/dev/null"))
(allow file-ioctl (literal "/dev/zero"))
(allow file-ioctl (literal "/dev/random"))
(allow file-ioctl (literal "/dev/urandom"))
(allow file-ioctl (literal "/dev/dtracehelper"))
(allow file-ioctl (literal "/dev/tty"))

; Allow ioctl on the inherited terminal (PTY slave). This is needed for
; isatty(), tcgetpgrp(), and tcsetpgrp() to work on the inherited stdin/
; stdout/stderr when they are connected to a terminal. This does not allow
; allocating new PTYs (that requires allowPty).
(allow file-ioctl (regex #"^/dev/ttys"))

(allow file-ioctl file-read-data file-write-data
  (require-all
    (literal "/dev/null")
    (vnode-type CHARACTER-DEVICE)
  )
)

`)

	if len(params.DeniedExecPaths) > 0 {
		profile.WriteString("; Runtime executable deny (applies to child processes)\n")
		for _, execPath := range params.DeniedExecPaths {
			profile.WriteString("(deny process-exec\n")
			profile.WriteString(fmt.Sprintf("  (literal %s)\n", escapePath(execPath)))
			profile.WriteString(fmt.Sprintf("  (with message %q))\n", logTag))
		}
		profile.WriteString("\n")
	}

	// Network rules
	profile.WriteString("; Network\n")
	if !params.NeedsNetworkRestriction {
		profile.WriteString("(allow network*)\n")
	} else {
		if params.AllowLocalBinding {
			// Allow binding and inbound connections on localhost (for servers)
			profile.WriteString(`(allow network-bind (local ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))
`)
			// Process can make outbound connections to localhost
			if params.AllowLocalOutbound {
				profile.WriteString(`(allow network-outbound (local ip "localhost:*"))
`)
			}
		}

		if params.AllowAllUnixSockets {
			profile.WriteString("(allow network* (subpath \"/\"))\n")
		} else if len(params.AllowUnixSockets) > 0 {
			for _, socketPath := range params.AllowUnixSockets {
				normalized := NormalizePath(socketPath)
				profile.WriteString(fmt.Sprintf("(allow network* (subpath %s))\n", escapePath(normalized)))
			}
		}

		if params.HTTPProxyPort > 0 {
			profile.WriteString(fmt.Sprintf(`(allow network-bind (local ip "localhost:%d"))
(allow network-inbound (local ip "localhost:%d"))
(allow network-outbound (remote ip "localhost:%d"))
`, params.HTTPProxyPort, params.HTTPProxyPort, params.HTTPProxyPort))
		}

		if params.SOCKSProxyPort > 0 {
			profile.WriteString(fmt.Sprintf(`(allow network-bind (local ip "localhost:%d"))
(allow network-inbound (local ip "localhost:%d"))
(allow network-outbound (remote ip "localhost:%d"))
`, params.SOCKSProxyPort, params.SOCKSProxyPort, params.SOCKSProxyPort))
		}
	}
	profile.WriteString("\n")

	// Read rules
	profile.WriteString("; File read\n")
	for _, rule := range generateReadRules(params.DefaultDenyRead, params.ReadAllowPaths, params.ReadDenyPaths, logTag) {
		profile.WriteString(rule + "\n")
	}
	profile.WriteString("\n")

	// Write rules
	profile.WriteString("; File write\n")
	for _, rule := range generateWriteRules(params.WriteAllowPaths, params.WriteDenyPaths, params.AllowGitConfig, logTag) {
		profile.WriteString(rule + "\n")
	}

	// PTY support
	if params.AllowPty {
		profile.WriteString(`
; Pseudo-terminal (pty) support
(allow pseudo-tty)
(allow file-ioctl
  (literal "/dev/ptmx")
  (regex #"^/dev/ttys")
)
(allow file-read* file-write*
  (literal "/dev/ptmx")
  (regex #"^/dev/ttys")
)
`)
	}

	return profile.String()
}

// WrapCommandMacOS wraps a command with macOS sandbox restrictions.
func WrapCommandMacOS(cfg *config.Config, command string, httpPort, socksPort int, exposedPorts []int, debug bool, shellMode string, shellLogin bool) (string, error) {
	// In wildcard mode ("*"), still run the proxy for apps that respect
	// HTTP_PROXY, but allow direct connections for apps that don't.
	hasWildcardAllow := hasWildcardAllowedDomain(cfg)

	needsNetwork := len(cfg.Network.AllowedDomains) > 0 || len(cfg.Network.DeniedDomains) > 0

	// Build allow paths: default + configured
	allowPaths := append(GetDefaultWritePaths(), cfg.Filesystem.AllowWrite...)

	// Expand /tmp <-> /private/tmp for macOS symlink compatibility
	allowPaths = expandMacOSTmpPaths(allowPaths)

	// Enable local binding if ports are exposed or if explicitly configured
	allowLocalBinding := cfg.Network.AllowLocalBinding || len(exposedPorts) > 0

	allowLocalOutbound := allowLocalBinding
	if cfg.Network.AllowLocalOutbound != nil {
		allowLocalOutbound = *cfg.Network.AllowLocalOutbound
	}

	// If wildcard allow, don't restrict network at sandbox level (allow direct connections).
	// Otherwise, restrict to localhost/proxy only (strict mode).
	needsNetworkRestriction := !hasWildcardAllow && (needsNetwork || len(cfg.Network.AllowedDomains) == 0)

	if debug && hasWildcardAllow {
		fmt.Fprintf(os.Stderr, "[fence:macos] Wildcard allowedDomains detected - allowing direct network connections\n")
		fmt.Fprintf(os.Stderr, "[fence:macos] Note: deniedDomains only enforced for apps that respect HTTP_PROXY\n")
	}

	shellPath, shellFlag, err := ResolveExecutionShell(shellMode, shellLogin)
	if err != nil {
		return "", err
	}

	deniedExecPaths := GetRuntimeDeniedExecutablePaths(cfg)
	if resolvedShellPath, err := filepath.EvalSymlinks(shellPath); err == nil {
		deniedExecPaths = slices.DeleteFunc(deniedExecPaths, func(p string) bool {
			return p == shellPath || p == resolvedShellPath
		})
	} else {
		deniedExecPaths = slices.DeleteFunc(deniedExecPaths, func(p string) bool {
			return p == shellPath
		})
	}

	params := MacOSSandboxParams{
		Command:                 command,
		NeedsNetworkRestriction: needsNetworkRestriction,
		HTTPProxyPort:           httpPort,
		SOCKSProxyPort:          socksPort,
		AllowUnixSockets:        cfg.Network.AllowUnixSockets,
		AllowAllUnixSockets:     cfg.Network.AllowAllUnixSockets,
		AllowLocalBinding:       allowLocalBinding,
		AllowLocalOutbound:      allowLocalOutbound,
		DefaultDenyRead:         cfg.Filesystem.DefaultDenyRead,
		ReadAllowPaths:          cfg.Filesystem.AllowRead,
		ReadDenyPaths:           cfg.Filesystem.DenyRead,
		WriteAllowPaths:         allowPaths,
		WriteDenyPaths:          cfg.Filesystem.DenyWrite,
		DeniedExecPaths:         deniedExecPaths,
		AllowPty:                cfg.AllowPty,
		AllowGitConfig:          cfg.Filesystem.AllowGitConfig,
	}

	if debug && len(exposedPorts) > 0 {
		fmt.Fprintf(os.Stderr, "[fence:macos] Enabling local binding for exposed ports: %v\n", exposedPorts)
	}
	if debug && allowLocalBinding && !allowLocalOutbound {
		fmt.Fprintf(os.Stderr, "[fence:macos] Blocking localhost outbound (AllowLocalOutbound=false)\n")
	}

	profile := GenerateSandboxProfile(params)

	proxyEnvs := GenerateProxyEnvVars(httpPort, socksPort)

	// Build the command
	// env VAR1=val1 VAR2=val2 sandbox-exec -p 'profile' shell -c 'command'
	var parts []string
	parts = append(parts, "env")
	parts = append(parts, proxyEnvs...)
	parts = append(parts, "sandbox-exec", "-p", profile, shellPath, shellFlag, command)

	return ShellQuote(parts), nil
}
