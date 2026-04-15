//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Use-Tusk/fence/internal/fencelog"
	"golang.org/x/sys/unix"
)

// SeccompFilter generates and manages seccomp BPF filters.
type SeccompFilter struct {
	debug bool
}

const (
	seccompDataSyscallOffset uint32 = 0
	seccompDataArgsOffset    uint32 = 16
	seccompArgSize           uint32 = 8
)

// NewSeccompFilter creates a new seccomp filter generator.
func NewSeccompFilter(debug bool) *SeccompFilter {
	return &SeccompFilter{debug: debug}
}

// DangerousSyscalls lists syscalls that should be blocked for security.
var DangerousSyscalls = []string{
	"ptrace",            // Process debugging/injection
	"process_vm_readv",  // Read another process's memory
	"process_vm_writev", // Write another process's memory
	"keyctl",            // Kernel keyring operations
	"add_key",           // Add key to keyring
	"request_key",       // Request key from keyring
	"personality",       // Change execution domain (can bypass ASLR)
	"userfaultfd",       // User-space page fault handling (potential sandbox escape)
	"perf_event_open",   // Performance monitoring (info leak)
	"bpf",               // eBPF operations (without CAP_BPF)
	"kexec_load",        // Load new kernel
	"kexec_file_load",   // Load new kernel from file
	"reboot",            // Reboot system
	"syslog",            // Kernel log access
	"acct",              // Process accounting
	"mount",             // Mount filesystems
	"umount2",           // Unmount filesystems
	"pivot_root",        // Change root filesystem
	"swapon",            // Enable swap
	"swapoff",           // Disable swap
	"sethostname",       // Change hostname
	"setdomainname",     // Change domain name
	"init_module",       // Load kernel module
	"finit_module",      // Load kernel module from file
	"delete_module",     // Unload kernel module
	"ioperm",            // I/O port permissions
	"iopl",              // I/O privilege level
}

// GenerateBPFFilter generates a seccomp-bpf filter that blocks dangerous syscalls.
// Returns the path to the generated BPF filter file.
func (s *SeccompFilter) GenerateBPFFilter() (string, error) {
	features := DetectLinuxFeatures()
	if !features.HasSeccomp {
		return "", fmt.Errorf("seccomp not available on this system")
	}

	// Create a temporary directory for the filter
	tmpDir := filepath.Join(os.TempDir(), "fence-seccomp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return "", fmt.Errorf("failed to create seccomp dir: %w", err)
	}

	filterPath := filepath.Join(tmpDir, fmt.Sprintf("fence-seccomp-%d.bpf", os.Getpid()))

	// Generate the filter using the seccomp library or raw BPF
	// For now, we'll use bwrap's built-in seccomp support via --seccomp
	// which accepts a file descriptor with a BPF program

	// Write a simple seccomp policy using bpf assembly
	if err := s.writeBPFProgram(filterPath); err != nil {
		return "", fmt.Errorf("failed to write BPF program: %w", err)
	}

	if s.debug {
		fencelog.Printf("[fence:seccomp] Generated BPF filter at %s\n", filterPath)
	}

	return filterPath, nil
}

// writeBPFProgram writes a BPF program that blocks dangerous syscalls.
// This generates a compact BPF program in the format expected by bwrap --seccomp.
func (s *SeccompFilter) writeBPFProgram(path string) error {
	// For bwrap, we need to pass the seccomp filter via file descriptor
	// The filter format is: struct sock_filter array
	//
	// We'll build a simple filter:
	// 1. Load syscall number
	// 2. For each dangerous syscall: if match, return ERRNO(EPERM) or LOG+ERRNO
	// 3. Default: allow

	program, err := s.buildBPFProgram()
	if err != nil {
		return err
	}

	// Write the program to file
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // path is controlled
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	for _, inst := range program {
		if err := inst.writeTo(f); err != nil {
			return err
		}
	}

	return nil
}

func (s *SeccompFilter) buildBPFProgram() ([]bpfInstruction, error) {
	// Get syscall numbers for the current architecture
	syscallNums := make(map[string]uint32)
	for _, name := range DangerousSyscalls {
		if num, ok := getSyscallNumber(name); ok {
			syscallNums[name] = num
		}
	}

	if len(syscallNums) == 0 {
		// No syscalls to block (unknown architecture?)
		return nil, fmt.Errorf("no syscall numbers found for dangerous syscalls")
	}

	// Build BPF program
	var program []bpfInstruction

	// Load syscall number from seccomp_data
	// BPF_LD | BPF_W | BPF_ABS: load word from absolute offset
	program = append(program, bpfInstruction{
		code: BPF_LD | BPF_W | BPF_ABS,
		k:    seccompDataSyscallOffset,
	})

	// Note: SECCOMP_RET_ERRNO returns -1 with errno in the low 16 bits
	// SECCOMP_RET_LOG means "log and allow" which is NOT what we want
	// We use SECCOMP_RET_ERRNO to block with EPERM
	action := SECCOMP_RET_ERRNO | (unix.EPERM & 0xFFFF)

	// Allow interactive PTY sessions without bwrap --new-session, but block
	// TIOCSTI specifically so sandboxed processes cannot inject keystrokes into
	// the caller's terminal. Only the low 32 bits are relevant for ioctl cmds.
	if ioctlNum, ok := getSyscallNumber("ioctl"); ok {
		program = append(program,
			bpfInstruction{
				code: BPF_JMP | BPF_JEQ | BPF_K,
				jt:   0,
				jf:   4,
				k:    ioctlNum,
			},
			bpfInstruction{
				code: BPF_LD | BPF_W | BPF_ABS,
				k:    seccompArgLow32Offset(1),
			},
			bpfInstruction{
				code: BPF_JMP | BPF_JEQ | BPF_K,
				jt:   0,
				jf:   1,
				k:    uint32(unix.TIOCSTI),
			},
			bpfInstruction{
				code: BPF_RET | BPF_K,
				k:    uint32(action),
			},
			bpfInstruction{
				code: BPF_RET | BPF_K,
				k:    SECCOMP_RET_ALLOW,
			},
		)
	}

	// For each dangerous syscall, add a comparison and block
	for _, name := range DangerousSyscalls {
		num, ok := syscallNums[name]
		if !ok {
			continue
		}

		// BPF_JMP | BPF_JEQ | BPF_K: if A == K, jump jt else jump jf
		program = append(program, bpfInstruction{
			code: BPF_JMP | BPF_JEQ | BPF_K,
			jt:   0, // if match, go to next instruction (block)
			jf:   1, // if not match, skip the block instruction
			k:    num,
		})

		// Return action (block with EPERM)
		program = append(program, bpfInstruction{
			code: BPF_RET | BPF_K,
			k:    uint32(action),
		})
	}

	// Default: allow
	program = append(program, bpfInstruction{
		code: BPF_RET | BPF_K,
		k:    SECCOMP_RET_ALLOW,
	})

	return program, nil
}

func seccompArgLow32Offset(argIndex uint32) uint32 {
	return seccompDataArgsOffset + argIndex*seccompArgSize
}

// CleanupFilter removes a generated filter file.
func (s *SeccompFilter) CleanupFilter(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

// BPF instruction codes
const (
	BPF_LD  = 0x00
	BPF_JMP = 0x05
	BPF_RET = 0x06
	BPF_W   = 0x00
	BPF_ABS = 0x20
	BPF_JEQ = 0x10
	BPF_K   = 0x00
)

// Seccomp return values
const (
	SECCOMP_RET_ALLOW = 0x7fff0000
	SECCOMP_RET_ERRNO = 0x00050000
	SECCOMP_RET_LOG   = 0x7ffc0000
)

// bpfInstruction represents a single BPF instruction
type bpfInstruction struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

func (i *bpfInstruction) writeTo(f *os.File) error {
	// BPF instruction is 8 bytes: code(2) + jt(1) + jf(1) + k(4)
	buf := make([]byte, 8)
	buf[0] = byte(i.code)
	buf[1] = byte(i.code >> 8)
	buf[2] = i.jt
	buf[3] = i.jf
	buf[4] = byte(i.k)
	buf[5] = byte(i.k >> 8)
	buf[6] = byte(i.k >> 16)
	buf[7] = byte(i.k >> 24)
	_, err := f.Write(buf)
	return err
}

// getSyscallNumber returns the syscall number for the current architecture.
func getSyscallNumber(name string) (uint32, bool) {
	// Detect architecture using uname
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return 0, false
	}

	// Convert machine to string
	machine := string(utsname.Machine[:])
	// Trim null bytes
	for i, c := range machine {
		if c == 0 {
			machine = machine[:i]
			break
		}
	}

	var syscallMap map[string]uint32

	if machine == "aarch64" || machine == "arm64" {
		// ARM64 syscall numbers (from asm-generic/unistd.h)
		syscallMap = map[string]uint32{
			"ptrace":            117,
			"process_vm_readv":  270,
			"process_vm_writev": 271,
			"ioctl":             29,
			"keyctl":            219,
			"add_key":           217,
			"request_key":       218,
			"personality":       92,
			"userfaultfd":       282,
			"perf_event_open":   241,
			"bpf":               280,
			"kexec_load":        104,
			"kexec_file_load":   294,
			"reboot":            142,
			"syslog":            116,
			"acct":              89,
			"mount":             40,
			"umount2":           39,
			"pivot_root":        41,
			"swapon":            224,
			"swapoff":           225,
			"sethostname":       161,
			"setdomainname":     162,
			"init_module":       105,
			"finit_module":      273,
			"delete_module":     106,
			// ioperm and iopl don't exist on ARM64
		}
	} else {
		// x86_64 syscall numbers
		syscallMap = map[string]uint32{
			"ptrace":            101,
			"process_vm_readv":  310,
			"process_vm_writev": 311,
			"ioctl":             16,
			"keyctl":            250,
			"add_key":           248,
			"request_key":       249,
			"personality":       135,
			"userfaultfd":       323,
			"perf_event_open":   298,
			"bpf":               321,
			"kexec_load":        246,
			"kexec_file_load":   320,
			"reboot":            169,
			"syslog":            103,
			"acct":              163,
			"mount":             165,
			"umount2":           166,
			"pivot_root":        155,
			"swapon":            167,
			"swapoff":           168,
			"sethostname":       170,
			"setdomainname":     171,
			"init_module":       175,
			"finit_module":      313,
			"delete_module":     176,
			"ioperm":            173,
			"iopl":              172,
		}
	}

	num, ok := syscallMap[name]
	return num, ok
}

// Note: SeccompMonitor was removed because SECCOMP_RET_ERRNO (which we use to block
// syscalls) is completely silent - it doesn't log to dmesg, audit, or anywhere else.
// The monitor code attempted to parse dmesg for seccomp events, but those only appear
// with SECCOMP_RET_LOG (allows the syscall) or SECCOMP_RET_KILL (kills the process).
//
// Alternative approaches considered:
// - SECCOMP_RET_USER_NOTIF: Complex supervisor architecture with latency on every blocked call
// - auditd integration: Requires audit daemon setup and root access
// - SECCOMP_RET_LOG: Logs but doesn't block (defeats the purpose)
//
// The eBPF monitor in linux_ebpf.go now handles syscall failure detection instead,
// which catches EPERM/EACCES errors regardless of their source.
