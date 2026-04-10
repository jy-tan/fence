//go:build linux

package sandbox

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Use-Tusk/fence/internal/config"
	"golang.org/x/sys/unix"
)

const (
	fenceLinuxArgvExecPlanEnv = "FENCE_LINUX_ARGV_EXEC_PLAN"

	linuxArgvExecRunnerMode = "--linux-argv-exec-run"
	linuxArgvExecShimMode   = "--linux-argv-exec-shim"

	linuxArgvExecMaxArgs        = 256
	linuxArgvExecMaxStringBytes = 32 * 1024
	linuxArgvExecReadChunkBytes = 256
)

type linuxArgvExecPlan struct {
	BwrapArgs                              []string       `json:"bwrapArgs"`
	Config                                 *config.Config `json:"config,omitempty"`
	Debug                                  bool           `json:"debug,omitempty"`
	SeccompFilterPath                      string         `json:"seccompFilterPath,omitempty"`
	AllowedMultithreadedBootstrapContinues int            `json:"allowedMultithreadedBootstrapContinues"`
}

type linuxArgvExecHandshake struct {
	Error string `json:"error,omitempty"`
}

type linuxSeccompData struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

type linuxSeccompNotif struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  linuxSeccompData
}

type linuxSeccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

type linuxRuntimeExecDecision struct {
	Allow   bool
	Message string
}

type linuxArgvExecSupervisorState struct {
	remainingMultithreadedBootstrapContinues int
}

type linuxThreadCountFunc func(int) (int, error)

type runtimeExecPolicyMatch struct {
	BlockedPrefix string
	IsDefault     bool
}

func buildLinuxArgvExecRunnerCommand(fenceExePath string, plan linuxArgvExecPlan) (string, error) {
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("failed to encode Linux argv exec plan: %w", err)
	}
	runner := ShellQuote([]string{fenceExePath, linuxArgvExecRunnerMode})
	return fmt.Sprintf("%s=%s exec %s",
		fenceLinuxArgvExecPlanEnv,
		ShellQuoteSingle(string(planJSON)),
		runner,
	), nil
}

// RunLinuxArgvExecRunnerFromEnv executes the host-side supervisor mode.
func RunLinuxArgvExecRunnerFromEnv() (int, error) {
	planJSON := os.Getenv(fenceLinuxArgvExecPlanEnv)
	if strings.TrimSpace(planJSON) == "" {
		return 1, errors.New("missing Linux argv exec plan")
	}

	var plan linuxArgvExecPlan
	if err := json.Unmarshal([]byte(planJSON), &plan); err != nil {
		return 1, fmt.Errorf("failed to parse Linux argv exec plan: %w", err)
	}
	if len(plan.BwrapArgs) == 0 {
		return 1, errors.New("Linux argv exec plan has no bubblewrap command")
	}
	if plan.AllowedMultithreadedBootstrapContinues <= 0 {
		return 1, errors.New("Linux argv exec plan has no multithreaded bootstrap continue budget")
	}

	socketDir, err := os.MkdirTemp("", "fence-argv-exec-")
	if err != nil {
		return 1, fmt.Errorf("failed to create argv exec temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(socketDir) }()

	socketPath := filepath.Join(socketDir, "control.sock")
	unixListener, err := net.Listen("unix", socketPath)
	if err != nil {
		return 1, fmt.Errorf("failed to listen on argv exec socket %q: %w", socketPath, err)
	}
	defer func() { _ = unixListener.Close() }()

	var extraFiles []*os.File

	var filterFile *os.File
	if plan.SeccompFilterPath != "" {
		filterFile, err = os.Open(plan.SeccompFilterPath) //nolint:gosec // path comes from fence-generated temp file
		if err != nil {
			return 1, fmt.Errorf("failed to open seccomp filter file %q: %w", plan.SeccompFilterPath, err)
		}
		extraFiles = append(extraFiles, filterFile)
		_ = os.Remove(plan.SeccompFilterPath)
	}

	bwrapArgs := insertLinuxArgsBeforeBwrapCommand(plan.BwrapArgs, []string{"--bind", socketDir, socketDir})

	cmd := exec.Command(bwrapArgs[0], bwrapArgs[1:]...) //nolint:gosec // args are generated internally
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "FENCE_LINUX_ARGV_EXEC_SOCKET="+socketPath)
	cmd.ExtraFiles = extraFiles

	if err := cmd.Start(); err != nil {
		if filterFile != nil {
			_ = filterFile.Close()
		}
		return 1, fmt.Errorf("failed to start Linux argv exec sandbox: %w", err)
	}

	if filterFile != nil {
		_ = filterFile.Close()
	}

	stopSignals := startLinuxArgvExecSignalForwarder(cmd)
	defer stopSignals()

	if unixSocketListener, ok := unixListener.(*net.UnixListener); ok {
		_ = unixSocketListener.SetDeadline(time.Now().Add(30 * time.Second))
	}
	conn, acceptErr := unixListener.Accept()
	if acceptErr != nil {
		waitErr := cmd.Wait()
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		if waitErr != nil {
			return 1, waitErr
		}
		return 1, fmt.Errorf("failed to accept argv exec shim connection: %w", acceptErr)
	}
	defer func() { _ = conn.Close() }()

	listenerFD, handshakeErr := recvLinuxArgvExecHandshake(conn)
	if handshakeErr != nil {
		waitErr := cmd.Wait()
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		if waitErr != nil {
			return 1, waitErr
		}
		return 1, handshakeErr
	}

	waitErrCh := make(chan error, 1)
	go func() {
		waitErrCh <- cmd.Wait()
	}()

	supervisorState := &linuxArgvExecSupervisorState{
		remainingMultithreadedBootstrapContinues: plan.AllowedMultithreadedBootstrapContinues,
	}
	supervisorErrCh := make(chan error, 1)
	go func() {
		supervisorErrCh <- runLinuxArgvExecSupervisor(listenerFD, plan.Config, plan.Debug, supervisorState)
	}()

	select {
	case waitErr := <-waitErrCh:
		_ = unix.Close(listenerFD)
		supervisorErr := <-supervisorErrCh
		if supervisorErr != nil {
			return 1, supervisorErr
		}
		if waitErr != nil {
			if exitErr, ok := waitErr.(*exec.ExitError); ok {
				return exitErr.ExitCode(), nil
			}
			return 1, waitErr
		}
		return 0, nil
	case supervisorErr := <-supervisorErrCh:
		if supervisorErr != nil {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			waitErr := <-waitErrCh
			if waitErr != nil {
				if exitErr, ok := waitErr.(*exec.ExitError); ok {
					return exitErr.ExitCode(), supervisorErr
				}
				return 1, errors.Join(supervisorErr, waitErr)
			}
			return 1, supervisorErr
		}

		waitErr := <-waitErrCh
		if waitErr != nil {
			if exitErr, ok := waitErr.(*exec.ExitError); ok {
				return exitErr.ExitCode(), nil
			}
			return 1, waitErr
		}
		return 0, nil
	}
}

func startLinuxArgvExecSignalForwarder(cmd *exec.Cmd) func() {
	sigChan := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGWINCH)

	go func() {
		for {
			select {
			case <-done:
				return
			case sig := <-sigChan:
				if cmd.Process == nil {
					continue
				}
				if forwarded, ok := sig.(syscall.Signal); ok {
					_ = cmd.Process.Signal(forwarded)
				}
			}
		}
	}()

	return func() {
		signal.Stop(sigChan)
		close(done)
	}
}

func recvLinuxArgvExecHandshake(conn net.Conn) (int, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("argv exec handshake connection is %T, want *net.UnixConn", conn)
	}

	connFile, err := unixConn.File()
	if err != nil {
		return -1, fmt.Errorf("failed to access argv exec handshake fd: %w", err)
	}
	defer func() { _ = connFile.Close() }()

	payload := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, recvErr := unix.Recvmsg(int(connFile.Fd()), payload, oob, 0)
	if recvErr != nil {
		return -1, recvErr
	}
	if n == 0 && oobn == 0 {
		return -1, io.EOF
	}

	var handshake linuxArgvExecHandshake
	if err := json.Unmarshal(payload[:n], &handshake); err != nil {
		return -1, fmt.Errorf("failed to decode argv exec handshake: %w", err)
	}
	if handshake.Error != "" {
		return -1, errors.New(handshake.Error)
	}

	controlMessages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("failed to parse argv exec control message: %w", err)
	}
	for _, msg := range controlMessages {
		fds, err := unix.ParseUnixRights(&msg)
		if err != nil {
			return -1, fmt.Errorf("failed to parse argv exec listener fd: %w", err)
		}
		if len(fds) > 0 {
			return fds[0], nil
		}
	}

	return -1, errors.New("argv exec handshake did not include a listener fd")
}

// RunLinuxArgvExecShim executes the sandbox-side shim mode.
func RunLinuxArgvExecShim(args []string) (int, error) {
	var debug bool
	cmdStart := -1

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--debug":
			debug = true
		case "--":
			cmdStart = i + 1
			i = len(args)
		default:
			return 1, fmt.Errorf("unknown Linux argv exec shim argument %q", args[i])
		}
	}

	if cmdStart < 0 || cmdStart >= len(args) {
		return 1, errors.New("missing command for Linux argv exec shim")
	}

	socketPath := os.Getenv("FENCE_LINUX_ARGV_EXEC_SOCKET")
	if strings.TrimSpace(socketPath) == "" {
		return 1, errors.New("missing FENCE_LINUX_ARGV_EXEC_SOCKET for Linux argv exec shim")
	}

	listenerFD, err := installLinuxArgvExecNotifyFilter()
	if err != nil {
		wrappedErr := fmt.Errorf("failed to install Linux argv-aware exec filter: %w", err)
		_ = sendLinuxArgvExecHandshake(socketPath, -1, wrappedErr)
		return 1, wrappedErr
	}

	if err := sendLinuxArgvExecHandshake(socketPath, listenerFD, nil); err != nil {
		_ = unix.Close(listenerFD)
		return 1, fmt.Errorf("failed to send Linux argv exec listener fd: %w", err)
	}

	_ = unix.Close(listenerFD)

	command := args[cmdStart:]
	execPath, err := exec.LookPath(command[0])
	if err != nil {
		return 127, fmt.Errorf("command not found: %s", command[0])
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[fence:linux] argv exec shim installed, execing %s\n", ShellQuote(command))
	}

	err = syscall.Exec(execPath, command, FilterDangerousEnv(os.Environ())) //nolint:gosec // execing trusted argv slice
	if err != nil {
		return 1, fmt.Errorf("Linux argv exec shim failed to exec %q: %w", execPath, err)
	}
	return 0, nil
}

func sendLinuxArgvExecHandshake(socketPath string, listenerFD int, handshakeErr error) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("argv exec handshake connection is %T, want *net.UnixConn", conn)
	}
	connFile, err := unixConn.File()
	if err != nil {
		return err
	}
	defer func() { _ = connFile.Close() }()

	payload, err := json.Marshal(linuxArgvExecHandshake{
		Error: errorString(handshakeErr),
	})
	if err != nil {
		return err
	}

	var oob []byte
	if handshakeErr == nil && listenerFD >= 0 {
		oob = unix.UnixRights(listenerFD)
	}

	_, err = unix.SendmsgN(int(connFile.Fd()), payload, oob, nil, 0)
	return err
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func installLinuxArgvExecNotifyFilter() (int, error) {
	features := DetectLinuxFeatures()
	if !features.HasSeccomp || features.SeccompLogLevel < 2 {
		return -1, errors.New("seccomp user notification is not available on this system")
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return -1, fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}

	filter := []unix.SockFilter{
		{Code: BPF_LD | BPF_W | BPF_ABS, K: seccompDataSyscallOffset},
		{Code: BPF_JMP | BPF_JEQ | BPF_K, Jt: 0, Jf: 1, K: uint32(unix.SYS_EXECVE)},
		{Code: BPF_RET | BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
		{Code: BPF_JMP | BPF_JEQ | BPF_K, Jt: 0, Jf: 1, K: uint32(unix.SYS_EXECVEAT)},
		{Code: BPF_RET | BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
		{Code: BPF_RET | BPF_K, K: SECCOMP_RET_ALLOW},
	}
	var filterLen uint16
	for range filter {
		if filterLen == math.MaxUint16 {
			return -1, fmt.Errorf("seccomp filter too large: %d instructions", len(filter))
		}
		filterLen++
	}
	prog := unix.SockFprog{
		Len:    filterLen,
		Filter: &filter[0],
	}

	listenerFD, _, errno := linuxSeccompSetModeFilter(
		uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER),
		&prog,
	)
	if errno != 0 {
		return -1, errno
	}

	return int(listenerFD), nil
}

func runLinuxArgvExecSupervisor(
	listenerFD int,
	cfg *config.Config,
	debug bool,
	state *linuxArgvExecSupervisorState,
) error {
	for {
		req := &linuxSeccompNotif{}
		if err := linuxRecvSeccompNotif(listenerFD, req); err != nil {
			switch {
			case errors.Is(err, unix.EINTR):
				continue
			case errors.Is(err, unix.ENOENT):
				continue
			case errors.Is(err, unix.EBADF):
				return nil
			default:
				return fmt.Errorf("failed to receive argv exec notification: %w", err)
			}
		}

		decision := evaluateLinuxRuntimeExecDecision(req, listenerFD, cfg, state)
		resp := &linuxSeccompNotifResp{ID: req.ID}
		if decision.Allow {
			// CONTINUE is safe enough here only after we verify the notification is
			// still valid and reject multithreaded tracees. This narrows, but does
			// not entirely remove, the TOCTOU window documented by seccomp_unotify(2).
			resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		} else {
			resp.Error = -int32(unix.EPERM)
			if decision.Message != "" {
				fmt.Fprintln(os.Stderr, decision.Message)
			}
		}

		if debug && decision.Allow {
			fmt.Fprintf(os.Stderr, "[fence:linux] argv exec allowed for pid=%d\n", req.PID)
		}

		if err := linuxSendSeccompNotifResp(listenerFD, resp); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return nil
			}
			return fmt.Errorf("failed to send argv exec notification response: %w", err)
		}
	}
}

func evaluateLinuxRuntimeExecDecision(
	req *linuxSeccompNotif,
	listenerFD int,
	cfg *config.Config,
	state *linuxArgvExecSupervisorState,
) linuxRuntimeExecDecision {
	execPath, argv, err := readLinuxExecCandidate(req, listenerFD)
	if err != nil {
		return linuxRuntimeExecDecision{
			Allow: false,
			Message: fmt.Sprintf("[fence:linux] Runtime exec policy blocked pid=%d: unable to inspect %s: %v",
				req.PID,
				linuxExecSyscallName(req.Data.Nr),
				err,
			),
		}
	}

	return evaluateLinuxRuntimeExecDecisionForCandidate(int(req.PID), execPath, argv, cfg, state, linuxProcessThreadCount)
}

func evaluateLinuxRuntimeExecDecisionForCandidate(
	pid int,
	execPath string,
	argv []string,
	cfg *config.Config,
	state *linuxArgvExecSupervisorState,
	threadCountFunc linuxThreadCountFunc,
) linuxRuntimeExecDecision {
	if decision := classifyLinuxRuntimeExecDecision(execPath, argv, cfg); !decision.Allow {
		return decision
	}

	if decision := verifyLinuxRuntimeExecSafeToContinue(pid, execPath, argv, state, threadCountFunc); !decision.Allow {
		return decision
	}

	return linuxRuntimeExecDecision{Allow: true}
}

func classifyLinuxRuntimeExecDecision(execPath string, argv []string, cfg *config.Config) linuxRuntimeExecDecision {
	if isLinuxBootstrapExecPath(execPath) {
		return linuxRuntimeExecDecision{Allow: true}
	}

	if match, blocked := matchRuntimeExecPolicy(execPath, argv, cfg); blocked {
		source := "command.deny"
		if match.IsDefault {
			source = "default"
		}
		return linuxRuntimeExecDecision{
			Allow: false,
			Message: fmt.Sprintf("[fence:linux] Runtime exec policy blocked exec=%q argv=%s matched=%q source=%s",
				execPath,
				quoteRuntimeArgv(argv),
				match.BlockedPrefix,
				source,
			),
		}
	}

	return linuxRuntimeExecDecision{Allow: true}
}

// Every allow path eventually returns SECCOMP_USER_NOTIF_FLAG_CONTINUE, so
// they must all pass the same replay-safety checks before we let the kernel
// continue the exec.
func verifyLinuxRuntimeExecSafeToContinue(
	pid int,
	execPath string,
	argv []string,
	state *linuxArgvExecSupervisorState,
	threadCountFunc linuxThreadCountFunc,
) linuxRuntimeExecDecision {
	if threadCountFunc == nil {
		threadCountFunc = linuxProcessThreadCount
	}

	threadCount, err := threadCountFunc(pid)
	if err != nil {
		return linuxRuntimeExecDecision{
			Allow: false,
			Message: fmt.Sprintf("[fence:linux] Runtime exec policy blocked exec=%q argv=%s: unable to verify thread state: %v",
				execPath,
				quoteRuntimeArgv(argv),
				err,
			),
		}
	}
	if threadCount > 1 {
		if consumeLinuxMultithreadedBootstrapContinue(state, execPath) {
			return linuxRuntimeExecDecision{Allow: true}
		}
		return linuxRuntimeExecDecision{
			Allow: false,
			Message: fmt.Sprintf("[fence:linux] Runtime exec policy blocked exec=%q argv=%s: multithreaded exec cannot be safely continued in argv mode",
				execPath,
				quoteRuntimeArgv(argv),
			),
		}
	}

	return linuxRuntimeExecDecision{Allow: true}
}

func consumeLinuxMultithreadedBootstrapContinue(state *linuxArgvExecSupervisorState, execPath string) bool {
	if state == nil || state.remainingMultithreadedBootstrapContinues <= 0 || !isLinuxBootstrapExecPath(execPath) {
		return false
	}
	state.remainingMultithreadedBootstrapContinues--
	return true
}

func linuxArgvExecMultithreadedBootstrapContinueBudget(useLandlockWrapper bool) int {
	budget := 1 // shim -> staged shell
	if useLandlockWrapper {
		budget++ // landlock wrapper -> staged shell
	}
	return budget
}

func linuxRecvSeccompNotif(listenerFD int, req *linuxSeccompNotif) error {
	return linuxIoctlValue(listenerFD, uintptr(unix.SECCOMP_IOCTL_NOTIF_RECV), req)
}

func linuxSendSeccompNotifResp(listenerFD int, resp *linuxSeccompNotifResp) error {
	return linuxIoctlValue(listenerFD, uintptr(unix.SECCOMP_IOCTL_NOTIF_SEND), resp)
}

func linuxIoctlValue[T any](fd int, request uintptr, value *T) error {
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		request,
		uintptr(unsafe.Pointer(value)), //nolint:gosec // ioctl(2) requires a pointer to the kernel ABI value.
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func linuxSeccompNotifIDValid(listenerFD int, id uint64) bool {
	idCopy := id
	return linuxIoctlValue(listenerFD, uintptr(unix.SECCOMP_IOCTL_NOTIF_ID_VALID), &idCopy) == nil
}

func readLinuxExecCandidate(req *linuxSeccompNotif, listenerFD int) (string, []string, error) {
	pid := int(req.PID)

	var pathPtr uintptr
	var argvPtr uintptr

	switch req.Data.Nr {
	case int32(unix.SYS_EXECVE):
		pathPtr = uintptr(req.Data.Args[0])
		argvPtr = uintptr(req.Data.Args[1])
	case int32(unix.SYS_EXECVEAT):
		pathPtr = uintptr(req.Data.Args[1])
		argvPtr = uintptr(req.Data.Args[2])
		flags := req.Data.Args[4]
		if flags&uint64(unix.AT_EMPTY_PATH) != 0 {
			return "", nil, errors.New("execveat with AT_EMPTY_PATH is not supported in argv mode")
		}
	default:
		return "", nil, fmt.Errorf("unexpected syscall number %d", req.Data.Nr)
	}

	if pathPtr == 0 {
		return "", nil, errors.New("missing executable path pointer")
	}
	if !linuxSeccompNotifIDValid(listenerFD, req.ID) {
		return "", nil, errors.New("notification no longer valid before argv read")
	}

	execPath, err := readRemoteCString(pid, pathPtr, linuxArgvExecMaxStringBytes)
	if err != nil {
		return "", nil, fmt.Errorf("read exec path: %w", err)
	}
	argv, err := readRemoteCStringArray(pid, argvPtr, linuxArgvExecMaxArgs, linuxArgvExecMaxStringBytes)
	if err != nil {
		return "", nil, fmt.Errorf("read argv: %w", err)
	}

	if !linuxSeccompNotifIDValid(listenerFD, req.ID) {
		return "", nil, errors.New("notification no longer valid after argv read")
	}

	return execPath, argv, nil
}

func readRemoteCStringArray(pid int, vectorAddr uintptr, maxArgs int, maxStringBytes int) ([]string, error) {
	if vectorAddr == 0 {
		return nil, nil
	}

	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	argv := make([]string, 0, min(maxArgs, 8))
	for i := 0; i < maxArgs; i++ {
		ptrBytes, err := readRemoteMemory(pid, vectorAddr+uintptr(i*ptrSize), ptrSize)
		if err != nil {
			return nil, err
		}

		var argPtr uintptr
		switch ptrSize {
		case 4:
			argPtr = uintptr(binary.NativeEndian.Uint32(ptrBytes))
		case 8:
			argPtr = uintptr(binary.NativeEndian.Uint64(ptrBytes))
		default:
			return nil, fmt.Errorf("unsupported pointer size %d", ptrSize)
		}

		if argPtr == 0 {
			return argv, nil
		}

		arg, err := readRemoteCString(pid, argPtr, maxStringBytes)
		if err != nil {
			return nil, err
		}
		argv = append(argv, arg)
	}

	return nil, fmt.Errorf("argv exceeded %d entries", maxArgs)
}

func readRemoteCString(pid int, addr uintptr, maxBytes int) (string, error) {
	if addr == 0 {
		return "", errors.New("null pointer")
	}

	var buf bytes.Buffer
	for read := 0; read < maxBytes; read += linuxArgvExecReadChunkBytes {
		chunkSize := min(linuxArgvExecReadChunkBytes, maxBytes-read)
		chunk, err := readRemoteMemory(pid, addr+uintptr(read), chunkSize)
		if err != nil {
			return "", err
		}
		if idx := bytes.IndexByte(chunk, 0); idx >= 0 {
			buf.Write(chunk[:idx])
			return buf.String(), nil
		}
		buf.Write(chunk)
	}
	return "", fmt.Errorf("string exceeded %d bytes", maxBytes)
}

func readRemoteMemory(pid int, addr uintptr, size int) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}

	buf := make([]byte, size)
	localIov := []unix.Iovec{{Base: &buf[0]}}
	localIov[0].SetLen(size)
	remoteIov := []unix.RemoteIovec{{Base: addr, Len: size}}

	n, err := unix.ProcessVMReadv(pid, localIov, remoteIov, 0)
	if err != nil {
		return nil, err
	}
	if n != size {
		return nil, fmt.Errorf("short process_vm_readv read (%d/%d)", n, size)
	}
	return buf, nil
}

func linuxProcessThreadCount(pid int) (int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

func matchRuntimeExecPolicy(execPath string, argv []string, cfg *config.Config) (runtimeExecPolicyMatch, bool) {
	if cfg == nil {
		cfg = config.Default()
	}

	actual := normalizeRuntimeExecArgv(execPath, argv)
	if len(actual) == 0 {
		return runtimeExecPolicyMatch{}, false
	}

	for _, allow := range cfg.Command.Allow {
		if matchesRuntimeArgvPrefix(actual, allow) {
			return runtimeExecPolicyMatch{}, false
		}
	}

	for _, deny := range cfg.Command.Deny {
		if matchesRuntimeArgvPrefix(actual, deny) {
			return runtimeExecPolicyMatch{
				BlockedPrefix: deny,
				IsDefault:     false,
			}, true
		}
	}

	if cfg.Command.UseDefaultDeniedCommands() {
		for _, deny := range config.DefaultDeniedCommands {
			if matchesRuntimeArgvPrefix(actual, deny) {
				return runtimeExecPolicyMatch{
					BlockedPrefix: deny,
					IsDefault:     true,
				}, true
			}
		}
	}

	return runtimeExecPolicyMatch{}, false
}

func normalizeRuntimeExecArgv(execPath string, argv []string) []string {
	if len(argv) == 0 {
		base := filepath.Base(strings.TrimSpace(execPath))
		if base == "" || base == "." || base == string(filepath.Separator) {
			return nil
		}
		return []string{base}
	}

	normalized := append([]string(nil), argv...)
	base := filepath.Base(strings.TrimSpace(execPath))
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = filepath.Base(strings.TrimSpace(normalized[0]))
	}
	normalized[0] = base
	return normalized
}

func matchesRuntimeArgvPrefix(actual []string, rule string) bool {
	ruleTokens := normalizeCommandTokens(rule)
	return matchesTokenizedCommandRule(actual, ruleTokens)
}

func quoteRuntimeArgv(argv []string) string {
	if len(argv) == 0 {
		return "[]"
	}

	quoted := make([]string, 0, len(argv))
	for _, arg := range argv {
		quoted = append(quoted, strconv.Quote(arg))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func isLinuxBootstrapExecPath(path string) bool {
	cleaned := filepath.Clean(path)
	switch cleaned {
	case linuxBootstrapShellPath, linuxBootstrapFencePath, linuxBootstrapSocatPath:
		return true
	default:
		return false
	}
}

func insertLinuxArgsBeforeBwrapCommand(args []string, insert []string) []string {
	for i, arg := range args {
		if arg == "--" {
			updated := make([]string, 0, len(args)+len(insert))
			updated = append(updated, args[:i]...)
			updated = append(updated, insert...)
			updated = append(updated, args[i:]...)
			return updated
		}
	}
	return append(args, insert...)
}

func linuxExecSyscallName(nr int32) string {
	switch nr {
	case int32(unix.SYS_EXECVE):
		return "execve"
	case int32(unix.SYS_EXECVEAT):
		return "execveat"
	default:
		return fmt.Sprintf("syscall(%d)", nr)
	}
}

func linuxSeccompSetModeFilter(flags uintptr, prog *unix.SockFprog) (uintptr, uintptr, syscall.Errno) {
	return unix.Syscall(
		unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		flags,
		uintptr(unsafe.Pointer(prog)), //nolint:gosec // seccomp(2) requires a pointer to struct sock_fprog.
	)
}
