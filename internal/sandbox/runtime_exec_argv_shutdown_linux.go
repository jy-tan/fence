//go:build linux

package sandbox

import (
	"encoding/binary"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// argvRunnerShutdown coordinates teardown of the argv-exec runner.
// Begin is idempotent and safe to call concurrently; it wakes any
// goroutine parked in ppoll on WakeFD and closes Done.
type argvRunnerShutdown struct {
	wakeFD    int
	done      chan struct{}
	beginOnce sync.Once
	closeOnce sync.Once
	begun     atomic.Bool
}

// newArgvRunnerShutdown creates an eventfd-backed shutdown coordinator.
//
// The eventfd is created with EFD_NONBLOCK | EFD_CLOEXEC so that:
//   - reads return EAGAIN instead of blocking when the counter is zero, and
//   - the fd is not leaked across an exec.
func newArgvRunnerShutdown() (*argvRunnerShutdown, error) {
	fd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &argvRunnerShutdown{
		wakeFD: fd,
		done:   make(chan struct{}),
	}, nil
}

// WakeFD is owned by the coordinator; do not close it directly.
func (s *argvRunnerShutdown) WakeFD() int { return s.wakeFD }

func (s *argvRunnerShutdown) Done() <-chan struct{} { return s.done }

func (s *argvRunnerShutdown) Begun() bool { return s.begun.Load() }

func (s *argvRunnerShutdown) Begin() {
	s.beginOnce.Do(func() {
		s.begun.Store(true)
		close(s.done)
		// EAGAIN here is fine: counter is saturated, reader has a
		// pending wake.
		var buf [8]byte
		binary.NativeEndian.PutUint64(buf[:], 1)
		_, _ = unix.Write(s.wakeFD, buf[:])
	})
}

func (s *argvRunnerShutdown) Close() {
	s.closeOnce.Do(func() {
		_ = unix.Close(s.wakeFD)
	})
}
