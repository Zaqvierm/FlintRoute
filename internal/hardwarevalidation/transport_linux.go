//go:build linux

package hardwarevalidation

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func markedDialer(mark uint32, timeout time.Duration) (*net.Dialer, error) {
	dialer := &net.Dialer{Timeout: timeout}
	dialer.Control = func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		return socketErr
	}
	return dialer, nil
}
