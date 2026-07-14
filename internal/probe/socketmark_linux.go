//go:build linux

package probe

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func socketMarkAvailable() bool { return true }

func setSocketMarkControl(dialer *net.Dialer, mark uint32, observed *uint32) {
	dialer.Control = func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
				socketErr = err
				return
			}
			actual, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
			if err != nil {
				socketErr = err
				return
			}
			*observed = uint32(actual)
		}); err != nil {
			return err
		}
		return socketErr
	}
}
