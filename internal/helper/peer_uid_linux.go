//go:build linux

package helper

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func peerUID(connection net.Conn) (int, error) {
	syscallConnection, ok := connection.(syscall.Conn)
	if !ok {
		return 0, errors.New("connection does not expose peer credentials")
	}
	raw, err := syscallConnection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if controlErr != nil || credential == nil {
		return 0, controlErr
	}
	return int(credential.Uid), nil
}
