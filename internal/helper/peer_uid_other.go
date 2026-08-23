//go:build !linux

package helper

import (
	"errors"
	"net"
)

func peerUID(_ net.Conn) (int, error) {
	return 0, errors.New("peer credentials are unavailable on this platform")
}
