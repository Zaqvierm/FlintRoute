//go:build !linux

package hardwarevalidation

import (
	"errors"
	"net"
	"time"
)

func markedDialer(_ uint32, _ time.Duration) (*net.Dialer, error) {
	return nil, errors.New("SO_MARK transport proof requires Linux")
}
