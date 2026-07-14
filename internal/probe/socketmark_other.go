//go:build !linux

package probe

import "net"

func socketMarkAvailable() bool { return false }

func setSocketMarkControl(_ *net.Dialer, _ uint32, _ *uint32) {}
