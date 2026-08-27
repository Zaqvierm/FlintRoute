//go:build aix || android || darwin || dragonfly || freebsd || hurd || illumos || linux || netbsd || openbsd || solaris

package main

import "os"

func processIsRoot() bool { return os.Getuid() == 0 }
