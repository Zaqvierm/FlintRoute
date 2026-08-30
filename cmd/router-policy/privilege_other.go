//go:build windows || plan9 || js

package main

// Non-Unix targets do not expose the OpenWrt root process model. Production
// OpenWrt builds use privilege_unix.go; keeping this conservative helper
// separate avoids pretending Windows test processes have a meaningful uid.
func processIsRoot() bool { return false }
