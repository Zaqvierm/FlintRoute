package config

import (
	"path"
	"path/filepath"
)

// DNSObservationPath returns a tmpfs path visible inside OpenWrt's dnsmasq jail.
// Custom runtimes keep observations beside their other transient state.
func DNSObservationPath(runtimeDir string) string {
	if path.Clean(filepath.ToSlash(runtimeDir)) == "/tmp/router-policy" {
		return "/var/run/dnsmasq/router-policy-observations.log"
	}
	return filepath.Join(runtimeDir, "dns-observations.log")
}
