package config

import (
	"path/filepath"
	"testing"
)

func TestDNSObservationPathUsesDnsmasqJailRuntimeOnOpenWrt(t *testing.T) {
	if got := DNSObservationPath("/tmp/router-policy"); got != "/var/run/dnsmasq/router-policy-observations.log" {
		t.Fatalf("unexpected production observation path: %q", got)
	}
	custom := filepath.Join(t.TempDir(), "runtime")
	if got, want := DNSObservationPath(custom), filepath.Join(custom, "dns-observations.log"); got != want {
		t.Fatalf("custom runtime path=%q want=%q", got, want)
	}
}
