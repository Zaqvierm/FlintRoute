package netpolicy

import (
	"net/netip"
	"testing"
)

func TestPublicResolverAddrRejectsSpecialRanges(t *testing.T) {
	for _, raw := range []string{"0.0.0.0", "127.0.0.1", "192.168.1.1", "100.64.0.1", "192.0.2.53", "198.51.100.53", "203.0.113.53", "224.0.0.1", "::1", "2001:db8::53", "fc00::53"} {
		if PublicResolverAddr(netip.MustParseAddr(raw)) {
			t.Fatalf("special-purpose resolver accepted: %s", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !PublicResolverAddr(netip.MustParseAddr(raw)) {
			t.Fatalf("public resolver rejected: %s", raw)
		}
	}
}
