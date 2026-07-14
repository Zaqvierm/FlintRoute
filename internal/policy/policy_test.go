package policy

import (
	"testing"

	"router-policy/internal/config"
)

func TestOverridePrecedenceExactBeforeDeviceAndService(t *testing.T) {
	cfg := &config.Config{Overrides: []config.PolicyOverride{
		{ID: "category", Scope: "category", Category: "DIRECT_PREFERRED", RouteType: "vless"},
		{ID: "service", Scope: "service", Service: "video", RouteType: "zapret"},
		{ID: "device-domain", Scope: "device_domain", DeviceMAC: "aa:bb:cc:dd:ee:ff", Domain: "api.example.com", RouteType: "drop"},
		{ID: "exact", Scope: "exact_domain", Domain: "api.example.com", RouteType: "direct"},
	}}
	match, ok, err := Match(cfg, "API.EXAMPLE.COM.", "AA-BB-CC-DD-EE-FF", "video", "DIRECT_PREFERRED")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || match.Override.ID != "exact" || match.Source != "manual_override:exact_domain" {
		t.Fatalf("wrong precedence result: %+v ok=%v", match, ok)
	}
}

func TestDeviceDomainBeforeDeviceServiceAndService(t *testing.T) {
	cfg := &config.Config{Overrides: []config.PolicyOverride{
		{ID: "service", Scope: "service", Service: "video", RouteType: "direct"},
		{ID: "device-service", Scope: "device_service", DeviceMAC: "aa:bb:cc:dd:ee:ff", Service: "video", RouteType: "zapret"},
		{ID: "device-domain", Scope: "device_domain", DeviceMAC: "aa:bb:cc:dd:ee:ff", Domain: "api.example.com", RouteType: "vless"},
	}}
	match, ok, err := Match(cfg, "api.example.com", "aa:bb:cc:dd:ee:ff", "video", "DIRECT_PREFERRED")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || match.Override.ID != "device-domain" {
		t.Fatalf("device-domain did not win: %+v", match)
	}
}

func TestSelectRouteHonorsTagThenPriority(t *testing.T) {
	routes := []config.Route{
		{Type: "vless", Tag: "slow", Priority: 20},
		{Type: "vless", Tag: "fast", Priority: 10},
	}
	selected, ok := SelectRoute(MatchResult{Override: config.PolicyOverride{RouteTag: "slow"}}, routes)
	if !ok || selected.Tag != "slow" {
		t.Fatalf("route tag was ignored: %+v", selected)
	}
	selected, ok = SelectRoute(MatchResult{Override: config.PolicyOverride{RouteType: "vless"}}, routes)
	if !ok || selected.Tag != "fast" {
		t.Fatalf("route type did not use priority: %+v", selected)
	}
}

func TestMatchRejectsInvalidDeviceIdentity(t *testing.T) {
	if _, _, err := Match(&config.Config{}, "example.com", "not-a-mac", "", ""); err == nil {
		t.Fatal("invalid device identity was accepted")
	}
}
