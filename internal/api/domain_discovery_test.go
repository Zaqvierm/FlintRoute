package api

import (
	"testing"

	"router-policy/internal/planner"
	"router-policy/internal/probe"
)

func TestAutomaticServiceUsesVerifiedTSPUFallbackOrder(t *testing.T) {
	check := planner.DomainCheck{
		Domain: "www.video.example", ETLDPlusOne: "video.example",
		Category: "DIRECT_PREFERRED", TSPUStatus: "MATCH",
		Selected: &probe.RouteResult{Route: "zapret", RouteType: "zapret"},
	}
	service, id, ok := automaticServiceForDecision(check)
	if !ok || id != "auto_video_example" || service.Category != "TSPU_RESTRICTED" || service.SelectedRouteTag != "zapret" {
		t.Fatalf("automatic TSPU service mismatch: id=%q service=%+v ok=%v", id, service, ok)
	}
	expected := []string{"zapret", "smart_dns", "vless", "direct", "drop"}
	if len(service.AllowedPaths) != len(expected) {
		t.Fatalf("fallback count=%d", len(service.AllowedPaths))
	}
	for index := range expected {
		if service.AllowedPaths[index] != expected[index] {
			t.Fatalf("fallback order=%v", service.AllowedPaths)
		}
	}
}

func TestAutomaticServiceKeepsSmartDNSBeforeVPNForGeoDecision(t *testing.T) {
	check := planner.DomainCheck{
		Domain: "app.example", ETLDPlusOne: "app.example", Category: "GEO_LOCKED",
		Selected: &probe.RouteResult{Route: "smart-primary", RouteType: "smart_dns"},
	}
	service, _, ok := automaticServiceForDecision(check)
	if !ok || service.Category != "GEO_LOCKED" || !service.RequireNonRUEgress {
		t.Fatalf("automatic GEO service mismatch: %+v ok=%v", service, ok)
	}
	if len(service.AllowedPaths) < 2 || service.AllowedPaths[0] != "smart_dns" || service.AllowedPaths[1] != "vless" {
		t.Fatalf("Smart DNS is not checked before VPN: %v", service.AllowedPaths)
	}
}

func TestAutomaticServiceDoesNotPersistDirectOrDrop(t *testing.T) {
	for _, routeType := range []string{"direct", "drop"} {
		check := planner.DomainCheck{
			Domain: "plain.example", ETLDPlusOne: "plain.example",
			Selected: &probe.RouteResult{Route: routeType, RouteType: routeType},
		}
		if _, _, ok := automaticServiceForDecision(check); ok {
			t.Fatalf("%s decision should stay runtime-only", routeType)
		}
	}
}

func TestManualServiceRulePreservesUserFallbackOrder(t *testing.T) {
	category, service, err := serviceForClassifyRequest(serviceClassifyRequest{
		Domain:       "ChatGPT.com",
		Category:     "geo_locked",
		AllowedPaths: []string{"vless", "smart_dns"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if category != "GEO_LOCKED" || service.Domains[0] != "chatgpt.com" {
		t.Fatalf("normalized rule mismatch: category=%q service=%+v", category, service)
	}
	if len(service.ProbeURLs) != 1 || service.ProbeURLs[0].URL != "https://chatgpt.com/" || !service.ProbeURLs[0].Required {
		t.Fatalf("manual rule has no production probe target: %v", service.ProbeURLs)
	}
	if got := service.AllowedPaths; len(got) != 2 || got[0] != "vless" || got[1] != "smart_dns" {
		t.Fatalf("user fallback order changed: %v", got)
	}
	if !service.RequireNonRUEgress {
		t.Fatal("GEO rule lost non-RU egress requirement")
	}
}

func TestManualServiceRuleRejectsUnsafeOrDuplicateFallback(t *testing.T) {
	for name, paths := range map[string][]string{
		"unsafe_geo_direct": {"vless", "direct"},
		"duplicate":         {"zapret", "zapret"},
		"unsupported":       {"magic_proxy"},
	} {
		t.Run(name, func(t *testing.T) {
			category := "TSPU_RESTRICTED"
			if name == "unsafe_geo_direct" {
				category = "GEO_LOCKED"
			}
			if _, _, err := serviceForClassifyRequest(serviceClassifyRequest{
				Domain: "example.com", Category: category, AllowedPaths: paths,
			}); err == nil {
				t.Fatal("invalid custom fallback was accepted")
			}
		})
	}
}

func TestManualServiceRuleSupportsDirectAndDrop(t *testing.T) {
	tests := []struct {
		category string
		path     string
	}{
		{category: "DIRECT_ONLY", path: "direct"},
		{category: "BLOCKED", path: "drop"},
	}
	for _, test := range tests {
		t.Run(test.category, func(t *testing.T) {
			category, service, err := serviceForClassifyRequest(serviceClassifyRequest{
				Domain: "route.example", Category: test.category,
			})
			if err != nil {
				t.Fatal(err)
			}
			if category != test.category || len(service.AllowedPaths) != 1 || service.AllowedPaths[0] != test.path {
				t.Fatalf("unexpected service: category=%q service=%+v", category, service)
			}
		})
	}
}
