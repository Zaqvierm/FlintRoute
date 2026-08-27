package api

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"router-policy/internal/config"
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
	expected := []string{"zapret", "smart_dns", "vless", "drop"}
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

func TestAutomaticServiceAllowsVerifiedUnknownRouteAssignment(t *testing.T) {
	check := planner.DomainCheck{
		Domain: "new.example", ETLDPlusOne: "new.example", Category: "DIRECT_PREFERRED",
		Selected: &probe.RouteResult{Route: "smart-primary", RouteType: "smart_dns"},
	}
	service, _, ok := automaticServiceForDecision(check)
	if !ok || service.Category != "DIRECT_PREFERRED" || len(service.AllowedPaths) != 5 {
		t.Fatalf("unknown route assignment was not represented as a bounded direct-preferred policy: %+v ok=%v", service, ok)
	}
	for _, path := range []string{"direct", "zapret", "smart_dns", "vless", "drop"} {
		found := false
		for _, allowed := range service.AllowedPaths {
			if allowed == path {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("unknown route assignment omitted allowed path %q: %v", path, service.AllowedPaths)
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

func TestTSPUDefaultFallbackIsZapretThenVLESSThenDrop(t *testing.T) {
	_, service, err := serviceForClassifyRequest(serviceClassifyRequest{
		Domain: "discord.com", Category: "TSPU_RESTRICTED",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"zapret", "smart_dns", "vless", "drop"}
	if !reflect.DeepEqual(service.AllowedPaths, want) {
		t.Fatalf("TSPU fallback=%v, want %v", service.AllowedPaths, want)
	}
}

func TestManualServiceRuleStoresOnlyVerifiedSelectedRoute(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Routes = append(cfg.Routes, config.Route{Type: "vless", Tag: "vpn"})
	srv := &Server{activeConfig: cfg, activeRevision: "rev-test"}
	srv.domainChecker = func(_ context.Context, candidate *config.Config, domain, serviceID string, opts planner.Options) (planner.DomainCheck, error) {
		if domain != "discord.com" || serviceID != "user_discord_com" {
			t.Fatalf("unexpected verification target: %s %s", domain, serviceID)
		}
		if got := candidate.Services[serviceID].AllowedPaths; len(got) != 4 || got[0] != "zapret" || got[1] != "smart_dns" || got[2] != "vless" || got[3] != "drop" {
			t.Fatalf("candidate lost fallback order: %v", got)
		}
		if opts.TSPUResult.Status != "MATCH" {
			t.Fatalf("manual TSPU classification did not start with Zapret: %+v", opts.TSPUResult)
		}
		return planner.DomainCheck{
			Domain: domain, Service: serviceID, Status: "SELECTED",
			Selected: &probe.RouteResult{Route: "vpn", RouteType: "vless", Status: "OK", ServiceOK: true, PathVerified: true},
		}, nil
	}
	service := config.Service{
		Category: "TSPU_RESTRICTED", Domains: []string{"discord.com"},
		AllowedPaths: []string{"zapret", "smart_dns", "vless", "drop"},
		ProbeURLs:    []config.ProbeCheck{{URL: "https://discord.com/", Required: true}},
	}
	check, err := srv.selectVerifiedServiceRoute(context.Background(), "user_discord_com", service)
	if err != nil {
		t.Fatal(err)
	}
	if check.Selected == nil || check.Selected.Route != "vpn" {
		t.Fatalf("verified route was not selected: %+v", check)
	}
}

func TestManualServiceRuleAcceptsTransportVerifiedCandidateForGuardedApply(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Routes = append(cfg.Routes, config.Route{Type: "vless", Tag: "vpn"})
	srv := &Server{activeConfig: cfg, activeRevision: "rev-test"}
	srv.domainChecker = func(context.Context, *config.Config, string, string, planner.Options) (planner.DomainCheck, error) {
		return planner.DomainCheck{
			Status: "NO_SAFE_ROUTE",
			Results: []probe.RouteResult{{
				Route: "vpn", RouteType: "vless", Status: "UNVERIFIED",
				DNSOK: true, TransportOK: true, TLSOK: true, HTTPOK: true, ContentOK: true, ServiceOK: true,
				ReasonCode: "route_not_bound_to_verification_plan",
			}},
		}, nil
	}
	check, err := srv.selectVerifiedServiceRoute(context.Background(), "user_chatgpt_com", config.Service{
		Category: "GEO_LOCKED", Domains: []string{"chatgpt.com"}, AllowedPaths: []string{"smart_dns", "vless", "drop"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if check.Selected == nil || check.Selected.Route != "vpn" || check.Selected.PathVerified || check.Status != "CANDIDATE_REQUIRES_APPLY" {
		t.Fatalf("guarded apply candidate was not preserved honestly: %+v", check)
	}
}

func TestManualServiceRuleRejectsUnboundCandidateWithoutServiceProof(t *testing.T) {
	cfg := testAPIConfig(t)
	srv := &Server{activeConfig: cfg, activeRevision: "rev-test"}
	srv.domainChecker = func(context.Context, *config.Config, string, string, planner.Options) (planner.DomainCheck, error) {
		return planner.DomainCheck{Results: []probe.RouteResult{{
			Route: "smart", RouteType: "smart_dns", Status: "UNVERIFIED", DNSOK: true, TransportOK: true,
			ReasonCode: "route_not_bound_to_verification_plan",
		}}}, nil
	}
	_, err := srv.selectVerifiedServiceRoute(context.Background(), "user_chatgpt_com", config.Service{
		Category: "GEO_LOCKED", Domains: []string{"chatgpt.com"}, AllowedPaths: []string{"smart_dns", "vless", "drop"},
	})
	if err == nil || !strings.Contains(err.Error(), "no safe route") {
		t.Fatalf("candidate without service proof was accepted: %v", err)
	}
}

func TestObservationClassificationDoesNotExposeResolvedDirectAsUnknown(t *testing.T) {
	classification, display := observationClassification("UNKNOWN:chess.com", "DIRECT_PREFERRED", "direct", 1)
	if classification != "direct" || display != "chess.com" {
		t.Fatalf("direct observation classification=(%q,%q)", classification, display)
	}
	classification, display = observationClassification("UNKNOWN:sentry.io", "DIRECT_PREFERRED", "", 0)
	if classification != "unknown" || display != "sentry.io" {
		t.Fatalf("unresolved observation classification=(%q,%q)", classification, display)
	}
	classification, _ = observationClassification("discord", "TSPU_RESTRICTED", "zapret", 1)
	if classification != "known_service" {
		t.Fatalf("known service classification=%q", classification)
	}
}

func TestRouteTypeInOrderRejectsStaleDirectForTSPU(t *testing.T) {
	order := []string{"zapret", "smart_dns", "vless", "drop"}
	if routeTypeInOrder(order, "direct") || !routeTypeInOrder(order, "vless") {
		t.Fatalf("route order membership is wrong for TSPU: %v", order)
	}
}

func TestManualServiceRuleRejectsNoSafeRouteBeforeDraft(t *testing.T) {
	cfg := testAPIConfig(t)
	srv := &Server{activeConfig: cfg, activeRevision: "rev-test"}
	srv.domainChecker = func(context.Context, *config.Config, string, string, planner.Options) (planner.DomainCheck, error) {
		return planner.DomainCheck{Status: "NO_SAFE_ROUTE", TSPUStatus: "UNAVAILABLE"}, nil
	}
	_, err := srv.selectVerifiedServiceRoute(context.Background(), "user_example_com", config.Service{
		Category: "DIRECT_PREFERRED", Domains: []string{"example.com"}, AllowedPaths: []string{"direct", "drop"},
	})
	if err == nil || !strings.Contains(err.Error(), "no safe route") {
		t.Fatalf("unsafe rule was accepted: %v", err)
	}
}
