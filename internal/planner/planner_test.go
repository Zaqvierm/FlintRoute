package planner

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/domaincache"
	"router-policy/internal/probe"
	"router-policy/internal/state"
	"router-policy/internal/tspu"
)

func TestGeoLockedCandidatesExcludeDirectAndZapret(t *testing.T) {
	cfg := &config.Config{
		Version: 2,
		Policy:  config.Policy{},
		Routes: []config.Route{
			{Type: "direct", Tag: "direct"},
			{Type: "zapret", Tag: "zapret"},
			{Type: "smart_dns", Tag: "smart"},
			{Type: "vless", Tag: "vless-a"},
		},
		Services: map[string]config.Service{
			"openai": {
				Category:       "GEO_LOCKED",
				AllowedPaths:   []string{"smart_dns", "vless", "drop"},
				ForbiddenPaths: []string{"direct", "zapret"},
			},
		},
	}
	plan, err := BuildCandidates(cfg, "chatgpt.com", "openai", Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range plan.Candidates {
		if c.Type == "direct" || c.Type == "zapret" {
			t.Fatalf("unsafe route in GEO_LOCKED candidates: %+v", plan.Candidates)
		}
	}
}

func TestSelectBestPrefersRoutePriorityOverSmallLatencyWin(t *testing.T) {
	results := []probe.RouteResult{
		{Route: "zapret", RouteType: "zapret", RoutePriority: 20, Status: "OK", PathVerified: true, ServiceOK: true, LatencyMS: 100},
		{Route: "vless-frankfurt", RouteType: "vless", RoutePriority: 50, Status: "OK", PathVerified: true, ServiceOK: true, LatencyMS: 70},
	}
	selected := SelectBest(results)
	if selected == nil || selected.Route != "zapret" {
		t.Fatalf("expected zapret to win by priority, got %+v", selected)
	}
}

func TestDirectOnlyCandidatesOnlyDirect(t *testing.T) {
	cfg := &config.Config{
		Version: 2,
		Routes: []config.Route{
			{Type: "direct", Tag: "direct"},
			{Type: "vless", Tag: "vless-a"},
		},
		Services: map[string]config.Service{
			"bank": {
				Category:       "DIRECT_ONLY",
				AllowedPaths:   []string{"direct"},
				ForbiddenPaths: []string{"vless"},
			},
		},
	}
	plan, err := BuildCandidates(cfg, "bank.test", "bank", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) != 1 || plan.Candidates[0].Type != "direct" {
		t.Fatalf("expected only direct, got %+v", plan.Candidates)
	}
}

func TestSelectBestRejectsUnverifiedApplicationSuccess(t *testing.T) {
	results := []probe.RouteResult{{
		Route: "direct", RouteType: "direct", Status: "UNVERIFIED", ApplicationStatus: "OK", ServiceOK: true,
	}}
	if selected := SelectBest(results); selected != nil {
		t.Fatalf("unverified route must not be selected: %+v", selected)
	}
}

func TestBuildCandidatesUsesSmartDNSHealthOrder(t *testing.T) {
	tracker := probe.NewHealthTracker([]probe.RouteHealth{
		{RouteTag: "smart-primary", RouteType: "smart_dns", State: "unhealthy", Score: 0},
		{RouteTag: "smart-secondary", RouteType: "smart_dns", State: "healthy", Score: 80},
	})
	cfg := &config.Config{
		Routes: []config.Route{
			{Type: "smart_dns", Tag: "smart-primary", Priority: 10, DNSServer: "192.0.2.53", ConnectToResolvedIP: true},
			{Type: "smart_dns", Tag: "smart-secondary", Priority: 20, DNSServer: "192.0.2.54", ConnectToResolvedIP: true},
		},
		Services: map[string]config.Service{"svc": {Category: "GEO_LOCKED", AllowedPaths: []string{"smart_dns"}}},
	}
	plan, err := BuildCandidates(cfg, "example.test", "svc", Options{HealthTracker: tracker})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) < 2 || plan.Candidates[0].Tag != "smart-secondary" {
		t.Fatalf("health-aware Smart DNS failover order not used: %+v", plan.Candidates)
	}
}

func TestUnknownDomainDirectSuccessIsCachedAndReused(t *testing.T) {
	cfg := discoveryConfig(t)
	cache := openDecisionCache(t, cfg)
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct": successfulResult("direct", "direct", "rev-active"),
	}}
	opts := Options{
		RouteProber: prober, DecisionCache: cache, ActiveRevision: "rev-active",
		Now: func() time.Time { return now },
	}
	first, err := CheckDomain(context.Background(), cfg, "Api.Example.COM.", "", opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.Service != "UNKNOWN:example.com" || first.Selected == nil || first.Selected.Route != "direct" || first.Cached {
		t.Fatalf("unexpected discovery result: %+v", first)
	}
	if got := prober.calls; len(got) != 1 || got[0] != "direct" {
		t.Fatalf("direct success should stop fallback queue: %v", got)
	}

	second, err := CheckDomain(context.Background(), cfg, "api.example.com", "", opts)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Cached || second.Selected == nil || second.Selected.Route != "direct" || len(prober.calls) != 1 {
		t.Fatalf("cached decision was not reused: %+v calls=%v", second, prober.calls)
	}
}

func TestCachedNoMatchDecisionIsInvalidatedByFreshTSPUMatch(t *testing.T) {
	cfg := discoveryConfig(t)
	cache := openDecisionCache(t, cfg)
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct": successfulResult("direct", "direct", "rev-active"),
		"zapret": successfulResult("zapret", "zapret", "rev-active"),
	}}
	base := Options{RouteProber: prober, DecisionCache: cache, ActiveRevision: "rev-active", Now: func() time.Time { return now }}
	if _, err := CheckDomain(context.Background(), cfg, "api.example.com", "", base); err != nil {
		t.Fatal(err)
	}
	base.TSPUResult = tspu.Match{Status: "MATCH", Confidence: 0.9}
	result, err := CheckDomain(context.Background(), cfg, "api.example.com", "", base)
	if err != nil {
		t.Fatal(err)
	}
	if result.Cached || result.Selected == nil || result.Selected.Route != "zapret" {
		t.Fatalf("fresh TSPU signal reused unsafe cached direct route: %+v", result)
	}
	if len(prober.calls) != 2 || prober.calls[1] != "zapret" {
		t.Fatalf("expected a fresh Zapret probe, calls=%v", prober.calls)
	}
}

func TestManualExactOverrideWinsBeforeTSPUAndCache(t *testing.T) {
	cfg := discoveryConfig(t)
	cfg.Overrides = []config.PolicyOverride{{ID: "force-direct", Scope: "exact_domain", Domain: "api.example.com", RouteTag: "direct"}}
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct": successfulResult("direct", "direct", "rev-active"),
		"zapret": successfulResult("zapret", "zapret", "rev-active"),
	}}
	result, err := CheckDomain(context.Background(), cfg, "api.example.com", "", Options{
		RouteProber: prober, ActiveRevision: "rev-active", TSPUResult: tspu.Match{Status: "MATCH", Confidence: 0.99},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Selected == nil || result.Selected.Route != "direct" || result.OverrideID != "force-direct" || result.PolicySource != "manual_override:exact_domain" {
		t.Fatalf("manual exact policy did not win: %+v", result)
	}
	if len(prober.calls) != 1 || prober.calls[0] != "direct" {
		t.Fatalf("TSPU path ran before manual override: %v", prober.calls)
	}
}

func TestInvalidDeviceIdentityBlocksPolicyResolution(t *testing.T) {
	cfg := discoveryConfig(t)
	if _, err := BuildCandidates(cfg, "example.com", "", Options{DeviceMAC: "not-a-mac"}); err == nil {
		t.Fatal("invalid device identity was silently ignored")
	}
}

func TestDirectTSPUSymptomFallsBackToZapret(t *testing.T) {
	cfg := discoveryConfig(t)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct": {
			Route: "direct", RouteType: "direct", Status: "SUSPECTED_TSPU", SuspectedTSPU: true,
			AdapterRevision: "rev-active", Checks: []probe.CheckResult{{Name: "https", Status: "SUSPECTED_TSPU"}},
		},
		"zapret": successfulResult("zapret", "zapret", "rev-active"),
	}}
	result, err := CheckDomain(context.Background(), cfg, "blocked.example", "", Options{RouteProber: prober, ActiveRevision: "rev-active"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Selected == nil || result.Selected.Route != "zapret" {
		t.Fatalf("zapret fallback not selected: %+v", result)
	}
	if got := prober.calls; len(got) != 2 || got[0] != "direct" || got[1] != "zapret" {
		t.Fatalf("wrong fallback order: %v", got)
	}
}

func TestOrdinaryDirectFailureSkipsZapretAndTriesSmartDNS(t *testing.T) {
	cfg := discoveryConfig(t)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct":    failedResult("direct", "direct", "dns_failed"),
		"smart-one": successfulResult("smart-one", "smart_dns", "rev-active"),
	}}
	result, err := CheckDomain(context.Background(), cfg, "offline.example", "", Options{RouteProber: prober, ActiveRevision: "rev-active"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Selected == nil || result.Selected.Route != "smart-one" {
		t.Fatalf("Smart DNS fallback not selected: %+v", result)
	}
	if got := prober.calls; len(got) != 2 || got[0] != "direct" || got[1] != "smart-one" {
		t.Fatalf("ordinary failure must not invoke Zapret: %v", got)
	}
}

func TestFreshTSPUMatchStartsWithZapret(t *testing.T) {
	cfg := discoveryConfig(t)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"zapret": successfulResult("zapret", "zapret", "rev-active"),
	}}
	result, err := CheckDomain(context.Background(), cfg, "listed.example", "", Options{
		RouteProber: prober, ActiveRevision: "rev-active",
		TSPUResult: tspu.Match{Status: "MATCH", Confidence: 0.94},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Selected == nil || result.Selected.Route != "zapret" || len(prober.calls) != 1 || prober.calls[0] != "zapret" {
		t.Fatalf("fresh TSPU match did not start with Zapret: %+v calls=%v", result, prober.calls)
	}
}

func TestRegionalBlockRemovesDirectAndZapretFromRemainingQueue(t *testing.T) {
	cfg := discoveryConfig(t)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct": {
			Route: "direct", RouteType: "direct", Status: "REGION_BLOCK", RegionalBlock: true,
			AdapterRevision: "rev-active",
		},
		"smart-one": successfulResult("smart-one", "smart_dns", "rev-active"),
	}}
	result, err := CheckDomain(context.Background(), cfg, "geo.example", "", Options{RouteProber: prober, ActiveRevision: "rev-active"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Category != "GEO_LOCKED" || result.Selected == nil || result.Selected.Route != "smart-one" {
		t.Fatalf("regional fallback failed: %+v", result)
	}
	if got := prober.calls; len(got) != 2 || got[0] != "direct" || got[1] != "smart-one" {
		t.Fatalf("Zapret was not excluded after regional block: %v", got)
	}
	if len(prober.services) < 2 || !prober.services[1].RequireNonRUEgress || prober.services[1].Category != "GEO_LOCKED" {
		t.Fatalf("GEO_LOCKED evidence requirements not applied to fallback: %+v", prober.services)
	}
}

func TestStaleTSPUFailClosedUsesOnlyDrop(t *testing.T) {
	cfg := discoveryConfig(t)
	cfg.Policy.TSPUStalePolicy = "fail_closed"
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"drop": successfulResult("drop", "drop", "rev-active"),
	}}
	result, err := CheckDomain(context.Background(), cfg, "stale.example", "", Options{
		RouteProber: prober, ActiveRevision: "rev-active", TSPUResult: tspu.Match{Status: "STALE_MATCH"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "DROP" || result.Selected == nil || result.Selected.RouteType != "drop" {
		t.Fatalf("stale fail-closed did not enforce drop: %+v", result)
	}
	if len(prober.calls) != 1 || prober.calls[0] != "drop" {
		t.Fatalf("fail-closed probed unsafe paths: %v", prober.calls)
	}
}

func TestWrongRevisionCannotBeSelected(t *testing.T) {
	cfg := discoveryConfig(t)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct":    successfulResult("direct", "direct", "rev-old"),
		"smart-one": successfulResult("smart-one", "smart_dns", "rev-active"),
	}}
	result, err := CheckDomain(context.Background(), cfg, "revision.example", "", Options{RouteProber: prober, ActiveRevision: "rev-active"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Selected == nil || result.Selected.Route != "smart-one" || result.Results[0].Status != "UNVERIFIED" || result.Results[0].ReasonCode != "probe_adapter_revision_mismatch" {
		t.Fatalf("wrong revision evidence was accepted: %+v", result)
	}
}

func TestBuildCandidatesUsesSelectedVLESSFirst(t *testing.T) {
	tracker := probe.NewHealthTracker([]probe.RouteHealth{
		{RouteTag: "vless-standby", RouteType: "vless", State: "healthy", Role: "standby", Score: 95, EWMALatencyMS: 20},
		{RouteTag: "vless-selected", RouteType: "vless", State: "healthy", Role: "selected", Score: 80, EWMALatencyMS: 80},
	})
	cfg := &config.Config{
		Routes:   []config.Route{{Type: "vless", Tag: "vless-standby"}, {Type: "vless", Tag: "vless-selected"}},
		Services: map[string]config.Service{"svc": {Category: "GEO_LOCKED", AllowedPaths: []string{"vless"}}},
	}
	plan, err := BuildCandidates(cfg, "example.test", "svc", Options{HealthTracker: tracker})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) != 2 || plan.Candidates[0].Tag != "vless-selected" {
		t.Fatalf("selected VLESS was not first: %+v", plan.Candidates)
	}
}

type scriptedProber struct {
	results  map[string]probe.RouteResult
	calls    []string
	services []config.Service
}

func (p *scriptedProber) ProbeRoute(_ context.Context, _ *config.Config, domain, serviceName string, service config.Service, route config.Route) probe.RouteResult {
	p.calls = append(p.calls, route.Tag)
	p.services = append(p.services, service)
	result, ok := p.results[route.Tag]
	if !ok {
		result = failedResult(route.Tag, route.Type, "scripted_failure")
	}
	result.Domain = domain
	result.Service = serviceName
	result.RoutePriority = route.Priority
	return result
}

func successfulResult(tag, routeType, revision string) probe.RouteResult {
	return probe.RouteResult{
		Route: tag, RouteType: routeType, Status: "OK", ApplicationStatus: "OK",
		PathVerified: true, ServiceOK: true, AdapterRevision: revision,
	}
}

func failedResult(tag, routeType, reason string) probe.RouteResult {
	return probe.RouteResult{
		Route: tag, RouteType: routeType, Status: "FAIL", ApplicationStatus: "FAIL",
		ReasonCode: reason, Checks: []probe.CheckResult{{Name: "https", Status: "FAIL", Reason: reason}},
	}
}

func discoveryConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Platform: config.Platform{Target: "test"},
		Storage:  config.Storage{StateDir: dir, Database: filepath.Join(dir, "state.bbolt")},
		Policy:   config.Policy{DomainDecisionTTLSeconds: 86400, TSPUStalePolicy: "zapret_first"},
		Routes: []config.Route{
			{Type: "direct", Tag: "direct", Priority: 10},
			{Type: "zapret", Tag: "zapret", Priority: 20},
			{Type: "smart_dns", Tag: "smart-one", Priority: 30, DNSServer: "192.0.2.53", ConnectToResolvedIP: true},
			{Type: "vless", Tag: "vless-one", Priority: 40, SOCKS5: "127.0.0.1:12080", DNSMode: "socks_remote"},
			{Type: "drop", Tag: "drop", Priority: 1000},
		},
		Services: map[string]config.Service{},
	}
}

func openDecisionCache(t *testing.T, cfg *config.Config) *domaincache.Manager {
	t.Helper()
	store, err := state.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	manager, err := domaincache.New(store, 100)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}
