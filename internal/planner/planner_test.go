package planner

import (
	"context"
	"path/filepath"
	"reflect"
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

func TestSelectBestDoesNotTreatUnknownLatencyAsZero(t *testing.T) {
	results := []probe.RouteResult{
		{Route: "measured", RouteType: "vless", RoutePriority: 50, Status: "OK", PathVerified: true, ServiceOK: true, RouteLatencyMS: 120, RouteLatencyAvailable: true},
		{Route: "unknown", RouteType: "direct", RoutePriority: 50, Status: "OK", PathVerified: true, ServiceOK: true},
	}
	selected := SelectBest(results)
	if selected == nil || selected.Route != "measured" {
		t.Fatalf("unknown latency must not rank as zero: %+v", selected)
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

func TestUnknownDomainFailureIsNotCached(t *testing.T) {
	cfg := discoveryConfig(t)
	cache := openDecisionCache(t, cfg)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	prober := &scriptedProber{results: map[string]probe.RouteResult{}}
	opts := Options{
		RouteProber: prober, DecisionCache: cache, ActiveRevision: "rev-active",
		Now: func() time.Time { return now },
	}
	first, err := CheckDomain(context.Background(), cfg, "unreachable.example", "", opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "NO_SAFE_ROUTE" || first.VerificationState != "terminal_no_safe_route" || first.Confidence != 0 || first.Selected != nil {
		t.Fatalf("unexpected failed decision: %+v", first)
	}
	if got := cache.Snapshot(); len(got) != 0 {
		t.Fatalf("failed observation was persisted as a route decision: %+v", got)
	}
	firstCalls := len(prober.calls)
	if _, err := CheckDomain(context.Background(), cfg, "unreachable.example", "", opts); err != nil {
		t.Fatal(err)
	}
	if len(prober.calls) <= firstCalls {
		t.Fatalf("failed observation suppressed a fresh probe: before=%d after=%d", firstCalls, len(prober.calls))
	}
}

func TestCancelledDomainCheckNeverBecomesTerminalNoSafeRoute(t *testing.T) {
	cfg := discoveryConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	prober := &scriptedProber{results: map[string]probe.RouteResult{}}
	check, err := CheckDomain(ctx, cfg, "cancelled.example", "", Options{RouteProber: prober, ActiveRevision: "rev-active"})
	if err != nil {
		t.Fatal(err)
	}
	if check.Status != "VERIFYING" || check.VerificationState != "in_progress" || check.Reason != "verification_incomplete" {
		t.Fatalf("cancelled verification was exposed as terminal: %+v", check)
	}
	if len(prober.calls) != 0 {
		t.Fatalf("cancelled verification still probed candidates: %v", prober.calls)
	}
}

func TestClassificationConfidenceIsIndependentFromRouteConfidence(t *testing.T) {
	cfg := discoveryConfig(t)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"zapret": successfulResult("zapret", "zapret", "rev-active"),
	}}
	check, err := CheckDomain(context.Background(), cfg, "listed.example", "", Options{
		RouteProber: prober, ActiveRevision: "rev-active",
		TSPUResult: tspu.Match{Status: "MATCH", Source: "fixture", Evidence: "curated_match", Confidence: 0.42},
	})
	if err != nil {
		t.Fatal(err)
	}
	if check.Confidence != 1 || check.ClassificationConfidence != 0.42 || check.ClassificationSource != "fixture" || check.ClassificationEvidence != "curated_match" {
		t.Fatalf("classification and route confidence were mixed: %+v", check)
	}
}

func TestUnknownBaselineUsesSystemDefaultBeforeManagedDirect(t *testing.T) {
	cfg := discoveryConfig(t)
	cfg.Routes[0].RequiresAdapter = true
	cfg.Routes[0].AdapterMode = "direct"
	cfg.Routes[0].Mark = "0x41"
	plan, err := BuildCandidates(cfg, "new.example", "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) < 2 {
		t.Fatalf("candidate list is incomplete: %+v", plan.Candidates)
	}
	system := plan.Candidates[0]
	if system.Tag != "system-default" || system.Type != "direct" || system.AdapterMode != "system_default" || system.RequiresAdapter || system.Mark != "" {
		t.Fatalf("first unknown-domain candidate is not an unmarked system path: %+v", system)
	}
	if plan.Candidates[1].Tag != "direct" || !plan.Candidates[1].RequiresAdapter {
		t.Fatalf("managed Direct candidate was lost: %+v", plan.Candidates)
	}
}

func TestUnknownTSPUMatchDoesNotProbeSystemDefault(t *testing.T) {
	cfg := discoveryConfig(t)
	cfg.Routes[0].RequiresAdapter = true
	cfg.Routes[0].AdapterMode = "direct"
	plan, err := BuildCandidates(cfg, "discord.example", "", Options{TSPUResult: tspu.Match{Status: "MATCH"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) == 0 || plan.Candidates[0].Type != "zapret" {
		t.Fatalf("TSPU candidate order does not start with Zapret: %+v", plan.Candidates)
	}
	for _, route := range plan.Candidates {
		if route.Tag == "system-default" {
			t.Fatalf("TSPU plan leaked system default candidate: %+v", plan.Candidates)
		}
	}
}

func TestSystemDefaultResultBindsToCurrentRevision(t *testing.T) {
	route := config.Route{Type: "direct", Tag: "system-default", AdapterMode: "system_default"}
	result := bindResultToCandidate(probe.RouteResult{
		Route: route.Tag, RouteType: route.Type, Status: "OK", ApplicationStatus: "OK",
		PathVerified: true, ServiceOK: true,
	}, route, "rev-active")
	if result.Status != "OK" || result.AdapterRevision != "rev-active" || !result.PathVerified {
		t.Fatalf("system default proof was not bound to the active revision: %+v", result)
	}
}

func TestVerifiedRouteDoesNotExposeArbitraryPartialConfidence(t *testing.T) {
	check := DomainCheck{Selected: &probe.RouteResult{Route: "vless", RouteType: "vless", PathVerified: true, ServiceOK: true}}
	if confidence := decisionConfidence(check, tspu.Match{}); confidence != 1 {
		t.Fatalf("verified route confidence=%v, want 1", confidence)
	}
	if confidence := decisionConfidence(DomainCheck{}, tspu.Match{Status: "MATCH", Confidence: 0.9}); confidence != 0 {
		t.Fatalf("unselected route confidence=%v, want 0", confidence)
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

func TestTSPUFallbackOrderUsesZapretThenVLESSThenDrop(t *testing.T) {
	got := orderForService("TSPU_RESTRICTED", "MATCH", "zapret_first")
	want := []string{"zapret", "vless", "drop"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TSPU fallback order = %v, want %v", got, want)
	}
}

func TestTSPUCheckFallsBackFromZapretToVLESS(t *testing.T) {
	cfg := discoveryConfig(t)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"zapret":    failedResult("zapret", "zapret", "strategy_failed"),
		"smart-one": successfulResult("smart-one", "smart_dns", "rev-active"),
		"vless-one": successfulResult("vless-one", "vless", "rev-active"),
	}}
	result, err := CheckDomain(context.Background(), cfg, "listed.example", "", Options{
		RouteProber: prober, ActiveRevision: "rev-active",
		TSPUResult: tspu.Match{Status: "MATCH", Confidence: 0.94},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Selected == nil || result.Selected.Route != "vless-one" {
		t.Fatalf("VLESS was not selected after Zapret failed: %+v", result)
	}
	want := []string{"zapret", "vless-one"}
	if !reflect.DeepEqual(prober.calls, want) {
		t.Fatalf("unexpected TSPU fallback calls=%v", prober.calls)
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

func TestFailedProbeKeepsItsRealReasonWhenNoRevisionProofExists(t *testing.T) {
	reason := "route_nft_counter_did_not_advance"
	result := bindResultToCandidate(probe.RouteResult{
		Route: "smart-one", RouteType: "smart_dns", Status: "UNVERIFIED",
		ReasonCode: reason, Reason: &reason,
	}, config.Route{Tag: "smart-one", Type: "smart_dns"}, "rev-active")
	if result.ReasonCode != reason {
		t.Fatalf("real probe failure was hidden by revision mismatch: %+v", result)
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

func TestSelectedVLESSRemainsAfterZapretForTSPU(t *testing.T) {
	cfg := discoveryConfig(t)
	cfg.Services["observed"] = config.Service{
		Category: "TSPU_RESTRICTED", AllowedPaths: []string{"zapret", "vless", "drop"},
		SelectedRouteTag: "vless-one",
	}
	plan, err := BuildCandidates(cfg, "observed.example", "observed", Options{
		TSPUResult: tspu.Match{Status: "MATCH"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(plan.Candidates))
	for _, candidate := range plan.Candidates {
		got = append(got, candidate.Tag)
	}
	want := []string{"zapret", "vless-one", "drop"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selected VLESS changed TSPU fallback: got=%v want=%v", got, want)
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
