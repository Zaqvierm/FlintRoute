package planner

import (
	"context"
	"reflect"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/probe"
	"router-policy/internal/tspu"
)

func measuredSelectionResult(route, routeType string, latency int64) probe.RouteResult {
	return probe.RouteResult{
		Route: route, RouteType: routeType, Status: "OK", ApplicationStatus: "OK",
		PathVerified: true, ServiceOK: true, AdapterRevision: "rev-active", EndToEndLatencyMS: latency,
		EndToEndLatencyAvailable: true, ExternalCountry: "DE", EgressConsensus: true,
	}
}

func TestDropIsASelectableTerminalSafetyOutcome(t *testing.T) {
	results := []probe.RouteResult{
		{Route: "drop", RouteType: "drop", Status: "DROP", ReasonCode: "no_safe_route"},
	}
	if got := SelectBestWithPolicy(results, configPolicyForSelection(), "", nil); got == nil || got.Route != "drop" {
		t.Fatalf("DROP must remain a selectable terminal outcome: %+v", got)
	}
}

func TestSelectionUsesEndToEndLatencyNotPolicyOrder(t *testing.T) {
	results := []probe.RouteResult{
		measuredSelectionResult("smart-primary", "smart_dns", 70),
		measuredSelectionResult("vless-de", "vless", 40),
	}
	if got := SelectBestWithPolicy(results, configPolicyForSelection(), "", nil); got == nil || got.Route != "vless-de" {
		t.Fatalf("VLESS with lower end-to-end latency should win: %+v", got)
	}
	results[0].EndToEndLatencyMS = 35
	results[1].EndToEndLatencyMS = 60
	if got := SelectBestWithPolicy(results, configPolicyForSelection(), "", nil); got == nil || got.Route != "smart-primary" {
		t.Fatalf("Smart DNS with lower end-to-end latency should win: %+v", got)
	}
}

func TestDomainCheckExposesTheScoreUsedForSelection(t *testing.T) {
	cfg := discoveryConfig(t)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct":    measuredSelectionResult("direct", "direct", 90),
		"smart-one": measuredSelectionResult("smart-one", "smart_dns", 70),
		"vless-one": measuredSelectionResult("vless-one", "vless", 40),
	}}
	check, err := CheckDomain(context.Background(), cfg, "score.example", "", Options{RouteProber: prober, ActiveRevision: "rev-active"})
	if err != nil || check.Selected == nil || check.Selected.Route != "vless-one" {
		t.Fatalf("selection failed: %+v err=%v", check, err)
	}
	for _, result := range check.Results {
		if result.Route == "vless-one" && result.SelectionScore <= 0 {
			t.Fatalf("selected candidate did not expose its policy score: %+v", result)
		}
	}
}

func TestOrdinaryDomainSelectionUsesMeasuredDirectPath(t *testing.T) {
	cfg := discoveryConfig(t)
	cfg.Routes[0].RequiresAdapter = true
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"system-default": measuredSelectionResult("system-default", "direct", 20),
		"direct":         measuredSelectionResult("direct", "direct", 80),
		"smart-one":      measuredSelectionResult("smart-one", "smart_dns", 60),
		"vless-one":      measuredSelectionResult("vless-one", "vless", 50),
		"drop":           {Route: "drop", RouteType: "drop", Status: "DROP", ApplicationStatus: "DROP"},
	}}
	check, err := CheckDomain(context.Background(), cfg, "ordinary.example", "", Options{RouteProber: prober, ActiveRevision: "rev-active"})
	if err != nil || check.Selected == nil || check.Selected.Route != "system-default" || check.ClassificationState != "UNKNOWN" {
		t.Fatalf("ordinary domain did not select the fastest functional Direct path: %+v err=%v", check, err)
	}
}

func TestChatLikeServiceConfirmsGEOFromBackendRegionalDenial(t *testing.T) {
	cfg := discoveryConfig(t)
	cfg.Services["chat"] = config.Service{
		Category: "DIRECT_PREFERRED", ClassificationSeed: "GEO_LOCKED", Domains: []string{"chat.example"},
		AllowedPaths: []string{"direct", "smart_dns", "vless", "drop"},
		ProbeURLs: []config.ProbeCheck{
			{Name: "landing", URL: "https://chat.example/", Required: true, ExpectedCodes: []int{200}},
			{Name: "backend", URL: "https://chat.example/backend", Required: true, ExpectedCodes: []int{200}, RegionalBlockMarkers: []string{"unsupported_country"}},
		},
	}
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct":    {Route: "direct", RouteType: "direct", Status: "REGION_BLOCK", RegionalBlock: true},
		"smart-one": measuredSelectionResult("smart-one", "smart_dns", 70),
		"vless-one": measuredSelectionResult("vless-one", "vless", 40),
		"drop":      {Route: "drop", RouteType: "drop", Status: "DROP", ApplicationStatus: "DROP"},
	}}
	check, err := CheckDomain(context.Background(), cfg, "chat.example", "chat", Options{RouteProber: prober, ActiveRevision: "rev-active"})
	if err != nil || check.ClassificationState != "CONFIRMED_GEO_LOCKED" || check.ClassificationConfidence != 0 || check.Selected == nil || check.Selected.Route != "vless-one" {
		t.Fatalf("chat-like GEO flow did not require differential evidence and scoring: %+v err=%v", check, err)
	}
}

func TestSelectionHardFiltersRegionalAndIncompleteEvidence(t *testing.T) {
	results := []probe.RouteResult{
		{Route: "direct", RouteType: "direct", Status: "REGION_BLOCK", PathVerified: true, ServiceOK: false, RegionalBlock: true, EndToEndLatencyMS: 1, EndToEndLatencyAvailable: true},
		{Route: "fast-unverified", RouteType: "vless", Status: "OK", PathVerified: false, ServiceOK: true, EndToEndLatencyMS: 2, EndToEndLatencyAvailable: true},
		{Route: "fast-service-fail", RouteType: "smart_dns", Status: "OK", PathVerified: true, ServiceOK: false, EndToEndLatencyMS: 3, EndToEndLatencyAvailable: true},
		measuredSelectionResult("safe", "vless", 80),
	}
	got := SelectBestWithPolicy(results, configPolicyForSelection(), "", nil)
	if got == nil || got.Route != "safe" {
		t.Fatalf("hard safety filter selected an unsafe route: %+v", got)
	}
}

func TestSelectionHysteresisAvoidsFlapping(t *testing.T) {
	policy := configPolicyForSelection()
	policy.RouteSelectionHysteresisPercent = 15
	current := measuredSelectionResult("current", "vless", 100)
	newRoute := measuredSelectionResult("new", "smart_dns", 98)
	if got := SelectBestWithPolicy([]probe.RouteResult{current, newRoute}, policy, "current", nil); got == nil || got.Route != "current" {
		t.Fatalf("2%% improvement should not switch current route: %+v", got)
	}
	newRoute.EndToEndLatencyMS = 70
	if got := SelectBestWithPolicy([]probe.RouteResult{current, newRoute}, policy, "current", nil); got == nil || got.Route != "new" {
		t.Fatalf("material improvement should switch route: %+v", got)
	}
}

func TestSelectionCooldownHoldsCurrentRoute(t *testing.T) {
	now := time.Now().UTC()
	tracker := probe.NewHealthTracker([]probe.RouteHealth{{
		RouteTag: "current", RouteType: "vless", State: "healthy", Role: "selected",
		LastSuccessAt: now, ConsecutiveSuccesses: 3, AvailabilityEWMA: 1,
	}})
	policy := configPolicyForSelection()
	policy.RouteSelectionCooldownSeconds = 60
	results := []probe.RouteResult{measuredSelectionResult("current", "vless", 100), measuredSelectionResult("new", "smart_dns", 20)}
	if got := SelectBestWithPolicy(results, policy, "current", tracker); got == nil || got.Route != "current" {
		t.Fatalf("cooldown switched routes too early: %+v", got)
	}
}

func TestTSPUCandidateSetIncludesAllEligibleRouteTypes(t *testing.T) {
	cfg := discoveryConfig(t)
	plan, err := BuildCandidates(cfg, "blocked.example", "", Options{TSPUResult: tspuMatch("MATCH")})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, route := range plan.Candidates {
		seen[route.Type] = true
	}
	for _, routeType := range []string{"zapret", "smart_dns", "vless", "drop"} {
		if !seen[routeType] {
			t.Fatalf("TSPU eligibility omitted %s: %+v", routeType, plan.Candidates)
		}
	}
}

func TestDifferentialRegionalEvidenceRequiresFunctionalAlternate(t *testing.T) {
	cfg := discoveryConfig(t)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct":    {Route: "direct", RouteType: "direct", Status: "REGION_BLOCK", RegionalBlock: true, AdapterRevision: "rev-active"},
		"smart-one": measuredSelectionResult("smart-one", "smart_dns", 70),
		"vless-one": measuredSelectionResult("vless-one", "vless", 40),
	}}
	check, err := CheckDomain(context.Background(), cfg, "chat.example", "", Options{RouteProber: prober, ActiveRevision: "rev-active"})
	if err != nil {
		t.Fatal(err)
	}
	if check.ClassificationState != "CONFIRMED_GEO_LOCKED" || check.Selected == nil || check.Selected.Route != "vless-one" {
		t.Fatalf("differential GEO classification/selection wrong: %+v", check)
	}
	if !reflect.DeepEqual(prober.calls, []string{"direct", "smart-one", "vless-one", "drop"}) {
		t.Fatalf("unexpected differential probe set: %v", prober.calls)
	}
}

func TestGEOSelectionRejectsUnknownAlternateEgress(t *testing.T) {
	cfg := discoveryConfig(t)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct":    {Route: "direct", RouteType: "direct", Status: "REGION_BLOCK", RegionalBlock: true, AdapterRevision: "rev-active"},
		"smart-one": {Route: "smart-one", RouteType: "smart_dns", Status: "OK", PathVerified: true, ServiceOK: true, EndToEndLatencyMS: 1, EndToEndLatencyAvailable: true, AdapterRevision: "rev-active"},
		"vless-one": {Route: "vless-one", RouteType: "vless", Status: "OK", PathVerified: true, ServiceOK: true, EndToEndLatencyMS: 2, EndToEndLatencyAvailable: true, AdapterRevision: "rev-active"},
	}}
	check, err := CheckDomain(context.Background(), cfg, "unknown-egress.example", "", Options{RouteProber: prober, ActiveRevision: "rev-active"})
	if err != nil {
		t.Fatal(err)
	}
	if check.Selected != nil {
		t.Fatalf("unknown egress must not be selected for GEO_LOCKED: %+v", check.Selected)
	}
	if check.ClassificationState == "CONFIRMED_GEO_LOCKED" {
		t.Fatalf("unknown egress must not provide differential GEO confirmation: %q", check.ClassificationState)
	}
}

func TestGenericForbiddenResponsesDoNotConfirmGEO(t *testing.T) {
	cfg := discoveryConfig(t)
	for _, tag := range []string{"direct", "smart-one", "vless-one"} {
		// A generic 403 is not a regional denial. Keep the response typed as a
		// failed service check so the planner cannot turn it into GEO_LOCKED.
		_ = tag
	}
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct":    {Route: "direct", RouteType: "direct", Status: "FAIL", Checks: []probe.CheckResult{{HTTPCode: 403, Status: "FAIL", Reason: "unexpected_http_403"}}},
		"vless-one": {Route: "vless-one", RouteType: "vless", Status: "FAIL", Checks: []probe.CheckResult{{HTTPCode: 403, Status: "FAIL", Reason: "unexpected_http_403"}}},
	}}
	check, err := CheckDomain(context.Background(), cfg, "auth.example", "", Options{RouteProber: prober, ActiveRevision: "rev-active"})
	if err != nil {
		t.Fatal(err)
	}
	if check.ClassificationState == "CONFIRMED_GEO_LOCKED" || check.Category == "GEO_LOCKED" {
		t.Fatalf("generic 403 responses falsely confirmed GEO: %+v", check)
	}
}

func TestDecisionCacheInvalidatesWhenCandidateInventoryChanges(t *testing.T) {
	cfg := discoveryConfig(t)
	cache := openDecisionCache(t, cfg)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct": successfulResult("direct", "direct", "rev-active"),
	}}
	opts := Options{RouteProber: prober, DecisionCache: cache, ActiveRevision: "rev-active"}
	first, err := CheckDomain(context.Background(), cfg, "cache.example", "", opts)
	if err != nil || first.Cached || first.Selected == nil {
		t.Fatalf("initial decision failed: %+v err=%v", first, err)
	}
	initialCalls := len(prober.calls)
	cfg.Routes = append(cfg.Routes, config.Route{Type: "vless", Tag: "new-vless", Priority: 5, SOCKS5: "127.0.0.1:12080", DNSMode: "socks_remote"})
	second, err := CheckDomain(context.Background(), cfg, "cache.example", "", opts)
	if err != nil {
		t.Fatal(err)
	}
	if second.Cached || len(prober.calls) <= initialCalls {
		t.Fatalf("candidate inventory change reused stale cache: cached=%v calls=%v", second.Cached, prober.calls)
	}
}

func TestDecisionCacheInvalidatesWhenServiceManifestChanges(t *testing.T) {
	cfg := discoveryConfig(t)
	cfg.Services["known"] = config.Service{
		Category: "DIRECT_PREFERRED", Domains: []string{"manifest.example"},
		AllowedPaths: []string{"direct", "smart_dns", "vless", "drop"},
		ProbeURLs:    []config.ProbeCheck{{Name: "landing", URL: "https://manifest.example/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}},
	}
	cache := openDecisionCache(t, cfg)
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct":    successfulResult("direct", "direct", "rev-active"),
		"smart-one": successfulResult("smart-one", "smart_dns", "rev-active"),
		"vless-one": successfulResult("vless-one", "vless", "rev-active"),
		"drop":      successfulResult("drop", "drop", "rev-active"),
	}}
	opts := Options{RouteProber: prober, DecisionCache: cache, ActiveRevision: "rev-active"}
	if _, err := CheckDomain(context.Background(), cfg, "manifest.example", "known", opts); err != nil {
		t.Fatal(err)
	}
	initialCalls := len(prober.calls)
	cfg.Services["known"].ProbeURLs[0].SuccessMarkers = []string{"new-marker"}
	second, err := CheckDomain(context.Background(), cfg, "manifest.example", "known", opts)
	if err != nil {
		t.Fatal(err)
	}
	if second.Cached || len(prober.calls) <= initialCalls {
		t.Fatalf("service manifest change reused cached decision: cached=%v calls=%v", second.Cached, prober.calls)
	}
}

func TestDecisionCacheInvalidatesAfterRouteHealthDegradation(t *testing.T) {
	cfg := discoveryConfig(t)
	cfg.Policy.FailAfterConsecutiveErrors = 1
	cache := openDecisionCache(t, cfg)
	tracker := configHealthTrackerForTest("direct")
	prober := &scriptedProber{results: map[string]probe.RouteResult{
		"direct": successfulResult("direct", "direct", "rev-active"),
	}}
	opts := Options{RouteProber: prober, DecisionCache: cache, ActiveRevision: "rev-active", HealthTracker: tracker}
	if _, err := CheckDomain(context.Background(), cfg, "health-cache.example", "", opts); err != nil {
		t.Fatal(err)
	}
	// The first successful observation changes the cache fingerprint once; the
	// next call refreshes it, and a third call must then be a true cache hit.
	if _, err := CheckDomain(context.Background(), cfg, "health-cache.example", "", opts); err != nil {
		t.Fatal(err)
	}
	settled, err := CheckDomain(context.Background(), cfg, "health-cache.example", "", opts)
	if err != nil {
		t.Fatal(err)
	}
	settledCalls := len(prober.calls)
	if !settled.Cached {
		t.Fatalf("settled healthy decision was not cached: %+v", settled)
	}
	if _, ok := tracker.Get("direct"); !ok {
		t.Fatal("direct route health was not tracked")
	}
	tracker.Observe(failedResult("direct", "direct", "connect_timeout"), cfg.Policy, time.Now().UTC())
	check, err := CheckDomain(context.Background(), cfg, "health-cache.example", "", opts)
	if err != nil {
		t.Fatal(err)
	}
	if check.Cached || len(prober.calls) <= settledCalls {
		t.Fatalf("health degradation reused cached decision: cached=%v calls=%v", check.Cached, prober.calls)
	}
}

func configHealthTrackerForTest(routeTag string) *probe.HealthTracker {
	return probe.NewHealthTracker([]probe.RouteHealth{{
		RouteTag: routeTag, RouteType: "direct", State: "healthy", Role: "active", AvailabilityEWMA: 1,
	}})
}

func configPolicyForSelection() config.Policy {
	return config.Policy{RouteSelectionStrategy: "fastest"}
}

func tspuMatch(status string) tspu.Match { return tspu.Match{Status: status} }
