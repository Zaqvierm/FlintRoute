package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/discovery"
	"router-policy/internal/planner"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
)

func newDiscoveryModeServer(t *testing.T, mode string, verified bool, fake *fakeAdapter) (*Server, *int) {
	t.Helper()
	cfg := testAPIConfig(t)
	cfg.Services = map[string]config.Service{}
	cfg.Policy.DiscoveryMode = mode
	cfg.Policy.DiscoveryMaxNewRulesPerHour = 4
	cfg.Policy.DiscoveryMaxConsecutiveRollbacks = 3
	cfg.OpenWrt.RollbackTimeoutSeconds = 120
	calls := 0
	checker := func(_ context.Context, _ *config.Config, domain, _ string, _ planner.Options) (planner.DomainCheck, error) {
		calls++
		return planner.DomainCheck{
			Domain: domain, ETLDPlusOne: domain, Category: "GEO_LOCKED", Status: "OK", Confidence: 0.99,
			Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", Status: "OK", ApplicationStatus: "OK", PathVerified: verified, ServiceOK: true},
		}, nil
	}
	srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true, DomainChecker: checker})
	if err != nil {
		t.Fatal(err)
	}
	return srv, &calls
}

func TestDiscoveryObserveOnlyNeverCreatesSuggestionOrChange(t *testing.T) {
	fake := newFakeAdapter()
	srv, calls := newDiscoveryModeServer(t, "observe_only", true, fake)
	defer srv.Close()
	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "observe.example", QueryType: "A"})
	if *calls != 0 || len(srv.discoverySuggestions(10)) != 0 || len(fake.calls) != 0 {
		t.Fatalf("observe_only changed state: calls=%d suggestions=%d adapter=%v", *calls, len(srv.discoverySuggestions(10)), fake.calls)
	}
}

func TestDiscoveryDebouncesAAndAAAAForSameDomain(t *testing.T) {
	fake := newFakeAdapter()
	srv, calls := newDiscoveryModeServer(t, "observe_only", true, fake)
	defer srv.Close()
	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "dual-stack.example", QueryType: "A"})
	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "dual-stack.example", QueryType: "AAAA"})
	if *calls != 0 {
		t.Fatalf("observe-only DNS lookup produced %d domain checks", *calls)
	}
}

func TestDiscoveryDeduplicatesSubdomainsByETLDPlusOne(t *testing.T) {
	fake := newFakeAdapter()
	srv, calls := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "cdn-a.example.com", QueryType: "A"})
	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "cdn-b.example.com", QueryType: "A"})
	if *calls != 1 {
		t.Fatalf("subdomains of one service were probed %d times", *calls)
	}
}

func TestDiscoveryCandidateDetailsExcludeProxySecrets(t *testing.T) {
	items := discoveryCandidateDetails([]probe.RouteResult{{
		Route: "vless-one", RouteType: "vless", Status: "OK", PathVerified: true, ServiceOK: true,
		XrayOutboundTag: "secret-bearing-tag",
	}})
	if len(items) != 1 {
		t.Fatalf("candidate details=%+v", items)
	}
	if _, ok := items[0]["xray_outbound"]; ok {
		t.Fatal("Xray outbound leaked into decision event")
	}
	if items[0]["route_latency_available"] != false || items[0]["verification_duration_ms"] != int64(0) {
		t.Fatalf("missing explicit latency/verification semantics: %+v", items[0])
	}
	if _, ok := items[0]["latency_ms"]; ok {
		t.Fatal("unavailable route latency was serialized as a zero measurement")
	}
}

func TestCachedVerificationDurationUsesStoredEvidence(t *testing.T) {
	check := planner.DomainCheck{
		Cached: true, VerificationDurationMS: 812,
		Selected: &probe.RouteResult{VerificationDurationMS: 731},
	}
	if got := checkVerificationDuration(check); got != 812 {
		t.Fatalf("cached decision duration=%d, want full stored evidence 812", got)
	}
	check.VerificationDurationMS = 0
	if got := checkVerificationDuration(check); got != 731 {
		t.Fatalf("cached legacy decision duration=%d, want selected evidence 731", got)
	}
	if got := checkVerificationDuration(planner.DomainCheck{Cached: true}); got != 0 {
		t.Fatalf("cached decision without selected evidence duration=%d, want 0", got)
	}
	if got := checkVerificationDuration(planner.DomainCheck{VerificationState: "verified"}); got != 0 {
		t.Fatalf("missing planner duration=%d, want 0", got)
	}
}

func TestPlannerProbeStateNeverTreatsVerificationAsNoSafeRoute(t *testing.T) {
	if got := plannerProbeState(planner.DomainCheck{Status: "VERIFYING", VerificationState: "in_progress"}); got != "verifying" {
		t.Fatalf("in-progress check mapped to %q", got)
	}
	if got := plannerProbeState(planner.DomainCheck{Status: "NO_SAFE_ROUTE", VerificationState: "terminal_no_safe_route"}); got != "no_safe_route" {
		t.Fatalf("terminal exhaustion mapped to %q", got)
	}
	if got := plannerProbeState(planner.DomainCheck{Status: "SELECTED", VerificationState: "verified", Selected: &probe.RouteResult{PathVerified: true}}); got != "verified_candidate" {
		t.Fatalf("verified check mapped to %q", got)
	}
	if got := plannerProbeState(planner.DomainCheck{Status: "SELECTED", VerificationState: "verified", Selected: &probe.RouteResult{PathVerified: false}}); got != "verifying" {
		t.Fatalf("unverified candidate mapped to %q", got)
	}
}

func TestDiscoveryObservationStatusDistinguishesWaitingAndReceiving(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "observe_only", true, fake)
	defer srv.Close()
	srv.dnsObservationPath = t.TempDir() + "/dns.log"
	if status := srv.discoveryObservationStatus()["status"]; status != "waiting" {
		t.Fatalf("missing observation log status=%v", status)
	}
	if err := os.WriteFile(srv.dnsObservationPath, []byte("query[A] example.test from 192.0.2.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if status := srv.discoveryObservationStatus()["status"]; status != "receiving" {
		t.Fatalf("active observation log status=%v", status)
	}
}

func TestDiscoverySuggestKeepsBoundedSuggestionWithoutApply(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "suggest.example", QueryType: "AAAA"})
	items := srv.discoverySuggestions(10)
	if len(items) != 1 || items[0].Domain != "suggest.example" || !items[0].PathVerified || len(fake.calls) != 0 {
		t.Fatalf("suggest mode result=%+v adapter=%v", items, fake.calls)
	}
	if items[0].ClassificationState != "classified" || items[0].ProbeState != "verified_candidate" || items[0].PolicyState != "suggested" {
		t.Fatalf("suggest mode mixed classification, probe and policy states: %+v", items[0])
	}
}

func TestDiscoverySuggestionsStayBoundedInMemory(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	for index := 0; index < maxDiscoverySuggestions+20; index++ {
		domain := fmt.Sprintf("domain-%03d.example", index)
		srv.saveDiscoverySuggestion(discovery.Observation{Domain: domain, QueryType: "A"}, planner.DomainCheck{Domain: domain})
	}
	if got := len(srv.discoverySuggestions(maxDiscoverySuggestions + 20)); got != maxDiscoverySuggestions {
		t.Fatalf("suggestion cache size=%d want=%d", got, maxDiscoverySuggestions)
	}
}

func TestDiscoveryLockedDoesNotProbe(t *testing.T) {
	fake := newFakeAdapter()
	srv, calls := newDiscoveryModeServer(t, "locked", true, fake)
	defer srv.Close()
	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "locked.example", QueryType: "A"})
	if *calls != 0 || len(fake.calls) != 0 {
		t.Fatalf("locked discovery ran work: checker=%d adapter=%v", *calls, fake.calls)
	}
}

func TestDiscoveryAutoApplyRequiresPathVerifiedAndRemainsNonMutating(t *testing.T) {
	t.Run("unverified", func(t *testing.T) {
		fake := newFakeAdapter()
		srv, _ := newDiscoveryModeServer(t, "auto_apply_verified", false, fake)
		defer srv.Close()
		srv.discoverDomain(context.Background(), discovery.Observation{Domain: "unverified.example", QueryType: "A"})
		if len(fake.calls) != 0 {
			t.Fatalf("unverified path reached adapter: %v", fake.calls)
		}
	})
	t.Run("verified", func(t *testing.T) {
		fake := newFakeAdapter()
		srv, _ := newDiscoveryModeServer(t, "auto_apply_verified", true, fake)
		defer srv.Close()
		srv.discoverDomain(context.Background(), discovery.Observation{Domain: "verified.example", QueryType: "A"})
		if service := srv.currentConfig().ServiceForDomain("verified.example"); service != "" || len(fake.calls) != 0 {
			t.Fatalf("verified discovery mutated dataplane: service=%q calls=%v", service, fake.calls)
		}
		suggestions := srv.discoverySuggestions(10)
		if len(suggestions) != 1 || suggestions[0].PolicyState != "suggested" {
			t.Fatalf("verified discovery did not leave a suggestion: %+v", suggestions)
		}
	})
}

func TestDiscoveryAutoApplySafetyLimits(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "auto_apply_verified", true, fake)
	defer srv.Close()
	check := planner.DomainCheck{Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", PathVerified: true}}

	srv.mu.Lock()
	srv.changes["busy"] = ChangeSet{ID: "busy", State: "awaiting_confirmation"}
	srv.mu.Unlock()
	if err := srv.discoveryAutoAllowed(srv.currentConfig(), check); err == nil {
		t.Fatal("active transaction did not block auto-apply")
	}
	srv.mu.Lock()
	delete(srv.changes, "busy")
	srv.mu.Unlock()

	now := time.Now().UTC()
	state := discoveryControlState{AppliedAt: []time.Time{now, now, now, now}}
	if err := srv.store.SaveJSON("discovery", discoveryStateKey, state); err != nil {
		t.Fatal(err)
	}
	if err := srv.discoveryAutoAllowed(srv.currentConfig(), check); err == nil {
		t.Fatal("hourly rule limit did not block auto-apply")
	}
	state = discoveryControlState{ConsecutiveRollbacks: 3, PausedReason: "consecutive_rollbacks"}
	if err := srv.store.SaveJSON("discovery", discoveryStateKey, state); err != nil {
		t.Fatal(err)
	}
	if err := srv.discoveryAutoAllowed(srv.currentConfig(), check); err == nil {
		t.Fatal("rollback circuit breaker did not block auto-apply")
	}
	if err := validateDiscoveryOperations([]ChangeOp{{Type: "set", Path: "/openwrt/firewall_include", Value: "/tmp/x"}}); err == nil {
		t.Fatal("discovery accepted a firewall change")
	}
	if err := validateDiscoveryOperations([]ChangeOp{{Type: "set", Path: "/platform/management", Value: true}}); err == nil {
		t.Fatal("discovery accepted a management change")
	}
}

func TestDiscoveryRollbackCircuitBreakerStopsFurtherApply(t *testing.T) {
	fake := newFakeAdapter()
	fake.fail["verify_management_path"] = true
	srv, _ := newDiscoveryModeServer(t, "auto_apply_verified", true, fake)
	defer srv.Close()
	for _, domain := range []string{"one.example", "two.example", "three.example", "four.example"} {
		srv.discoverDomain(context.Background(), discovery.Observation{Domain: domain, QueryType: "A"})
	}
	state := srv.loadDiscoveryState()
	if state.ConsecutiveRollbacks != 0 || state.PausedReason != "" || len(fake.calls) != 0 {
		t.Fatalf("disabled auto-apply performed mutation: state=%+v calls=%v", state, fake.calls)
	}
}

func TestDomainCheckerFailureDoesNotCreateSuggestion(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	srv.domainChecker = func(context.Context, *config.Config, string, string, planner.Options) (planner.DomainCheck, error) {
		return planner.DomainCheck{}, errors.New("probe failed")
	}
	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "failed.example", QueryType: "A"})
	if len(srv.discoverySuggestions(10)) != 0 {
		t.Fatal("failed observation created a suggestion")
	}
}

func TestDiscoveryRuntimeSettingsOverrideConfigWithoutAdapterWork(t *testing.T) {
	fake := newFakeAdapter()
	srv, calls := newDiscoveryModeServer(t, "observe_only", true, fake)
	defer srv.Close()
	state := discoveryControlState{Configured: true, Mode: "locked", MaxNewRulesPerHour: 9, MaxRollbacks: 5}
	if err := srv.store.SaveJSON("discovery", discoveryStateKey, state); err != nil {
		t.Fatal(err)
	}
	mode, hourly, rollbacks, loaded := srv.effectiveDiscoverySettings(srv.currentConfig())
	if mode != "locked" || hourly != 9 || rollbacks != 5 || !loaded.Configured {
		t.Fatalf("runtime settings were not applied: mode=%s hourly=%d rollbacks=%d state=%+v", mode, hourly, rollbacks, loaded)
	}
	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "locked-runtime.example", QueryType: "A"})
	if *calls != 0 || len(fake.calls) != 0 {
		t.Fatalf("runtime-only mode touched probe or adapter: checker=%d adapter=%v", *calls, fake.calls)
	}
}
