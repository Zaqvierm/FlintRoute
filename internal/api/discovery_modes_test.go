package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/discovery"
	"router-policy/internal/health"
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
			Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", Status: "OK", ApplicationStatus: "OK", PathVerified: verified, ServiceOK: true, ExternalCountry: "DE", EgressConsensus: true},
		}, nil
	}
	srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true, DomainChecker: checker})
	if err != nil {
		t.Fatal(err)
	}
	srv.probeEngineFactory = func(*config.Config) health.ProbeEngine {
		return routeAssignmentProofEngine{revision: srv.activeRevision}
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
	if got := plannerProbeState(planner.DomainCheck{Status: "NO_SAFE_ROUTE"}); got != "verifying" {
		t.Fatalf("unproven exhaustion mapped to %q", got)
	}
	if got := plannerProbeState(planner.DomainCheck{Status: "NO_SAFE_ROUTE", VerificationState: "corrupt"}); got != "verifying" {
		t.Fatalf("corrupt exhaustion mapped to %q", got)
	}
	if got := plannerProbeState(planner.DomainCheck{Status: "SELECTED", VerificationState: "verified", Selected: &probe.RouteResult{PathVerified: true}}); got != "verified_candidate" {
		t.Fatalf("verified check mapped to %q", got)
	}
	if got := plannerProbeState(planner.DomainCheck{Status: "SELECTED", VerificationState: "verified", Selected: &probe.RouteResult{PathVerified: false}}); got != "verifying" {
		t.Fatalf("unverified candidate mapped to %q", got)
	}
	if got := plannerProbeState(planner.DomainCheck{Status: "DROP", VerificationState: "verified", Selected: &probe.RouteResult{RouteType: "drop", Status: "DROP"}}); got != "drop_enforced" {
		t.Fatalf("terminal DROP mapped to %q", got)
	}
}

func TestDiscoveryObservationStatusDistinguishesWaitingAndReceiving(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "observe_only", true, fake)
	defer srv.Close()
	srv.mu.Lock()
	srv.activeConfig.Policy.UnknownDomainBackgroundCheck = true
	srv.mu.Unlock()
	srv.dnsObservationPath = t.TempDir() + "/dns.log"
	if status := srv.discoveryObservationStatus()["status"]; status != "waiting" {
		t.Fatalf("missing observation log status=%v", status)
	}
	if err := os.WriteFile(srv.dnsObservationPath, []byte("query[A] example.test from 192.0.2.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if status := srv.discoveryObservationStatus()["status"]; status != "listening" {
		t.Fatalf("active observation log status=%v", status)
	}
}

func TestDiscoveryObservationStatusReportsDisabledSeparately(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "observe_only", true, fake)
	defer srv.Close()
	srv.dnsObservationPath = filepath.Join(t.TempDir(), "dns.log")
	status := srv.discoveryObservationStatus()
	if status["status"] != "disabled" || status["enabled"] != false || status["source"] != "dnsmasq_query_log" {
		t.Fatalf("disabled observation was not reported explicitly: %#v", status)
	}
	if status["reason"] != "dns_observation_disabled" {
		t.Fatalf("disabled observation reason=%v", status["reason"])
	}
}

func TestDiscoveryObservationStatusReportsStaleLog(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "observe_only", true, fake)
	defer srv.Close()
	srv.mu.Lock()
	srv.activeConfig.Policy.UnknownDomainBackgroundCheck = true
	srv.mu.Unlock()
	srv.dnsObservationPath = filepath.Join(t.TempDir(), "dns.log")
	if err := os.WriteFile(srv.dnsObservationPath, []byte("query[A] old.example from 192.0.2.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(srv.dnsObservationPath, old, old); err != nil {
		t.Fatal(err)
	}
	status := srv.discoveryObservationStatus()
	if status["status"] != "stale" || status["enabled"] != true {
		t.Fatalf("stale observation log was not reported explicitly: %#v", status)
	}
}

func TestDiscoveryStatusReportsAutoApplyUnavailableWithoutRuntimeConsumer(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "auto_apply_verified", true, fake)
	defer srv.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/discovery", nil)
	srv.handleDiscovery(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("discovery status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data struct {
			Mode               string `json:"mode"`
			ConfiguredMode     string `json:"configured_mode"`
			EffectiveMode      string `json:"effective_mode"`
			AutoApplyAvailable bool   `json:"auto_apply_available"`
			AutoApplyReason    string `json:"auto_apply_reason"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	got := envelope.Data
	if got.Mode != "auto_apply_verified" || got.ConfiguredMode != "auto_apply_verified" {
		t.Fatalf("configured mode was not preserved for diagnosis: %+v", got)
	}
	if got.EffectiveMode != "suggest" || got.AutoApplyAvailable || got.AutoApplyReason != "route_assignment_runtime_unavailable" {
		t.Fatalf("unavailable auto-apply was not reported truthfully: %+v", got)
	}
}

func TestDiscoveryStatusReportsAutoApplyReadyWithRuntimeConsumer(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "auto_apply_verified", true, fake)
	defer srv.Close()
	srv.routeAssignmentRuntime = &fakeRouteAssignmentRuntime{}

	recorder := httptest.NewRecorder()
	srv.handleDiscovery(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/discovery", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("discovery status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"effective_mode":"auto_apply_verified"`) ||
		!strings.Contains(recorder.Body.String(), `"auto_apply_available":true`) {
		t.Fatalf("ready auto-apply status was not reported: %s", recorder.Body.String())
	}
}

func TestDNSObservationFlowsFromWriterToObserveOnlyDecision(t *testing.T) {
	fake := newFakeAdapter()
	srv, calls := newDiscoveryModeServer(t, "observe_only", true, fake)
	defer srv.Close()
	srv.mu.Lock()
	srv.activeConfig.Policy.UnknownDomainBackgroundCheck = true
	if srv.activeRevision == "" {
		srv.activeRevision = "fixture-revision"
	}
	srv.mu.Unlock()
	srv.dnsObservationPath = filepath.Join(t.TempDir(), "dns.log")
	if err := os.WriteFile(srv.dnsObservationPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.startDNSDiscovery(ctx)
	// StartAtEnd establishes the initial cursor asynchronously.  Wait for that
	// bounded startup pass before appending; otherwise the test write can race
	// with initialization and be classified as historical input by design.
	time.Sleep(1200 * time.Millisecond)
	file, err := os.OpenFile(srv.dnsObservationPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("query[A] fresh-observation.example from 192.0.2.44\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(4 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		for _, event := range srv.broker.Recent(0, 100) {
			if event.Type != "route.decision" || event.ReasonCode != "domain_observed_only" {
				continue
			}
			if event.Details["domain"] == "fresh-observation.example" {
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !found {
		t.Fatalf("DNS observation did not reach Decision Flow; events=%+v", srv.broker.Recent(0, 100))
	}
	if *calls != 0 || len(fake.calls) != 0 {
		t.Fatalf("observe-only DNS observation performed active work: checker=%d adapter=%v", *calls, fake.calls)
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
	if items[0].ClassificationState != "UNKNOWN" || items[0].ProbeState != "verified_candidate" || items[0].PolicyState != "suggested" {
		t.Fatalf("suggest mode mixed classification, probe and policy states: %+v", items[0])
	}
}

func TestDiscoverySuggestionApplyCommitsRevisionBoundRouteAssignment(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	srv.routeAssignmentRuntime = &fakeRouteAssignmentRuntime{}
	srv.saveDiscoverySuggestion(discovery.Observation{Domain: "apply.example", QueryType: "A"}, planner.DomainCheck{
		Domain: "apply.example", ETLDPlusOne: "apply.example", Category: "GEO_LOCKED", Confidence: 0.99,
		ClassificationConfidence: 0.95, ClassificationSource: "fixture", ClassificationEvidence: "geo_match",
		Status: "SELECTED", VerificationState: "verified",
		Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", PathVerified: true, ServiceOK: true, Status: "OK", ExternalCountry: "DE", EgressConsensus: true},
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/suggestions/apply.example/apply", strings.NewReader("{}"))
	srv.handleDiscoverySuggestionAction(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("suggestion apply status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"post_apply_proof_kind":"revision_bound_path_evidence"`) {
		t.Fatalf("suggestion apply did not describe its proof boundary: %s", recorder.Body.String())
	}
	if calls := fakeAdapterCallCount(fake); calls != 0 {
		t.Fatalf("route-only suggestion apply invoked adapter calls=%d", calls)
	}
	decision, ok, err := srv.domainDecisions.Lookup("apply.example", srv.activeRevision, time.Now().UTC())
	if err != nil || !ok || decision.SelectedRoute != "smart" || decision.Status != "SELECTED" {
		t.Fatalf("suggestion apply did not persist selected route: ok=%v err=%v decision=%+v", ok, err, decision)
	}
	items := srv.discoverySuggestions(10)
	if len(items) != 1 || items[0].PolicyState != "applied" {
		t.Fatalf("suggestion was not marked applied: %+v", items)
	}
}

func TestDiscoverySuggestionApplyIsFencedWithoutRuntimeConsumer(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	srv.saveDiscoverySuggestion(discovery.Observation{Domain: "fenced.example", QueryType: "A"}, planner.DomainCheck{
		Domain: "fenced.example", ETLDPlusOne: "fenced.example", Category: "GEO_LOCKED", Confidence: 0.99,
		ClassificationConfidence: 0.95, ClassificationSource: "fixture", ClassificationEvidence: "geo_match",
		Status: "SELECTED", VerificationState: "verified",
		Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", PathVerified: true, ServiceOK: true, Status: "OK", ExternalCountry: "DE", EgressConsensus: true},
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/suggestions/fenced.example/apply", strings.NewReader("{}"))
	srv.handleDiscoverySuggestionAction(recorder, request)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "route_assignment_runtime_unavailable") {
		t.Fatalf("missing runtime consumer was not exposed as a safe conflict: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if items := srv.discoverySuggestions(10); len(items) != 1 || items[0].PolicyState != "suggested" {
		t.Fatalf("fenced suggestion was not retained for later retry: %+v", items)
	}
}

func TestDiscoverySuggestionPersistsAndReloadsWithoutPerObservationStateWrite(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	srv.saveDiscoverySuggestion(discovery.Observation{Domain: "persisted.example", QueryType: "A", Client: "192.0.2.44"}, planner.DomainCheck{
		Domain: "persisted.example", Category: "GEO_LOCKED", Confidence: 0.91,
		ClassificationConfidence: 0.8, ClassificationSource: "fixture", ClassificationEvidence: "geo_match",
		Status: "SELECTED", VerificationState: "verified",
		Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", PathVerified: true, Status: "OK"},
	})
	var persisted []discoverySuggestion
	if err := srv.store.LoadJSON("discovery", discoverySuggestionKey, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 1 || persisted[0].Domain != "persisted.example" || persisted[0].Count != 1 {
		t.Fatalf("persisted suggestion=%+v", persisted)
	}
	srv.mu.Lock()
	srv.discoverySuggestionMap = map[string]discoverySuggestion{}
	srv.mu.Unlock()
	srv.loadPersistedDiscoverySuggestions()
	items := srv.discoverySuggestions(10)
	if len(items) != 1 || items[0].Domain != "persisted.example" || items[0].Client != "192.0.2.44" {
		t.Fatalf("reloaded suggestion=%+v", items)
	}
}

func TestDiscoverySuggestionsDeduplicatePersistedSubdomainsByETLDPlusOne(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()

	for _, domain := range []string{"cdn-a.example.com", "cdn-b.example.com"} {
		if err := srv.saveDiscoverySuggestion(discovery.Observation{Domain: domain, QueryType: "A"}, planner.DomainCheck{
			Domain: domain, Category: "UNKNOWN", Confidence: 0.9,
			Status: "SELECTED", VerificationState: "verified",
			Selected: &probe.RouteResult{Route: "direct", RouteType: "direct", PathVerified: true, ServiceOK: true, Status: "OK"},
		}); err != nil {
			t.Fatalf("save suggestion %s: %v", domain, err)
		}
	}
	items := srv.discoverySuggestions(10)
	if len(items) != 1 || items[0].Domain != "cdn-b.example.com" || items[0].Count != 2 {
		t.Fatalf("persisted subdomains were not coalesced: %+v", items)
	}
	var persisted []discoverySuggestion
	if err := srv.store.LoadJSON("discovery", discoverySuggestionKey, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 1 || persisted[0].Count != 2 {
		t.Fatalf("durable subdomain suggestions were duplicated: %+v", persisted)
	}
}

func TestDiscoverySuggestionPersistenceFailureIsReturned(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	srv.store.SetFaultHook(func(operation string) error {
		if operation == "save_json:discovery" {
			return errors.New("injected discovery persistence failure")
		}
		return nil
	})

	err := srv.saveDiscoverySuggestion(discovery.Observation{Domain: "durability.example", QueryType: "A"}, planner.DomainCheck{
		Domain: "durability.example", Category: "UNKNOWN", Confidence: 0.9,
		Status: "SELECTED", VerificationState: "verified",
		Selected: &probe.RouteResult{Route: "direct", RouteType: "direct", PathVerified: true, ServiceOK: true, Status: "OK"},
	})
	if err == nil || !strings.Contains(err.Error(), "injected discovery persistence failure") {
		t.Fatalf("discovery persistence failure was hidden: %v", err)
	}
	if items := srv.discoverySuggestions(10); len(items) != 1 || items[0].Domain != "durability.example" {
		t.Fatalf("in-memory suggestion was unexpectedly discarded after observable write failure: %+v", items)
	}
}

func TestDiscoverySuggestionRejectsUnverifiedTerminalClaim(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()

	err := srv.saveDiscoverySuggestion(discovery.Observation{Domain: "unverified.example", QueryType: "A"}, planner.DomainCheck{
		Domain: "unverified.example", Category: "UNKNOWN", Status: "NO_SAFE_ROUTE",
		VerificationState: "terminal_no_safe_route", Reason: "no_verified_policy_allowed_route",
	})
	if err == nil || !strings.Contains(err.Error(), "terminal candidate evidence") {
		t.Fatalf("empty terminal claim was accepted: %v", err)
	}
	if got := len(srv.discoverySuggestions(10)); got != 0 {
		t.Fatalf("unverified terminal claim created %d suggestions", got)
	}
}

func TestDiscoveryPersistenceFailureBlocksAutomaticAssignment(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "auto_apply_verified", true, fake)
	defer srv.Close()
	runtime := &fakeRouteAssignmentRuntime{}
	srv.routeAssignmentRuntime = runtime
	srv.domainChecker = func(_ context.Context, _ *config.Config, domain, _ string, _ planner.Options) (planner.DomainCheck, error) {
		selected := probe.RouteResult{Route: "smart", RouteType: "smart_dns", Status: "OK", PathVerified: true, ServiceOK: true, ExternalCountry: "DE", EgressConsensus: true}
		return planner.DomainCheck{Domain: domain, ETLDPlusOne: domain, Category: "GEO_LOCKED", Status: "SELECTED", VerificationState: "verified", Confidence: 0.99, Selected: &selected, Results: []probe.RouteResult{selected}}, nil
	}
	srv.store.SetFaultHook(func(operation string) error {
		if operation == "save_json:discovery" {
			return errors.New("injected discovery persistence failure")
		}
		return nil
	})

	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "durability-auto.example", QueryType: "A"})
	if runtime.applied != 0 || runtime.rolledBack != 0 {
		t.Fatalf("automatic assignment ran without durable suggestion evidence: runtime=%+v", runtime)
	}
	found := false
	for _, event := range srv.broker.Recent(0, 0) {
		if event.ReasonCode == "discovery_suggestion_persist_failed" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("discovery persistence failure was not published as an observable event: %+v", srv.broker.Recent(0, 0))
	}
}

func TestDiscoveryControlStatePersistenceFailureIsReturned(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "auto_apply_verified", true, fake)
	defer srv.Close()
	srv.store.SetFaultHook(func(operation string) error {
		if operation == "save_json:discovery" {
			return errors.New("injected discovery control-state failure")
		}
		return nil
	})

	err := srv.recordDiscoveryAutoResult(automaticCommitResult{Applied: true, Reason: "fixture"})
	if err == nil || !strings.Contains(err.Error(), "injected discovery control-state failure") {
		t.Fatalf("discovery control-state persistence failure was hidden: %v", err)
	}
}

func TestDiscoveryVerifyingSuggestionRemainsTransient(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	srv.saveDiscoverySuggestionTransient(discovery.Observation{Domain: "pending.example", QueryType: "A"}, planner.DomainCheck{
		Domain: "pending.example", Category: "UNKNOWN", Status: "VERIFYING", VerificationState: "in_progress",
	})
	items := srv.discoverySuggestions(10)
	if len(items) != 1 || items[0].ProbeState != "verifying" {
		t.Fatalf("transient suggestion=%+v", items)
	}
	var persisted []discoverySuggestion
	if err := srv.store.LoadJSON("discovery", discoverySuggestionKey, &persisted); err == nil && len(persisted) != 0 {
		t.Fatalf("in-progress suggestion was persisted: %+v", persisted)
	}
}

func TestDiscoverySuggestionSeparatesClassificationAndDecisionConfidence(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	srv.saveDiscoverySuggestion(discovery.Observation{Domain: "evidence.example", QueryType: "A"}, planner.DomainCheck{
		Domain: "evidence.example", Category: "TSPU_RESTRICTED", Confidence: 1,
		ClassificationConfidence: 0.42, ClassificationSource: "fixture", ClassificationEvidence: "curated_match",
		Status: "SELECTED", VerificationState: "verified",
		Selected: &probe.RouteResult{Route: "zapret", RouteType: "zapret", PathVerified: true, ServiceOK: true, Status: "OK"},
	})
	items := srv.discoverySuggestions(10)
	if len(items) != 1 {
		t.Fatalf("suggestion count=%d", len(items))
	}
	item := items[0]
	if item.DecisionConfidence != 1 || item.ClassificationConfidence != 0.42 || item.ClassificationSource != "fixture" || item.ClassificationEvidence != "curated_match" {
		t.Fatalf("confidence fields were mixed or dropped: %+v", item)
	}
}

func TestDiscoverySuggestionDoesNotPersistDropAsUsableRoute(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	srv.saveDiscoverySuggestion(discovery.Observation{Domain: "blocked.example", QueryType: "A"}, planner.DomainCheck{
		Domain: "blocked.example", Category: "GEO_LOCKED", Status: "DROP", VerificationState: "verified",
		Selected: &probe.RouteResult{Route: "drop", RouteType: "drop", Status: "OK", ApplicationStatus: "DROP"},
	})
	items := srv.discoverySuggestions(10)
	if len(items) != 1 || items[0].Route != "" || items[0].PathVerified || items[0].ProbeState != "drop_enforced" {
		t.Fatalf("DROP was persisted as a usable suggestion: %+v", items)
	}
}

func TestDiscoverySuggestionsStayBoundedInMemory(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	for index := 0; index < maxDiscoverySuggestions+20; index++ {
		domain := fmt.Sprintf("domain-%03d.example", index)
		if err := srv.saveDiscoverySuggestion(discovery.Observation{Domain: domain, QueryType: "A"}, planner.DomainCheck{
			Domain: domain, Category: "UNKNOWN", Confidence: 0.9,
			Status: "SELECTED", VerificationState: "verified",
			Selected: &probe.RouteResult{Route: "direct", RouteType: "direct", PathVerified: true, ServiceOK: true, Status: "OK"},
		}); err != nil {
			t.Fatalf("save suggestion %s: %v", domain, err)
		}
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
