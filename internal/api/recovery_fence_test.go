package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/health"
	"router-policy/internal/planner"
	"router-policy/internal/probe"
)

func fakeAdapterCallCount(fake *fakeAdapter) int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return len(fake.calls)
}

type routeAssignmentProofEngine struct {
	revision  string
	fail      bool
	failRoute string
}

type fakeRouteAssignmentRuntime struct {
	applied       int
	rolledBack    int
	invalid       bool
	badBinding    bool
	appliedRoutes []string
}

func (r *fakeRouteAssignmentRuntime) ApplyRouteAssignment(_ context.Context, request RouteAssignmentRequest) (RouteAssignmentReceipt, error) {
	r.applied++
	r.appliedRoutes = append(r.appliedRoutes, request.RouteTag)
	receipt := RouteAssignmentReceipt{
		ProtocolVersion: request.ProtocolVersion,
		RequestID:       request.RequestID,
		Operation:       "route_assignment.apply",
		Applied:         true,
		Verified:        true,
		Generation:      request.Generation,
		RevisionID:      request.RevisionID,
		Domain:          request.Domain,
		RouteTag:        request.RouteTag,
		RouteType:       request.RouteType,
		RouteSetID:      request.RouteSetID,
		AssignmentID:    request.AssignmentID,
		MappingHash:     request.MappingHash,
	}
	if r.invalid {
		receipt.Operation = "route_assignment.unknown"
	}
	if r.badBinding {
		receipt.MappingHash = "sha256:wrong-binding"
	}
	return receipt, nil
}

func (r *fakeRouteAssignmentRuntime) RollbackRouteAssignment(_ context.Context, _ RouteAssignmentRequest, _ RouteAssignmentReceipt) error {
	r.rolledBack++
	return nil
}

func (e routeAssignmentProofEngine) ProbeRoute(_ context.Context, _ *config.Config, domain, service string, _ config.Service, route config.Route) probe.RouteResult {
	if e.fail || route.Tag == e.failRoute {
		return probe.RouteResult{
			Domain: domain, Service: service, Route: route.Tag, RouteType: route.Type,
			Status: "FAIL", ApplicationStatus: "FAIL", AdapterRevision: e.revision,
		}
	}
	return probe.RouteResult{
		Domain: domain, Service: service, Route: route.Tag, RouteType: route.Type,
		Status: "OK", ApplicationStatus: "OK", PathVerified: true, ServiceOK: true,
		DNSOK: true, TransportOK: true, TLSOK: true, HTTPOK: true, ContentOK: true,
		ExternalCountry: "DE", EgressConsensus: true, AdapterRevision: e.revision,
	}
}

func TestAutomaticDomainCommitRetriesNextVerifiedCandidateAfterPostProofFailure(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Routes = append(cfg.Routes, config.Route{Type: "vless", Tag: "vless", SOCKS5: "127.0.0.1:12000", DNSMode: "socks_remote", DNSServer: cfg.Xray.ProbeDNSResolver, Mark: "0x44"})
	cfg.Xray.OutboundBundleSHA256 = "sha256:" + strings.Repeat("a", 64)
	fake := newFakeAdapter()
	srv, ts, _, _, _ := newTransactionHTTP(t, cfg, fake)
	defer ts.Close()
	defer srv.Close()
	runtime := &fakeRouteAssignmentRuntime{}
	srv.routeAssignmentRuntime = runtime
	srv.probeEngineFactory = func(*config.Config) health.ProbeEngine {
		return routeAssignmentProofEngine{revision: srv.activeRevision, failRoute: "smart"}
	}

	selected := probe.RouteResult{Route: "smart", RouteType: "smart_dns", Status: "OK", PathVerified: true, ServiceOK: true, SelectionScore: 1, ExternalCountry: "DE", EgressConsensus: true}
	next := probe.RouteResult{Route: "vless", RouteType: "vless", Status: "OK", PathVerified: true, ServiceOK: true, SelectionScore: 2, ExternalCountry: "DE", EgressConsensus: true}
	result := srv.commitAutomaticDomain(context.Background(), planner.DomainCheck{
		Domain: "retry.example", ETLDPlusOne: "retry.example", Category: "GEO_LOCKED", Confidence: 1,
		Selected: &selected, Results: []probe.RouteResult{selected, next},
	})
	if !result.Applied || result.RolledBack || runtime.applied != 2 || runtime.rolledBack != 1 {
		t.Fatalf("post-proof failure did not retry next candidate: result=%+v runtime=%+v", result, runtime)
	}
	if got, want := strings.Join(runtime.appliedRoutes, ","), "smart,vless"; got != want {
		t.Fatalf("unexpected candidate order: got=%q want=%q", got, want)
	}
	decision, ok, err := srv.domainDecisions.Lookup("retry.example", srv.activeRevision, time.Now().UTC())
	if err != nil || !ok || decision.SelectedRoute != "vless" || decision.SelectedType != "vless" {
		t.Fatalf("retry did not persist the verified next candidate: decision=%+v ok=%v err=%v", decision, ok, err)
	}
}

func TestAutomaticDomainCommitRollsBackRuntimeBeforePersistingFailedPostProof(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer ts.Close()
	defer srv.Close()
	runtime := &fakeRouteAssignmentRuntime{}
	srv.routeAssignmentRuntime = runtime
	srv.probeEngineFactory = func(*config.Config) health.ProbeEngine {
		return routeAssignmentProofEngine{revision: srv.activeRevision, fail: true}
	}

	result := srv.commitAutomaticDomain(context.Background(), planner.DomainCheck{
		Domain: "post-proof-failure.example", ETLDPlusOne: "post-proof-failure.example", Category: "GEO_LOCKED", Confidence: 1,
		Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", Status: "OK", PathVerified: true, ServiceOK: true, ExternalCountry: "DE", EgressConsensus: true},
	})
	if result.Applied || !result.RolledBack || runtime.applied != 1 || runtime.rolledBack != 1 {
		t.Fatalf("failed post-apply proof did not roll back runtime: result=%+v runtime=%+v", result, runtime)
	}
	if _, ok, err := srv.domainDecisions.Lookup("post-proof-failure.example", srv.activeRevision, time.Now().UTC()); err != nil || ok {
		t.Fatalf("failed post-apply proof left a durable route decision: ok=%v err=%v", ok, err)
	}
}

func TestRecoveryMutationFenceBlocksEveryUnsafeStatus(t *testing.T) {
	for _, status := range []string{"starting", "error", "recovery_required", ""} {
		t.Run("status_"+status, func(t *testing.T) {
			fake := newFakeAdapter()
			srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
			defer ts.Close()
			defer srv.Close()

			change := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
			if err := srv.setRecoveryStatus(recoveryStatus{Status: status, Reason: "test fence"}); err != nil {
				t.Fatalf("set recovery status: %v", err)
			}
			_, code := postAction(t, client, csrf, ts.URL, change.ID, "apply", `{}`)
			if code != http.StatusServiceUnavailable {
				t.Fatalf("apply status=%d want=%d", code, http.StatusServiceUnavailable)
			}
			if calls := fakeAdapterCallCount(fake); calls != 0 {
				t.Fatalf("unsafe recovery status allowed adapter calls=%d", calls)
			}
		})
	}
}

func TestOnboardingMutationRespectsRecoveryFence(t *testing.T) {
	for _, status := range []string{"starting", "error", "recovery_required", ""} {
		t.Run("status_"+status, func(t *testing.T) {
			fake := newFakeAdapter()
			srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
			defer ts.Close()
			defer srv.Close()

			if err := srv.setRecoveryStatus(recoveryStatus{Status: status, Reason: "test fence"}); err != nil {
				t.Fatalf("set recovery status: %v", err)
			}
			if code := postOnboarding(t, client, csrf, ts.URL, "methods", "accept"); code != http.StatusServiceUnavailable {
				t.Fatalf("onboarding status=%d want=%d", code, http.StatusServiceUnavailable)
			}
			if value := srv.loadOnboardingState(); value.Steps["methods"].Status != "pending" {
				t.Fatalf("unsafe recovery status changed onboarding state: %+v", value.Steps["methods"])
			}
		})
	}
}

func TestRecoveryMutationFenceAllowsOnlyProvenStatuses(t *testing.T) {
	tests := []struct {
		name   string
		status recoveryStatus
	}{
		{name: "ok", status: recoveryStatus{Status: "ok"}},
		{name: "confirmed_baseline", status: recoveryStatus{Status: "not_required", RevisionID: "rev_baseline", CandidateHash: "sha256:baseline", CommitPhase: "baseline_confirmed"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeAdapter()
			srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
			defer ts.Close()
			defer srv.Close()

			change := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
			if err := srv.setRecoveryStatus(test.status); err != nil {
				t.Fatalf("set recovery status: %v", err)
			}
			_, code := postAction(t, client, csrf, ts.URL, change.ID, "apply", `{}`)
			if code != http.StatusOK {
				t.Fatalf("apply status=%d want=%d", code, http.StatusOK)
			}
			if calls := fakeAdapterCallCount(fake); calls == 0 {
				t.Fatal("proven safe recovery status did not permit adapter work")
			}
		})
	}
}

func TestRecoveryMutationFenceRejectsUnprovenNotRequiredIdentity(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer ts.Close()
	defer srv.Close()
	if err := srv.setRecoveryStatus(recoveryStatus{Status: "not_required", RevisionID: "rev_fake", CandidateHash: "sha256:fake"}); err != nil {
		t.Fatalf("set recovery status: %v", err)
	}
	if failure := srv.mutationFailure(); failure == nil || failure.Status != http.StatusServiceUnavailable {
		t.Fatalf("unproven not_required status opened mutation gate: %+v", failure)
	}
}

func TestRecoveryStatusPersistenceFailureInstallsMemoryFence(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer ts.Close()
	defer srv.Close()

	srv.store.SetFaultHook(func(operation string) error {
		if operation == "save_json:meta" {
			return errors.New("injected recovery status write failure")
		}
		return nil
	})
	err := srv.setRecoveryStatus(recoveryStatus{Status: "ok"})
	srv.store.SetFaultHook(nil)
	if err == nil {
		t.Fatal("status persistence failure was hidden")
	}
	status := srv.currentRecoveryStatus()
	if status.Status != "recovery_required" || status.ReasonCode != "recovery_status_persist_failed" {
		t.Fatalf("persistence failure did not install visible fence: %+v", status)
	}
	if failure := srv.mutationFailure(); failure == nil || failure.Status != http.StatusServiceUnavailable {
		t.Fatalf("memory fence did not block mutation: %+v", failure)
	}
}

func TestRecoveryTransitionExcludesConcurrentMutation(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer ts.Close()
	defer srv.Close()

	release, failure := srv.acquireMutationLease()
	if failure != nil {
		t.Fatalf("acquire initial mutation lease: %+v", failure)
	}
	statusDone := make(chan error, 1)
	go func() {
		statusDone <- srv.setRecoveryStatus(recoveryStatus{Status: "starting", Reason: "transition"})
	}()
	select {
	case err := <-statusDone:
		t.Fatalf("recovery transition completed while mutation lease was held: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	mutationDone := make(chan *actionFailure, 1)
	go func() {
		_, blocked := srv.acquireMutationLease()
		mutationDone <- blocked
	}()
	release()
	if err := <-statusDone; err != nil {
		t.Fatalf("recovery transition failed: %v", err)
	}
	select {
	case blocked := <-mutationDone:
		if blocked == nil || blocked.Status != http.StatusServiceUnavailable {
			t.Fatalf("concurrent mutation was not fenced: %+v", blocked)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent mutation did not complete")
	}
}

func TestDiscoveryDraftCreationRespectsRecoveryFence(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer ts.Close()
	defer srv.Close()

	for _, status := range []string{"starting", "error"} {
		if err := srv.setRecoveryStatus(recoveryStatus{Status: status, Reason: "scheduler fence"}); err != nil {
			t.Fatalf("set status %q: %v", status, err)
		}
		_, err := srv.createDraftChange("blocked", "blocked", srv.configVersion, nil, "scheduler")
		if err == nil {
			t.Fatalf("status %q allowed background draft mutation", status)
		}
		if calls := fakeAdapterCallCount(fake); calls != 0 {
			t.Fatalf("status %q caused adapter calls=%d", status, calls)
		}
	}
}

func TestAutomaticDomainCommitRespectsRecoveryFence(t *testing.T) {
	for _, status := range []string{"starting", "error"} {
		t.Run(status, func(t *testing.T) {
			fake := newFakeAdapter()
			srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
			defer ts.Close()
			defer srv.Close()

			if err := srv.setRecoveryStatus(recoveryStatus{Status: status, Reason: "scheduler fence"}); err != nil {
				t.Fatalf("set status: %v", err)
			}
			result := srv.commitAutomaticDomain(nil, planner.DomainCheck{
				Domain: "blocked.example", Category: "GEO_LOCKED", Confidence: 1,
				Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", Status: "OK", PathVerified: true, ServiceOK: true, ExternalCountry: "DE", EgressConsensus: true},
			})
			if result.Reason == "" {
				t.Fatalf("status %q returned an empty blocked reason: %+v", status, result)
			}
			if calls := fakeAdapterCallCount(fake); calls != 0 {
				t.Fatalf("status %q caused adapter calls=%d", status, calls)
			}
		})
	}
}

func TestAutomaticDomainCommitRequiresRuntimeConsumer(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer ts.Close()
	defer srv.Close()
	srv.probeEngineFactory = func(*config.Config) health.ProbeEngine {
		return routeAssignmentProofEngine{revision: srv.activeRevision}
	}

	result := srv.commitAutomaticDomain(context.Background(), planner.DomainCheck{
		Domain: "verified.example", ETLDPlusOne: "verified.example", Category: "GEO_LOCKED", Confidence: 1,
		Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", Status: "OK", PathVerified: true, ServiceOK: true, ExternalCountry: "DE", EgressConsensus: true},
	})
	if result.Applied || result.Reason != "route_assignment_runtime_unavailable" {
		t.Fatalf("assignment without runtime consumer was not fenced: %+v", result)
	}
	if calls := fakeAdapterCallCount(fake); calls != 0 {
		t.Fatalf("automatic discovery invoked the adapter despite route-only being unavailable: %d calls", calls)
	}
	if _, ok, err := srv.domainDecisions.Lookup("verified.example", srv.activeRevision, time.Now().UTC()); err != nil || ok {
		t.Fatalf("fenced assignment persisted a decision: ok=%v err=%v", ok, err)
	}
}

func TestAutomaticDomainCommitRequiresSemanticRuntimeReceipt(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer ts.Close()
	defer srv.Close()
	runtime := &fakeRouteAssignmentRuntime{}
	srv.routeAssignmentRuntime = runtime
	srv.probeEngineFactory = func(*config.Config) health.ProbeEngine {
		return routeAssignmentProofEngine{revision: srv.activeRevision}
	}

	result := srv.commitAutomaticDomain(context.Background(), planner.DomainCheck{
		Domain: "verified.example", ETLDPlusOne: "verified.example", Category: "GEO_LOCKED", Confidence: 1,
		Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", Status: "OK", PathVerified: true, ServiceOK: true, ExternalCountry: "DE", EgressConsensus: true},
	})
	if !result.Applied || result.RolledBack || runtime.applied != 1 || runtime.rolledBack != 0 {
		t.Fatalf("verified semantic runtime receipt did not commit: result=%+v runtime=%+v", result, runtime)
	}
	if _, ok, err := srv.domainDecisions.Lookup("verified.example", srv.activeRevision, time.Now().UTC()); err != nil || !ok {
		t.Fatalf("committed assignment was not persisted: ok=%v err=%v", ok, err)
	}
}

func TestAutomaticDomainCommitRejectsContradictorySelectionEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*probe.RouteResult)
	}{
		{name: "regional_denial", mutate: func(result *probe.RouteResult) { result.RegionalBlock = true }},
		{name: "authentication_required", mutate: func(result *probe.RouteResult) { result.AuthenticationRequired = true }},
		{name: "waf_or_rate_limit", mutate: func(result *probe.RouteResult) { result.WAFOrRateLimit = true }},
		{name: "simulation", mutate: func(result *probe.RouteResult) { result.Simulation = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeAdapter()
			srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
			defer ts.Close()
			defer srv.Close()
			runtime := &fakeRouteAssignmentRuntime{}
			srv.routeAssignmentRuntime = runtime
			selected := probe.RouteResult{Route: "smart", RouteType: "smart_dns", Status: "OK", PathVerified: true, ServiceOK: true, ExternalCountry: "DE", EgressConsensus: true}
			tc.mutate(&selected)
			result := srv.commitAutomaticDomain(context.Background(), planner.DomainCheck{
				Domain: "contradictory.example", ETLDPlusOne: "contradictory.example", Category: "GEO_LOCKED", Confidence: 1,
				Selected: &selected,
			})
			if result.Applied || runtime.applied != 0 || !strings.Contains(result.Reason, "verified_evidence") {
				t.Fatalf("contradictory evidence reached route assignment: result=%+v runtime=%+v", result, runtime)
			}
		})
	}
}

func TestAutomaticDomainCommitRollsBackInvalidRuntimeReceipt(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer ts.Close()
	defer srv.Close()
	runtime := &fakeRouteAssignmentRuntime{invalid: true}
	srv.routeAssignmentRuntime = runtime
	result := srv.commitAutomaticDomain(context.Background(), planner.DomainCheck{
		Domain: "invalid-receipt.example", ETLDPlusOne: "invalid-receipt.example", Category: "GEO_LOCKED", Confidence: 1,
		Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", Status: "OK", PathVerified: true, ServiceOK: true, ExternalCountry: "DE", EgressConsensus: true},
	})
	if result.Applied || !result.RolledBack || runtime.applied != 1 || runtime.rolledBack != 1 {
		t.Fatalf("invalid runtime receipt was not rolled back: result=%+v runtime=%+v", result, runtime)
	}
	if _, ok, err := srv.domainDecisions.Lookup("invalid-receipt.example", srv.activeRevision, time.Now().UTC()); err != nil || ok {
		t.Fatalf("invalid receipt left a selected decision: ok=%v err=%v", ok, err)
	}
}

func TestAutomaticDomainCommitRollsBackMismatchedRouteBinding(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer ts.Close()
	defer srv.Close()
	runtime := &fakeRouteAssignmentRuntime{badBinding: true}
	srv.routeAssignmentRuntime = runtime
	srv.probeEngineFactory = func(*config.Config) health.ProbeEngine {
		return routeAssignmentProofEngine{revision: srv.activeRevision}
	}

	result := srv.commitAutomaticDomain(context.Background(), planner.DomainCheck{
		Domain: "bound.example", ETLDPlusOne: "bound.example", Category: "GEO_LOCKED", Confidence: 1,
		Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", Status: "OK", PathVerified: true, ServiceOK: true, ExternalCountry: "DE", EgressConsensus: true},
	})
	if result.Applied || !result.RolledBack || runtime.applied != 1 || runtime.rolledBack != 1 || !strings.Contains(result.Reason, "semantic") {
		t.Fatalf("mismatched route binding was not fenced and rolled back: result=%+v runtime=%+v", result, runtime)
	}
}

func TestHealthSchedulerSkipsProbesWhenRecoveryIsUnsafe(t *testing.T) {
	for _, status := range []string{"starting", "error"} {
		t.Run(status, func(t *testing.T) {
			srv := newTestServer(t)
			defer srv.Close()
			engine := &apiHealthEngine{}
			srv.probeEngineFactory = func(*config.Config) health.ProbeEngine { return engine }
			if err := srv.setRecoveryStatus(recoveryStatus{Status: status, Reason: "scheduler fence"}); err != nil {
				t.Fatal(err)
			}
			srv.runHealthCycle(context.Background())
			engine.mu.Lock()
			calls := engine.calls
			engine.mu.Unlock()
			if calls != 0 {
				t.Fatalf("unsafe recovery status %q allowed health probes=%d", status, calls)
			}
		})
	}
}
