package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-policy/internal/adapter"
	"router-policy/internal/config"
	"router-policy/internal/discovery"
	"router-policy/internal/health"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
	"router-policy/internal/state"
)

type baselineAssignmentReconciler struct{ calls int }

func (r *baselineAssignmentReconciler) ApplyRouteAssignment(context.Context, RouteAssignmentRequest) (RouteAssignmentReceipt, error) {
	return RouteAssignmentReceipt{}, errors.New("unexpected baseline assignment")
}
func (r *baselineAssignmentReconciler) RollbackRouteAssignment(context.Context, RouteAssignmentRequest, RouteAssignmentReceipt) error {
	return errors.New("unexpected baseline assignment rollback")
}
func (r *baselineAssignmentReconciler) ReconcileRouteAssignments(context.Context) error {
	r.calls++
	return errors.New("route assignment committed binding is unavailable")
}

type blockedAssignmentReconciler struct {
	baselineAssignmentReconciler
	started chan struct{}
	release chan struct{}
}

func (r *blockedAssignmentReconciler) ReconcileRouteAssignments(context.Context) error {
	close(r.started)
	<-r.release
	return errors.New("helper assignment binding mismatch")
}

func TestAssignmentRecoveryFailureFencesBeforeConcurrentMutationAdmission(t *testing.T) {
	cfg := testAPIConfig(t)
	srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(), Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	runtime := &blockedAssignmentReconciler{started: make(chan struct{}), release: make(chan struct{})}
	srv.routeAssignmentRuntime = runtime
	if err := srv.setRecoveryStatus(recoveryStatus{Status: "ok", RevisionID: srv.activeRevision}); err != nil {
		t.Fatal(err)
	}
	reconciled := make(chan error, 1)
	go func() { reconciled <- srv.reconcileRouteAssignments(context.Background()) }()
	select {
	case <-runtime.started:
	case <-time.After(5 * time.Second):
		close(runtime.release)
		t.Fatal("assignment reconcile did not reach its bounded barrier")
	}
	admitted := make(chan *actionFailure, 1)
	go func() {
		release, failure := srv.acquireMutationLease()
		if release != nil {
			release()
		}
		admitted <- failure
	}()
	select {
	case failure := <-admitted:
		close(runtime.release)
		<-reconciled
		t.Fatalf("mutation entered while assignment recovery was unresolved: %+v", failure)
	case <-time.After(20 * time.Millisecond):
	}
	close(runtime.release)
	select {
	case err := <-reconciled:
		if err == nil {
			t.Fatal("reconcile failure was swallowed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("assignment reconcile did not terminate")
	}
	select {
	case failure := <-admitted:
		if failure == nil || failure.Status != 503 {
			t.Fatalf("mutation was not fenced before unlock: %+v", failure)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mutation admission did not terminate")
	}
}

func TestFreshBaselineDoesNotRequireProductionAssignmentBinding(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		t.Run(fmt.Sprint(deferred), func(t *testing.T) {
			cfg := testAPIConfig(t)
			cfg.Services = map[string]config.Service{}
			cfg.OpenWrt.DNSMasqInclude = filepath.Join(t.TempDir(), "router-policy.conf")
			runtime := &baselineAssignmentReconciler{}
			fake := &baselineGuardFakeAdapter{fakeAdapter: newFakeAdapter()}
			srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, RouteAssignmentRuntime: runtime, Development: true, DeferRecovery: deferred})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			if deferred {
				srv.recoverCommittedDataplane(context.Background())
				if err := srv.reconcileRouteAssignments(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			status := srv.currentRecoveryStatus()
			if !recoveryStatusAllowsMutation(status) || status.Status != "not_required" || runtime.calls != 0 {
				t.Fatalf("empty baseline incorrectly requires production binding: recovery=%+v calls=%d", status, runtime.calls)
			}
		})
	}
}

func TestBaselineWithResidualAssignmentStateIsFenced(t *testing.T) {
	for _, residual := range []string{"manifest", "overlay"} {
		t.Run(residual, func(t *testing.T) {
			cfg := testAPIConfig(t)
			cfg.Services = map[string]config.Service{}
			confdir := t.TempDir()
			cfg.OpenWrt.DNSMasqInclude = filepath.Join(confdir, "router-policy.conf")
			path := filepath.Join(cfg.Storage.StateDir, "route-assignments.json")
			if residual == "overlay" {
				path = filepath.Join(confdir, "router-policy-route-assignments.conf")
			}
			if err := os.WriteFile(path, []byte("residual state\n"), 0600); err != nil {
				t.Fatal(err)
			}
			runtime := &baselineAssignmentReconciler{}
			srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(), RouteAssignmentRuntime: runtime, Development: true})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			if srv.mutationFailure() == nil || srv.currentRecoveryStatus().Status != "error" || runtime.calls != 0 {
				t.Fatalf("residual baseline was not fenced before helper: recovery=%+v calls=%d", srv.currentRecoveryStatus(), runtime.calls)
			}
			raw, err := os.ReadFile(path)
			if err != nil || string(raw) != "residual state\n" {
				t.Fatalf("residual evidence changed: %q %v", raw, err)
			}
		})
	}
}

func TestFreshStoreCreatesCommittedBaselineWithoutDataplaneCalls(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Services = map[string]config.Service{}
	cfg.Overrides = nil
	openWrtBefore := cfg.OpenWrt
	fake := newFakeAdapter()

	srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	if srv.activeRevision == "" || srv.configVersion != 1 {
		t.Fatalf("fresh store has no baseline identity: revision=%q version=%d", srv.activeRevision, srv.configVersion)
	}
	var revision revisionRecord
	if err := srv.store.LoadJSON("revisions", srv.activeRevision, &revision); err != nil {
		t.Fatal(err)
	}
	if err := validateBaselineRevision(revision, srv.activeRevision, srv.currentConfig()); err != nil {
		t.Fatalf("baseline revision is invalid: %v", err)
	}
	if revision.State != "committed" || revision.Kind != baselineRevisionKind || revision.TransactionID != "" || revision.ChangeID != "" || revision.ArtifactManifestHash != "" {
		t.Fatalf("baseline has deployment state: %+v", revision)
	}
	if len(srv.currentConfig().Services) != 0 || len(srv.currentConfig().Overrides) != 0 {
		t.Fatalf("baseline created domain policy: services=%d overrides=%d", len(srv.currentConfig().Services), len(srv.currentConfig().Overrides))
	}
	if len(fake.calls) != 0 {
		t.Fatalf("baseline touched the OpenWrt adapter: %v", fake.calls)
	}
	if srv.currentConfig().OpenWrt != openWrtBefore {
		t.Fatalf("baseline changed OpenWrt routing settings: before=%+v after=%+v", openWrtBefore, srv.currentConfig().OpenWrt)
	}
	if recovery := srv.currentRecoveryStatus(); recovery.Status != "not_required" || recovery.RevisionID != srv.activeRevision {
		t.Fatalf("baseline recovery status is dishonest: %+v", recovery)
	}
}

type baselineGuardFakeAdapter struct {
	*fakeAdapter
	calls int
}

func (f *baselineGuardFakeAdapter) ClearBootGuardForBaseline(_ context.Context, revisionID, candidateHash string) adapter.StepResult {
	f.calls++
	return adapter.StepResult{
		ProtocolVersion: adapter.AdapterProtocolVersion,
		Operation:       "clear-boot-guard-baseline",
		Step:            "clear_boot_guard_baseline",
		Status:          "OK",
		OK:              true,
		SemanticState:   "baseline_confirmed",
		Evidence: map[string]any{
			"boot_guard":            "cleared",
			"route_assignments":     "absent",
			"active_revision":       revisionID,
			"active_candidate_hash": candidateHash,
		},
		StartedAt:  time.Now().UTC(),
		FinishedAt: time.Now().UTC(),
	}
}

type missingBaselineAssignmentProofAdapter struct{ baselineGuardFakeAdapter }

func (f *missingBaselineAssignmentProofAdapter) ClearBootGuardForBaseline(ctx context.Context, revision, hash string) adapter.StepResult {
	result := f.baselineGuardFakeAdapter.ClearBootGuardForBaseline(ctx, revision, hash)
	delete(result.Evidence, "route_assignments")
	return result
}

func TestBaselineCannotOpenMutationGateWithoutHelperAbsenceProof(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Services = map[string]config.Service{}
	fake := &missingBaselineAssignmentProofAdapter{baselineGuardFakeAdapter{fakeAdapter: newFakeAdapter()}}
	srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	status := srv.currentRecoveryStatus()
	if status.Status != "error" || status.ReasonCode != "baseline_assignment_proof_missing" || srv.mutationFailure() == nil {
		t.Fatalf("missing privileged absence proof admitted mutation: %+v", status)
	}
}

func TestBaselineRecoveryClearsOnlyThroughBaselineBoundAdapterOperation(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Services = map[string]config.Service{}
	fake := &baselineGuardFakeAdapter{fakeAdapter: newFakeAdapter()}
	srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if fake.calls != 1 {
		t.Fatalf("baseline recovery did not clear the early guard exactly once: calls=%d", fake.calls)
	}
	if recovery := srv.currentRecoveryStatus(); recovery.Status != "not_required" || recovery.CommitPhase != "baseline_confirmed" {
		t.Fatalf("baseline recovery status is not confirmed: %+v", recovery)
	}
}

func TestPackagedDefaultProducesSafeBaseline(t *testing.T) {
	cfg, err := config.Load("../../config/default.json")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cfg.Platform.Target = "test"
	cfg.Storage.StateDir = root
	cfg.Storage.RuntimeDir = root
	cfg.Storage.Database = filepath.Join(root, "router-policy.bbolt")
	fake := newFakeAdapter()
	srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	active := srv.currentConfig()
	if len(active.Services) != 0 || len(active.Overrides) != 0 {
		t.Fatalf("packaged default contains domain policy: services=%d overrides=%d", len(active.Services), len(active.Overrides))
	}
	for _, route := range active.Routes {
		if (route.Type == "zapret" || route.Type == "vless") && route.Enabled() {
			t.Fatalf("packaged baseline enables %s route %s", route.Type, route.Tag)
		}
	}
	if active.Xray.OutboundBundleSHA256 != "" || active.Zapret.AdaptiveEnabled || active.OpenWrt.FlowOffloadingPolicy != "preserve" {
		t.Fatalf("packaged baseline is not passive: xray_hash=%q adaptive_zapret=%t flow=%q", active.Xray.OutboundBundleSHA256, active.Zapret.AdaptiveEnabled, active.OpenWrt.FlowOffloadingPolicy)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("packaged baseline touched the OpenWrt adapter: %v", fake.calls)
	}
}

func TestBaselineBootstrapIsIdempotentAcrossRestart(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Services = map[string]config.Service{}
	firstAdapter := newFakeAdapter()
	srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: firstAdapter, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	revisionID := srv.activeRevision
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}

	secondAdapter := newFakeAdapter()
	srv, err = NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: secondAdapter, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	rows, err := srv.store.ListRaw("revisions")
	if err != nil {
		t.Fatal(err)
	}
	if srv.activeRevision != revisionID || len(rows) != 1 {
		t.Fatalf("restart duplicated or replaced baseline: before=%q after=%q revisions=%d", revisionID, srv.activeRevision, len(rows))
	}
	if len(secondAdapter.calls) != 0 {
		t.Fatalf("baseline restart touched the OpenWrt adapter: %v", secondAdapter.calls)
	}
}

func TestBaselineDoesNotReplaceExistingCommittedRevision(t *testing.T) {
	cfg := testAPIConfig(t)
	store, err := state.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	existingID := "rev_7_001122334455"
	now := time.Now().UTC()
	existing := revisionRecord{RevisionID: existingID, Version: 7, State: "committed", CreatedAt: now, CommittedAt: &now}
	if err := store.SaveBatch(
		state.Entry{Bucket: "meta", Key: "active_config", Value: cfg},
		state.Entry{Bucket: "meta", Key: "active_revision", Value: existingID},
		state.Entry{Bucket: "meta", Key: "config_version", Value: int64(7)},
		state.Entry{Bucket: "revisions", Key: existingID, Value: existing},
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(), Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	rows, err := srv.store.ListRaw("revisions")
	if err != nil {
		t.Fatal(err)
	}
	if srv.activeRevision != existingID || srv.configVersion != 7 || len(rows) != 1 {
		t.Fatalf("existing commit was replaced: revision=%q version=%d rows=%d", srv.activeRevision, srv.configVersion, len(rows))
	}
}

func TestBaselineDoesNotOverwriteIncompleteOrCorruptState(t *testing.T) {
	t.Run("incomplete revision", func(t *testing.T) {
		cfg := testAPIConfig(t)
		store, err := state.Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		orphanID := "rev_2_aabbccddeeff"
		if err := store.SaveJSON("revisions", orphanID, map[string]any{"revision_id": orphanID, "state": "prepared"}); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}

		srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(), Development: true})
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Close()
		rows, err := srv.store.ListRaw("revisions")
		if err != nil {
			t.Fatal(err)
		}
		if srv.activeRevision != "" || len(rows) != 1 {
			t.Fatalf("incomplete state was overwritten: active=%q revisions=%d", srv.activeRevision, len(rows))
		}
	})

	t.Run("corrupt active revision", func(t *testing.T) {
		cfg := testAPIConfig(t)
		store, err := state.Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SaveJSON("meta", "active_revision", map[string]string{"invalid": "shape"}); err != nil {
			t.Fatal(err)
		}
		created, err := ensureBaselineRevision(store, cfg, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if created {
			t.Fatal("corrupt active revision was overwritten by baseline")
		}
		if _, _, err := loadActiveConfig(store, cfg); err == nil {
			t.Fatal("corrupt active revision was accepted")
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("corrupt baseline hash", func(t *testing.T) {
		cfg := testAPIConfig(t)
		cfg.Services = map[string]config.Service{}
		srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(), Development: true})
		if err != nil {
			t.Fatal(err)
		}
		activeRevision := srv.activeRevision
		var revision revisionRecord
		if err := srv.store.LoadJSON("revisions", activeRevision, &revision); err != nil {
			t.Fatal(err)
		}
		revision.CandidateHash = "sha256:" + strings.Repeat("f", 64)
		if err := srv.store.SaveJSON("revisions", activeRevision, revision); err != nil {
			t.Fatal(err)
		}
		if err := srv.Close(); err != nil {
			t.Fatal(err)
		}

		fake := newFakeAdapter()
		srv, err = NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Close()
		if recovery := srv.currentRecoveryStatus(); recovery.Status != "error" || recovery.ReasonCode != "active_baseline_invalid" {
			t.Fatalf("corrupt baseline was not rejected: %+v", recovery)
		}
		rows, err := srv.store.ListRaw("revisions")
		if err != nil {
			t.Fatal(err)
		}
		if srv.activeRevision != activeRevision || len(rows) != 1 || len(fake.calls) != 0 {
			t.Fatalf("corrupt baseline was replaced or applied: active=%q rows=%d calls=%v", srv.activeRevision, len(rows), fake.calls)
		}
	})
}

type baselineDiscoveryEngine struct {
	revision string
	calls    int
}

func (e *baselineDiscoveryEngine) ProbeRoute(_ context.Context, _ *config.Config, domain, service string, _ config.Service, route config.Route) probe.RouteResult {
	e.calls++
	return probe.RouteResult{
		Domain: domain, Service: service, Route: route.Tag, RouteType: route.Type, RoutePriority: route.Priority,
		Status: "OK", ApplicationStatus: "OK", PathVerified: true, ServiceOK: true, EgressConsensus: true,
		AdapterRevision: e.revision, ExternalIPHash: "sha256:" + strings.Repeat("a", 64), ExternalCountry: "RU",
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func TestDiscoveryRunsAfterBaselineWithoutApplyingOpenWrtState(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Services = map[string]config.Service{}
	fake := newFakeAdapter()
	srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	engine := &baselineDiscoveryEngine{revision: srv.activeRevision}
	srv.probeEngineFactory = func(*config.Config) health.ProbeEngine { return engine }

	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "fresh.example", QueryType: "A"})
	if engine.calls != 0 {
		t.Fatal("observe-only discovery performed an active probe after baseline creation")
	}
	classified := false
	for _, event := range srv.broker.Recent(0, 32) {
		if event.ReasonCode == "domain_observed_only" {
			classified = true
			if event.Details["decision_confidence"] != float64(0) && event.Details["decision_confidence"] != 0 {
				t.Fatalf("observe-only decision confidence was not zero: %#v", event.Details["decision_confidence"])
			}
			if _, ok := event.Details["classification_confidence"]; !ok {
				t.Fatal("observe-only event omitted classification confidence")
			}
			if _, ok := event.Details["classification_source"]; !ok {
				t.Fatal("observe-only event omitted classification source")
			}
			break
		}
	}
	if !classified {
		t.Fatal("discovery did not publish a classification result")
	}
	if len(fake.calls) != 0 {
		t.Fatalf("read-only discovery touched the OpenWrt adapter: %v", fake.calls)
	}
}
