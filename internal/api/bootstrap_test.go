package api

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/discovery"
	"router-policy/internal/health"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
	"router-policy/internal/state"
)

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
	if engine.calls == 0 {
		t.Fatal("discovery still exits before probing after baseline creation")
	}
	classified := false
	for _, event := range srv.broker.Recent(0, 32) {
		if event.ReasonCode == "domain_observed_and_classified" {
			classified = true
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
