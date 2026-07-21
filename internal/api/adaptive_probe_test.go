package api

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/health"
	"router-policy/internal/probe"
	"router-policy/internal/zapret"
)

type adaptiveCycleProbeEngine struct {
	mu          sync.Mutex
	familyCalls []string
}

func (e *adaptiveCycleProbeEngine) ProbeRoute(_ context.Context, _ *config.Config, domain, service string, _ config.Service, route config.Route) probe.RouteResult {
	return probe.RouteResult{Domain: domain, Service: service, Route: route.Tag, RouteType: route.Type, Status: "NOT_APPLICABLE", ApplicationStatus: "NOT_RUN", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
}

func (e *adaptiveCycleProbeEngine) ProbeRouteFamily(_ context.Context, _ *config.Config, domain, service string, _ config.Service, route config.Route, family string) probe.RouteResult {
	e.mu.Lock()
	e.familyCalls = append(e.familyCalls, family)
	e.mu.Unlock()
	return probe.RouteResult{
		Domain: domain, Service: service, Route: route.Tag, RouteType: route.Type,
		Status: "OK", ApplicationStatus: "OK", PathVerified: true, ServiceOK: true,
		DNSOK: true, TransportOK: true, TLSOK: true, HTTPOK: true, ContentOK: true,
		LatencyMS: 25, CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Checks: []probe.CheckResult{{
			Name: "web", URL: "https://discord.com/", Required: true, Status: "OK",
			DNSOK: true, Transport: "tcp", TransportOK: true, TLSOK: true, HTTPOK: true,
			ContentOK: true, ConnectedPort: 443, AddressFamily: family,
		}},
	}
}

func TestProductionAdaptiveCycleCollectsActiveAndCandidateEvidence(t *testing.T) {
	cfg := adaptiveCycleConfig(t)
	diagnostics := testArtifactNetworkDiagnostics(false)
	diagnostics.ExpiresAt = diagnostics.CollectedAt.Add(10 * time.Minute)
	engine := &adaptiveCycleProbeEngine{}
	srv, err := NewServerWithOptions(cfg, Options{
		ProductionAdapter: newFakeAdapter(),
		Provider:          artifactDiagnosticsTestProvider{diagnostics: diagnostics},
		ProbeEngineFactory: func(*config.Config) health.ProbeEngine {
			return engine
		},
		Development: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	now := diagnostics.CollectedAt.Add(time.Second)
	runtime := srv.currentAdaptiveRuntime()
	fingerprint, err := srv.adaptiveNetworkFingerprint(cfg, runtime, now)
	if err != nil {
		t.Fatal(err)
	}
	key := zapret.DecisionKey{BundleID: "discord", Transport: "tcp", Port: 443, IPFamily: "ipv4", NetworkFingerprint: fingerprint}

	srv.runAdaptiveZapretCycle(context.Background(), cfg, engine, now)
	active, err := runtime.ranker.Snapshot(key, "profile-a", now.Add(30*time.Second))
	if err != nil || active.Attempts != 1 || active.Successes != 1 {
		t.Fatalf("active profile observation missing: score=%+v err=%v", active, err)
	}

	srv.runAdaptiveZapretCycle(context.Background(), cfg, engine, now.Add(time.Minute))
	candidate, err := runtime.ranker.Snapshot(key, "profile-b", now.Add(2*time.Minute))
	if err != nil || candidate.Attempts != 1 || candidate.Successes != 1 {
		t.Fatalf("candidate calibration observation missing: score=%+v err=%v events=%+v", candidate, err, srv.broker.Recent(0, 50))
	}
	if got := profileForBundle(srv.currentConfig().Zapret.AdaptiveAssignments, "discord"); got != "profile-a" {
		t.Fatalf("calibration changed the committed profile: %s", got)
	}

	var persisted persistedAdaptiveProbeRuntime
	if err := srv.store.LoadJSON(adaptiveProbeBucket, adaptiveProbeKey, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.Observations) != 2 || persisted.CatalogDigest != runtime.catalogDigest {
		t.Fatalf("adaptive runtime persistence mismatch: %+v", persisted)
	}
	raw, err := json.Marshal(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), diagnostics.IPv4Gateway) || strings.Contains(string(raw), diagnostics.DNSResolvers[0]) {
		t.Fatal("raw network infrastructure leaked into persisted adaptive state")
	}
}

func TestAdaptiveNetworkFingerprintInvalidatesOldRanking(t *testing.T) {
	cfg := adaptiveCycleConfig(t)
	diagnostics := testArtifactNetworkDiagnostics(false)
	diagnostics.ExpiresAt = diagnostics.CollectedAt.Add(10 * time.Minute)
	engine := &adaptiveCycleProbeEngine{}
	srv, err := NewServerWithOptions(cfg, Options{
		ProductionAdapter: newFakeAdapter(), Provider: artifactDiagnosticsTestProvider{diagnostics: diagnostics},
		ProbeEngineFactory: func(*config.Config) health.ProbeEngine { return engine }, Development: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	now := diagnostics.CollectedAt.Add(time.Second)
	runtime := srv.currentAdaptiveRuntime()
	oldFingerprint, err := srv.adaptiveNetworkFingerprint(cfg, runtime, now)
	if err != nil {
		t.Fatal(err)
	}
	srv.runAdaptiveZapretCycle(context.Background(), cfg, engine, now)

	diagnostics.IPv4Gateway = "198.51.100.1"
	diagnostics.CollectedAt = now.Add(time.Minute)
	diagnostics.ExpiresAt = diagnostics.CollectedAt.Add(time.Minute)
	srv.provider = artifactDiagnosticsTestProvider{diagnostics: diagnostics}
	newFingerprint, err := srv.adaptiveNetworkFingerprint(cfg, runtime, diagnostics.CollectedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if newFingerprint == oldFingerprint {
		t.Fatal("network change did not invalidate the adaptive fingerprint")
	}
	newKey := zapret.DecisionKey{BundleID: "discord", Transport: "tcp", Port: 443, IPFamily: "ipv4", NetworkFingerprint: newFingerprint}
	if score, err := runtime.ranker.Snapshot(newKey, "profile-a", diagnostics.CollectedAt); err != nil || score.Attempts != 0 {
		t.Fatalf("old ranking leaked into a new network: score=%+v err=%v", score, err)
	}
	srv.runAdaptiveZapretCycle(context.Background(), cfg, engine, diagnostics.CollectedAt.Add(time.Second))
	if score, err := runtime.ranker.Snapshot(newKey, "profile-a", diagnostics.CollectedAt.Add(2*time.Second)); err != nil || score.Attempts != 1 {
		t.Fatalf("new network did not start independent calibration: score=%+v err=%v", score, err)
	}
}

func adaptiveCycleConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := testAPIConfig(t)
	cfg.Routes = append(cfg.Routes, config.Route{Type: "zapret", Tag: "zapret"})
	cfg.Services["discord"] = config.Service{
		Category: "TSPU_RESTRICTED", Domains: []string{"discord.com"},
		AllowedPaths: []string{"zapret", "drop"},
		ProbeURLs:    []config.ProbeCheck{{Name: "web", URL: "https://discord.com/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}},
	}
	cfg.Zapret = config.Zapret{
		Binary: "/usr/bin/nfqws", InitScript: "/etc/init.d/router-policy-zapret",
		ActiveConfig: "/etc/router-policy/zapret/nfqws.conf", ActivationMode: "managed",
		Strategy: "tls-fake-ttl3-v1", QueueNum: 200, AdaptiveEnabled: true,
		AdaptiveCatalogFile: filepath.Join(cfg.Storage.StateDir, "catalog.json"),
		AdaptiveAssignments: []config.ZapretProfileAssignment{{BundleID: "discord", ProfileID: "profile-a"}},
	}
	writeAdaptiveCatalog(t, cfg.Zapret.AdaptiveCatalogFile)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}
