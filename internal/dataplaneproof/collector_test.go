package dataplaneproof

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"router-policy/internal/artifact"
	"router-policy/internal/config"
	"router-policy/internal/evidence"
	"router-policy/internal/probe"
)

type fakeProber struct {
	results map[string]probe.RouteResult
}

type concurrentProber struct {
	mu      sync.Mutex
	active  int
	maximum int
	results map[string]probe.RouteResult
}

type blockingProber struct{}

func (blockingProber) ProbeRoute(ctx context.Context, _ *config.Config, _, _ string, _ config.Service, _ config.Route) probe.RouteResult {
	<-ctx.Done()
	return probe.RouteResult{Status: "FAIL", ReasonCode: "context_done"}
}

func (p *concurrentProber) ProbeRoute(ctx context.Context, _ *config.Config, _, _ string, _ config.Service, route config.Route) probe.RouteResult {
	p.mu.Lock()
	p.active++
	if p.active > p.maximum {
		p.maximum = p.active
	}
	p.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-time.After(25 * time.Millisecond):
	}
	p.mu.Lock()
	p.active--
	p.mu.Unlock()
	return p.results[route.Tag]
}

func (f fakeProber) ProbeRoute(_ context.Context, _ *config.Config, _, _ string, _ config.Service, route config.Route) probe.RouteResult {
	return f.results[route.Tag]
}

func TestCollectWritesStrictlyBoundReport(t *testing.T) {
	root := t.TempDir()
	binding := artifact.Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	manifestHash := "sha256:manifest"
	plan := artifact.VerificationPlan{Binding: binding, RequireDNSLeakCheck: true, RequireIPv6LeakCheck: true, RequiredRouteProof: []artifact.RouteProof{
		{Tag: "direct", Type: "direct", Mark: "0x41", Table: 100, RulePriority: 10010, RequiresDNS: true, RequiresIPv4: true, RequiresIPv6: true, RequiresEgress: true},
		{Tag: "drop", Type: "drop", Mark: "0x43", RulePriority: 10020, RequiresDropProof: true},
	}}
	planPath := filepath.Join(root, "plan.json")
	writeJSON(t, planPath, plan)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	direct := completeDirectProof(binding, manifestHash, now)
	drop := evidence.RouteResult{
		Domain: "blocked.example", RouteTag: "drop", RouteType: "drop", AdapterRevision: binding.RevisionID,
		CandidateHash: binding.CandidateHash, ArtifactManifestHash: manifestHash, NFTMark: "0x43", ConntrackMark: "0x43",
		IPRulePriority: 10020, DropIPv4Enforced: true, DropIPv6Enforced: true, DropDNSEnforced: true,
		ReasonCode: "drop_enforced", Status: "OK", EvidenceSource: "test", CheckedAt: now,
	}
	cfg := testConfig()
	cfg.Policy.ParallelServerChecks = 2
	out := filepath.Join(root, "evidence.json")
	prober := &concurrentProber{results: map[string]probe.RouteResult{
		"direct": {Status: "OK", PathVerified: true, PathEvidence: &direct},
		"drop":   {Status: "OK", PathVerified: true, PathEvidence: &drop},
	}}
	report, err := Collect(context.Background(), Options{Config: cfg, PlanPath: planPath, OutputPath: out, Binding: binding, ManifestHash: manifestHash, Prober: prober, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !report.DNSLeakFree || !report.IPv6LeakFree || !report.GeoLockedKillSwitch {
		t.Fatalf("incomplete aggregate proof: %+v", report)
	}
	if prober.maximum < 2 {
		t.Fatalf("bounded collector did not run independent route probes concurrently: max=%d", prober.maximum)
	}
	if _, err := evidence.LoadAndVerify(planPath, out, binding, manifestHash); err != nil {
		t.Fatal(err)
	}
}

func TestCollectRefusesUnboundProbeResult(t *testing.T) {
	root := t.TempDir()
	binding := artifact.Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	plan := artifact.VerificationPlan{Binding: binding, RequiredRouteProof: []artifact.RouteProof{{Tag: "direct", Type: "direct", Mark: "0x41", Table: 100, RulePriority: 10010, RequiresDNS: true, RequiresIPv4: true, RequiresIPv6: true, RequiresEgress: true}}}
	planPath := filepath.Join(root, "plan.json")
	writeJSON(t, planPath, plan)
	proof := completeDirectProof(binding, "sha256:wrong", time.Now().UTC())
	_, err := Collect(context.Background(), Options{Config: testConfig(), PlanPath: planPath, OutputPath: filepath.Join(root, "evidence.json"), Binding: binding, ManifestHash: "sha256:manifest", Prober: fakeProber{results: map[string]probe.RouteResult{
		"direct": {Status: "OK", PathVerified: true, PathEvidence: &proof},
	}}})
	if err == nil {
		t.Fatal("unbound path evidence was accepted")
	}
}

func TestCollectRouteSeparatesServiceClassificationFromVerifiedPath(t *testing.T) {
	binding := artifact.Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	manifestHash := "sha256:manifest"
	required := artifact.RouteProof{Tag: "direct", Type: "direct", Mark: "0x41", Table: 100, RulePriority: 10010, RequiresDNS: true, RequiresIPv4: true, RequiresIPv6: true, RequiresEgress: true}
	proof := completeDirectProof(binding, manifestHash, time.Now().UTC())
	result := probe.RouteResult{
		Status:       "SUSPECTED_TSPU",
		ReasonCode:   "route_path_verified",
		PathVerified: true,
		PathEvidence: &proof,
	}
	item := collectRoute(context.Background(), Options{
		Config: testConfig(), Binding: binding, ManifestHash: manifestHash,
		Prober: fakeProber{results: map[string]probe.RouteResult{"direct": result}},
	}, 0, required)
	if item.err != nil {
		t.Fatalf("verified route path was rejected because of service classification: %v", item.err)
	}
}

func TestCollectRouteEnforcesOverallProbeTimeout(t *testing.T) {
	required := artifact.RouteProof{Tag: "direct", Type: "direct"}
	start := time.Now()
	item := collectRoute(context.Background(), Options{
		Config: testConfig(), Prober: blockingProber{}, RouteTimeout: 25 * time.Millisecond,
	}, 0, required)
	if item.err == nil || !strings.Contains(item.err.Error(), "exceeded overall timeout") {
		t.Fatalf("expected bounded route timeout, got %v", item.err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("route timeout was not bounded: %s", elapsed)
	}
}

func TestProductionRouteProofsAreSerialized(t *testing.T) {
	cfg := testConfig()
	cfg.Platform.Target = "glinet-flint2"
	if got := routeProofParallelism(cfg, 4, 4); got != 1 {
		t.Fatalf("production path proofs run with parallelism %d, want 1", got)
	}
	cfg.Platform.Target = "test"
	if got := routeProofParallelism(cfg, 4, 4); got != 4 {
		t.Fatalf("test path proofs lost bounded concurrency: %d", got)
	}
}

func TestProductionRouteProofGetsWholeCollectionBudget(t *testing.T) {
	cfg := testConfig()
	cfg.OpenWrt.ProbeTimeoutSeconds = 20
	cfg.Platform.Target = "glinet-flint2"
	if got := routeProbeTimeout(Options{Config: cfg}); got != time.Minute {
		t.Fatalf("production route proof budget = %s, want 1m", got)
	}
	if got := routeProbeTimeout(Options{Config: cfg, RouteTimeout: 3 * time.Second}); got != 3*time.Second {
		t.Fatalf("explicit route proof budget was ignored: %s", got)
	}
}

func TestZapretProofTargetsAssignedAdaptiveBundle(t *testing.T) {
	cfg := testConfig()
	cfg.Routes = append(cfg.Routes, config.Route{Type: "zapret", Tag: "zapret"})
	cfg.Services["discord"] = config.Service{
		Category: "TSPU_RESTRICTED", Domains: []string{"discord.example"},
		AllowedPaths: []string{"zapret"}, ProbeURLs: []config.ProbeCheck{{URL: "https://discord.example/", Required: true}},
	}
	cfg.Services["youtube"] = config.Service{
		Category: "TSPU_RESTRICTED", Domains: []string{"youtube.example"},
		AllowedPaths: []string{"zapret"}, ProbeURLs: []config.ProbeCheck{{URL: "https://youtube.example/", Required: true}},
	}
	cfg.Zapret.AdaptiveEnabled = true
	cfg.Zapret.AdaptiveAssignments = []config.ZapretProfileAssignment{{BundleID: "youtube", ProfileID: "profile-1"}}

	name, domain, _, err := selectProbeTarget(cfg, config.Route{Type: "zapret", Tag: "zapret"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "youtube" || domain != "youtube.example" {
		t.Fatalf("zapret proof targeted %s (%s), want assigned youtube bundle", name, domain)
	}
}

func completeDirectProof(binding artifact.Binding, manifestHash string, checkedAt time.Time) evidence.RouteResult {
	return evidence.RouteResult{
		Domain: "direct.example", RouteTag: "direct", RouteType: "direct", AdapterRevision: binding.RevisionID,
		CandidateHash: binding.CandidateHash, ArtifactManifestHash: manifestHash, NFTMark: "0x41", ConntrackMark: "0x41",
		IPRulePriority: 10010, RouteTable: 100, Interface: "wan", DNSResolver: "192.0.2.53:53", DNSProtocol: "udp",
		ResolvedIP: "203.0.113.10", ConnectedIP: "203.0.113.10", ExternalIPHash: "sha256:egress", ExternalCountry: "RU",
		DirectBypassXray: true, DirectBypassZapret: true, InheritedMarkCleared: true, IPv4Verified: true, IPv6Verified: true,
		HTTPResult: "OK", ContentResult: "OK", ReasonCode: "route_path_verified", Status: "OK", EvidenceSource: "test", CheckedAt: checkedAt,
	}
}

func testConfig() *config.Config {
	return &config.Config{
		Platform: config.Platform{Target: "test"},
		Policy:   config.Policy{},
		Routes:   []config.Route{{Type: "direct", Tag: "direct"}, {Type: "drop", Tag: "drop"}},
		Services: map[string]config.Service{
			"direct":  {Category: "DIRECT_ONLY", Domains: []string{"direct.example"}, AllowedPaths: []string{"direct"}, ProbeURLs: []config.ProbeCheck{{URL: "https://direct.example/", Required: true}}},
			"blocked": {Category: "GEO_LOCKED", Domains: []string{"blocked.example"}, AllowedPaths: []string{"drop"}},
		},
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
