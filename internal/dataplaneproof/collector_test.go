package dataplaneproof

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
	out := filepath.Join(root, "evidence.json")
	report, err := Collect(context.Background(), Options{Config: cfg, PlanPath: planPath, OutputPath: out, Binding: binding, ManifestHash: manifestHash, Prober: fakeProber{results: map[string]probe.RouteResult{
		"direct": {Status: "OK", PathVerified: true, PathEvidence: &direct},
		"drop":   {Status: "OK", PathVerified: true, PathEvidence: &drop},
	}}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !report.DNSLeakFree || !report.IPv6LeakFree || !report.GeoLockedKillSwitch {
		t.Fatalf("incomplete aggregate proof: %+v", report)
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
		Policy: config.Policy{},
		Routes: []config.Route{{Type: "direct", Tag: "direct"}, {Type: "drop", Tag: "drop"}},
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
