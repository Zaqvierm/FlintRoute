package api

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/zapret"
)

func TestAdaptiveEvaluationCommitsThroughChangeSet(t *testing.T) {
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

	srv, err := NewServerWithOptions(cfg, Options{ProductionAdapter: newFakeAdapter(), Provider: artifactDiagnosticsTestProvider{diagnostics: testArtifactNetworkDiagnostics(false)}, Development: false})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	now := time.Date(2026, 7, 16, 20, 0, 0, 0, time.UTC)
	key := zapret.DecisionKey{BundleID: "discord", Transport: "tcp", Port: 443, IPFamily: "ipv4", NetworkFingerprint: "sha256:" + strings.Repeat("a", 64)}
	ranking := []zapret.CandidateScore{
		{Key: key, ProfileID: "profile-b", Eligible: true, SafetyGate: true, RequiredChecksPassed: true, WilsonLowerBound: 0.95, WilsonUpperBound: 1, SuccessRatio: 1, StableWindows: 3, MedianLatencyMS: 80},
		{Key: key, ProfileID: "profile-a", RecentHardFailure: true, FailureStreak: 3, FailedWindows: 2, WilsonUpperBound: 0.2},
	}
	response, failure := srv.evaluateAdaptiveZapret(context.Background(), adaptiveEvaluateRequest{Key: key, Ranking: ranking}, now)
	if failure != nil {
		t.Fatalf("adaptive evaluation failed: %+v", failure)
	}
	if response.Decision.Action != zapret.SwitchProfile || response.Decision.ToProfile != "profile-b" || response.Change == nil || response.Change.State != "committed" {
		t.Fatalf("unexpected adaptive response: %+v", response)
	}
	if got := profileForBundle(srv.currentConfig().Zapret.AdaptiveAssignments, "discord"); got != "profile-b" {
		t.Fatalf("active assignment was not committed: %s", got)
	}
}

func writeAdaptiveCatalog(t *testing.T, path string) {
	t.Helper()
	strategyA := "--qnum=200\n--filter-tcp=80,443\n--dpi-desync=fake\n"
	strategyB := "--qnum=200\n--filter-tcp=80,443\n--dpi-desync=fake\n--dpi-desync-ttl=3\n"
	document := zapret.CatalogFile{
		Version: 1,
		Profiles: []zapret.CatalogFileProfile{
			{ID: "profile-a", Provider: "nfqws-v1", ProviderVersion: "72.12", BinaryDigest: zapret.Digest([]byte("binary")), RouteType: "zapret", IPFamilies: []string{"ipv4"}, Transports: []string{"tcp"}, Ports: []uint16{80, 443}, Queue: 200, Safety: "reviewed", StrategyDigest: zapret.Digest([]byte(strategyA)), Strategy: strategyA},
			{ID: "profile-b", Provider: "nfqws-v1", ProviderVersion: "72.12", BinaryDigest: zapret.Digest([]byte("binary")), RouteType: "zapret", IPFamilies: []string{"ipv4"}, Transports: []string{"tcp"}, Ports: []uint16{80, 443}, Queue: 200, Safety: "reviewed", StrategyDigest: zapret.Digest([]byte(strategyB)), Strategy: strategyB},
		},
		Bundles: []zapret.BundleSpec{{ID: "discord", Category: "TSPU_RESTRICTED", RequiredDomains: []string{"discord.com"}, Protocols: []zapret.Protocol{{Transport: "tcp", Port: 80}, {Transport: "tcp", Port: 443}}, IPFamilies: []string{"ipv4"}, AllowedProfiles: []string{"profile-a", "profile-b"}, FailureRoute: "drop"}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
