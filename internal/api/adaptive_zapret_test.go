package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	runtime, _, stateFailure := srv.restoreAdaptiveState(key, now.Add(time.Second))
	if stateFailure != nil || runtime.controller.Snapshot(key, now.Add(time.Second)).ActiveProfileID != "profile-b" {
		t.Fatalf("committed adaptive runtime was not refreshed: failure=%+v", stateFailure)
	}
}

func TestAdaptivePinAPIValidatesCatalogAndPersistsState(t *testing.T) {
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
	key := zapret.DecisionKey{BundleID: "discord", Transport: "tcp", Port: 443, IPFamily: "ipv4", NetworkFingerprint: "sha256:" + strings.Repeat("b", 64)}

	invalid := adaptivePinRequest{Key: key, Pin: zapret.ManualPin{ProfileID: "profile-outside-catalog", Mode: zapret.PinFailClosed}}
	invalidRecorder := invokeAdaptiveHandler(t, srv.handleAdaptiveZapretPin, invalid)
	if invalidRecorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid catalog pin returned %d: %s", invalidRecorder.Code, invalidRecorder.Body.String())
	}

	request := adaptivePinRequest{Key: key, Pin: zapret.ManualPin{ProfileID: "profile-a", Mode: zapret.PinSafeFallback, AllowedFallbacks: []string{"profile-b"}}}
	recorder := invokeAdaptiveHandler(t, srv.handleAdaptiveZapretPin, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("pin returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data zapret.SwitchState `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Pin == nil || envelope.Data.Pin.Mode != zapret.PinSafeFallback || len(envelope.Data.Pin.AllowedFallbacks) != 1 {
		t.Fatalf("pin state was not returned: %+v", envelope.Data)
	}

	stateRecorder := invokeAdaptiveHandler(t, srv.handleAdaptiveZapretState, adaptiveStateRequest{Key: key})
	if stateRecorder.Code != http.StatusOK || !bytes.Contains(stateRecorder.Body.Bytes(), []byte(`"mode":"safe_fallback"`)) {
		t.Fatalf("persisted pin state is unavailable: %d %s", stateRecorder.Code, stateRecorder.Body.String())
	}
	unpinRecorder := invokeAdaptiveHandler(t, srv.handleAdaptiveZapretUnpin, adaptiveStateRequest{Key: key})
	if unpinRecorder.Code != http.StatusOK || bytes.Contains(unpinRecorder.Body.Bytes(), []byte(`"pin"`)) {
		t.Fatalf("pin was not cleared: %d %s", unpinRecorder.Code, unpinRecorder.Body.String())
	}
}

func TestAdaptiveActivationPathsAreTransactionalButManagedPathsStayImmutable(t *testing.T) {
	for _, path := range []string{"/zapret/adaptive_enabled", "/zapret/adaptive_catalog_file", "/zapret/adaptive_assignments"} {
		if !operationRootAllowed(path) {
			t.Fatalf("adaptive control path is unavailable: %s", path)
		}
	}
	for _, path := range []string{"/zapret/binary", "/zapret/init_script", "/zapret/active_config", "/zapret/queue_num"} {
		if operationRootAllowed(path) {
			t.Fatalf("managed Zapret path became mutable: %s", path)
		}
	}
}

func invokeAdaptiveHandler(t *testing.T, handler http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	return recorder
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
