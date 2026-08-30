package zapret

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type calibrationRunnerFunc func(context.Context, CalibrationRequest) ([]byte, error)

func (f calibrationRunnerFunc) Run(ctx context.Context, request CalibrationRequest) ([]byte, error) {
	return f(ctx, request)
}

type progressCalibrationRunner struct {
	completed int
	release   chan struct{}
	logTail   []string
	working   []string
}

func (r *progressCalibrationRunner) Run(context.Context, CalibrationRequest) ([]byte, error) {
	<-r.release
	return nil, context.Canceled
}

func (r *progressCalibrationRunner) Progress() (int, int) { return r.completed, 0 }
func (r *progressCalibrationRunner) Live() ([]string, []string) {
	return r.logTail, r.working
}

func TestCalibrationManagerCompletesWithBoundedCandidates(t *testing.T) {
	raw := []byte(`{"catalog":{"version":1,"profiles":[{"id":"auto-a","provider":"nfqws-v1","provider_version":"72.13","binary_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","route_type":"zapret","ip_families":["ipv4"],"transports":["tcp"],"ports":[443],"queue":200,"safety":"reviewed","strategy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","strategy":"--qnum=200"}],"bundles":[]},"evidence_level":"path_verified","path_verified":true,"attempts":[{"profile_id":"auto-a","target":"example.com","protocol":"https","result":"PASS","path_verified":true,"cleanup_verified":true,"nfqueue_packets":3}],"evidence":[{"profile_id":"auto-a","tests":["https_tls12"],"occurrences":3}]}`)
	raw = []byte(strings.Replace(string(raw), `"cleanup_verified":true,"nfqueue_packets":3`, `"cleanup_verified":true,"route_evidence":"default dev eth0","nfqueue_packets":3,"nfqueue_counter_delta":3`, 1))
	manager := NewCalibrationManager(calibrationRunnerFunc(func(context.Context, CalibrationRequest) ([]byte, error) { return raw, nil }))
	manager.Now = func() time.Time { return time.Unix(100, 0).UTC() }
	_, err := manager.Start(CalibrationRequest{Domain: "example.com", BundleID: "auto-example", NetworkFingerprint: "sha256:bad"})
	if err == nil {
		t.Fatal("invalid fingerprint must fail")
	}
	request := CalibrationRequest{Domain: "example.com", BundleID: "auto-example", NetworkFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if _, err := manager.Start(request); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for manager.Status().State == "running" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := manager.Status()
	if status.State != "completed" || status.CandidateCount != 1 || !status.ActivationRequired || status.RecommendedProfileID != "auto-a" || status.Concurrency != 1 || !status.PathVerified || status.EvidenceLevel != "path_verified" || len(status.Attempts) != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestCalibrationModeDefaultsToQuickAndIsPropagated(t *testing.T) {
	var got CalibrationRequest
	raw := []byte(`{"catalog":{"version":1,"profiles":[{"id":"auto-a","provider":"nfqws-v1","provider_version":"72.13","transports":["tcp"],"ports":[443],"strategy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]},"evidence":[]}`)
	manager := NewCalibrationManager(calibrationRunnerFunc(func(_ context.Context, request CalibrationRequest) ([]byte, error) {
		got = request
		return raw, nil
	}))
	request := CalibrationRequest{Domain: "example.com", BundleID: "auto-example", NetworkFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if _, err := manager.Start(request); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for manager.Status().State == "running" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got.Mode != CalibrationModeQuick {
		t.Fatalf("default mode=%q, want quick", got.Mode)
	}
	status := manager.Status()
	if status.Mode != CalibrationModeQuick || status.ScanLevel != "quick" {
		t.Fatalf("status mode=%q scan_level=%q", status.Mode, status.ScanLevel)
	}
}

func TestCalibrationModeRejectsUnknownAndMapsExhaustive(t *testing.T) {
	if _, err := NormalizeCalibrationMode("bogus"); err == nil {
		t.Fatal("unknown calibration mode must fail closed")
	}
	if mode, err := NormalizeCalibrationMode(" exhaustive "); err != nil || mode != CalibrationModeExhaustive || mode.scanLevel() != "force" || mode.defaultTimeout() != 6*time.Hour {
		t.Fatalf("unexpected exhaustive mode: mode=%q err=%v", mode, err)
	}
}

func TestQuickCalibrationCannotRestartManagedService(t *testing.T) {
	manager := NewCalibrationManager(calibrationRunnerFunc(func(context.Context, CalibrationRequest) ([]byte, error) {
		t.Fatal("quick calibration with managed restart must be rejected before runner invocation")
		return nil, nil
	}))
	_, err := manager.Start(CalibrationRequest{
		Domain: "example.com", BundleID: "auto-example",
		NetworkFingerprint:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AllowManagedRestart: true,
		Mode:                CalibrationModeQuick,
	})
	if err == nil || !strings.Contains(err.Error(), "cannot restart") {
		t.Fatalf("expected quick managed-restart rejection, got %v", err)
	}
}

func TestQuickCalibrationRejectsCurlOnlyEvidence(t *testing.T) {
	raw := []byte(`{"catalog":{"version":1,"profiles":[{"id":"auto-a","provider":"nfqws-v1","provider_version":"72.13","strategy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]},"evidence":[{"profile_id":"auto-a","occurrences":3}]}`)
	if _, err := parseCalibrationEvidence(raw, CalibrationModeQuick, "example.com"); !errors.Is(err, errCalibrationQuickEvidenceUnavailable) {
		t.Fatalf("quick must reject legacy curl-only evidence: %v", err)
	}
}

func TestQuickCalibrationReturnsAllAttemptsButOnlyVerifiedPassesAsCandidates(t *testing.T) {
	raw := []byte(`{"catalog":{"version":1,"profiles":[
		{"id":"profile-a","provider":"nfqws","provider_version":"72.13","strategy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{"id":"profile-b","provider":"nfqws","provider_version":"72.13","strategy_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		{"id":"profile-c","provider":"nfqws","provider_version":"72.13","strategy_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
		{"id":"profile-d","provider":"nfqws","provider_version":"72.13","strategy_digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
	]},"evidence_level":"path_verified","path_verified":true,
		"attempts":[
			{"profile_id":"profile-a","target":"example.com","protocol":"https","result":"PASS","path_verified":true,"cleanup_verified":true,"route_evidence":"default dev eth0","nfqueue_packets":4,"nfqueue_counter_delta":4},
			{"profile_id":"profile-b","target":"example.com","protocol":"https","result":"FAIL","path_verified":true,"cleanup_verified":true,"route_evidence":"default dev eth0","nfqueue_packets":2,"nfqueue_counter_delta":2},
			{"profile_id":"profile-c","target":"example.com","protocol":"https","result":"TIMEOUT","path_verified":true,"cleanup_verified":true,"route_evidence":"default dev eth0","nfqueue_packets":1,"nfqueue_counter_delta":1},
			{"profile_id":"profile-d","target":"example.com","protocol":"https","result":"INFRA_ERROR","path_verified":false,"cleanup_verified":true,"error_code":"nfqueue_unavailable"}
		]}`)
	parsed, err := parseCalibrationEvidence(raw, CalibrationModeQuick, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Attempts) != 4 || len(parsed.Candidates) != 1 || parsed.Candidates[0].ProfileID != "profile-a" || !parsed.PathVerified {
		t.Fatalf("unexpected quick result: %+v", parsed)
	}
}

func TestQuickCalibrationAllFailuresRemainTerminalWithoutRecommendation(t *testing.T) {
	raw := []byte(`{"catalog":{"version":1,"profiles":[
		{"id":"profile-a","provider":"nfqws","provider_version":"72.13","strategy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{"id":"profile-b","provider":"nfqws","provider_version":"72.13","strategy_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
	]},"evidence_level":"path_verified","path_verified":false,
		"attempts":[
			{"profile_id":"profile-a","target":"example.com","protocol":"https","result":"FAIL","path_verified":true,"cleanup_verified":true,"route_evidence":"default dev eth0","nfqueue_packets":1,"nfqueue_counter_delta":1},
			{"profile_id":"profile-b","target":"example.com","protocol":"https","result":"TIMEOUT","path_verified":true,"cleanup_verified":true,"route_evidence":"default dev eth0","nfqueue_packets":1,"nfqueue_counter_delta":1}
		]}`)
	parsed, err := parseCalibrationEvidence(raw, CalibrationModeQuick, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Attempts) != 2 || len(parsed.Candidates) != 0 || parsed.PathVerified {
		t.Fatalf("all-failure quick run was overstated: %+v", parsed)
	}
}

func TestQuickCalibrationRejectsUnboundOrDuplicateAttempts(t *testing.T) {
	base := `{"catalog":{"version":1,"profiles":[{"id":"profile-a","provider":"nfqws","provider_version":"72.13","strategy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]},"evidence_level":"path_verified","path_verified":true,"attempts":[%s]}`
	for name, attempt := range map[string]string{
		"unknown profile":        `{"profile_id":"profile-b","target":"example.com","protocol":"https","result":"PASS","path_verified":true,"cleanup_verified":true}`,
		"duplicate profile":      `{"profile_id":"profile-a","target":"example.com","protocol":"https","result":"PASS","path_verified":true,"cleanup_verified":true},{"profile_id":"profile-a","target":"example.com","protocol":"https","result":"FAIL","path_verified":true,"cleanup_verified":true}`,
		"wrong target":           `{"profile_id":"profile-a","target":"other.example","protocol":"https","result":"PASS","path_verified":true,"cleanup_verified":true}`,
		"missing route evidence": `{"profile_id":"profile-a","target":"example.com","protocol":"https","result":"PASS","path_verified":true,"cleanup_verified":true,"nfqueue_packets":1,"nfqueue_counter_delta":1}`,
		"missing queue counter":  `{"profile_id":"profile-a","target":"example.com","protocol":"https","result":"PASS","path_verified":true,"cleanup_verified":true,"route_evidence":"default dev eth0"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCalibrationEvidence([]byte(fmt.Sprintf(base, attempt)), CalibrationModeQuick, "example.com"); !errors.Is(err, errCalibrationQuickEvidenceUnavailable) {
				t.Fatalf("unsafe quick evidence accepted: %v", err)
			}
		})
	}
}

func TestProductionRunnerDoesNotFallBackToUpstreamForQuick(t *testing.T) {
	runner := ExecCalibrationRunner{Script: "/tmp/calibrate.sh", Blockcheck: "/tmp/blockcheck.sh"}
	if _, err := runner.Run(context.Background(), CalibrationRequest{Mode: CalibrationModeQuick}); !errors.Is(err, errCalibrationQuickEvidenceUnavailable) {
		t.Fatalf("quick unexpectedly fell back to upstream blockcheck: %v", err)
	}
}

func TestProductionQuickRunnerRequiresManagedQueueBinding(t *testing.T) {
	runner := ExecCalibrationRunner{
		QuickScript: "/tmp/quick-zapret-check.sh", Config: "/tmp/config.json",
		RouterPolicyBin: "/tmp/router-policy", NFQWSBin: "/tmp/nfqws",
		ZapretInit: "/tmp/zapret-init", RuntimeDir: "/tmp/runtime", CatalogOut: "/tmp/catalog.json",
	}
	_, err := runner.Run(context.Background(), CalibrationRequest{Mode: CalibrationModeQuick})
	if err == nil || !strings.Contains(err.Error(), "managed production NFQUEUE") {
		t.Fatalf("quick runner must require production queue binding, got %v", err)
	}
}

func TestExhaustiveLegacyEvidenceIsExplicitlyCurlOnly(t *testing.T) {
	raw := []byte(`{"catalog":{"version":1,"profiles":[{"id":"auto-a","provider":"nfqws-v1","provider_version":"72.13","strategy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]},"evidence":[{"profile_id":"auto-a","occurrences":3}]}`)
	parsed, err := parseCalibrationEvidence(raw, CalibrationModeExhaustive, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.EvidenceLevel != "curl_only" || parsed.PathVerified {
		t.Fatalf("legacy exhaustive evidence was overstated: %+v", parsed)
	}
}

func TestCalibrationManagerRejectsConcurrentRunAndCancels(t *testing.T) {
	started := make(chan struct{})
	var once sync.Once
	manager := NewCalibrationManager(calibrationRunnerFunc(func(ctx context.Context, _ CalibrationRequest) ([]byte, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	request := CalibrationRequest{Domain: "example.com", BundleID: "auto-example", NetworkFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if _, err := manager.Start(request); err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := manager.Start(request); err == nil {
		t.Fatal("concurrent calibration must be rejected")
	}
	manager.Cancel()
	deadline := time.Now().Add(time.Second)
	for manager.Status().State == "running" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if status := manager.Status(); status.State != "cancelled" {
		t.Fatalf("unexpected cancel status: %+v", status)
	}
}

func TestCalibrationCommandErrorKeepsBoundedPrintableTail(t *testing.T) {
	err := calibrationCommandError([]byte("first line\n\x00diagnostic reason\t" + strings.Repeat("x", 300)))
	message := err.Error()
	if strings.ContainsRune(message, '\x00') || strings.Contains(message, "\n") || len(message) > 280 {
		t.Fatalf("unsafe or unbounded diagnostic: %q", message)
	}
	if !strings.HasSuffix(message, strings.Repeat("x", 240)) {
		t.Fatalf("expected bounded tail, got %q", message)
	}
}

func TestCalibrationCommandErrorClassifiesUpstreamTimeout(t *testing.T) {
	err := calibrationCommandError([]byte("upstream blockcheck timed out after 2400s; bounded diagnostic tail follows\nlast strategy"))
	if !strings.Contains(err.Error(), "last strategy") || !errors.Is(err, errCalibrationUpstreamTimeout) {
		t.Fatalf("timeout classification was lost: %v", err)
	}
}

func TestCalibrationCommandErrorClassifiesMissingPrivilegeHelper(t *testing.T) {
	err := calibrationCommandError([]byte("quick Zapret check: su is unavailable"))
	if !errors.Is(err, errCalibrationPrivilegeHelperUnavailable) {
		t.Fatalf("missing privilege helper was not classified: %v", err)
	}
	if !strings.Contains(err.Error(), "su is unavailable") {
		t.Fatalf("diagnostic was lost: %v", err)
	}
}

func TestCalibrationStatusReportsLiveCompletedChecks(t *testing.T) {
	runner := &progressCalibrationRunner{completed: 2, release: make(chan struct{}), logTail: []string{"checking strategy"}, working: []string{"strategy-a"}}
	manager := NewCalibrationManager(runner)
	request := CalibrationRequest{Domain: "example.com", BundleID: "auto-example", NetworkFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if _, err := manager.Start(request); err != nil {
		t.Fatal(err)
	}
	status := manager.Status()
	if status.ChecksCompleted != 2 || status.ChecksTotal != quickCuratedProfileCount || len(status.LogTail) != 1 || len(status.WorkingStrategies) != 1 {
		t.Fatalf("unexpected live progress: %+v", status)
	}
	close(runner.release)
}

func TestCalibrationLiveSnapshotIsBoundedAndExtractsWorkingStrategies(t *testing.T) {
	raw := []byte("checking strategy-a\n!!!!! AVAILABLE !!!!!\nchecking strategy-b\nUNAVAILABLE code=28\n")
	logs, working := calibrationLiveSnapshot(raw)
	if len(logs) != 4 || len(working) != 1 || working[0] != "checking strategy-a" {
		t.Fatalf("unexpected live snapshot: logs=%v working=%v", logs, working)
	}
}

func TestCompletedCalibrationCheckCounterIgnoresAttempts(t *testing.T) {
	raw := []byte("[attempt 1] AVAILABLE\n!!!!! AVAILABLE !!!!!\n[attempt 2] timeout\nUNAVAILABLE code=28\n")
	if got := countCompletedCalibrationChecks(raw); got != 2 {
		t.Fatalf("completed checks=%d", got)
	}
}

func TestCalibrationPreResolvedIPv4IsBoundedAndPublic(t *testing.T) {
	got, err := normalizeCalibrationIPv4([]string{"8.8.8.8", "8.8.8.8", "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "8.8.8.8" || got[1] != "1.1.1.1" {
		t.Fatalf("unexpected normalized addresses: %v", got)
	}
	for _, invalid := range [][]string{{"127.0.0.1"}, {"192.168.1.1"}, {"203.0.113.10"}, {"not-an-ip"}} {
		if _, err := normalizeCalibrationIPv4(invalid); err == nil {
			t.Fatalf("unsafe address was accepted: %v", invalid)
		}
	}
}
