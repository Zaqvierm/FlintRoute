package zapret

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type calibrationRunnerFunc func(context.Context, CalibrationRequest) ([]byte, error)

func (f calibrationRunnerFunc) Run(ctx context.Context, request CalibrationRequest) ([]byte, error) {
	return f(ctx, request)
}

func TestCalibrationManagerCompletesWithBoundedCandidates(t *testing.T) {
	raw := []byte(`{"catalog":{"version":1,"profiles":[{"id":"auto-a","provider":"nfqws-v1","provider_version":"72.13","binary_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","route_type":"zapret","ip_families":["ipv4"],"transports":["tcp"],"ports":[443],"queue":200,"safety":"reviewed","strategy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","strategy":"--qnum=200"}],"bundles":[]},"evidence":[{"profile_id":"auto-a","tests":["https_tls12"],"occurrences":3}]}`)
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
	if status.State != "completed" || status.CandidateCount != 1 || !status.ActivationRequired || status.Concurrency != 1 {
		t.Fatalf("unexpected status: %+v", status)
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
