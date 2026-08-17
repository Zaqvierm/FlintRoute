package vpnsub

import (
	"context"
	"errors"
	"testing"
	"time"

	"router-policy/internal/config"
)

func TestThroughputTesterFallsBackToBoundedTelenorRange(t *testing.T) {
	var targets []speedTarget
	tester := CloudflareThroughputTester{measure: func(_ context.Context, _ string, bytes int64, target speedTarget, _ time.Duration) (SpeedMeasurement, error) {
		targets = append(targets, target)
		if target.Endpoint == cloudflareDownloadEndpoint {
			return SpeedMeasurement{}, errors.New("VLESS speed test returned HTTP 403")
		}
		if target.Endpoint != telenorDownloadEndpoint || !target.UseRange {
			t.Fatalf("unexpected fallback target: %+v", target)
		}
		return SpeedMeasurement{MeasuredMbps: 123, BytesUsed: bytes}, nil
	}}
	measurement, err := tester.Measure(context.Background(), "127.0.0.1:12000", 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || measurement.BytesUsed != 2<<20 {
		t.Fatalf("fallback was not bounded: targets=%+v measurement=%+v", targets, measurement)
	}
}

type fakeThroughputTester struct {
	called int
	bytes  int64
}

func (f *fakeThroughputTester) Measure(_ context.Context, endpoint string, bytes int64) (SpeedMeasurement, error) {
	f.called++
	f.bytes = bytes
	if endpoint != "127.0.0.1:12000" {
		return SpeedMeasurement{}, context.Canceled
	}
	return SpeedMeasurement{MeasuredMbps: 850, BytesUsed: bytes, DurationMS: 200, TestedAt: "2026-08-09T00:00:00Z"}, nil
}

func TestSelectedVLESSServerGetsBoundedCandidateSpeedMeasurement(t *testing.T) {
	root := t.TempDir()
	subscription := writeManagerSubscription(t, root)
	runner := &fakeXrayRunner{}
	checker := &sequenceChecker{checks: []OutboundCheck{{Status: "OK", LatencyMS: 20, ExternalIPHash: "sha256:egress", ExternalCountry: "DE"}}}
	tester := &fakeThroughputTester{}
	manager := &Manager{StateDir: root, Runner: runner, Checker: checker, SpeedTester: tester, TariffMbps: 300}
	result, err := manager.PrepareBundle(context.Background(), subscription, 12000)
	if err != nil {
		t.Fatal(err)
	}
	if tester.called != 1 || tester.bytes > 16<<20 || tester.bytes < 2<<20 || result.Servers[0].MeasuredMbps != 850 || result.Servers[0].SpeedBytes != tester.bytes {
		t.Fatalf("unexpected bounded speed measurement: tester=%+v server=%+v", tester, result.Servers[0])
	}
}

func TestSpeedTestBytesIsBoundedByTrafficBudget(t *testing.T) {
	for _, test := range []struct {
		tariff float64
		want   int64
	}{{1, 2 << 20}, {300, 13_125_000}, {1000, 16 << 20}} {
		if got := SpeedTestBytes(test.tariff); got != test.want {
			t.Fatalf("tariff=%v got=%d want=%d", test.tariff, got, test.want)
		}
	}
}

func TestMeasureServerRestartsVerifiedCandidateForBoundedSpeedTest(t *testing.T) {
	root := t.TempDir()
	subscription := writeManagerSubscription(t, root)
	runner := &fakeXrayRunner{}
	checker := &sequenceChecker{checks: []OutboundCheck{{Status: "OK", LatencyMS: 20, ExternalIPHash: "sha256:egress", ExternalCountry: "DE"}}}
	prepared, err := (&Manager{StateDir: root, Runner: runner, Checker: checker}).PrepareBundle(context.Background(), subscription, 12000)
	if err != nil {
		t.Fatal(err)
	}
	if err := StorePool(PoolPath(root), PoolSnapshot{BundleHash: prepared.BundleHash, TariffMbps: 300, Servers: prepared.Servers}); err != nil {
		t.Fatal(err)
	}
	runner.tests, runner.starts, runner.readiness, runner.stops = 0, 0, 0, 0
	tester := &fakeThroughputTester{}
	service := &SubscriptionService{Runner: runner, SpeedTester: tester}
	measurement, server, err := service.MeasureServer(context.Background(), &config.Config{Storage: config.Storage{StateDir: root}}, prepared.Servers[0].LogicalID)
	if err != nil {
		t.Fatal(err)
	}
	if runner.tests != 1 || runner.starts != 1 || runner.readiness != 1 || runner.stops != 1 {
		t.Fatalf("candidate lifecycle was not bounded: %+v", runner)
	}
	if measurement.MeasuredMbps != 850 || server.MeasuredMbps != 850 || server.EffectiveMbps != 300 {
		t.Fatalf("measurement was not stored and tariff-capped: measurement=%+v server=%+v", measurement, server)
	}
}

func TestMeasureServerUsesActiveManagedXrayWithoutPortCollision(t *testing.T) {
	root := t.TempDir()
	runner := &fakeXrayRunner{}
	tester := &fakeThroughputTester{}
	server := ServerStatus{LogicalID: "srv_active", SOCKS5: "127.0.0.1:12000", PathVerified: true}
	if err := StorePool(PoolPath(root), PoolSnapshot{TariffMbps: 300, Servers: []ServerStatus{server}}); err != nil {
		t.Fatal(err)
	}
	service := &SubscriptionService{Runner: runner, SpeedTester: tester}
	_, _, err := service.MeasureServer(context.Background(), &config.Config{Storage: config.Storage{StateDir: root}, Xray: config.Xray{ActivationMode: "managed"}}, server.LogicalID)
	if err != nil {
		t.Fatal(err)
	}
	if runner.tests != 0 || runner.starts != 0 || runner.readiness != 0 || runner.stops != 0 {
		t.Fatalf("managed Xray must be reused instead of starting a colliding candidate: %+v", runner)
	}
}
