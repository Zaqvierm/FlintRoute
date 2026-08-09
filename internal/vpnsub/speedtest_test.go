package vpnsub

import (
	"context"
	"testing"
)

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
