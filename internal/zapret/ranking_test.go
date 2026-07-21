package zapret

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"
)

func TestRankerUsesWilsonStabilityAndLatencyLexicographically(t *testing.T) {
	ranker, key, profiles := testRanker(t)
	start := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	for window := 0; window < 3; window++ {
		for attempt := 0; attempt < 4; attempt++ {
			at := start.Add(time.Duration(window)*time.Minute + time.Duration(attempt)*time.Second)
			observeRank(t, ranker, key, profiles[0], at, true, 120*time.Millisecond)
			observeRank(t, ranker, key, profiles[1], at, true, 80*time.Millisecond)
		}
	}
	ranking, err := ranker.Rank(key, map[string]int{profiles[0]: 1, profiles[1]: 1}, start.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(ranking) != 2 || ranking[0].ProfileID != profiles[1] {
		t.Fatalf("lower latency did not break an equal reliability tie: %+v", ranking)
	}
	if !ranking[0].ProductionReady || ranking[0].StableWindows != 3 || ranking[0].Attempts != 12 {
		t.Fatalf("unexpected production score: %+v", ranking[0])
	}
	if math.Abs(ranking[0].WilsonLowerBound-0.7575) > 0.001 {
		t.Fatalf("unexpected Wilson lower bound: %f", ranking[0].WilsonLowerBound)
	}
}

func TestRankerSafetyGateBeatsFastUnsafeCandidate(t *testing.T) {
	ranker, key, profiles := testRanker(t)
	start := time.Date(2026, 7, 16, 13, 0, 0, 0, time.UTC)
	for window := 0; window < 2; window++ {
		for attempt := 0; attempt < 3; attempt++ {
			at := start.Add(time.Duration(window)*time.Minute + time.Duration(attempt)*time.Second)
			observeRank(t, ranker, key, profiles[0], at, true, 150*time.Millisecond)
			unsafe := ProbeObservation{Key: key, ProfileID: profiles[1], ObservedAt: at, SafetyGate: false, RequiredChecksPassed: true, PathVerified: true, Latency: 5 * time.Millisecond}
			if _, err := ranker.Observe(unsafe); err != nil {
				t.Fatal(err)
			}
		}
	}
	ranking, err := ranker.Rank(key, nil, start.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if ranking[0].ProfileID != profiles[0] || ranking[1].SafetyGate {
		t.Fatalf("unsafe candidate outranked safe profile: %+v", ranking)
	}
}

func TestRankerSeparatesDecisionKeysAndExpiresOldSamples(t *testing.T) {
	ranker, key, profiles := testRanker(t)
	now := time.Date(2026, 7, 16, 14, 0, 0, 0, time.UTC)
	other := key
	other.NetworkFingerprint = Digest([]byte("other-network"))
	for i := 0; i < 6; i++ {
		observeRank(t, ranker, key, profiles[0], now.Add(time.Duration(i)*time.Second), true, 100*time.Millisecond)
	}
	if score, err := ranker.Snapshot(other, profiles[0], now.Add(time.Minute)); err != nil || score.Attempts != 0 {
		t.Fatalf("decision key leaked observations: score=%+v err=%v", score, err)
	}
	if score, err := ranker.Snapshot(key, profiles[0], now.Add(3*time.Hour)); err != nil || score.Attempts != 0 {
		t.Fatalf("expired samples remained active: score=%+v err=%v", score, err)
	}
}

func TestRankerPersistsBoundedObservationsWithoutCrossNetworkLeak(t *testing.T) {
	ranker, key, profiles := testRanker(t)
	now := time.Date(2026, 7, 16, 14, 30, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		observeRank(t, ranker, key, profiles[0], now.Add(time.Duration(i)*time.Second), true, 100*time.Millisecond)
	}
	snapshot, err := ranker.Observations(now.Add(time.Minute))
	if err != nil || len(snapshot) != 6 {
		t.Fatalf("unexpected persistence snapshot: count=%d err=%v", len(snapshot), err)
	}
	restored, _, _ := testRanker(t)
	if err := restored.Restore(snapshot, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if score, err := restored.Snapshot(key, profiles[0], now.Add(time.Minute)); err != nil || score.Attempts != 6 {
		t.Fatalf("persisted observations were not restored: score=%+v err=%v", score, err)
	}
	other := key
	other.NetworkFingerprint = Digest([]byte("new-network"))
	if score, err := restored.Snapshot(other, profiles[0], now.Add(time.Minute)); err != nil || score.Attempts != 0 {
		t.Fatalf("old network observations leaked into new fingerprint: score=%+v err=%v", score, err)
	}
	future := append([]ProbeObservation(nil), snapshot...)
	future[0].ObservedAt = now.Add(2 * time.Hour)
	if err := restored.Restore(future, now.Add(time.Minute)); err == nil {
		t.Fatal("future persisted observation was accepted")
	}
}

func TestRankerBoundsSamplesAndRejectsFalsePositiveSuccess(t *testing.T) {
	ranker, key, profiles := testRanker(t)
	now := time.Date(2026, 7, 16, 15, 0, 0, 0, time.UTC)
	bad := ProbeObservation{Key: key, ProfileID: profiles[0], ObservedAt: now, Success: true, SafetyGate: true, RequiredChecksPassed: true}
	if _, err := ranker.Observe(bad); err == nil {
		t.Fatal("successful probe without path proof was accepted")
	}
	for i := 0; i < 40; i++ {
		observeRank(t, ranker, key, profiles[0], now.Add(time.Duration(i)*time.Second), true, time.Duration(50+i)*time.Millisecond)
	}
	score, err := ranker.Snapshot(key, profiles[0], now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if score.Attempts != 32 {
		t.Fatalf("sample cap was not enforced: %+v", score)
	}
}

func TestRankerConcurrentObserveIsRaceSafe(t *testing.T) {
	ranker, key, profiles := testRanker(t)
	now := time.Date(2026, 7, 16, 16, 0, 0, 0, time.UTC)
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			observation := ProbeObservation{
				Key: key, ProfileID: profiles[index%len(profiles)], ObservedAt: now.Add(time.Duration(index) * time.Millisecond),
				Success: true, SafetyGate: true, RequiredChecksPassed: true, PathVerified: true, Latency: 100 * time.Millisecond,
			}
			if _, err := ranker.Observe(observation); err != nil {
				t.Errorf("observe: %v", err)
			}
		}(i)
	}
	group.Wait()
}

func testRanker(t *testing.T) (*Ranker, DecisionKey, []string) {
	t.Helper()
	strategyA := []byte("--qnum=200\n--filter-tcp=443\n--dpi-desync=fake\n")
	strategyB := []byte("--qnum=201\n--filter-tcp=443\n--dpi-desync=fake\n")
	profiles := []Profile{
		{ID: "zapret-a", Provider: "nfqws-v1", ProviderVersion: "72.12", BinaryDigest: Digest([]byte("binary")), RouteType: "zapret", IPFamilies: []string{"ipv4"}, Transports: []string{"tcp"}, Ports: []uint16{443}, Queue: 200, Safety: "reviewed", StrategyDigest: Digest(strategyA), Strategy: strategyA},
		{ID: "zapret-b", Provider: "nfqws-v1", ProviderVersion: "72.12", BinaryDigest: Digest([]byte("binary")), RouteType: "zapret", IPFamilies: []string{"ipv4"}, Transports: []string{"tcp"}, Ports: []uint16{443}, Queue: 201, Safety: "reviewed", StrategyDigest: Digest(strategyB), Strategy: strategyB},
	}
	profileCatalog, err := NewCatalog(profiles)
	if err != nil {
		t.Fatal(err)
	}
	bundleCatalog, err := NewBundleCatalog([]BundleSpec{{
		ID: "discord", Category: "TSPU_RESTRICTED", RequiredDomains: []string{"discord.com"},
		Protocols: []Protocol{{Transport: "tcp", Port: 443}}, IPFamilies: []string{"ipv4"},
		AllowedProfiles: []string{profiles[0].ID, profiles[1].ID}, FailureRoute: "vless-safe",
	}}, profileCatalog)
	if err != nil {
		t.Fatal(err)
	}
	policy := DefaultRankingPolicy()
	policy.WindowDuration = time.Minute
	policy.Retention = 2 * time.Hour
	policy.MaxSamplesPerProfile = 32
	policy.MinAttempts = 5
	policy.MinStableWindows = 2
	policy.ProductionMinAttempts = 10
	ranker, err := NewRanker(bundleCatalog, profileCatalog, policy)
	if err != nil {
		t.Fatal(err)
	}
	key := DecisionKey{BundleID: "discord", Transport: "tcp", Port: 443, IPFamily: "ipv4", NetworkFingerprint: Digest([]byte("network"))}
	return ranker, key, []string{profiles[0].ID, profiles[1].ID}
}

func observeRank(t *testing.T, ranker *Ranker, key DecisionKey, profileID string, at time.Time, success bool, latency time.Duration) {
	t.Helper()
	observation := ProbeObservation{
		Key: key, ProfileID: profileID, ObservedAt: at, Success: success,
		SafetyGate: true, RequiredChecksPassed: true, PathVerified: true, Latency: latency,
	}
	if !success {
		observation.PathVerified = false
	}
	if _, err := ranker.Observe(observation); err != nil {
		t.Fatal(fmt.Errorf("observe %s: %w", profileID, err))
	}
}
