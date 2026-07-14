package health

import (
	"context"
	"sync"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/probe"
)

type memoryStore struct {
	mu     sync.Mutex
	probes []probe.RouteResult
	health map[string]probe.RouteHealth
}

func (s *memoryStore) StoreProbeResult(result probe.RouteResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probes = append(s.probes, result)
	return nil
}

func (s *memoryStore) SaveRouteHealth(value probe.RouteHealth) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.health == nil {
		s.health = map[string]probe.RouteHealth{}
	}
	s.health[value.RouteTag] = value
	return nil
}

type fakeProbeEngine struct {
	mu                sync.Mutex
	active            int
	maxActive         int
	fail              bool
	revisionByService map[string]string
	latencyByRoute    map[string]int64
}

func (e *fakeProbeEngine) ProbeRoute(ctx context.Context, _ *config.Config, domain, serviceName string, _ config.Service, route config.Route) probe.RouteResult {
	e.mu.Lock()
	e.active++
	if e.active > e.maxActive {
		e.maxActive = e.active
	}
	fail := e.fail
	revision := e.revisionByService[serviceName]
	latency := e.latencyByRoute[route.Tag]
	e.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Millisecond):
	}
	e.mu.Lock()
	e.active--
	e.mu.Unlock()
	if revision == "" {
		revision = "rev_2_001122334455"
	}
	result := probe.RouteResult{
		Domain: domain, Service: serviceName, Route: route.Tag, RouteType: route.Type, RoutePriority: route.Priority,
		Status: "OK", ApplicationStatus: "OK", PathVerified: true, ServiceOK: true, EgressConsensus: true,
		AdapterRevision: revision, CandidateHash: "sha256:" + repeat("a", 64), ArtifactManifestHash: "sha256:" + repeat("b", 64),
		ExternalIPHash: "sha256:" + repeat("c", 64), ExternalCountry: "DE", LatencyMS: latency,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if fail {
		reason := "simulated_health_failure"
		result.Status = "UNVERIFIED"
		result.ApplicationStatus = "FAIL"
		result.PathVerified = false
		result.ServiceOK = false
		result.ReasonCode = reason
		result.Reason = &reason
	}
	return result
}

func TestCycleUsesBoundedWorkersAndSelectsLowestStableLatency(t *testing.T) {
	cfg := healthConfig()
	store := &memoryStore{}
	engine := &fakeProbeEngine{latencyByRoute: map[string]int64{"fast": 20, "slow": 80}}
	service := &Service{Tracker: probe.NewHealthTracker(nil), Store: store, Parallelism: 2, MaxControlServices: 3}
	cycle, err := service.RunCycle(context.Background(), cfg, engine, time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if cycle.Status != "OK" || cycle.SelectedTag != "fast" || cycle.RoutesChecked != 2 || cycle.ProbeCount != 6 || len(cycle.Health) != 2 {
		t.Fatalf("bad health cycle: %+v", cycle)
	}
	if engine.maxActive > 2 {
		t.Fatalf("worker bound exceeded: %d", engine.maxActive)
	}
	if len(store.probes) != 6 || store.health["fast"].Role != "selected" || store.health["slow"].Role != "standby" {
		t.Fatalf("health evidence was not persisted: probes=%d health=%+v", len(store.probes), store.health)
	}
}

func TestCycleRejectsMixedRevisionEvidence(t *testing.T) {
	cfg := healthConfig()
	cfg.Routes = cfg.Routes[:1]
	store := &memoryStore{}
	engine := &fakeProbeEngine{
		latencyByRoute: map[string]int64{"fast": 20},
		revisionByService: map[string]string{
			"control-a": "rev_2_001122334455",
			"control-b": "rev_3_001122334455",
			"control-c": "rev_2_001122334455",
		},
	}
	service := &Service{Tracker: probe.NewHealthTracker(nil), Store: store, Parallelism: 1, MaxControlServices: 3}
	cycle, err := service.RunCycle(context.Background(), cfg, engine, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if cycle.SelectedTag != "" || cycle.Status != "UNVERIFIED" || store.health["fast"].Role != "quarantined" || store.health["fast"].LastReason != "health_evidence_consensus_mismatch" {
		t.Fatalf("mixed revisions were accepted: cycle=%+v health=%+v", cycle, store.health["fast"])
	}
}

func TestCycleHysteresisQuarantinesAndRecoversRoute(t *testing.T) {
	cfg := healthConfig()
	cfg.Routes = cfg.Routes[:1]
	cfg.Policy.FailAfterConsecutiveErrors = 3
	cfg.Policy.RecoverAfterConsecutiveSuccess = 3
	cfg.Policy.RouteHoldSeconds = 60
	store := &memoryStore{}
	engine := &fakeProbeEngine{latencyByRoute: map[string]int64{"fast": 20}}
	tracker := probe.NewHealthTracker(nil)
	service := &Service{Tracker: tracker, Store: store, Parallelism: 1, MaxControlServices: 3}
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	if cycle, err := service.RunCycle(context.Background(), cfg, engine, base); err != nil || cycle.SelectedTag != "fast" {
		t.Fatalf("healthy precondition failed: cycle=%+v err=%v", cycle, err)
	}
	engine.fail = true
	for i := 1; i <= 2; i++ {
		cycle, err := service.RunCycle(context.Background(), cfg, engine, base.Add(time.Duration(i)*time.Second))
		if err != nil || cycle.SelectedTag != "fast" {
			t.Fatalf("route flapped before failure threshold: cycle=%+v err=%v", cycle, err)
		}
	}
	cycle, err := service.RunCycle(context.Background(), cfg, engine, base.Add(3*time.Second))
	if err != nil || cycle.SelectedTag != "" || store.health["fast"].State != "unhealthy" || store.health["fast"].Role != "quarantined" {
		t.Fatalf("route was not quarantined after threshold: cycle=%+v health=%+v err=%v", cycle, store.health["fast"], err)
	}
	engine.fail = false
	for i := 0; i < 3; i++ {
		cycle, err = service.RunCycle(context.Background(), cfg, engine, base.Add(time.Duration(70+i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
	}
	if cycle.SelectedTag != "fast" || store.health["fast"].State != "healthy" || store.health["fast"].Role != "selected" {
		t.Fatalf("route did not recover after hold and success threshold: cycle=%+v health=%+v", cycle, store.health["fast"])
	}
}

func healthConfig() *config.Config {
	return &config.Config{
		Policy: config.Policy{ParallelServerChecks: 2, FailAfterConsecutiveErrors: 3, RecoverAfterConsecutiveSuccess: 3, RouteHoldSeconds: 60},
		Routes: []config.Route{
			{Type: "vless", Tag: "fast", Priority: 10, SOCKS5: "127.0.0.1:12000"},
			{Type: "vless", Tag: "slow", Priority: 20, SOCKS5: "127.0.0.1:12001"},
		},
		Services: map[string]config.Service{
			"control-a": controlService("GEO_LOCKED", "a.example"),
			"control-b": controlService("TSPU_RESTRICTED", "b.example"),
			"control-c": controlService("DIRECT_PREFERRED", "c.example"),
		},
	}
}

func controlService(category, domain string) config.Service {
	return config.Service{
		Category: category, Domains: []string{domain}, AllowedPaths: []string{"vless"}, RequireNonRUEgress: true,
		ProbeURLs: []config.ProbeCheck{{Name: "web", URL: "https://" + domain + "/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}},
	}
}

func repeat(value string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += value
	}
	return result
}
