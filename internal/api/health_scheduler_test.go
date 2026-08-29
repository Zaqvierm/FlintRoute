package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/discovery"
	"router-policy/internal/health"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
	"router-policy/internal/tspu"
	"router-policy/internal/vpnsub"
)

type apiHealthEngine struct {
	mu    sync.Mutex
	calls int
}

func (e *apiHealthEngine) ProbeRoute(_ context.Context, _ *config.Config, domain, service string, _ config.Service, route config.Route) probe.RouteResult {
	e.mu.Lock()
	e.calls++
	e.mu.Unlock()
	latency := int64(80)
	if route.Tag == "vless-fast" {
		latency = 20
	}
	return probe.RouteResult{
		Domain: domain, Service: service, Route: route.Tag, RouteType: route.Type, RoutePriority: route.Priority,
		Status: "OK", ApplicationStatus: "OK", PathVerified: true, ServiceOK: true, EgressConsensus: true,
		AdapterRevision: "rev_2_001122334455", CandidateHash: "sha256:" + strings.Repeat("a", 64), ArtifactManifestHash: "sha256:" + strings.Repeat("b", 64),
		ExternalIPHash: "sha256:" + strings.Repeat("c", 64), ExternalCountry: "DE", LatencyMS: latency,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func TestSubscriptionOperationLockIsNonBlocking(t *testing.T) {
	srv := &Server{}
	srv.subscriptionMu.Lock()
	started := time.Now()
	if srv.tryLockSubscription() {
		srv.subscriptionMu.Unlock()
		t.Fatal("tryLockSubscription acquired an already-held lock")
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("busy subscription operation blocked for %s", elapsed)
	}
	srv.subscriptionMu.Unlock()
	if !srv.tryLockSubscription() {
		t.Fatal("tryLockSubscription did not acquire an available lock")
	}
	srv.subscriptionMu.Unlock()
}

func TestServerHealthCycleCallsInjectedEnginePersistsAndExposesStatus(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	active := srv.currentConfig()
	active.Routes = append(active.Routes,
		config.Route{Type: "vless", Tag: "vless-fast", Priority: 20, SOCKS5: "127.0.0.1:12000"},
		config.Route{Type: "vless", Tag: "vless-slow", Priority: 30, SOCKS5: "127.0.0.1:12001"},
	)
	active.Services["health-a"] = apiHealthControl("a.example")
	active.Services["health-b"] = apiHealthControl("b.example")
	active.Services["health-c"] = apiHealthControl("c.example")
	engine := &apiHealthEngine{}
	srv.probeEngineFactory = func(*config.Config) health.ProbeEngine { return engine }

	srv.runHealthCycle(context.Background())
	engine.mu.Lock()
	calls := engine.calls
	engine.mu.Unlock()
	if calls != 6 {
		t.Fatalf("scheduler made %d probes instead of 6", calls)
	}
	persisted, err := srv.store.ListRouteHealth()
	if err != nil {
		t.Fatal(err)
	}
	selected := ""
	for _, item := range persisted {
		if item.Role == "selected" {
			selected = item.RouteTag
		}
	}
	if selected != "vless-fast" {
		t.Fatalf("health state did not persist selected route: %+v", persisted)
	}

	recorder := httptest.NewRecorder()
	srv.handleRouteHealth(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/route-health", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("route health endpoint status=%d", recorder.Code)
	}
	var envelope Envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(envelope.Data)
	if !strings.Contains(string(raw), `"status":"OK"`) || strings.Contains(string(raw), "203.0.113.") {
		t.Fatalf("route health API is dishonest or leaked an IP: %s", raw)
	}
}

func TestServerHealthCycleFailsClosedWhenActiveConfigIsMissing(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.mu.Lock()
	srv.activeConfig = nil
	srv.mu.Unlock()
	srv.probeEngineFactory = func(*config.Config) health.ProbeEngine {
		t.Fatal("health scheduler constructed a probe engine without active config")
		return nil
	}

	srv.runHealthCycle(context.Background())
	events := srv.broker.Recent(0, 5)
	if len(events) == 0 || events[len(events)-1].ReasonCode != "active_config_unavailable" {
		t.Fatalf("missing active config was not reported as a fenced health state: %+v", events)
	}
}

func TestSmartDNSHandlersFailClosedWhenActiveConfigIsMissing(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.mu.Lock()
	srv.activeConfig = nil
	srv.mu.Unlock()

	get := httptest.NewRecorder()
	srv.handleSmartDNS(get, httptest.NewRequest(http.MethodGet, "/api/v1/smart-dns", nil))
	if get.Code != http.StatusServiceUnavailable || !strings.Contains(get.Body.String(), "active_config_unavailable") {
		t.Fatalf("Smart DNS read did not fail closed: status=%d body=%s", get.Code, get.Body.String())
	}
	post := httptest.NewRecorder()
	srv.handleSmartDNSConfigure(post, httptest.NewRequest(http.MethodPost, "/api/v1/smart-dns/configure", strings.NewReader(`{"base_version":1,"test_domain":"example.com","endpoints":["1.1.1.1:53"]}`)))
	if post.Code != http.StatusServiceUnavailable || !strings.Contains(post.Body.String(), "active_config_unavailable") {
		t.Fatalf("Smart DNS mutation did not fail closed: status=%d body=%s", post.Code, post.Body.String())
	}
}

func TestTSPURefreshPublishesSuccessAndFailureWithoutDomains(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.activeConfig.TSPUSources = []config.TSPUSource{{Name: "fixture", Type: "domains", URL: "https://example.test/list", MinEntries: 1, MaxDropRatio: 0.25}}
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	srv.tspuRefresh = func(context.Context, *config.Config, time.Time) (tspu.Cache, error) {
		calls++
		cache := tspu.BuildCache(now, time.Hour, []tspu.SourceReport{{Name: "fixture", Accepted: true, Fresh: true}}, map[string][]string{"fixture": {"blocked.example"}})
		if calls == 2 {
			return cache, errors.New("fixture source unavailable")
		}
		return cache, nil
	}
	if err := srv.runTSPURefresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := srv.runTSPURefresh(context.Background()); err == nil {
		t.Fatal("failed refresh unexpectedly succeeded")
	}
	events := srv.broker.Recent(0, 10)
	var success, failure *Event
	for index := range events {
		switch events[index].ReasonCode {
		case "tspu_cache_refresh_completed":
			success = &events[index]
		case "tspu_cache_refresh_failed":
			failure = &events[index]
		}
	}
	if success == nil || failure == nil || success.Details["entries"] != 1 || failure.Details["entries"] != 1 {
		t.Fatalf("TSPU refresh events are incomplete: %+v", events)
	}
	raw, _ := json.Marshal(events)
	if strings.Contains(string(raw), "blocked.example") {
		t.Fatalf("TSPU event leaked cache domains: %s", raw)
	}
}

func TestTSPUSchedulerRunsInjectedRefresh(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.activeConfig.Policy.TSPUListUpdateIntervalSeconds = 3600
	srv.activeConfig.TSPUSources = []config.TSPUSource{{Name: "fixture", Type: "domains", URL: "https://example.test/list", MinEntries: 1, MaxDropRatio: 0.25}}
	srv.tspuDelay = func(time.Duration, int, bool) time.Duration { return time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	srv.tspuRefresh = func(context.Context, *config.Config, time.Time) (tspu.Cache, error) {
		cancel()
		return tspu.BuildCache(time.Now().UTC(), time.Hour, []tspu.SourceReport{{Name: "fixture", Accepted: true, Fresh: true}}, map[string][]string{"fixture": {"blocked.example"}}), nil
	}
	defer cancel()
	go func() {
		srv.runTSPUScheduler(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TSPU scheduler did not trigger refresh and stop")
	}
}

func TestTSPUDelayUsesStartupJitterAndBoundedFailureBackoff(t *testing.T) {
	interval := 6 * time.Hour
	if got := tspuBaseDelay(interval, 0, true); got != 5*time.Minute {
		t.Fatalf("startup delay=%s", got)
	}
	if got := tspuBaseDelay(interval, 0, false); got != interval {
		t.Fatalf("success delay=%s", got)
	}
	if got := tspuBaseDelay(interval, 1, false); got != time.Minute {
		t.Fatalf("first retry delay=%s", got)
	}
	if got := tspuBaseDelay(interval, 20, false); got != time.Hour {
		t.Fatalf("retry cap=%s", got)
	}
	base := time.Hour
	if low, high := jitterTSPUDelay(base, 0), jitterTSPUDelay(base, ^uint16(0)); low != 54*time.Minute || high != 66*time.Minute {
		t.Fatalf("jitter bounds low=%s high=%s", low, high)
	}
}

func TestInventoryHealthIntervalIsDailyAndJittered(t *testing.T) {
	base := 24 * time.Hour
	for i := 0; i < 20; i++ {
		got := jitteredHealthInterval(base)
		if got < 21*time.Hour || got > 27*time.Hour {
			t.Fatalf("inventory interval outside jitter window: %s", got)
		}
	}
	if got := jitteredHealthInterval(time.Minute); got != time.Hour {
		t.Fatalf("short inventory interval was not safely clamped: %s", got)
	}
}

func TestInventoryHealthDoesNotProbeImmediatelyAfterStartup(t *testing.T) {
	for i := 0; i < 20; i++ {
		got := startupHealthDelay()
		if got < 30*time.Second || got > 90*time.Second {
			t.Fatalf("startup health delay=%s outside 30-90s", got)
		}
	}
}

func TestServerUsesBoundedGlobalProbeBudgetAndDiscoveryQueue(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Policy.ProbeBudget = 2
	cfg.Policy.DiscoveryQueueLimit = 3
	srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(), Development: true, DeferRecovery: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if got := cap(srv.probeBudget); got != 2 {
		t.Fatalf("global probe budget capacity=%d want=2", got)
	}
	if got := cap(srv.discoveryQueue); got != 3 {
		t.Fatalf("discovery queue capacity=%d want=3", got)
	}
}

func TestDiscoveryAdmissionCoalescesPendingETLDPlusOne(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Policy.ProbeBudget = 1
	cfg.Policy.DiscoveryQueueLimit = 2
	srv, err := NewServerWithOptions(cfg, Options{
		Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(),
		Development: true, DeferRecovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	if accepted, full := srv.enqueueDiscoveryObservation(discovery.Observation{Domain: "a.example.com", QueryType: "A"}); !accepted || full {
		t.Fatalf("first admission accepted=%v full=%v", accepted, full)
	}
	if accepted, full := srv.enqueueDiscoveryObservation(discovery.Observation{Domain: "b.example.com", QueryType: "A"}); accepted || full {
		t.Fatalf("same eTLD+1 was not coalesced: accepted=%v full=%v", accepted, full)
	}
	if got := len(srv.discoveryQueue); got != 1 {
		t.Fatalf("pending duplicate occupied queue: depth=%d", got)
	}
	if accepted, full := srv.enqueueDiscoveryObservation(discovery.Observation{Domain: "other.example.net", QueryType: "A"}); !accepted || full {
		t.Fatalf("independent domain was not admitted: accepted=%v full=%v", accepted, full)
	}
	if accepted, full := srv.enqueueDiscoveryObservation(discovery.Observation{Domain: "third.example.org", QueryType: "A"}); accepted || !full {
		t.Fatalf("full queue was not reported: accepted=%v full=%v", accepted, full)
	}
	if got := len(srv.discoveryQueue); got != 2 {
		t.Fatalf("queue escaped configured bound: depth=%d cap=%d", got, cap(srv.discoveryQueue))
	}

	first := <-srv.discoveryQueue
	srv.releasePendingDiscovery(first.Domain)
	if accepted, full := srv.enqueueDiscoveryObservation(discovery.Observation{Domain: "c.example.com", QueryType: "A"}); !accepted || full {
		t.Fatalf("released eTLD+1 was not admitted: accepted=%v full=%v", accepted, full)
	}
}

func TestDiscoveryStormIsBoundedAndDrainsToBaseline(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Policy.ProbeBudget = 4
	cfg.Policy.DiscoveryQueueLimit = 32
	srv, err := NewServerWithOptions(cfg, Options{
		Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(),
		Development: true, DeferRecovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	accepted := 0
	for i := 0; i < 1000; i++ {
		observation := discovery.Observation{Domain: "storm-" + strconv.Itoa(i) + ".example", QueryType: "A"}
		select {
		case srv.discoveryQueue <- observation:
			accepted++
		default:
		}
	}
	if accepted != 32 || len(srv.discoveryQueue) != 32 {
		t.Fatalf("DNS storm escaped queue bound: accepted=%d queued=%d cap=%d", accepted, len(srv.discoveryQueue), cap(srv.discoveryQueue))
	}
	for len(srv.discoveryQueue) > 0 {
		<-srv.discoveryQueue
	}
	if got := len(srv.discoveryQueue); got != 0 {
		t.Fatalf("discovery queue did not return to baseline: %d", got)
	}
}

func TestProbeBudgetAndRuntimeResourcesReturnToBaseline(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Policy.ProbeBudget = 4
	cfg.Policy.DiscoveryQueueLimit = 32
	srv, err := NewServerWithOptions(cfg, Options{
		Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(),
		Development: true, DeferRecovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	baselineGoroutines := runtime.NumGoroutine()
	baselineFDs, hasFDs := processFDCount()

	var active, maxActive atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case srv.probeBudget <- struct{}{}:
				current := active.Add(1)
				for {
					old := maxActive.Load()
					if current <= old || maxActive.CompareAndSwap(old, current) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				active.Add(-1)
				<-srv.probeBudget
			case <-time.After(time.Second):
				t.Error("probe job waited longer than bounded budget")
			}
		}()
	}
	wg.Wait()
	if got := maxActive.Load(); got > int32(cfg.Policy.ProbeBudget) {
		t.Fatalf("active route jobs=%d want<=%d", got, cfg.Policy.ProbeBudget)
	}
	if got := len(srv.probeBudget); got != 0 {
		t.Fatalf("probe budget did not return to baseline: %d tokens held", got)
	}
	srv.Close()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baselineGoroutines+2 && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baselineGoroutines+2 {
		t.Fatalf("goroutines did not return near baseline: before=%d after=%d", baselineGoroutines, got)
	}
	if hasFDs {
		if got, ok := processFDCount(); ok && got > baselineFDs {
			t.Fatalf("process fd count grew after bounded storm: before=%d after=%d", baselineFDs, got)
		}
	}
}

func processFDCount() (int, bool) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	return len(entries), true
}

func TestSubscriptionRefreshDelayUsesProviderExpiry(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Storage.StateDir = t.TempDir()
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	pool := vpnsub.PoolSnapshot{Sources: []vpnsub.SubscriptionSource{{ID: "source-1", ExpiresAt: now.Add(6 * time.Hour).Format(time.RFC3339)}}}
	if err := vpnsub.StorePool(vpnsub.PoolPath(cfg.Storage.StateDir), pool); err != nil {
		t.Fatal(err)
	}
	srv := &Server{activeConfig: cfg}
	if got, want := srv.subscriptionRefreshDelay(now), 5*time.Hour; got != want {
		t.Fatalf("expiry-aware refresh delay=%s want=%s", got, want)
	}
}

func TestSubscriptionRefreshBackoffIsBoundedAndExponential(t *testing.T) {
	first := subscriptionRefreshBackoff(1)
	if first < 54*time.Second || first > 66*time.Second {
		t.Fatalf("first subscription retry backoff=%s, want roughly one minute", first)
	}
	second := subscriptionRefreshBackoff(2)
	if second < 108*time.Second || second > 132*time.Second {
		t.Fatalf("second subscription retry backoff=%s, want roughly two minutes", second)
	}
	maxed := subscriptionRefreshBackoff(32)
	if maxed < 54*time.Minute || maxed > 6*time.Hour {
		t.Fatalf("bounded subscription retry backoff=%s, want <=6h with jitter", maxed)
	}
	if got := subscriptionRefreshBackoff(0); got != 0 {
		t.Fatalf("zero subscription failures produced backoff=%s", got)
	}
}

func TestTSPUInitialDelayUsesPersistedFreshness(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Storage.StateDir = t.TempDir()
	now := time.Date(2026, 7, 27, 2, 0, 0, 0, time.UTC)
	cache := tspu.BuildCache(now, time.Hour,
		[]tspu.SourceReport{{Name: "fixture", Accepted: true, Fresh: true, Confidence: 0.9}},
		map[string][]string{"fixture": {"one.example"}})
	if err := tspu.Save(filepath.Join(cfg.Storage.StateDir, "tspu-cache.json"), cache); err != nil {
		t.Fatal(err)
	}

	fallback := 30 * time.Second
	if got, want := tspuInitialDelay(cfg, 6*time.Hour, now, fallback), 55*time.Minute; got != want {
		t.Fatalf("fresh cache initial delay=%s want=%s", got, want)
	}
	if got := tspuInitialDelay(cfg, 6*time.Hour, cache.ExpiresAt.Add(time.Second), fallback); got != fallback {
		t.Fatalf("expired cache initial delay=%s want fallback=%s", got, fallback)
	}
}

func TestTSPUInitialDelayDoesNotMaterializeCorruptLargeCache(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Storage.StateDir = t.TempDir()
	now := time.Date(2026, 7, 27, 2, 0, 0, 0, time.UTC)
	cache := tspu.BuildCache(now, time.Hour,
		[]tspu.SourceReport{{Name: "fixture", Accepted: true, Fresh: true, Confidence: 0.9}},
		map[string][]string{"fixture": {"one.example"}})
	cachePath := filepath.Join(cfg.Storage.StateDir, "tspu-cache.json")
	if err := tspu.Save(cachePath, cache); err != nil {
		t.Fatal(err)
	}
	// Scheduling only needs the validated freshness sidecar.  A damaged or
	// very large index must not be materialised merely to calculate the next
	// refresh time; the refresh path will handle that error when it runs.
	if err := os.WriteFile(cachePath, []byte(strings.Repeat("{", 1024*1024)), 0o600); err != nil {
		t.Fatal(err)
	}
	fallback := 30 * time.Second
	if got, want := tspuInitialDelay(cfg, 6*time.Hour, now, fallback), 55*time.Minute; got != want {
		t.Fatalf("freshness-only initial delay=%s want=%s", got, want)
	}
}

func TestTSPUSchedulerConfigInheritsBootstrapSourcesWithoutChangingActiveConfig(t *testing.T) {
	bootstrap := testAPIConfig(t)
	bootstrap.TSPUSources = []config.TSPUSource{{Name: "primary", Type: "domains", URL: "https://example.test/domains"}}
	active := *bootstrap
	active.TSPUSources = nil
	srv := &Server{cfg: bootstrap, activeConfig: &active}

	merged := srv.tspuSchedulerConfig()
	if len(merged.TSPUSources) != len(bootstrap.TSPUSources) || len(merged.TSPUSources) == 0 {
		t.Fatalf("bootstrap TSPU sources were not inherited: got=%d want=%d", len(merged.TSPUSources), len(bootstrap.TSPUSources))
	}
	if len(active.TSPUSources) != 0 {
		t.Fatal("active committed config was mutated")
	}
}

func apiHealthControl(domain string) config.Service {
	return config.Service{
		Category: "GEO_LOCKED", Domains: []string{domain}, AllowedPaths: []string{"vless"}, RequireNonRUEgress: true,
		ProbeURLs: []config.ProbeCheck{{Name: "web", URL: "https://" + domain + "/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}},
	}
}
