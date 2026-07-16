package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/health"
	"router-policy/internal/probe"
	"router-policy/internal/tspu"
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
	if got := tspuBaseDelay(interval, 0, true); got != 30*time.Second {
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
