package api

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/health"
	"router-policy/internal/probe"
)

type reactiveRouteEngine struct {
	mu    sync.Mutex
	calls []string
}

func (e *reactiveRouteEngine) ProbeRoute(_ context.Context, _ *config.Config, domain, service string, _ config.Service, route config.Route) probe.RouteResult {
	e.mu.Lock()
	e.calls = append(e.calls, route.Tag)
	e.mu.Unlock()
	if route.Tag == "vless-a" {
		return probe.RouteResult{Domain: domain, Service: service, Route: route.Tag, RouteType: route.Type, Status: "FAIL", ApplicationStatus: "FAIL", ReasonCode: "connect_timeout"}
	}
	return probe.RouteResult{Domain: domain, Service: service, Route: route.Tag, RouteType: route.Type, Status: "OK", ApplicationStatus: "OK", PathVerified: true, ServiceOK: true, EgressConsensus: true, AdapterRevision: "rev", CandidateHash: "candidate", ArtifactManifestHash: "manifest", ExternalIPHash: "ip", ExternalCountry: "DE"}
}

func TestReactiveFailureIsHystereticAndBounded(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	active := srv.currentConfig()
	active.Routes = append(active.Routes,
		config.Route{Type: "vless", Tag: "vless-a", Priority: 10, SOCKS5: "127.0.0.1:12000"},
		config.Route{Type: "vless", Tag: "vless-b", Priority: 20, SOCKS5: "127.0.0.1:12001"},
	)
	service := active.Services["github"]
	service.AllowedPaths = []string{"vless"}
	service.SelectedRouteTag = "vless-a"
	active.Services["github"] = service
	srv.healthTracker = probe.NewHealthTracker([]probe.RouteHealth{
		{RouteTag: "vless-a", RouteType: "vless", State: "healthy", Role: "selected", Score: 80},
		{RouteTag: "vless-b", RouteType: "vless", State: "healthy", Role: "standby", Score: 70},
	})
	engine := &reactiveRouteEngine{}
	srv.probeEngineFactory = func(*config.Config) health.ProbeEngine { return engine }
	base := time.Now().UTC()
	for i := 0; i < 2; i++ {
		srv.processRouteFailure(context.Background(), routeFailureReport{Domain: "github.com", Route: "vless-a", Reason: "connect_timeout", SeenAt: base.Add(time.Duration(i) * time.Second)})
	}
	if events := srv.broker.Recent(0, 20); len(events) == 0 || events[len(events)-1].ReasonCode != "route_failure_suspected" {
		t.Fatalf("one or two failures should remain suspect: %+v", events)
	}
	srv.processRouteFailure(context.Background(), routeFailureReport{Domain: "github.com", Route: "vless-a", Reason: "connect_timeout", SeenAt: base.Add(2 * time.Second)})
	engine.mu.Lock()
	calls := append([]string(nil), engine.calls...)
	engine.mu.Unlock()
	if len(calls) != 2 || calls[0] != "vless-a" || calls[1] != "vless-b" {
		t.Fatalf("reactive failover fanned out beyond selected+one fallback: %v", calls)
	}
	var sawFallback bool
	for _, event := range srv.broker.Recent(0, 40) {
		if event.ReasonCode == "route_failover_pending_review" {
			sawFallback = true
		}
	}
	if !sawFallback {
		t.Fatal("thresholded failure did not produce a reviewable fallback outcome")
	}
	if fake, ok := srv.adapter.(*fakeAdapter); ok {
		if calls := fakeAdapterCallCount(fake); calls != 0 {
			t.Fatalf("reactive fallback invoked full adapter apply: %d calls", calls)
		}
	}
}

func TestClassifiedRevalidationUsesOnlyOneDirectProbe(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	active := srv.currentConfig()
	service := active.Services["github"]
	service.Category = "TSPU_RESTRICTED"
	service.AllowedPaths = []string{"direct", "vless", "drop"}
	service.SelectedRouteTag = "vless-a"
	active.Services["github"] = service
	active.Routes = append(active.Routes, config.Route{Type: "vless", Tag: "vless-a", Priority: 10, SOCKS5: "127.0.0.1:12000"})
	engine := &reactiveRouteEngine{}
	srv.probeEngineFactory = func(*config.Config) health.ProbeEngine { return engine }
	if err := srv.RevalidateClassifiedDomain(context.Background(), "github.com"); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	calls := append([]string(nil), engine.calls...)
	engine.mu.Unlock()
	if len(calls) != 1 || calls[0] != "direct" {
		t.Fatalf("classification revalidation must be one direct probe, got %v", calls)
	}
	found := false
	for _, event := range srv.broker.Recent(0, 20) {
		if event.ReasonCode == "direct_path_recovered_suggestion" {
			found = true
		}
	}
	if !found {
		t.Fatal("successful Direct revalidation did not create a policy suggestion")
	}
}

func TestReportSelectedRouteFailureDeduplicatesHotPath(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	active := srv.currentConfig()
	service := active.Services["github"]
	service.AllowedPaths = []string{"vless"}
	service.SelectedRouteTag = "vless-a"
	active.Services["github"] = service
	active.Routes = append(active.Routes, config.Route{Type: "vless", Tag: "vless-a", Priority: 10, SOCKS5: "127.0.0.1:12000"})
	ctx := context.Background()
	if err := srv.ReportSelectedRouteFailure(ctx, "github.com", "vless-a", "reset"); err != nil {
		t.Fatal(err)
	}
	if err := srv.ReportSelectedRouteFailure(ctx, "github.com", "vless-a", "reset"); err != nil {
		t.Fatal(err)
	}
	if got := len(srv.routeFailureQueue); got != 1 {
		t.Fatalf("duplicate route failures were not deduplicated: queue=%d", got)
	}
	report := <-srv.routeFailureQueue
	if !strings.Contains(report.Reason, "reset") {
		t.Fatalf("failure reason was not retained: %+v", report)
	}
}

func TestFailedRouteRecoveryUsesOneProbeAndBackoff(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	active := srv.currentConfig()
	service := active.Services["github"]
	service.AllowedPaths = []string{"vless"}
	service.SelectedRouteTag = "vless-a"
	active.Services["github"] = service
	active.Routes = append(active.Routes, config.Route{Type: "vless", Tag: "vless-a", Priority: 10, SOCKS5: "127.0.0.1:12000"})
	srv.healthTracker = probe.NewHealthTracker([]probe.RouteHealth{{RouteTag: "vless-a", RouteType: "vless", State: "unhealthy", Role: "quarantined", Score: 10}})
	engine := &reactiveRouteEngine{}
	srv.probeEngineFactory = func(*config.Config) health.ProbeEngine { return engine }
	now := time.Now().UTC()
	srv.scheduleFailedRouteRecovery("vless-a", now.Add(-time.Second), 5*time.Minute)
	srv.runDueFailedRouteRecovery(context.Background(), now)
	engine.mu.Lock()
	calls := append([]string(nil), engine.calls...)
	engine.mu.Unlock()
	if len(calls) != 1 || calls[0] != "vless-a" {
		t.Fatalf("recovery probe fan-out: %v", calls)
	}
	srv.routeFailureMu.Lock()
	next := srv.routeRecoveryNext["vless-a"]
	backoff := srv.routeRecoveryBackoff["vless-a"]
	srv.routeFailureMu.Unlock()
	if !next.After(now) || backoff <= 5*time.Minute {
		t.Fatalf("failed recovery did not increase cooldown: next=%v backoff=%v", next, backoff)
	}
}
