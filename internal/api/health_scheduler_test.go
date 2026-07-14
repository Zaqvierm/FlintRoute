package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/health"
	"router-policy/internal/probe"
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

func apiHealthControl(domain string) config.Service {
	return config.Service{
		Category: "GEO_LOCKED", Domains: []string{domain}, AllowedPaths: []string{"vless"}, RequireNonRUEgress: true,
		ProbeURLs: []config.ProbeCheck{{Name: "web", URL: "https://" + domain + "/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}},
	}
}
