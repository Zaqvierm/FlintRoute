package health_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/health"
	"router-policy/internal/probe"
	"router-policy/internal/state"
)

type restartEngine struct{}

func (restartEngine) ProbeRoute(_ context.Context, _ *config.Config, domain, service string, _ config.Service, route config.Route) probe.RouteResult {
	return probe.RouteResult{
		Domain: domain, Service: service, Route: route.Tag, RouteType: route.Type, RoutePriority: route.Priority,
		Status: "OK", ApplicationStatus: "OK", PathVerified: true, ServiceOK: true, EgressConsensus: true,
		AdapterRevision: "rev_2_001122334455", CandidateHash: "sha256:" + strings.Repeat("a", 64), ArtifactManifestHash: "sha256:" + strings.Repeat("b", 64),
		ExternalIPHash: "sha256:" + strings.Repeat("c", 64), ExternalCountry: "DE", LatencyMS: 25,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func TestVLESSHealthAndSelectionSurviveBboltRestart(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		Storage: config.Storage{StateDir: root, Database: filepath.Join(root, "state.bbolt"), MaxProbeResults: 100},
		Policy:  config.Policy{ParallelServerChecks: 1, FailAfterConsecutiveErrors: 3, RecoverAfterConsecutiveSuccess: 3, RouteHoldSeconds: 60},
		Routes:  []config.Route{{Type: "vless", Tag: "vless-a", Priority: 10, SOCKS5: "127.0.0.1:12000"}},
		Services: map[string]config.Service{
			"control-a": restartControl("a.example"),
			"control-b": restartControl("b.example"),
		},
	}
	store, err := state.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	service := health.Service{Tracker: probe.NewHealthTracker(nil), Store: store, Parallelism: 1, MaxControlServices: 2}
	if cycle, err := service.RunCycle(context.Background(), cfg, restartEngine{}, time.Now().UTC()); err != nil || cycle.SelectedTag != "vless-a" {
		t.Fatalf("health cycle failed: cycle=%+v err=%v", cycle, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = state.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	persisted, err := store.ListRouteHealth()
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 1 || persisted[0].RouteTag != "vless-a" || persisted[0].Role != "selected" || persisted[0].State != "healthy" || persisted[0].AdapterRevision == "" || persisted[0].ExternalIPHash == "" {
		t.Fatalf("route health did not survive restart: %+v", persisted)
	}
	tracker := probe.NewHealthTracker(persisted)
	restored := tracker.AssignVLESSRoles(cfg.Routes, cfg.Policy, time.Now().UTC())
	if len(restored) != 1 || restored[0].Role != "selected" {
		t.Fatalf("restart lost selected route role: %+v", restored)
	}
}

func restartControl(domain string) config.Service {
	return config.Service{
		Category: "GEO_LOCKED", Domains: []string{domain}, AllowedPaths: []string{"vless"}, RequireNonRUEgress: true,
		ProbeURLs: []config.ProbeCheck{{Name: "web", URL: "https://" + domain + "/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}},
	}
}
