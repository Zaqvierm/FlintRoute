package api

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/discovery"
	"router-policy/internal/planner"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
)

func newDiscoveryModeServer(t *testing.T, mode string, verified bool, fake *fakeAdapter) (*Server, *int) {
	t.Helper()
	cfg := testAPIConfig(t)
	cfg.Services = map[string]config.Service{}
	cfg.Policy.DiscoveryMode = mode
	cfg.Policy.DiscoveryMaxNewRulesPerHour = 4
	cfg.Policy.DiscoveryMaxConsecutiveRollbacks = 3
	cfg.OpenWrt.RollbackTimeoutSeconds = 120
	calls := 0
	checker := func(_ context.Context, _ *config.Config, domain, _ string, _ planner.Options) (planner.DomainCheck, error) {
		calls++
		return planner.DomainCheck{
			Domain: domain, ETLDPlusOne: domain, Category: "GEO_LOCKED", Status: "OK", Confidence: 0.99,
			Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", Status: "OK", ApplicationStatus: "OK", PathVerified: verified, ServiceOK: true},
		}, nil
	}
	srv, err := NewServerWithOptions(cfg, Options{Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true, DomainChecker: checker})
	if err != nil {
		t.Fatal(err)
	}
	return srv, &calls
}

func TestDiscoveryObserveOnlyNeverCreatesSuggestionOrChange(t *testing.T) {
	fake := newFakeAdapter()
	srv, calls := newDiscoveryModeServer(t, "observe_only", true, fake)
	defer srv.Close()
	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "observe.example", QueryType: "A"})
	if *calls != 1 || len(srv.discoverySuggestions(10)) != 0 || len(fake.calls) != 0 {
		t.Fatalf("observe_only changed state: calls=%d suggestions=%d adapter=%v", *calls, len(srv.discoverySuggestions(10)), fake.calls)
	}
}

func TestDiscoverySuggestKeepsBoundedSuggestionWithoutApply(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "suggest.example", QueryType: "AAAA"})
	items := srv.discoverySuggestions(10)
	if len(items) != 1 || items[0].Domain != "suggest.example" || !items[0].PathVerified || len(fake.calls) != 0 {
		t.Fatalf("suggest mode result=%+v adapter=%v", items, fake.calls)
	}
}

func TestDiscoverySuggestionsStayBoundedInMemory(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	for index := 0; index < maxDiscoverySuggestions+20; index++ {
		domain := fmt.Sprintf("domain-%03d.example", index)
		srv.saveDiscoverySuggestion(discovery.Observation{Domain: domain, QueryType: "A"}, planner.DomainCheck{Domain: domain})
	}
	if got := len(srv.discoverySuggestions(maxDiscoverySuggestions + 20)); got != maxDiscoverySuggestions {
		t.Fatalf("suggestion cache size=%d want=%d", got, maxDiscoverySuggestions)
	}
}

func TestDiscoveryLockedDoesNotProbe(t *testing.T) {
	fake := newFakeAdapter()
	srv, calls := newDiscoveryModeServer(t, "locked", true, fake)
	defer srv.Close()
	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "locked.example", QueryType: "A"})
	if *calls != 0 || len(fake.calls) != 0 {
		t.Fatalf("locked discovery ran work: checker=%d adapter=%v", *calls, fake.calls)
	}
}

func TestDiscoveryAutoApplyRequiresPathVerifiedAndCommits(t *testing.T) {
	t.Run("unverified", func(t *testing.T) {
		fake := newFakeAdapter()
		srv, _ := newDiscoveryModeServer(t, "auto_apply_verified", false, fake)
		defer srv.Close()
		srv.discoverDomain(context.Background(), discovery.Observation{Domain: "unverified.example", QueryType: "A"})
		if len(fake.calls) != 0 {
			t.Fatalf("unverified path reached adapter: %v", fake.calls)
		}
	})
	t.Run("verified", func(t *testing.T) {
		fake := newFakeAdapter()
		srv, _ := newDiscoveryModeServer(t, "auto_apply_verified", true, fake)
		defer srv.Close()
		srv.discoverDomain(context.Background(), discovery.Observation{Domain: "verified.example", QueryType: "A"})
		if service := srv.currentConfig().ServiceForDomain("verified.example"); service == "" || fake.callCount("commit") != 1 {
			t.Fatalf("verified discovery was not committed: service=%q calls=%v", service, fake.calls)
		}
		state := srv.loadDiscoveryState()
		if len(state.AppliedAt) != 1 || state.ConsecutiveRollbacks != 0 {
			t.Fatalf("successful auto-apply state=%+v", state)
		}
	})
}

func TestDiscoveryAutoApplySafetyLimits(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "auto_apply_verified", true, fake)
	defer srv.Close()
	check := planner.DomainCheck{Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", PathVerified: true}}

	srv.mu.Lock()
	srv.changes["busy"] = ChangeSet{ID: "busy", State: "awaiting_confirmation"}
	srv.mu.Unlock()
	if err := srv.discoveryAutoAllowed(srv.currentConfig(), check); err == nil {
		t.Fatal("active transaction did not block auto-apply")
	}
	srv.mu.Lock()
	delete(srv.changes, "busy")
	srv.mu.Unlock()

	now := time.Now().UTC()
	state := discoveryControlState{AppliedAt: []time.Time{now, now, now, now}}
	if err := srv.store.SaveJSON("discovery", discoveryStateKey, state); err != nil {
		t.Fatal(err)
	}
	if err := srv.discoveryAutoAllowed(srv.currentConfig(), check); err == nil {
		t.Fatal("hourly rule limit did not block auto-apply")
	}
	state = discoveryControlState{ConsecutiveRollbacks: 3, PausedReason: "consecutive_rollbacks"}
	if err := srv.store.SaveJSON("discovery", discoveryStateKey, state); err != nil {
		t.Fatal(err)
	}
	if err := srv.discoveryAutoAllowed(srv.currentConfig(), check); err == nil {
		t.Fatal("rollback circuit breaker did not block auto-apply")
	}
	if err := validateDiscoveryOperations([]ChangeOp{{Type: "set", Path: "/openwrt/firewall_include", Value: "/tmp/x"}}); err == nil {
		t.Fatal("discovery accepted a firewall change")
	}
	if err := validateDiscoveryOperations([]ChangeOp{{Type: "set", Path: "/platform/management", Value: true}}); err == nil {
		t.Fatal("discovery accepted a management change")
	}
}

func TestDiscoveryRollbackCircuitBreakerStopsFurtherApply(t *testing.T) {
	fake := newFakeAdapter()
	fake.fail["verify_management_path"] = true
	srv, _ := newDiscoveryModeServer(t, "auto_apply_verified", true, fake)
	defer srv.Close()
	for _, domain := range []string{"one.example", "two.example", "three.example", "four.example"} {
		srv.discoverDomain(context.Background(), discovery.Observation{Domain: domain, QueryType: "A"})
	}
	state := srv.loadDiscoveryState()
	if state.ConsecutiveRollbacks != 3 || state.PausedReason != "consecutive_rollbacks" || fake.callCount("apply_candidate") != 3 {
		t.Fatalf("rollback circuit breaker failed: state=%+v calls=%v", state, fake.calls)
	}
}

func TestDomainCheckerFailureDoesNotCreateSuggestion(t *testing.T) {
	fake := newFakeAdapter()
	srv, _ := newDiscoveryModeServer(t, "suggest", true, fake)
	defer srv.Close()
	srv.domainChecker = func(context.Context, *config.Config, string, string, planner.Options) (planner.DomainCheck, error) {
		return planner.DomainCheck{}, errors.New("probe failed")
	}
	srv.discoverDomain(context.Background(), discovery.Observation{Domain: "failed.example", QueryType: "A"})
	if len(srv.discoverySuggestions(10)) != 0 {
		t.Fatal("failed observation created a suggestion")
	}
}
