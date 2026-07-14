package probe

import (
	"testing"
	"time"

	"router-policy/internal/config"
)

func TestSmartDNSHealthHysteresisAndRecovery(t *testing.T) {
	tracker := NewHealthTracker(nil)
	policy := config.Policy{FailAfterConsecutiveErrors: 3, RecoverAfterConsecutiveSuccess: 3, RouteHoldSeconds: 60}
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	failure := RouteResult{Route: "primary", RouteType: "smart_dns", Status: "UNVERIFIED", ReasonCode: "dns_timeout"}
	for i := 0; i < 3; i++ {
		tracker.Observe(failure, policy, base.Add(time.Duration(i)*time.Second))
	}
	routes := []config.Route{
		{Type: "smart_dns", Tag: "primary", Priority: 10},
		{Type: "smart_dns", Tag: "secondary", Priority: 20},
	}
	ordered := tracker.OrderSmartDNS(routes)
	if ordered[0].Tag != "secondary" {
		t.Fatalf("unhealthy primary was not failed over: %+v", ordered)
	}

	success := RouteResult{Route: "primary", RouteType: "smart_dns", Status: "OK", PathVerified: true, ServiceOK: true, LatencyMS: 25}
	tracker.Observe(success, policy, base.Add(10*time.Second))
	tracker.Observe(success, policy, base.Add(20*time.Second))
	if ordered = tracker.OrderSmartDNS(routes); ordered[0].Tag != "secondary" {
		t.Fatalf("primary returned before hysteresis/hold completed: %+v", ordered)
	}
	tracker.Observe(success, policy, base.Add(65*time.Second))
	if ordered = tracker.OrderSmartDNS(routes); ordered[0].Tag != "primary" {
		t.Fatalf("primary did not recover after hold and successes: %+v", ordered)
	}
	health := tracker.Snapshot()
	if len(health) != 1 || health[0].State != "healthy" || health[0].ConsecutiveSuccesses != 3 || health[0].EWMALatencyMS == 0 {
		t.Fatalf("unexpected recovered health: %+v", health)
	}
}

func TestNotConfiguredRouteStaysLast(t *testing.T) {
	tracker := NewHealthTracker(nil)
	tracker.Observe(RouteResult{Route: "primary", RouteType: "smart_dns", Status: "NOT_CONFIGURED", ReasonCode: "missing_address"}, config.Policy{}, time.Now())
	ordered := tracker.OrderSmartDNS([]config.Route{{Tag: "primary", Priority: 1}, {Tag: "secondary", Priority: 2}})
	if ordered[0].Tag != "secondary" {
		t.Fatalf("NOT_CONFIGURED route was preferred: %+v", ordered)
	}
}
