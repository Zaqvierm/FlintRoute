package vpnsub

import (
	"context"
	"os"
	"testing"
	"time"

	"router-policy/internal/config"
)

func TestLiveVPNSubscriptionBundle(t *testing.T) {
	xrayPath := os.Getenv("ROUTER_POLICY_TEST_XRAY")
	subscriptionPath := os.Getenv("ROUTER_POLICY_TEST_SUBSCRIPTION")
	if xrayPath == "" || subscriptionPath == "" {
		t.Skip("set ROUTER_POLICY_TEST_XRAY and ROUTER_POLICY_TEST_SUBSCRIPTION for live VPN subscription verification")
	}
	service := config.Service{
		Category: "LIVE_CONTROL", Domains: []string{"www.gstatic.com"}, AllowedPaths: []string{"vless"}, RequireNonRUEgress: true,
		ProbeURLs: []config.ProbeCheck{{
			Name: "gstatic-204", URL: "https://www.gstatic.com/generate_204", Required: true,
			ExpectedCodes: []int{204}, BodyMode: "empty",
		}},
	}
	cfg := &config.Config{
		Version: 2, Platform: config.Platform{Target: "live-local"}, Storage: config.Storage{StateDir: t.TempDir()},
		Policy: config.Policy{MaxProbeSeconds: 30}, Xray: config.Xray{ProbeSocksBasePort: 12000, ProbeDNSResolver: "1.1.1.1:53"},
		GeoIP: config.GeoIP{Endpoints: []config.GeoIPEndpoint{
			{Name: "country-is", Provider: "country_is", URL: "https://api.country.is/"},
			{Name: "ipwho-is", Provider: "ipwho_is", URL: "https://ipwho.is/"},
		}},
	}
	runner := &ExecXrayRunner{path: xrayPath}
	manager := &Manager{
		StateDir: cfg.Storage.StateDir, Runner: runner, Checker: EngineOutboundChecker{Config: cfg, Service: service},
		Parallelism: 4, CheckAttempts: 1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	result, err := manager.PrepareBundle(ctx, subscriptionPath, cfg.Xray.ProbeSocksBasePort)
	for _, check := range result.Checks {
		t.Logf("tag=%s status=%s country=%s latency_ms=%d reason=%s", check.Tag, check.Status, check.ExternalCountry, check.LatencyMS, check.Reason)
	}
	if err != nil {
		t.Fatalf("live VPN subscription candidate was not safely verified: %v", err)
	}
	if !result.Ready || result.SelectedTag == "" || result.BundleHash == "" {
		t.Fatalf("live VPN subscription result is incomplete: ready=%t selected=%q hash_present=%t", result.Ready, result.SelectedTag, result.BundleHash != "")
	}
	t.Logf("ready=true unique_servers=%d selected=%s bundle_hash=%s", len(result.Routes), result.SelectedTag, result.BundleHash)
}
