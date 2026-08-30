package vpnsub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"router-policy/internal/config"
	"router-policy/internal/remotefetch"
)

func TestEffectiveSubscriptionMaxBytesUpgradesLegacyDefault(t *testing.T) {
	if got, want := effectiveSubscriptionMaxBytes(2<<20), int64(4<<20); got != want {
		t.Fatalf("legacy default max bytes=%d, want %d", got, want)
	}
	if got, want := effectiveSubscriptionMaxBytes(1<<20), int64(1<<20); got != want {
		t.Fatalf("explicit smaller max bytes=%d, want %d", got, want)
	}
	if got, want := effectiveSubscriptionMaxBytes(0), int64(4<<20); got != want {
		t.Fatalf("unset max bytes=%d, want %d", got, want)
	}
}

func TestSubscriptionServiceDownloadsChecksAndStagesBundle(t *testing.T) {
	root := t.TempDir()
	subscription := mustManagerSubscriptionBytes(t, root)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(subscription)
	}))
	defer server.Close()
	secretFile := filepath.Join(root, "subscription-url.secret")
	if err := os.WriteFile(secretFile, []byte(server.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeXrayRunner{}
	checker := &sequenceChecker{checks: []OutboundCheck{{Status: "OK", LatencyMS: 15, ExternalIPHash: "sha256:egress", ExternalCountry: "DE"}}}
	service := &SubscriptionService{
		Runner: runner, HTTPClient: server.Client(),
		CheckerFactory: func(*config.Config, config.Service) OutboundChecker { return checker },
	}
	cfg := &config.Config{
		Version: 2, Storage: config.Storage{StateDir: filepath.Join(root, "state")},
		Policy: config.Policy{MaxSubscriptionBytes: 1 << 20, MaxProbeSeconds: 10},
		Xray:   config.Xray{SubscriptionSecretFile: secretFile, ProbeSocksBasePort: 12000},
		GeoIP: config.GeoIP{Endpoints: []config.GeoIPEndpoint{{
			Name: "country-is", Provider: "country_is", URL: "https://api.country.is/",
		}}},
		Services: map[string]config.Service{},
	}
	result, err := service.Prepare(remotefetch.WithLoopbackForTests(context.Background()), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Ready || result.BundleHash == "" || result.SubscriptionHash == "" || result.SubscriptionBytes != len(subscription) || runner.tests != 1 || runner.starts != 1 {
		t.Fatalf("subscription service did not complete the real preparation chain: result=%+v runner=%+v", result, runner)
	}
	if _, err := os.Stat(result.BundlePath); err != nil {
		t.Fatalf("content-addressed bundle missing: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(cfg.Storage.StateDir, "xray", "downloads"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary subscription download was retained: %+v", entries)
	}
}

func TestSubscriptionServiceRequiresVerificationTargetBeforeDownload(t *testing.T) {
	root := t.TempDir()
	secretFile := filepath.Join(root, "subscription-url.secret")
	if err := os.WriteFile(secretFile, []byte("https://example.invalid/private\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := &SubscriptionService{Runner: &fakeXrayRunner{}}
	_, err := service.Prepare(context.Background(), &config.Config{
		Storage: config.Storage{StateDir: filepath.Join(root, "state")},
		Xray:    config.Xray{SubscriptionSecretFile: secretFile, ProbeSocksBasePort: 12000},
	})
	if err == nil || err.Error() != "VPN subscription verification target is not configured" {
		t.Fatalf("missing verification target was not rejected before network access: %v", err)
	}
}

func TestSubscriptionServiceAcceptsManualServerWithoutSubscription(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, _, err := AddManualServer(ManualServersPath(stateDir), testManualVLESSURI); err != nil {
		t.Fatal(err)
	}
	runner := &fakeXrayRunner{}
	checker := &sequenceChecker{checks: []OutboundCheck{{Status: "OK", LatencyMS: 18, ExternalIPHash: "sha256:egress", ExternalCountry: "DE"}}}
	service := &SubscriptionService{
		Runner:         runner,
		CheckerFactory: func(*config.Config, config.Service) OutboundChecker { return checker },
	}
	cfg := &config.Config{
		Storage: config.Storage{StateDir: stateDir},
		Policy:  config.Policy{MaxProbeSeconds: 10},
		Xray:    config.Xray{SubscriptionSecretFile: filepath.Join(root, "missing-subscription.secret"), ProbeSocksBasePort: 12000},
		GeoIP: config.GeoIP{Endpoints: []config.GeoIPEndpoint{{
			Name: "country-is", Provider: "country_is", URL: "https://api.country.is/",
		}}},
	}
	result, err := service.Prepare(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Ready || result.SubscriptionHash == "" || result.SubscriptionBytes != 0 || len(result.Servers) != 1 {
		t.Fatalf("manual-only bundle was not prepared: %+v", result)
	}
}

func TestSubscriptionProbeServiceDoesNotDependOnConfiguredServices(t *testing.T) {
	cfg := &config.Config{
		GeoIP: config.GeoIP{Endpoints: []config.GeoIPEndpoint{{
			Name: "country-is", Provider: "country_is", URL: "https://api.country.is/",
		}}},
		Services: map[string]config.Service{},
	}
	service, err := subscriptionProbeService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(service.Domains) != 1 || service.Domains[0] != "api.country.is" {
		t.Fatalf("unexpected verification domain: %#v", service.Domains)
	}
	if !service.RequireNonRUEgress || len(service.ProbeURLs) != 1 {
		t.Fatalf("verification service is incomplete: %#v", service)
	}
}

func mustManagerSubscriptionBytes(t *testing.T, root string) []byte {
	t.Helper()
	path := writeManagerSubscription(t, root)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
