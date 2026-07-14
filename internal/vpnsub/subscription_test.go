package vpnsub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"router-policy/internal/config"
)

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
		Services: map[string]config.Service{
			"control": {Domains: []string{"example.com"}, ProbeURLs: []config.ProbeCheck{{Name: "web", URL: "https://example.com/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}}, RequireNonRUEgress: true},
		},
	}
	result, err := service.Prepare(context.Background(), cfg)
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

func TestSubscriptionServiceRequiresProbeServiceBeforeDownload(t *testing.T) {
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
	if err == nil || err.Error() != "no service is configured for VLESS verification" {
		t.Fatalf("missing probe service was not rejected before network access: %v", err)
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
