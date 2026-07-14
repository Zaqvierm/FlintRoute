package vpnsub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchSubscriptionHTTPSAndMode0600(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"outbounds":[]}`))
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "subscription.json")
	summary, err := FetchSubscription(context.Background(), server.Client(), server.URL+"/secret-token", output, FetchOptions{MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Bytes == 0 || summary.SHA256 == "" || summary.SecretsShown {
		t.Fatalf("bad safe fetch summary: %+v", summary)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeModeMustBe0600() && info.Mode().Perm() != 0o600 {
		t.Fatalf("subscription mode=%o", info.Mode().Perm())
	}
}

func TestFetchSubscriptionRejectsHTTPSDowngradeWithoutLeakingURL(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://127.0.0.1/secret-token")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	_, err := FetchSubscription(context.Background(), server.Client(), server.URL+"/private-token", filepath.Join(t.TempDir(), "subscription.json"), FetchOptions{})
	if err == nil {
		t.Fatal("HTTPS to HTTP redirect was accepted")
	}
	if strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("download error leaked subscription URL: %v", err)
	}
}

func TestFetchSubscriptionRejectsOversizeBeforeWrite(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "subscription.json")
	if _, err := FetchSubscription(context.Background(), server.Client(), server.URL, output, FetchOptions{MaxBytes: 1024}); err == nil {
		t.Fatal("oversized subscription was accepted")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("oversized subscription left an output file")
	}
}

func TestSubscriptionURLMustComeFromMode0600HTTPSFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "url.secret")
	if err := os.WriteFile(path, []byte("http://example.test/token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSubscriptionURLFile(path); err == nil {
		t.Fatal("HTTP subscription URL was accepted")
	}
}
