package vpnsub

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-policy/internal/remotefetch"
)

func TestFetchSubscriptionHTTPSAndMode0600(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"outbounds":[]}`))
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "subscription.json")
	summary, err := FetchSubscription(remotefetch.WithLoopbackForTests(context.Background()), server.Client(), server.URL+"/secret-token", output, FetchOptions{MaxBytes: 1024})
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
	_, err := FetchSubscription(remotefetch.WithLoopbackForTests(context.Background()), server.Client(), server.URL+"/private-token", filepath.Join(t.TempDir(), "subscription.json"), FetchOptions{})
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
	if _, err := FetchSubscription(remotefetch.WithLoopbackForTests(context.Background()), server.Client(), server.URL, output, FetchOptions{MaxBytes: 1024}); err == nil {
		t.Fatal("oversized subscription was accepted")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("oversized subscription left an output file")
	}
}

func TestFetchSubscriptionAcceptsProviderResponseAboveLegacyTwoMiBLimit(t *testing.T) {
	// The real Happ provider currently returns a 2.3 MiB JSON body. The hard
	// cap is 4 MiB; the old packaged policy default of 2 MiB rejected it before
	// parsing even though the request and HWID were valid.
	body := bytes.Repeat([]byte("x"), (2<<20)+1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "subscription.json")
	summary, err := FetchSubscription(remotefetch.WithLoopbackForTests(context.Background()), server.Client(), server.URL, output, FetchOptions{MaxBytes: 4 << 20})
	if err != nil {
		t.Fatalf("provider response above the legacy 2 MiB default was rejected: %v", err)
	}
	if summary.Bytes != len(body) {
		t.Fatalf("summary bytes=%d, want %d", summary.Bytes, len(body))
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

type fixedSourceResolver struct{ resolution SourceResolution }

func (r fixedSourceResolver) Resolve(context.Context, string) (SourceResolution, error) {
	return r.resolution, nil
}

func TestFetchSourceAddsHWIDOnlyToHappProvider(t *testing.T) {
	type requestHeaders struct {
		hwid, accept, encoding, userAgent string
	}
	seen := make(chan requestHeaders, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- requestHeaders{
			hwid: r.Header.Get("X-HWID"), accept: r.Header.Get("Accept"),
			encoding: r.Header.Get("Accept-Encoding"), userAgent: r.Header.Get("User-Agent"),
		}
		_, _ = w.Write([]byte(`{"outbounds":[]}`))
	}))
	defer server.Close()
	resolution := SourceResolution{
		OriginalSource: "happ://crypt4/masked", OriginalSourceMasked: "happ://crypt4/masked",
		ResolvedSource: server.URL + "/provider-token", ResolvedSourceMasked: server.URL + "/****",
		SourceType: SourceTypeHapp, CryptoVersion: "crypt4", RequiresHWID: true,
	}
	output := filepath.Join(t.TempDir(), "subscription.json")
	if _, err := FetchSource(remotefetch.WithLoopbackForTests(context.Background()), server.Client(), "ignored", output, FetchOptions{HWID: "33333333-3333-4333-8333-333333333333"}, fixedSourceResolver{resolution}); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got.hwid != "33333333-3333-4333-8333-333333333333" || got.accept != "*/*" || got.encoding != "identity" || got.userAgent != "Happ/3.26.1" {
		t.Fatalf("Happ request headers=%+v, want preset HWID and Happ-compatible negotiation", got)
	}

	seenPlain := make(chan string, 1)
	plain := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPlain <- r.Header.Get("X-HWID")
		_, _ = w.Write([]byte(`{"outbounds":[]}`))
	}))
	defer plain.Close()
	resolution.SourceType = SourceTypeHTTPS
	resolution.RequiresHWID = false
	resolution.ResolvedSource = plain.URL
	if _, err := FetchSource(remotefetch.WithLoopbackForTests(context.Background()), plain.Client(), "ignored", filepath.Join(t.TempDir(), "plain.json"), FetchOptions{HWID: "should-not-be-sent"}, fixedSourceResolver{resolution}); err != nil {
		t.Fatal(err)
	}
	if got := <-seenPlain; got != "" {
		t.Fatalf("plain provider unexpectedly received X-HWID: %q", got)
	}
}

func TestFetchSourceResolvesPortalHappSubkeyAndSendsPresetHWID(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	const expectedHWID = "a330268d-7d9d-4343-8672-f6191f80a25c"
	seenHWID := make(chan string, 1)
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHWID <- r.Header.Get("X-HWID")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"outbounds":[]}`))
	}))
	defer provider.Close()
	payload := encryptCrypt4(t, key, []byte(provider.URL+"/subscription"), base64.StdEncoding)
	original := "https://portal.example/add-key?subkey=" + url.QueryEscape("happ://crypt4/"+payload)
	output := filepath.Join(t.TempDir(), "subscription.json")
	_, err = FetchSource(remotefetch.WithLoopbackForTests(context.Background()), provider.Client(), original, output, FetchOptions{HWID: expectedHWID}, NewSourceResolver(NewCrypt4Decoder(key)))
	if err != nil {
		t.Fatal(err)
	}
	if got := <-seenHWID; got != expectedHWID {
		t.Fatalf("portal Happ request sent HWID %q, want preset %q", got, expectedHWID)
	}
	data, err := os.ReadFile(output)
	if err != nil || string(data) != `{"outbounds":[]}` {
		t.Fatalf("resolved provider response was not stored: err=%v data=%q", err, data)
	}
}
