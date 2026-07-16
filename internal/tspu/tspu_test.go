package tspu

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-policy/internal/config"
)

func TestParseDomainsNormalizesIDNHostsAndWildcards(t *testing.T) {
	domains, err := ParseDomains(strings.NewReader(`
# comment
||youtube.com^
.googlevideo.com
0.0.0.0 Example.COM
*.пример.рф
foo.*.invalid
bad/path
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"*.xn--e1afmkfd.xn--p1ai", "example.com", "googlevideo.com", "youtube.com"}
	if strings.Join(domains, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected normalized domains: got=%v want=%v", domains, want)
	}
	if _, err := NormalizeDomain("foo.*.invalid"); err == nil {
		t.Fatal("malformed wildcard was accepted as a domain")
	}
	if _, err := NormalizeDomain("bad_label.example"); err == nil {
		t.Fatal("malformed IDN/ASCII label was accepted")
	}
}

func TestFindDistinguishesFreshAndStaleWildcardMatches(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	reports := []SourceReport{{Name: "test", Accepted: true, Fresh: true, Confidence: 0.9}}
	cache := BuildCache(now, time.Hour, reports, map[string][]string{"test": {"youtube.com", "*.example.com"}})
	match, ok := Find(cache, "rr1---sn.youtube.com", now)
	if !ok || match.Matched != "youtube.com" || match.Expired || match.Status != "MATCH" {
		t.Fatalf("bad fresh suffix match: %+v ok=%v", match, ok)
	}
	wildcard, ok := Find(cache, "api.example.com", now)
	if !ok || wildcard.Matched != "*.example.com" || wildcard.MatchType != "wildcard" {
		t.Fatalf("bad wildcard match: %+v ok=%v", wildcard, ok)
	}
	if _, ok := Find(cache, "example.com", now); ok {
		t.Fatal("wildcard unexpectedly matched its apex")
	}
	stale, ok := Find(cache, "youtube.com", now.Add(2*time.Hour))
	if !ok || !stale.Expired || stale.Status != "STALE_MATCH" || stale.Evidence != "tspu_cache_stale_match" {
		t.Fatalf("expected explicit stale match, got %+v ok=%v", stale, ok)
	}
}

func TestUpdateUsesHTTPSConditionalRequestAnd304(t *testing.T) {
	etag := `"fixture-v1"`
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.Header().Set("ETag", etag)
		writer.Header().Set("Last-Modified", "Sat, 11 Jul 2026 00:00:00 GMT")
		if request.Header.Get("If-None-Match") == etag {
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = writer.Write([]byte("youtube.com\nyoutu.be\ngooglevideo.com\n"))
	}))
	defer server.Close()
	source := config.TSPUSource{Name: "fixture", Type: "domains", URL: server.URL, MinEntries: 3, MaxDropRatio: 0.5}
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	first, err := Update(context.Background(), server.Client(), []config.TSPUSource{source}, 4096, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := UpdateWithPrevious(context.Background(), server.Client(), []config.TSPUSource{source}, 4096, time.Hour, now.Add(time.Hour), &first)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(second.Entries) != 3 || !second.Sources[0].Accepted || !second.Sources[0].Fresh || !second.Sources[0].NotModified || second.Sources[0].ETag != etag || second.PreviousSHA256 != first.SHA256 {
		t.Fatalf("conditional update failed: requests=%d cache=%+v", requests, second)
	}
}

func TestUpdateRejectsOversizedSourceInsteadOfTruncating(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("a", 128)))
	}))
	defer server.Close()
	cache, err := Update(context.Background(), server.Client(), []config.TSPUSource{{Name: "fixture", Type: "domains", URL: server.URL, MinEntries: 1}}, 64, time.Hour, time.Now().UTC())
	if err == nil || len(cache.Sources) != 1 || cache.Sources[0].Reason != "source_size_limit_exceeded" || len(cache.Entries) != 0 {
		t.Fatalf("oversized source was not rejected: cache=%+v err=%v", cache, err)
	}
}

func TestDropRatioRetainsPreviousAcceptedVersion(t *testing.T) {
	oldDomains := []string{"a.example", "b.example", "c.example", "d.example"}
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	previous := BuildCache(now, 24*time.Hour, []SourceReport{{Name: "fixture", Type: "domains", Accepted: true, Fresh: true, Entries: 4, Confidence: 0.9}}, map[string][]string{"fixture": oldDomains})
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("a.example\n"))
	}))
	defer server.Close()
	source := config.TSPUSource{Name: "fixture", Type: "domains", URL: server.URL, MinEntries: 1, MaxDropRatio: 0.25}
	cache, err := UpdateWithPrevious(context.Background(), server.Client(), []config.TSPUSource{source}, 4096, time.Hour, now.Add(time.Hour), &previous)
	if err == nil || len(cache.Entries) != 4 || !cache.Sources[0].RetainedPrevious || cache.Sources[0].Accepted || cache.Sources[0].DropRatio != 0.75 || !strings.HasPrefix(cache.Sources[0].Reason, "drop_ratio_exceeded") {
		t.Fatalf("suspicious source shrink replaced previous data: cache=%+v err=%v", cache, err)
	}
}

func TestRefreshFilePreservesValidCacheWhenAllSourcesFail(t *testing.T) {
	fail := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if fail {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = writer.Write([]byte("one.example\ntwo.example\nthree.example\n"))
	}))
	defer server.Close()
	cfg := &config.Config{
		Policy:      config.Policy{TSPUListUpdateIntervalSeconds: 3600, MaxTSPUListBytes: 4096},
		TSPUSources: []config.TSPUSource{{Name: "fixture", Type: "domains", URL: server.URL, MinEntries: 3, MaxDropRatio: 0.25}},
	}
	path := filepath.Join(t.TempDir(), "tspu-cache.json")
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	first, err := RefreshFile(context.Background(), server.Client(), cfg, path, now)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	fail = true
	retained, err := RefreshFile(context.Background(), server.Client(), cfg, path, now.Add(time.Hour))
	if err == nil || len(retained.Entries) != len(first.Entries) || !retained.Sources[0].RetainedPrevious {
		t.Fatalf("failed source did not report retained previous cache: cache=%+v err=%v", retained, err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed refresh replaced the last valid cache")
	}
	loaded, err := Load(path)
	if err != nil || loaded.SHA256 != first.SHA256 {
		t.Fatalf("last valid cache is no longer loadable: cache=%+v err=%v", loaded, err)
	}
}

func TestSaveKeepsPreviousAndLoadRejectsCorruption(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tspu-cache.json")
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	first := BuildCache(now, time.Hour, []SourceReport{{Name: "one", Accepted: true, Fresh: true, Confidence: 0.9}}, map[string][]string{"one": {"one.example"}})
	if err := Save(path, first); err != nil {
		t.Fatal(err)
	}
	loadedFirst, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	second := BuildCache(now.Add(time.Minute), time.Hour, []SourceReport{{Name: "two", Accepted: true, Fresh: true, Confidence: 0.9}}, map[string][]string{"two": {"two.example"}})
	second.PreviousSHA256 = loadedFirst.SHA256
	if err := Save(path, second); err != nil {
		t.Fatal(err)
	}
	previous, err := Load(PreviousPath(path))
	if err != nil || previous.SHA256 != loadedFirst.SHA256 {
		t.Fatalf("previous cache was not retained: previous=%+v err=%v", previous, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), "two.example", "evil.example", 1))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("corrupted cache was accepted: %v", err)
	}
}

func TestHTTPSRedirectToHTTPIsRejected(t *testing.T) {
	httpTarget := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("one.example\n"))
	}))
	defer httpTarget.Close()
	tlsSource := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Redirect(writer, &http.Request{}, httpTarget.URL, http.StatusFound)
	}))
	defer tlsSource.Close()
	_, err := Update(context.Background(), tlsSource.Client(), []config.TSPUSource{{Name: "fixture", Type: "domains", URL: tlsSource.URL, MinEntries: 1}}, 4096, time.Hour, time.Now().UTC())
	if err == nil {
		t.Fatal("HTTPS to HTTP redirect was accepted")
	}
}
