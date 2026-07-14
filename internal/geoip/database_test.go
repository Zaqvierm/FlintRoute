package geoip

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func TestUpdateLookupPreviousAndNotModified(t *testing.T) {
	first := buildCountryMMDB(t, "DE")
	second := buildCountryMMDB(t, "NL")
	currentBody := first
	etag := `"v1"`
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", "Sat, 12 Jul 2026 00:00:00 GMT")
		_, _ = w.Write(currentBody)
	}))
	defer server.Close()
	root := t.TempDir()
	database := filepath.Join(root, "geoip.mmdb")
	defer Invalidate(database)
	defer Invalidate(PreviousPath(database))
	now := time.Date(2026, 7, 12, 1, 0, 0, 0, time.UTC)

	result, err := Update(context.Background(), server.Client(), server.URL, database, 1<<20, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "UPDATED" || result.PreviousPreserved || result.SHA256 == "" {
		t.Fatalf("bad initial update: %+v", result)
	}
	country, evidence, err := Lookup(database, netip.MustParseAddr("8.8.8.8"), 24*time.Hour, now)
	if err != nil || country != "DE" || evidence.SHA256 != result.SHA256 {
		t.Fatalf("bad initial lookup: country=%s evidence=%+v err=%v", country, evidence, err)
	}

	currentBody = second
	etag = `"v2"`
	result, err = Update(context.Background(), server.Client(), server.URL, database, 1<<20, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "UPDATED" || !result.PreviousPreserved {
		t.Fatalf("previous database was not preserved: %+v", result)
	}
	country, _, err = Lookup(database, netip.MustParseAddr("8.8.8.8"), 24*time.Hour, now.Add(time.Hour))
	if err != nil || country != "NL" {
		t.Fatalf("updated lookup failed: country=%s err=%v", country, err)
	}
	previousCountry, _, err := Lookup(PreviousPath(database), netip.MustParseAddr("8.8.8.8"), 24*time.Hour, now.Add(time.Hour))
	if err != nil || previousCountry != "DE" {
		t.Fatalf("previous lookup failed: country=%s err=%v", previousCountry, err)
	}

	result, err = Update(context.Background(), server.Client(), server.URL, database, 1<<20, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "NOT_MODIFIED" || requests != 3 {
		t.Fatalf("conditional update failed: result=%+v requests=%d", result, requests)
	}
}

func TestLookupFailsClosedOnCorruptionAndStaleness(t *testing.T) {
	raw := buildCountryMMDB(t, "DE")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(raw) }))
	defer server.Close()
	database := filepath.Join(t.TempDir(), "geoip.mmdb")
	defer Invalidate(database)
	now := time.Now().UTC()
	if _, err := Update(context.Background(), server.Client(), server.URL, database, 1<<20, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Lookup(database, netip.MustParseAddr("8.8.8.8"), time.Hour, now.Add(2*time.Hour)); err == nil {
		t.Fatal("stale GeoIP database was accepted")
	}
	Invalidate(database)
	if err := os.WriteFile(database, append(raw, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Lookup(database, netip.MustParseAddr("8.8.8.8"), 0, now); err == nil {
		t.Fatal("corrupted GeoIP database was accepted")
	}
}

func TestUpdateRejectsInvalidOrOversizedDatabase(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(bytes.Repeat([]byte("x"), 2048)) }))
	defer server.Close()
	database := filepath.Join(t.TempDir(), "geoip.mmdb")
	if _, err := Update(context.Background(), server.Client(), server.URL, database, 1024, time.Now().UTC()); err == nil {
		t.Fatal("oversized invalid GeoIP database was accepted")
	}
	if _, err := os.Stat(database); !os.IsNotExist(err) {
		t.Fatal("failed update created an active GeoIP database")
	}
}

func buildCountryMMDB(t *testing.T, country string) []byte {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "router-policy-country", IPVersion: 6, RecordSize: 24,
		IncludeReservedNetworks: true, DisableIPv4Aliasing: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"8.8.8.0/24", "1.1.1.0/24"} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.Insert(network, mmdbtype.Map{"country_code": mmdbtype.String(country)}); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if _, err := tree.WriteTo(&output); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
