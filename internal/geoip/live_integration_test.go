package geoip

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveGeoIPUpdate(t *testing.T) {
	source := os.Getenv("ROUTER_POLICY_TEST_GEOIP_SOURCE")
	if source == "" {
		t.Skip("set ROUTER_POLICY_TEST_GEOIP_SOURCE for live MMDB update")
	}
	database := filepath.Join(t.TempDir(), "user-country.mmdb")
	defer Invalidate(database)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	result, err := Update(ctx, nil, source, database, DefaultMaxBytes, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	country, evidence, err := Lookup(database, netip.MustParseAddr("8.8.8.8"), 24*time.Hour, time.Now().UTC())
	if err != nil || country == "" || evidence.SHA256 != result.SHA256 {
		t.Fatalf("live MMDB lookup failed: country=%s evidence=%+v err=%v", country, evidence, err)
	}
	t.Logf("status=%s bytes=%d sha256=%s database_type=%s sample_country=%s", result.Status, result.Bytes, result.SHA256, result.DatabaseType, country)
}
