package vpnsub

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogicalServerDeduplicatesDifferentCredentials(t *testing.T) {
	raw := subscriptionWithServers(t,
		vlessServer("Germany 3", "de03.example.com", "11111111-1111-4111-8111-111111111111"),
		vlessServer("DE Frankfurt 03", "de03.example.com", "22222222-2222-4222-8222-222222222222"),
	)
	summary, err := Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if summary.DeduplicatedVLESSCount != 1 || len(summary.Servers) != 1 || summary.Servers[0].SourceCount != 2 {
		t.Fatalf("credential sources were shown as physical servers: %+v", summary)
	}
	encoded, _ := json.Marshal(summary)
	if strings.Contains(string(encoded), "11111111-1111-4111-8111-111111111111") || strings.Contains(string(encoded), "22222222-2222-4222-8222-222222222222") {
		t.Fatalf("logical pool leaked credentials: %s", encoded)
	}
}

func TestSameDisplayNameDifferentEndpointIsNotDeduplicated(t *testing.T) {
	raw := subscriptionWithServers(t,
		vlessServer("Germany 3", "de03.example.com", "11111111-1111-4111-8111-111111111111"),
		vlessServer("Germany 3", "de04.example.com", "22222222-2222-4222-8222-222222222222"),
	)
	summary, err := Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if summary.DeduplicatedVLESSCount != 0 || len(summary.Servers) != 2 || summary.Servers[0].LogicalID == summary.Servers[1].LogicalID {
		t.Fatalf("different endpoints were merged: %+v", summary)
	}
}

func TestSubscriptionExpiryAndProviderNameAreSafe(t *testing.T) {
	if got := subscriptionExpiry("upload=1; download=2; expire=1788134400; total=3"); got != "2026-08-31T00:00:00Z" {
		t.Fatalf("expiry=%q", got)
	}
	if got := safeProviderName("Provider%20One%0AInjected"); got != "" {
		t.Fatalf("unsafe provider name accepted: %q", got)
	}
}

func TestProviderOverlapRequiresConfirmationAcrossOrigins(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "one.json"), filepath.Join(dir, "two.json")}
	credentials := []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}
	for index := range paths {
		if err := os.WriteFile(paths[index], subscriptionWithServers(t, vlessServer("Germany 3", "de03.example.com", credentials[index])), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sources, matches, _, err := analyzeSubscriptionSources(
		[]string{"https://one.example/sub/a", "https://two.example/sub/b"}, paths,
		[]FetchSummary{{ProviderName: "Provider One"}, {ProviderName: "Provider Two"}}, time.Unix(0, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 || len(matches) != 1 || matches[0].MatchedServers != 1 || matches[0].Recommendation != "confirmation_required" {
		t.Fatalf("provider overlap was not surfaced: sources=%+v matches=%+v", sources, matches)
	}
}

func TestServerScoreCapsThroughputByTariffAndBalancesLatency(t *testing.T) {
	fastLinkSlowLatency := ScoreServer(ServerMetrics{PathVerified: true, LatencyMS: 180, JitterMS: 10, MeasuredMbps: 850, TariffMbps: 300, SuccessfulProbes: 10})
	nearTariffLowLatency := ScoreServer(ServerMetrics{PathVerified: true, LatencyMS: 40, JitterMS: 3, MeasuredMbps: 280, TariffMbps: 300, SuccessfulProbes: 10})
	if fastLinkSlowLatency.EffectiveThroughput != 300 {
		t.Fatalf("throughput was not capped by tariff: %+v", fastLinkSlowLatency)
	}
	if nearTariffLowLatency.Total <= fastLinkSlowLatency.Total {
		t.Fatalf("latency/stability balance selected raw speed only: A=%+v B=%+v", fastLinkSlowLatency, nearTariffLowLatency)
	}
	if ScoreServer(ServerMetrics{LatencyMS: 10, MeasuredMbps: 1000, TariffMbps: 300}).Eligible {
		t.Fatal("unverified server was eligible")
	}
}

func TestRecentSpeedMeasurementIsReusedWithoutTraffic(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now().UTC()
	snapshot := PoolSnapshot{Servers: []ServerStatus{{LogicalID: "srv_same", MeasuredMbps: 275, SpeedBytes: 2 << 20, SpeedDuration: 100, SpeedTestedAt: now.Add(-time.Hour).Format(time.RFC3339)}}}
	if err := StorePool(PoolPath(stateDir), snapshot); err != nil {
		t.Fatal(err)
	}
	server := ServerStatus{LogicalID: "srv_same"}
	if !reuseRecentSpeedMeasurement(&server, stateDir, now) || server.MeasuredMbps != 275 {
		t.Fatalf("recent measurement was not reused: %+v", server)
	}
	if reuseRecentSpeedMeasurement(&ServerStatus{LogicalID: "srv_other"}, stateDir, now) {
		t.Fatal("measurement from another logical server was reused")
	}
}

func TestVerifiedEgressCountryIsUsedWhenNameHasNoCountry(t *testing.T) {
	servers := []ServerStatus{{Tag: "node-1", Name: "Fast node", Hostname: "node.example"}}
	result := enrichServerInventory(context.Background(), servers, []OutboundCheck{{Tag: "node-1", Status: "OK", ExternalCountry: "DE", LatencyMS: 42}}, "node-1", time.Now().UTC(), nil)
	if result[0].Country != "DE" || result[0].CountrySource != "verified_egress" {
		t.Fatalf("verified country was not attached: %+v", result[0])
	}
}

func vlessServer(tag, address, credential string) map[string]any {
	return map[string]any{
		"tag": tag, "remarks": tag, "protocol": "vless",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": address, "port": 443,
			"users": []any{map[string]any{"id": credential, "encryption": "none", "flow": "xtls-rprx-vision"}},
		}}},
		"streamSettings": map[string]any{
			"network": "tcp", "security": "reality",
			"realitySettings": map[string]any{"serverName": "cdn.example.com", "publicKey": "PUBLIC_KEY", "fingerprint": "chrome", "shortId": "01234567"},
		},
	}
}

func subscriptionWithServers(t *testing.T, servers ...map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"outbounds": servers})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
