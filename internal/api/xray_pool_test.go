package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"router-policy/internal/vpnsub"
)

type fixedThroughputTester struct {
	calls int
}

func (t *fixedThroughputTester) Measure(context.Context, string, int64) (vpnsub.SpeedMeasurement, error) {
	t.calls++
	return vpnsub.SpeedMeasurement{MeasuredMbps: 287, BytesUsed: 2 << 20, DurationMS: 250, TestedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}

func TestVLESSPoolAPIIsSafeAndTariffRefreshesScore(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	stateDir := srv.cfg.Storage.StateDir
	snapshot := vpnsub.PoolSnapshot{
		TariffMbps: 300,
		Sources:    []vpnsub.SubscriptionSource{{ID: "sub_safe", Name: "Subscription 1", ProviderName: "Provider"}},
		Servers:    []vpnsub.ServerStatus{{LogicalID: "srv_safe", Name: "Germany 3", Hostname: "de.example", PathVerified: true, LatencyMS: 43, MeasuredMbps: 850, SourceIDs: []string{"sub_safe"}}},
	}
	if err := vpnsub.StorePool(vpnsub.PoolPath(stateDir), snapshot); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	body, _ := json.Marshal(map[string]float64{"tariff_mbps": 300})
	request, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/xray/pool/settings", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("tariff status=%d", response.StatusCode)
	}

	var envelope struct {
		Data vpnsub.PoolSnapshot `json:"data"`
	}
	getResponse, err := client.Get(ts.URL + "/api/v1/xray/pool")
	if err != nil {
		t.Fatal(err)
	}
	defer getResponse.Body.Close()
	if err := json.NewDecoder(getResponse.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Data.Servers) != 1 || envelope.Data.Servers[0].EffectiveMbps != 300 || envelope.Data.Servers[0].SourceCount != 1 {
		t.Fatalf("unexpected pool response: %+v", envelope.Data)
	}
}

func TestVLESSPoolSpeedTestRequiresVerifiedLoopbackPathAndStoresResult(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	tester := &fixedThroughputTester{}
	srv.vlessThroughputTester = tester
	snapshot := vpnsub.PoolSnapshot{TariffMbps: 300, Servers: []vpnsub.ServerStatus{{
		LogicalID: "srv_safe", Name: "Germany 3", SOCKS5: "127.0.0.1:12001", PathVerified: true, LatencyMS: 43,
	}}}
	if err := vpnsub.StorePool(vpnsub.PoolPath(srv.cfg.Storage.StateDir), snapshot); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)
	body, _ := json.Marshal(map[string]string{"logical_id": "srv_safe"})
	request, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/xray/pool/speedtest", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || tester.calls != 1 {
		t.Fatalf("speed test status=%d calls=%d", response.StatusCode, tester.calls)
	}
	stored, err := vpnsub.LoadPool(vpnsub.PoolPath(srv.cfg.Storage.StateDir))
	if err != nil || stored.Servers[0].MeasuredMbps != 287 || stored.Servers[0].EffectiveMbps != 287 {
		t.Fatalf("speed result was not stored and scored: pool=%+v err=%v", stored, err)
	}
}
