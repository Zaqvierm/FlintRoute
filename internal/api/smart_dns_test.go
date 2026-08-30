package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/probe"
)

func TestNormalizeSmartDNSEndpointRejectsUnsafeAddresses(t *testing.T) {
	for _, value := range []string{"127.0.0.1:53", "192.168.1.1:53", "192.0.2.53:53", "198.51.100.53:53", "203.0.113.53:53", "not-an-ip:53", "1.1.1.1:0"} {
		if _, err := normalizeSmartDNSEndpoint(value); err == nil {
			t.Fatalf("unsafe Smart DNS endpoint was accepted: %s", value)
		}
	}
	if got, err := normalizeSmartDNSEndpoint("1.1.1.1:53"); err != nil || got != "1.1.1.1:53" {
		t.Fatalf("public Smart DNS endpoint rejected: got=%q err=%v", got, err)
	}
	if got, err := normalizeSmartDNSEndpoint("1.1.1.1"); err != nil || got != "1.1.1.1:53" {
		t.Fatalf("default Smart DNS port was not applied: got=%q err=%v", got, err)
	}
	if got, err := normalizeSmartDNSEndpoint("2606:4700:4700::1111"); err != nil || got != "[2606:4700:4700::1111]:53" {
		t.Fatalf("bare IPv6 Smart DNS endpoint rejected: got=%q err=%v", got, err)
	}
}

func TestSmartDNSConfigureCreatesDraft(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.smartDNSValidator = func(_ context.Context, endpoint, domain string) (probe.SmartDNSValidationResult, error) {
		return probe.SmartDNSValidationResult{
			Endpoint: endpoint, Domain: domain, UDP: probe.DNSResolverTransportResult{Transport: "udp", Safe: true, Addresses: []string{"93.184.216.34"}},
			TCP: probe.DNSResolverTransportResult{Transport: "tcp", Safe: true, Addresses: []string{"93.184.216.34"}}, Addresses: []string{"93.184.216.34"},
			ConnectedIP: "93.184.216.34", HTTPStatus: 200, TLSOK: true, HTTPOK: true,
		}, nil
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	request, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/smart-dns/configure", strings.NewReader(`{"base_version":1,"resolvers":[{"ip":"9.9.9.9"}],"test_domain":"example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("configure status=%d", response.StatusCode)
	}
	var envelope Envelope
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"endpoint_count":1`) || !strings.Contains(string(raw), `"state":"draft"`) || !strings.Contains(string(raw), `"addresses":["93.184.216.34"]`) {
		t.Fatalf("configure response lacks draft metadata: %s", raw)
	}
	var data struct {
		Change ChangeSet `json:"change"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	validated, status := postAction(t, client, csrf, ts.URL, data.Change.ID, "validate", `{}`)
	if status != http.StatusOK || validated.State != "validated" {
		t.Fatalf("validated Smart DNS candidate rejected: status=%d change=%+v", status, validated)
	}

	var proof smartDNSValidationRecord
	proofKey := smartDNSValidationKey("9.9.9.9:53")
	if err := srv.store.LoadJSON("smart_dns_validations", proofKey, &proof); err != nil {
		t.Fatal(err)
	}
	proof.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if err := srv.store.SaveJSON("smart_dns_validations", proofKey, proof); err != nil {
		t.Fatal(err)
	}
	_, status = postAction(t, client, csrf, ts.URL, data.Change.ID, "apply", `{}`)
	if status != http.StatusConflict {
		t.Fatalf("apply accepted expired Smart DNS proof: status=%d", status)
	}
}

func TestSmartDNSConfigureAutoAppliesInBackground(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.smartDNSValidator = func(_ context.Context, endpoint, domain string) (probe.SmartDNSValidationResult, error) {
		return probe.SmartDNSValidationResult{
			Endpoint: endpoint, Domain: domain,
			UDP:       probe.DNSResolverTransportResult{Transport: "udp", Safe: true, Addresses: []string{"93.184.216.34"}},
			TCP:       probe.DNSResolverTransportResult{Transport: "tcp", Safe: true, Addresses: []string{"93.184.216.34"}},
			Addresses: []string{"93.184.216.34"}, ConnectedIP: "93.184.216.34",
			HTTPStatus: 200, TLSOK: true, HTTPOK: true,
		}, nil
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	request, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/smart-dns/configure", strings.NewReader(`{"base_version":1,"resolvers":[{"ip":"9.9.9.9"}],"test_domain":"example.com","auto_apply":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("configure status=%d", response.StatusCode)
	}
	var envelope Envelope
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope.Data)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Change           ChangeSet `json:"change"`
		AutoApplyStarted bool      `json:"auto_apply_started"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	if !data.Change.AutoApply || !data.AutoApplyStarted {
		t.Fatalf("automatic continuation was not started: %+v", data)
	}

	deadline := time.Now().Add(3 * time.Second)
	var committed ChangeSet
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		committed = srv.changes[data.Change.ID]
		srv.mu.Unlock()
		if committed.State == "committed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if committed.State != "committed" {
		t.Fatalf("automatic Smart DNS transaction did not commit: %+v", committed)
	}
	srv.mu.Lock()
	active := srv.activeConfig
	srv.mu.Unlock()
	var configured bool
	for _, route := range active.Routes {
		if route.Type == "smart_dns" && route.DNSServer == "9.9.9.9:53" && !route.Disabled && route.Status == "CONFIGURED" {
			configured = true
		}
	}
	if !configured {
		t.Fatalf("committed config does not contain Smart DNS endpoint: %+v", active.Routes)
	}
	fake := srv.adapter.(*fakeAdapter)
	if fake.callCount("apply_candidate") == 0 || fake.callCount("commit") == 0 {
		t.Fatalf("automatic continuation skipped adapter transaction: calls=%v", fake.calls)
	}
}

func TestSmartDNSAutoApplyFailurePreservesActiveConfig(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.smartDNSValidator = func(_ context.Context, endpoint, domain string) (probe.SmartDNSValidationResult, error) {
		return probe.SmartDNSValidationResult{
			Endpoint: endpoint, Domain: domain,
			UDP:       probe.DNSResolverTransportResult{Transport: "udp", Safe: true, Addresses: []string{"93.184.216.34"}},
			TCP:       probe.DNSResolverTransportResult{Transport: "tcp", Safe: true, Addresses: []string{"93.184.216.34"}},
			Addresses: []string{"93.184.216.34"}, ConnectedIP: "93.184.216.34",
			HTTPStatus: 200, TLSOK: true, HTTPOK: true,
		}, nil
	}
	fake := srv.adapter.(*fakeAdapter)
	fake.fail["apply_candidate"] = true
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)
	request, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/smart-dns/configure", strings.NewReader(`{"base_version":1,"resolvers":[{"ip":"9.9.9.9"}],"test_domain":"example.com","auto_apply":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("configure status=%d", response.StatusCode)
	}
	var envelope Envelope
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope.Data)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Change ChangeSet `json:"change"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var final ChangeSet
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		final = srv.changes[data.Change.ID]
		active := srv.activeConfig
		srv.mu.Unlock()
		if final.State != "draft" && final.State != "validated" && final.State != "applying" && final.State != "awaiting_confirmation" && final.State != "committing" {
			if active.Routes[1].DNSServer != "1.1.1.1:53" {
				t.Fatalf("failed auto-apply changed active config: %+v", active.Routes)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if final.State == "committed" || final.State == "draft" || final.State == "validated" || final.State == "applying" || final.State == "awaiting_confirmation" || final.State == "committing" {
		t.Fatalf("failed auto-apply did not reach a terminal failure: %+v", final)
	}
}

func TestSmartDNSConfigureDoesNotCreateDraftWhenValidationFails(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.smartDNSValidator = func(context.Context, string, string) (probe.SmartDNSValidationResult, error) {
		return probe.SmartDNSValidationResult{}, errors.New("TCP DNS query timed out")
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)
	request, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/smart-dns/configure", strings.NewReader(`{"base_version":1,"resolvers":[{"ip":"1.1.1.1","port":53}],"test_domain":"example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("failed resolver validation status=%d", response.StatusCode)
	}
	srv.mu.Lock()
	changeCount := len(srv.changes)
	srv.mu.Unlock()
	if changeCount != 0 {
		t.Fatalf("failed resolver validation created %d changes", changeCount)
	}
}

func TestSmartDNSStatusPublishesConditionalDNSFallback(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, _ := login(t, ts.URL)

	response, err := client.Get(ts.URL + "/api/v1/smart-dns")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var envelope Envelope
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"tspu":["zapret","smart_dns","vless","drop"]`) {
		t.Fatalf("Smart DNS fallback contract is wrong: %s", raw)
	}
}

func TestSmartDNSResolverStateTreatsFreshUnboundValidationAsIdleReady(t *testing.T) {
	route := config.Route{Type: "smart_dns", Tag: "smart", DNSServer: "1.1.1.1:53"}
	health := probe.RouteHealth{State: "unhealthy", LastReason: "route_not_bound_to_verification_plan"}
	ready, status := smartDNSResolverState(route, health, true, true)
	if !ready || status != "validated_idle" {
		t.Fatalf("fresh unbound resolver state=(%v,%q), want ready validated_idle", ready, status)
	}
}

func TestSmartDNSResolverStateKeepsRealHealthFailureUnavailable(t *testing.T) {
	route := config.Route{Type: "smart_dns", Tag: "smart", DNSServer: "1.1.1.1:53"}
	health := probe.RouteHealth{State: "unhealthy", LastReason: "dns_failed"}
	ready, status := smartDNSResolverState(route, health, true, true)
	if ready || status != "unhealthy" {
		t.Fatalf("failed resolver state=(%v,%q), want unavailable unhealthy", ready, status)
	}
}

func TestSmartDNSHealthFreshUsesBoundedCheckWindow(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	fresh := probe.RouteHealth{LastCheckedAt: now.Add(-9 * time.Minute)}
	if !smartDNSHealthFresh(fresh, now, 300) {
		t.Fatal("health result inside two check intervals was marked stale")
	}
	stale := probe.RouteHealth{LastCheckedAt: now.Add(-11 * time.Minute)}
	if smartDNSHealthFresh(stale, now, 300) {
		t.Fatal("health result outside two check intervals was marked fresh")
	}
	if smartDNSHealthFresh(probe.RouteHealth{}, now, 300) {
		t.Fatal("health result without a check timestamp was marked fresh")
	}
	if smartDNSHealthFresh(probe.RouteHealth{LastCheckedAt: now.Add(time.Second)}, now, 300) {
		t.Fatal("future health timestamp was marked fresh")
	}
}
