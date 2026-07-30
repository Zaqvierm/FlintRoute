package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeSmartDNSEndpointRejectsUnsafeAddresses(t *testing.T) {
	for _, value := range []string{"127.0.0.1:53", "192.168.1.1:53", "not-an-ip:53", "1.1.1.1", "1.1.1.1:0"} {
		if _, err := normalizeSmartDNSEndpoint(value); err == nil {
			t.Fatalf("unsafe Smart DNS endpoint was accepted: %s", value)
		}
	}
	if got, err := normalizeSmartDNSEndpoint("1.1.1.1:53"); err != nil || got != "1.1.1.1:53" {
		t.Fatalf("public Smart DNS endpoint rejected: got=%q err=%v", got, err)
	}
}

func TestSmartDNSConfigureCreatesDraft(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	request, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/smart-dns/configure", strings.NewReader(`{"base_version":1,"endpoints":["1.1.1.1:53"]}`))
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
	if !strings.Contains(string(raw), `"endpoint_count":1`) || !strings.Contains(string(raw), `"state":"draft"`) {
		t.Fatalf("configure response lacks draft metadata: %s", raw)
	}
}

func TestSmartDNSStatusPublishesVPNAfterResolverFallback(t *testing.T) {
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
	if !strings.Contains(string(raw), `"tspu":["zapret","smart_dns","vless","direct","drop"]`) {
		t.Fatalf("Smart DNS fallback contract is wrong: %s", raw)
	}
}
