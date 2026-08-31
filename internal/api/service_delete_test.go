package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"router-policy/internal/config"
)

func TestServiceDeleteCreatesBoundedAutoApplyChange(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.mu.Lock()
	clone := *srv.activeConfig
	clone.Routes = append(clone.Routes, config.Route{Type: "vless", Tag: "vless-test", SOCKS5: "127.0.0.1:12080", DNSMode: "socks_remote"})
	clone.Services = map[string]config.Service{
		"youtube": {Category: "TSPU_RESTRICTED", Domains: []string{"youtube.com"}, AllowedPaths: []string{"zapret", "smart_dns", "vless", "drop"}},
		"keep":    {Category: "DIRECT_PREFERRED", Domains: []string{"keep.example"}, AllowedPaths: []string{"direct"}},
	}
	srv.activeConfig = &clone
	srv.mu.Unlock()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)
	request, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/services/delete", strings.NewReader(`{"service_id":"youtube","base_version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", response.StatusCode, body)
	}
	var envelope Envelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(envelope.Data)
	if !strings.Contains(string(raw), `"service_id":"youtube"`) || !strings.Contains(string(raw), `"auto_apply_requested":true`) {
		t.Fatalf("delete response did not expose transactional operation: %s", raw)
	}
	if strings.Contains(string(raw), `"operation":"shell"`) {
		t.Fatalf("delete response exposed an arbitrary operation: %s", raw)
	}
}

func TestServicesExposeDynamicCandidateMatrixForLegacyTSPUPolicy(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.mu.Lock()
	clone := *srv.activeConfig
	clone.Routes = append(clone.Routes, config.Route{Type: "vless", Tag: "vless-test", SOCKS5: "127.0.0.1:12080", DNSMode: "socks_remote"})
	clone.Services = map[string]config.Service{
		"youtube": {Category: "TSPU_RESTRICTED", Domains: []string{"youtube.com"}, AllowedPaths: []string{"zapret", "direct", "drop"}},
	}
	srv.activeConfig = &clone
	srv.mu.Unlock()
	recorder := httptest.NewRecorder()
	srv.handleServices(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/services", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("services status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"eligible_route_types"`) || !strings.Contains(recorder.Body.String(), `"route_type":"smart_dns"`) || !strings.Contains(recorder.Body.String(), `"route_type":"vless"`) {
		t.Fatalf("dynamic candidate matrix omitted eligible routes: %s", recorder.Body.String())
	}
}

func TestAutoApplyFailureDoesNotLeaveDraftForever(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	change, err := srv.createDraftChangeWithOptions("test product action", "test", srv.configVersion, []ChangeOp{{Type: "set", Path: "/policy/route_hold_seconds", Value: 600}}, "admin", true)
	if err != nil {
		t.Fatal(err)
	}
	srv.recordAutoApplyFailure(change.ID, "candidate_invalid", "candidate rejected", "failed")
	srv.mu.Lock()
	got := srv.changes[change.ID]
	srv.mu.Unlock()
	if got.State != "failed" {
		t.Fatalf("auto-apply failure left change in %q", got.State)
	}
	if len(got.Validation) == 0 || got.Validation[len(got.Validation)-1].Code != "candidate_invalid" {
		t.Fatalf("auto-apply failure did not persist actionable validation: %+v", got.Validation)
	}
}
