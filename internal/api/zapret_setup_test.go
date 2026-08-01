package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"router-policy/internal/config"
	"router-policy/internal/zapret"
)

type fakeZapretSetupChecker struct {
	report zapret.SetupReport
	err    error
	calls  int
}

func (f *fakeZapretSetupChecker) Check(context.Context, zapret.SetupRequest) (zapret.SetupReport, error) {
	f.calls++
	return f.report, f.err
}

const zapretSetupJSON = `{"base_version":1,"source_url":"https://downloads.example/nfqws/72.12/nfqws","provider_version":"72.12","binary_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","test_domain":"example.com"}`

func TestZapretSetupCheckDoesNotCreateChangeSet(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	configureZapretSetupTestServer(srv)
	checker := &fakeZapretSetupChecker{report: zapret.SetupReport{Ready: true, DryRun: true, NFQueueAvailable: true, TestDomain: "example.com"}}
	srv.zapretSetupChecker = checker
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	response := postZapretSetup(t, client, csrf, ts.URL+"/api/v1/zapret/setup/check", zapretSetupJSON)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || checker.calls != 1 {
		t.Fatalf("check status=%d calls=%d", response.StatusCode, checker.calls)
	}
	srv.mu.Lock()
	count := len(srv.changes)
	srv.mu.Unlock()
	if count != 0 {
		t.Fatalf("preflight created %d ChangeSets", count)
	}
}

func TestZapretSetupActivationCreatesOnePinnedManagedChangeSet(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	configureZapretSetupTestServer(srv)
	srv.zapretSetupChecker = &fakeZapretSetupChecker{report: zapret.SetupReport{Ready: true, DryRun: true, NFQueueAvailable: true, TestDomain: "example.com"}}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	response := postZapretSetup(t, client, csrf, ts.URL+"/api/v1/zapret/setup/activate", zapretSetupJSON)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("activate status=%d", response.StatusCode)
	}
	var envelope Envelope
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(envelope.Data)
	var payload struct {
		Change ChangeSet `json:"change"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Change.State != "draft" || len(payload.Change.Operations) != 6 {
		t.Fatalf("bad setup ChangeSet: %+v", payload.Change)
	}
	validated := changeActionForTest(t, client, csrf, ts.URL, payload.Change.ID, "validate")
	if validated.State != "validated" {
		t.Fatalf("setup ChangeSet did not validate: %+v", validated)
	}
	var candidate candidateRecord
	if err := srv.store.LoadJSON("candidates", validated.ID, &candidate); err != nil {
		t.Fatal(err)
	}
	if candidate.Config.Zapret.ProviderVersion != "72.12" || candidate.Config.Zapret.BinarySHA256 == "" || candidate.Config.Zapret.ProviderSource == "" {
		t.Fatalf("provider pins missing: %+v", candidate.Config.Zapret)
	}
	route, ok := candidate.Config.RouteByTag("zapret")
	if !ok || !route.Enabled() || route.Status != "CONFIGURED" {
		t.Fatalf("managed Zapret route was not enabled: %+v", route)
	}
	serviceName := candidate.Config.ServiceForDomain("example.com")
	service, ok := candidate.Config.Services[serviceName]
	if !ok || service.SelectedRouteTag != "zapret" || len(service.ProbeURLs) == 0 {
		t.Fatalf("Zapret test domain is not bound to the verified route: %+v", service)
	}
	applied := changeActionForTest(t, client, csrf, ts.URL, validated.ID, "apply")
	if applied.State != "awaiting_confirmation" || !applied.DataPlaneVerified {
		t.Fatalf("managed Zapret did not reach verified confirmation: %+v", applied)
	}
	confirmed := changeActionForTest(t, client, csrf, ts.URL, applied.ID, "confirm")
	if confirmed.State != "committed" {
		t.Fatalf("managed Zapret did not commit: %+v", confirmed)
	}
}

func TestZapretSetupFailureCreatesNoChangeSet(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	configureZapretSetupTestServer(srv)
	srv.zapretSetupChecker = &fakeZapretSetupChecker{err: errors.New("nfqws digest mismatch")}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	response := postZapretSetup(t, client, csrf, ts.URL+"/api/v1/zapret/setup/activate", zapretSetupJSON)
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("failure status=%d", response.StatusCode)
	}
	srv.mu.Lock()
	count := len(srv.changes)
	srv.mu.Unlock()
	if count != 0 {
		t.Fatalf("failed setup created %d ChangeSets", count)
	}
}

func configureZapretSetupTestServer(srv *Server) {
	zapretConfig := config.Zapret{
		Binary: "/usr/bin/nfqws", InitScript: "/etc/init.d/router-policy-zapret",
		ActiveConfig: "/etc/router-policy/zapret/nfqws.conf", ActivationMode: "managed",
		Strategy: "tls-fake-ttl3-v1", QueueNum: 200,
	}
	route := config.Route{Type: "zapret", Tag: "zapret", Disabled: true, Status: "NOT_CONFIGURED", RequiresAdapter: true, AdapterMode: "zapret", Mark: "0x42", ForbidProxy: true}
	srv.cfg.Zapret = zapretConfig
	srv.cfg.Routes = append(srv.cfg.Routes, route)
	srv.mu.Lock()
	srv.activeConfig.Zapret = zapretConfig
	srv.activeConfig.Routes = append(srv.activeConfig.Routes, route)
	srv.mu.Unlock()
}

func postZapretSetup(t *testing.T, client *http.Client, csrf, endpoint, body string) *http.Response {
	t.Helper()
	request, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
