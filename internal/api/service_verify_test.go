package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/domaincache"
	"router-policy/internal/planner"
	"router-policy/internal/probe"
)

func TestServiceVerifyIsReadOnlyAndPersistsFreshEvidence(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.mu.Lock()
	clone := *srv.activeConfig
	clone.Services = map[string]config.Service{
		"youtube": {
			Category: "TSPU_RESTRICTED", Domains: []string{"youtube.com"},
			AllowedPaths: []string{"direct", "drop"},
			ProbeURLs:    []config.ProbeCheck{{Name: "youtube", URL: "https://youtube.com/", Required: true}},
		},
	}
	srv.activeConfig = &clone
	srv.mu.Unlock()
	called := 0
	srv.domainChecker = func(_ context.Context, candidate *config.Config, domain, serviceID string, _ planner.Options) (planner.DomainCheck, error) {
		called++
		if domain != "youtube.com" || serviceID != "youtube" || candidate.Services[serviceID].Domains[0] != domain {
			t.Fatalf("unexpected verification input: domain=%q service=%q service=%+v", domain, serviceID, candidate.Services[serviceID])
		}
		return planner.DomainCheck{
			Domain: domain, Service: serviceID, Status: "SELECTED", VerificationState: "verified",
			CheckedAt: time.Now().UTC(), Selected: &probe.RouteResult{
				Domain: domain, Service: serviceID, Route: "direct", RouteType: "direct", Status: "OK", PathVerified: true, ServiceOK: true,
				CheckedAt: time.Now().UTC().Format(time.RFC3339), RouteLatencyMS: 74, LatencyMS: 74, RouteLatencyAvailable: true,
			},
			Results: []probe.RouteResult{{
				Domain: domain, Service: serviceID, Route: "direct", RouteType: "direct", Status: "OK", PathVerified: true, ServiceOK: true,
				CheckedAt: time.Now().UTC().Format(time.RFC3339), RouteLatencyMS: 74, LatencyMS: 74, RouteLatencyAvailable: true,
			}},
		}, nil
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)
	request, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/services/verify", strings.NewReader(`{"service_id":"youtube","domain":"youtube.com"}`))
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
	if response.StatusCode != http.StatusOK || called != 1 {
		t.Fatalf("verify status=%d calls=%d body=%s", response.StatusCode, called, body)
	}
	var envelope Envelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(envelope.Data)
	if !strings.Contains(string(raw), `"verification_state":"verified"`) || !strings.Contains(string(raw), `"path_verified":true`) {
		t.Fatalf("verification proof missing: %s", raw)
	}
	if got, err := srv.store.ListProbeResults(10); err != nil || len(got) != 1 {
		t.Fatalf("verification evidence was not stored: count=%d err=%v", len(got), err)
	}
	if len(srv.changes) != 0 {
		t.Fatalf("read-only verification created changes: %d", len(srv.changes))
	}

	request, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/v1/services", nil)
	request.Header.Set("X-CSRF-Token", csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ = io.ReadAll(response.Body)
	if !strings.Contains(string(body), `"status":"VERIFIED"`) || !strings.Contains(string(body), `"verification_state":"verified"`) {
		t.Fatalf("services did not surface fresh proof: %s", body)
	}
}

func TestConfiguredServiceWithoutEvidenceRemainsNotChecked(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	recorder := httptest.NewRecorder()
	srv.handleServices(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/services", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"verification_state":"not_checked"`) {
		t.Fatalf("configured service was presented as verified without evidence: %s", recorder.Body.String())
	}
}

func TestConfiguredServiceProofRejectsContradictoryEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*probe.RouteResult)
	}{
		{name: "regional_denial", mutate: func(result *probe.RouteResult) { result.RegionalBlock = true }},
		{name: "authentication_required", mutate: func(result *probe.RouteResult) { result.AuthenticationRequired = true }},
		{name: "waf_or_rate_limit", mutate: func(result *probe.RouteResult) { result.WAFOrRateLimit = true }},
		{name: "simulation", mutate: func(result *probe.RouteResult) { result.Simulation = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t)
			defer srv.Close()
			result := probe.RouteResult{
				Domain: "github.com", Service: "github", Route: "direct", RouteType: "direct",
				Status: "OK", ApplicationStatus: "OK", PathVerified: true, ServiceOK: true,
				CheckedAt: time.Now().UTC().Format(time.RFC3339),
			}
			tc.mutate(&result)
			if err := srv.store.StoreProbeResult(result); err != nil {
				t.Fatal(err)
			}
			service := srv.currentConfig().Services["github"]
			service.SelectedRouteTag = "direct"
			if _, ok := srv.latestConfiguredServiceProof("github", service, time.Now().UTC()); ok {
				t.Fatalf("contradictory proof was returned as fresh configured evidence: %+v", result)
			}
		})
	}
}

func TestAutomaticDecisionRouteIDWithoutMatchingProofRemainsVerifying(t *testing.T) {
	decision := domaincache.Decision{
		Status:        "SELECTED",
		SelectedRoute: "zapret",
		SelectedType:  "zapret",
		Results: []probe.RouteResult{{
			Route: "zapret", RouteType: "zapret", Status: "OK", PathVerified: false, ServiceOK: false,
		}},
	}
	if got := automaticDecisionProbeState(decision, decision.SelectedRoute, decision.SelectedType, decision.Status); got != "verifying" {
		t.Fatalf("unproven selected route was presented as %q", got)
	}
	decision.Results[0].PathVerified = true
	decision.Results[0].ServiceOK = true
	if got := automaticDecisionProbeState(decision, decision.SelectedRoute, decision.SelectedType, decision.Status); got != "verified_candidate" {
		t.Fatalf("proven selected route was presented as %q", got)
	}
}

func TestAutomaticDecisionAcceptsCaseVariantVerifiedEvidence(t *testing.T) {
	decision := domaincache.Decision{
		Status:        "selected",
		SelectedRoute: "vless-de",
		SelectedType:  "vless",
		Results: []probe.RouteResult{{
			Route: "vless-de", RouteType: "vless", Status: "ok", PathVerified: true, ServiceOK: true,
		}},
	}
	if got := automaticDecisionProbeState(decision, decision.SelectedRoute, decision.SelectedType, decision.Status); got != "verified_candidate" {
		t.Fatalf("case-variant verified evidence was not recognized: %q", got)
	}
}

func TestAutomaticDecisionRejectsContradictoryVerifiedEvidence(t *testing.T) {
	tests := []struct {
		name string
		set  func(*probe.RouteResult)
	}{
		{name: "regional block", set: func(result *probe.RouteResult) { result.RegionalBlock = true }},
		{name: "authentication required", set: func(result *probe.RouteResult) { result.AuthenticationRequired = true }},
		{name: "waf or rate limit", set: func(result *probe.RouteResult) { result.WAFOrRateLimit = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := probe.RouteResult{
				Route: "vless-de", RouteType: "vless", Status: "OK", PathVerified: true, ServiceOK: true,
			}
			test.set(&result)
			decision := domaincache.Decision{
				Status: "SELECTED", SelectedRoute: result.Route, SelectedType: result.RouteType,
				Results: []probe.RouteResult{result},
			}
			if got := automaticDecisionProbeState(decision, decision.SelectedRoute, decision.SelectedType, decision.Status); got != "verifying" {
				t.Fatalf("contradictory evidence was presented as %q", got)
			}
		})
	}
}

func TestAutomaticDecisionNoSafeRouteRequiresTerminalEvidence(t *testing.T) {
	decision := domaincache.Decision{Status: "NO_SAFE_ROUTE"}
	if got := automaticDecisionProbeState(decision, "", "", decision.Status); got != "verifying" {
		t.Fatalf("empty no-safe-route decision was presented as %q", got)
	}
	decision.Results = []probe.RouteResult{{Route: "direct", RouteType: "direct", Status: "FAIL"}}
	if got := automaticDecisionProbeState(decision, "", "", decision.Status); got != "no_safe_route" {
		t.Fatalf("terminal no-safe-route decision was presented as %q", got)
	}
}
