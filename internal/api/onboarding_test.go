package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"router-policy/internal/config"
	"router-policy/internal/platform"
)

type onboardingReadyProvider struct {
	platform.DevelopmentMockProvider
}

func (p onboardingReadyProvider) Overview(cfg *config.Config) map[string]any {
	value := p.DevelopmentMockProvider.Overview(cfg)
	value["internet"] = "ROUTE_AVAILABLE"
	value["dns"] = "AVAILABLE"
	value["simulation"] = false
	return value
}

func postOnboarding(t *testing.T, client *http.Client, csrf, base, step, action string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/onboarding", strings.NewReader(`{"step":"`+step+`","action":"`+action+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestOnboardingStateIsBackendPersistedAndCannotCompleteFromBrowserHint(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.provider = onboardingReadyProvider{}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	var initial map[string]any
	data := getAPIData(t, client, ts.URL+"/api/v1/onboarding")
	if err := json.Unmarshal(data, &initial); err != nil {
		t.Fatal(err)
	}
	if initial["source"] != "backend" || initial["completed"] == true {
		t.Fatalf("unexpected initial onboarding state: %+v", initial)
	}
	if status := postOnboarding(t, client, csrf, ts.URL, "complete", "complete"); status != http.StatusConflict {
		t.Fatalf("browser-side completion hint bypassed backend gate: status=%d", status)
	}
	if status := postOnboarding(t, client, csrf, ts.URL, "methods", "skip"); status != http.StatusOK {
		t.Fatalf("methods skip status=%d", status)
	}
	if status := postOnboarding(t, client, csrf, ts.URL, "sources", "skip"); status != http.StatusOK {
		t.Fatalf("sources skip status=%d", status)
	}
	if status := postOnboarding(t, client, csrf, ts.URL, "services", "automatic"); status != http.StatusOK {
		t.Fatalf("services acceptance status=%d", status)
	}
	if status := postOnboarding(t, client, csrf, ts.URL, "complete", "complete"); status != http.StatusOK {
		t.Fatalf("backend completion status=%d", status)
	}
	if got := srv.loadOnboardingState(); !got.Completed || got.Steps["methods"].Status != "skipped" {
		t.Fatalf("onboarding state was not durably persisted: %+v", got)
	}
}

func TestOnboardingResponseFailsClosedForCorruptPersistedStep(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.provider = onboardingReadyProvider{}
	state := defaultOnboardingState()
	state.Steps["methods"] = onboardingStep{Status: "corrupted"}
	state.Steps["sources"] = onboardingStep{Status: "accepted"}
	state.Steps["services"] = onboardingStep{Status: "accepted"}
	if err := srv.store.SaveJSON("onboarding", onboardingStateKey, state); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, _ := login(t, ts.URL)
	data := getAPIData(t, client, ts.URL+"/api/v1/onboarding")
	var response map[string]any
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if response["can_complete"] == true {
		t.Fatalf("corrupt persisted step unlocked completion: %+v", response)
	}
}

func TestOnboardingOverviewReadyRequiresProofStates(t *testing.T) {
	tests := []struct {
		name     string
		overview map[string]any
		want     bool
	}{
		{name: "verified route and dns", overview: map[string]any{"internet": "ROUTE_AVAILABLE", "dns": "AVAILABLE"}, want: true},
		{name: "simulation is not proof", overview: map[string]any{"internet": "simulation", "dns": "simulation"}, want: false},
		{name: "unverified is not proof", overview: map[string]any{"internet": "UNVERIFIED", "dns": "UNVERIFIED"}, want: false},
		{name: "missing upstream is not proof", overview: map[string]any{"internet": "ROUTE_AVAILABLE", "dns": "NO_UPSTREAM"}, want: false},
		{name: "nested statuses are supported", overview: map[string]any{"internet": map[string]any{"status": "ok"}, "dns": map[string]any{"state": "ready"}}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := onboardingOverviewReady(test.overview); got != test.want {
				t.Fatalf("onboardingOverviewReady(%v)=%v, want %v", test.overview, got, test.want)
			}
		})
	}
}

func TestOnboardingStepCompletionRejectsUnknownStatuses(t *testing.T) {
	for _, status := range []string{"", "pending", "verified", "bogus", "completed"} {
		t.Run("methods_"+status, func(t *testing.T) {
			value := defaultOnboardingState()
			value.Steps["methods"] = onboardingStep{Status: status}
			if onboardingStepCompleted(value, "methods") {
				t.Fatalf("unknown onboarding status %q was treated as complete", status)
			}
		})
	}
	for _, status := range []string{"accepted", "skipped"} {
		t.Run("accepted_"+status, func(t *testing.T) {
			value := defaultOnboardingState()
			value.Steps["methods"] = onboardingStep{Status: status}
			if !onboardingStepCompleted(value, "methods") {
				t.Fatalf("explicit onboarding status %q was not treated as complete", status)
			}
		})
	}
}
