package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
