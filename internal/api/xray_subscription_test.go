package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"router-policy/internal/config"
	"router-policy/internal/vpnsub"
	"router-policy/internal/xraybundle"
)

type fakeSubscriptionPreparer struct {
	result vpnsub.PreparedBundle
	err    error
	calls  int
}

type failingHWIDFingerprintProvider struct{}

func (failingHWIDFingerprintProvider) Components(context.Context) (vpnsub.FingerprintComponents, error) {
	return vpnsub.FingerprintComponents{}, errors.New("fingerprint unavailable")
}

func (f *fakeSubscriptionPreparer) Prepare(context.Context, *config.Config) (vpnsub.PreparedBundle, error) {
	f.calls++
	return f.result, f.err
}

func TestXraySubscriptionPrepareOffersManagedActivationWithoutChangeSet(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	prepared := stagePreparedBundleForAPI(t, srv.cfg.Storage.StateDir)
	preparer := &fakeSubscriptionPreparer{result: prepared}
	srv.subscriptionPreparer = preparer
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	body := bytes.NewBufferString(`{"base_version":1}`)
	request, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/xray/subscription/prepare", body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("prepare status=%d", response.StatusCode)
	}
	var envelope Envelope
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	rawResponse, _ := json.Marshal(envelope.Data)
	for _, secret := range []string{"33333333-3333-4333-8333-333333333333", "new.example", "subscription-secret", prepared.BundlePath} {
		if strings.Contains(string(rawResponse), secret) {
			t.Fatalf("subscription preparation response leaked %q: %s", secret, rawResponse)
		}
	}
	var payload struct {
		Change      ChangeSet `json:"change"`
		Preparation struct {
			BundleHash     string `json:"bundle_hash"`
			SelectedTag    string `json:"selected_tag"`
			Ready          bool   `json:"ready"`
			SecretsPrinted bool   `json:"secrets_printed"`
		} `json:"preparation"`
	}
	if err := json.Unmarshal(rawResponse, &payload); err != nil {
		t.Fatal(err)
	}
	if preparer.calls != 1 || payload.Change.ID != "" || !payload.Preparation.Ready || payload.Preparation.SecretsPrinted || payload.Preparation.BundleHash != prepared.BundleHash {
		t.Fatalf("bad prepare payload: %+v", payload)
	}
	srv.mu.Lock()
	changeCount := len(srv.changes)
	srv.mu.Unlock()
	if changeCount != 0 {
		t.Fatalf("candidate-only preparation created %d ChangeSets", changeCount)
	}
}

func TestXrayManagedActivationBindsModeBundleAndRoutesInOneChangeSet(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.cfg.Xray.InitScript = "/etc/init.d/router-policy-xray"
	srv.mu.Lock()
	srv.activeConfig.Xray.InitScript = srv.cfg.Xray.InitScript
	srv.mu.Unlock()
	prepared := stagePreparedBundleForAPI(t, srv.cfg.Storage.StateDir)
	srv.subscriptionPreparer = &fakeSubscriptionPreparer{result: prepared}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	request, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/xray/subscription/prepare", strings.NewReader(`{"base_version":1,"activate_managed":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("managed prepare status=%d", response.StatusCode)
	}
	var envelope Envelope
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	rawResponse, _ := json.Marshal(envelope.Data)
	var payload struct {
		Change ChangeSet `json:"change"`
	}
	if err := json.Unmarshal(rawResponse, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Change.State != "draft" || len(payload.Change.Operations) != 3 {
		t.Fatalf("managed activation did not create one complete ChangeSet: %+v", payload.Change)
	}
	validated := changeActionForTest(t, client, csrf, ts.URL, payload.Change.ID, "validate")
	if validated.State != "validated" {
		t.Fatalf("prepared ChangeSet did not validate: %+v", validated)
	}
	var record candidateRecord
	if err := srv.store.LoadJSON("candidates", validated.ID, &record); err != nil {
		t.Fatalf("could not load validated candidate: %v", err)
	}
	if record.Config.Xray.OutboundBundleSHA256 != prepared.BundleHash {
		t.Fatalf("candidate did not bind prepared bundle: %+v", record.Config.Xray)
	}
	if record.Config.Xray.ActivationMode != "managed" {
		t.Fatalf("candidate did not explicitly activate managed Xray: %+v", record.Config.Xray)
	}
	bound, ok := record.Config.RouteByTag("new-vless")
	if !ok || bound.SOCKS5 != "127.0.0.1:13000" || bound.DNSServer != srv.cfg.Xray.ProbeDNSResolver || bound.DNSMode != "socks_remote" || bound.Status != "SELECTED" || bound.Disabled {
		t.Fatalf("candidate does not contain verified VLESS route: %+v", bound)
	}
	applied := changeActionForTest(t, client, csrf, ts.URL, validated.ID, "apply")
	if applied.State != "awaiting_confirmation" || !applied.DataPlaneVerified {
		t.Fatalf("managed Xray did not reach verified confirmation: %+v", applied)
	}
	confirmed := changeActionForTest(t, client, csrf, ts.URL, applied.ID, "confirm")
	if confirmed.State != "committed" {
		t.Fatalf("managed Xray did not commit: %+v", confirmed)
	}
}

func TestXraySubscriptionPrepareFailureCreatesNoChangeSet(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.subscriptionPreparer = &fakeSubscriptionPreparer{err: errors.New("candidate verification failed")}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	request, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/xray/subscription/prepare", strings.NewReader(`{"base_version":1}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("failure status=%d", response.StatusCode)
	}
	srv.mu.Lock()
	changeCount := len(srv.changes)
	srv.mu.Unlock()
	if changeCount != 0 {
		t.Fatalf("failed preparation created %d ChangeSets", changeCount)
	}
}

func TestXraySubscriptionSecretIsStoredWithoutEchoingIt(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	secretPath := filepath.Join(srv.cfg.Storage.StateDir, "secrets", "vpn-subscription-url")
	srv.cfg.Xray.SubscriptionSecretFile = secretPath
	srv.mu.Lock()
	srv.activeConfig.Xray.SubscriptionSecretFile = secretPath
	srv.mu.Unlock()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	const secretURL = "https://subscription.example/api/list?token=private-value"
	request, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/xray/subscription/secret", strings.NewReader(`{"url":"`+secretURL+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("secret update status=%d", response.StatusCode)
	}
	rawResponse, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawResponse), secretURL) || strings.Contains(string(rawResponse), "private-value") {
		t.Fatalf("secret update echoed the subscription URL: %s", rawResponse)
	}
	rawFile, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	expectedFile, err := json.Marshal([]string{secretURL})
	if err != nil {
		t.Fatal(err)
	}
	expectedFile = append(expectedFile, '\n')
	if !bytes.Equal(rawFile, expectedFile) || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("subscription secret was not stored securely: mode=%o bytes=%d", info.Mode().Perm(), len(rawFile))
	}
}

func TestXraySubscriptionSecretRejectsInsecureURLAndSymlink(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "subscription")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := storeSubscriptionSecret(link, "https://subscription.example/list"); err == nil {
		t.Fatal("subscription secret writer followed a symlink")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "keep\n" {
		t.Fatalf("symlink target was modified: bytes=%q err=%v", got, err)
	}
	if _, err := normalizeSubscriptionURL("http://subscription.example/list"); err == nil {
		t.Fatal("plain HTTP subscription URL was accepted")
	}
}

func TestXraySubscriptionSecretAcceptsHappSourceAndMasksIt(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	secretPath := filepath.Join(srv.cfg.Storage.StateDir, "secrets", "vpn-subscription-url")
	srv.cfg.Xray.SubscriptionSecretFile = secretPath
	srv.mu.Lock()
	srv.activeConfig.Xray.SubscriptionSecretFile = secretPath
	srv.mu.Unlock()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)
	const source = `happ://crypt4/very-secret-payload`
	request, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/xray/subscription/secret", strings.NewReader(`{"url":"`+source+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Happ source update status=%d", response.StatusCode)
	}
	var updateEnvelope Envelope
	updateBody, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if err := json.Unmarshal(updateBody, &updateEnvelope); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updateBody), "source_masked") || strings.Contains(string(updateBody), "very-secret-payload") {
		t.Fatalf("Happ source metadata was not returned safely on update: %s", updateBody)
	}
	request, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/v1/xray/subscription/secret", nil)
	request.Header.Set("X-CSRF-Token", csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if strings.Contains(string(raw), source) || strings.Contains(string(raw), "very-secret-payload") {
		t.Fatalf("Happ source leaked through status API: %s", raw)
	}
	if !strings.Contains(string(raw), "crypt4") || !strings.Contains(string(raw), "source_masked") {
		t.Fatalf("Happ source metadata missing: %s", raw)
	}
	request, _ = http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/xray/subscription/secret", strings.NewReader(`{"index":0}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Happ source removal status=%d", response.StatusCode)
	}
	removed, _ := io.ReadAll(response.Body)
	if strings.Contains(string(removed), source) || strings.Contains(string(removed), "very-secret-payload") || !strings.Contains(string(removed), `"count":0`) {
		t.Fatalf("Happ source removal response was unsafe: %s", removed)
	}
}

func TestXraySubscriptionSecretAcceptsPortalHappWrapper(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	secretPath := filepath.Join(srv.cfg.Storage.StateDir, "secrets", "vpn-subscription-url")
	srv.cfg.Xray.SubscriptionSecretFile = secretPath
	srv.mu.Lock()
	srv.activeConfig.Xray.SubscriptionSecretFile = secretPath
	srv.mu.Unlock()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)
	// The portal URL is the original source.  The nested Happ value is kept
	// encoded so the API must not mistake the portal HTML response for the
	// subscription payload; source resolution happens later in vpnsub.Fetch.
	const source = "https://portal.example/add-key?subkey=happ%3A%2F%2Fcrypt4%2Fmasked-payload"
	request, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/xray/subscription/secret", strings.NewReader(`{"url":"`+source+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("portal source update status=%d body=%s", response.StatusCode, body)
	}
	if !strings.Contains(string(body), "portal.example") || !strings.Contains(string(body), "crypt4") || strings.Contains(string(body), "masked-payload") {
		t.Fatalf("portal source was not stored/masked safely: %s", body)
	}
	stored, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stored, []byte("portal.example")) || !bytes.Contains(stored, []byte("subkey=")) {
		t.Fatalf("original portal source was not retained: %s", stored)
	}
}

func TestSubscriptionHWIDEndpointPersistsDeterministicSettings(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	secretPath := filepath.Join(srv.cfg.Storage.StateDir, "secrets", "vpn-subscription-url")
	srv.cfg.Xray.SubscriptionSecretFile = secretPath
	srv.mu.Lock()
	srv.activeConfig.Xray.SubscriptionSecretFile = secretPath
	srv.mu.Unlock()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)
	body := `{"mode":"preset","preset":"33333333-3333-4333-8333-333333333333"}`
	request, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/xray/subscription/hwid", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	rawResponse, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HWID update status=%d", response.StatusCode)
	}
	settings, err := vpnsub.LoadHWIDSettings(vpnsub.HWIDSettingsPath(srv.cfg.Xray.SubscriptionSecretFile))
	if err != nil || settings.Mode != vpnsub.HWIDModePreset {
		t.Fatalf("HWID settings were not persisted: %+v %v", settings, err)
	}
	var envelope Envelope
	// The response is intentionally useful to the UI: it contains preview rows
	// but never any subscription source or provider credential.
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err := json.NewDecoder(bytes.NewReader(rawResponse)).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	data, ok := envelope.Data.(map[string]any)
	if !ok || data["current_hwid"] != "33333333-3333-4333-8333-333333333333" {
		t.Fatalf("HWID response did not contain the selected preset: %#v", envelope.Data)
	}
}

func TestSubscriptionHWIDFailedFingerprintPreservesPreviousSettings(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	secretPath := filepath.Join(srv.cfg.Storage.StateDir, "secrets", "vpn-subscription-url")
	srv.cfg.Xray.SubscriptionSecretFile = secretPath
	srv.mu.Lock()
	srv.activeConfig.Xray.SubscriptionSecretFile = secretPath
	srv.mu.Unlock()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	put := func(body string) *http.Response {
		t.Helper()
		request, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/xray/subscription/hwid", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	response := put(`{"mode":"preset","preset":"33333333-3333-4333-8333-333333333333"}`)
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("initial HWID update status=%d body=%s", response.StatusCode, body)
	}
	response.Body.Close()

	// The injected provider fails deterministically. The old preset must remain
	// active because resolution failed before persistence.
	srv.hwidFingerprintProvider = failingHWIDFingerprintProvider{}
	response = put(`{"mode":"generated","source":"mac"}`)
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError || !strings.Contains(string(body), "subscription_hwid_unavailable") {
		t.Fatalf("failed fingerprint was not rejected semantically: status=%d body=%s", response.StatusCode, body)
	}
	settings, err := vpnsub.LoadHWIDSettings(vpnsub.HWIDSettingsPath(secretPath))
	if err != nil {
		t.Fatal(err)
	}
	if settings.Mode != vpnsub.HWIDModePreset || settings.Preset != "33333333-3333-4333-8333-333333333333" {
		t.Fatalf("failed fingerprint replaced previous settings: %+v", settings)
	}
}

func stagePreparedBundleForAPI(t *testing.T, stateDir string) vpnsub.PreparedBundle {
	t.Helper()
	raw := []byte(`{"log":{"loglevel":"warning"},"inbounds":[{"tag":"socks-new-vless","listen":"127.0.0.1","port":13000,"protocol":"socks","settings":{"auth":"noauth","udp":true,"ip":"127.0.0.1"}}],"outbounds":[{"tag":"new-vless","protocol":"vless","settings":{"vnext":[{"address":"new.example","port":443,"users":[{"id":"33333333-3333-4333-8333-333333333333","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["socks-new-vless"],"outboundTag":"new-vless"}]}}`)
	source := filepath.Join(stateDir, "prepared-source.json")
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := xraybundle.Hash(raw)
	path, err := xraybundle.Store(stateDir, source, hash)
	if err != nil {
		t.Fatal(err)
	}
	return vpnsub.PreparedBundle{
		CandidateID: "cand_test", BundleHash: hash, BundlePath: path,
		SubscriptionHash: "sha256:" + strings.Repeat("a", 64), SubscriptionBytes: len(raw), SelectedTag: "new-vless",
		Checks:  []vpnsub.OutboundCheck{{Tag: "new-vless", Status: "OK", LatencyMS: 25, ExternalIPHash: "sha256:egress", ExternalCountry: "DE"}},
		Servers: []vpnsub.ServerStatus{{Tag: "new-vless", Status: "SUPPORTED", SOCKS5: "127.0.0.1:13000"}},
		Routes:  []vpnsub.GeneratedRoute{{Type: "vless", Tag: "new-vless", Priority: 100, SOCKS5: "127.0.0.1:13000", DNSMode: "socks_remote", ExternalIPProbe: true}},
		Ready:   true, SecretsPrinted: false,
	}
}
