package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func (f *fakeSubscriptionPreparer) Prepare(context.Context, *config.Config) (vpnsub.PreparedBundle, error) {
	f.calls++
	return f.result, f.err
}

func TestXraySubscriptionPrepareCreatesValidatableChangeSet(t *testing.T) {
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
	if preparer.calls != 1 || payload.Change.State != "draft" || len(payload.Change.Operations) != 2 || !payload.Preparation.Ready || payload.Preparation.SecretsPrinted || payload.Preparation.BundleHash != prepared.BundleHash {
		t.Fatalf("bad prepare payload: %+v", payload)
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
	bound, ok := record.Config.RouteByTag("new-vless")
	if !ok || bound.SOCKS5 != "127.0.0.1:13000" || bound.DNSServer != srv.cfg.Xray.ProbeDNSResolver || bound.DNSMode != "socks_remote" || bound.Status != "SELECTED" || bound.Disabled {
		t.Fatalf("candidate does not contain verified VLESS route: %+v", bound)
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
