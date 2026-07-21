package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-policy/internal/auth"
	"router-policy/internal/config"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
)

func TestAuthAndOverview(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/overview")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	client, csrf := login(t, ts.URL)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/overview", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestEventBrokerUsesNewEpochAfterRestart(t *testing.T) {
	first, err := NewEventBroker(8)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewEventBroker(8)
	if err != nil {
		t.Fatal(err)
	}
	if first.Epoch() == "" || second.Epoch() == "" || first.Epoch() == second.Epoch() {
		t.Fatalf("event stream epochs are not process-unique: first=%q second=%q", first.Epoch(), second.Epoch())
	}
	for _, event := range first.Recent(0, 8) {
		if event.StreamEpoch != first.Epoch() {
			t.Fatalf("event lacks broker epoch: %+v", event)
		}
	}
}

func TestEventsEndpointMergesPersistedHistoryAcrossRestart(t *testing.T) {
	cfg := testAPIConfig(t)
	authStore, err := auth.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := authStore.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authStore.SetupAdmin("admin", "CorrectHorse123!", token); err != nil {
		t.Fatal(err)
	}
	first, err := NewServerWithOptions(cfg, Options{Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(), Development: true})
	if err != nil {
		t.Fatal(err)
	}
	oldEpoch := first.broker.Epoch()
	first.publishEvent(Event{Type: "test.persisted", Severity: "info", ReasonCode: "persisted_before_restart", Details: map[string]any{"remote": "192.0.2.44"}})
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := NewServerWithOptions(cfg, Options{Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(), Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.broker.Epoch() == oldEpoch {
		t.Fatal("restart reused the old event epoch")
	}
	ts := httptest.NewServer(second.Handler())
	defer ts.Close()
	client, _ := login(t, ts.URL)
	raw := getAPIData(t, client, ts.URL+"/api/v1/events?limit=100")
	var events []Event
	if err := json.Unmarshal(raw, &events); err != nil {
		t.Fatal(err)
	}
	foundOld := false
	foundNewStart := false
	for _, event := range events {
		if event.Type == "test.persisted" && event.StreamEpoch == oldEpoch {
			foundOld = true
			if event.Details["remote"] != "[redacted]" {
				t.Fatalf("persisted event exposed a remote IP: %+v", event)
			}
		}
		if event.Type == "system.start" && event.StreamEpoch == second.broker.Epoch() {
			foundNewStart = true
		}
	}
	if !foundOld || !foundNewStart {
		t.Fatalf("event history did not merge old and current epochs: old=%v new=%v events=%+v", foundOld, foundNewStart, events)
	}
}

func TestActionLocksAreReleasedAfterWaitersFinish(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	releaseFirst := srv.acquireChangeActionLock("chg_lock_test")
	acquiredSecond := make(chan struct{})
	done := make(chan struct{})
	go func() {
		releaseSecond := srv.acquireChangeActionLock("chg_lock_test")
		close(acquiredSecond)
		releaseSecond()
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		refs := srv.actionLocks["chg_lock_test"].refs
		srv.mu.Unlock()
		if refs == 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	releaseFirst()
	select {
	case <-acquiredSecond:
	case <-time.After(time.Second):
		t.Fatal("second action waiter never acquired the lock")
	}
	<-done
	srv.mu.Lock()
	remaining := len(srv.actionLocks)
	srv.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("completed action locks were retained: %d", remaining)
	}
}

func TestServerCloseIsIdempotent(t *testing.T) {
	srv := newTestServer(t)
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestChangeSetRequiresCSRF(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)

	body := []byte(`{"title":"Test change","base_version":1,"operations":[{"type":"set","path":"/policies/test","value":{"route":"direct"}}]}`)
	resp, err := client.Post(ts.URL+"/api/v1/changes", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected csrf 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/changes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(env.Data)
	var cs ChangeSet
	if err := json.Unmarshal(data, &cs); err != nil {
		t.Fatal(err)
	}
	if cs.State != "draft" {
		t.Fatalf("expected draft, got %s", cs.State)
	}
}

func TestChangeSetCommitPersistsAcrossRestart(t *testing.T) {
	cfg := testAPIConfig(t)
	authStore, err := auth.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := authStore.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authStore.SetupAdmin("admin", "CorrectHorse123!", token); err != nil {
		t.Fatal(err)
	}
	fake := newFakeAdapter()
	srv, err := NewServerWithOptions(cfg, Options{Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	client, csrf := login(t, ts.URL)

	body := []byte(`{"title":"Persistent change","base_version":1,"operations":[{"type":"set","path":"/services/github/category","value":"GEO_LOCKED"},{"type":"set","path":"/services/github/allowed_paths","value":["smart_dns","drop"]},{"type":"set","path":"/services/github/require_non_ru_egress","value":true}]}`)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/changes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	data, _ := json.Marshal(env.Data)
	var cs ChangeSet
	if err := json.Unmarshal(data, &cs); err != nil {
		t.Fatal(err)
	}

	cs = changeActionForTest(t, client, csrf, ts.URL, cs.ID, "validate")
	if cs.State != "validated" || cs.CandidateHash == "" || cs.CandidatePath == "" || len(cs.Diff) == 0 {
		t.Fatalf("expected validated, got %s", cs.State)
	}
	var candidate candidateRecord
	if err := srv.store.LoadJSON("candidates", cs.ID, &candidate); err != nil {
		t.Fatal(err)
	}
	if candidate.Config.Services["github"].Category != "GEO_LOCKED" || len(candidate.Config.Routes) != len(cfg.Routes) {
		t.Fatalf("candidate is not the full applied config: %+v", candidate.Config)
	}
	canonical, _ := json.Marshal(candidate.Config)
	if got := hashBytes(canonical); got != cs.CandidateHash {
		t.Fatalf("candidate hash is not from full config: %s != %s", got, cs.CandidateHash)
	}
	cs = changeActionForTest(t, client, csrf, ts.URL, cs.ID, "apply")
	if cs.State != "awaiting_confirmation" || !cs.ManagementVerified || !cs.DataPlaneVerified {
		t.Fatalf("expected verified awaiting_confirmation, got %+v", cs)
	}
	cs = changeActionForTest(t, client, csrf, ts.URL, cs.ID, "confirm")
	if cs.State != "committed" || fake.callCount("commit") != 1 {
		t.Fatalf("commit was not completed through adapter: %+v calls=%v", cs, fake.calls)
	}
	ts.Close()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}

	srv2, err := NewServerWithOptions(cfg, Options{Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv2.Close()
	srv2.mu.Lock()
	persisted, ok := srv2.changes[cs.ID]
	srv2.mu.Unlock()
	if !ok || persisted.State != "committed" || srv2.configVersion != 2 || srv2.activeRevision != cs.RevisionID || srv2.currentConfig().Services["github"].Category != "GEO_LOCKED" {
		t.Fatalf("change was not persisted across reopen: %+v", persisted)
	}
	ts2 := httptest.NewServer(srv2.Handler())
	defer ts2.Close()
	client2, _ := login(t, ts2.URL)
	var revisions struct {
		Source         string           `json:"source"`
		Status         string           `json:"status"`
		ActiveRevision string           `json:"active_revision"`
		ConfigVersion  int64            `json:"config_version"`
		Items          []revisionRecord `json:"items"`
	}
	if err := json.Unmarshal(getAPIData(t, client2, ts2.URL+"/api/v1/revisions"), &revisions); err != nil {
		t.Fatal(err)
	}
	if revisions.Source != "bbolt" || revisions.Status != "OK" || revisions.ActiveRevision != cs.RevisionID || revisions.ConfigVersion != 2 || len(revisions.Items) != 1 || revisions.Items[0].RevisionID != cs.RevisionID {
		t.Fatalf("revision endpoint did not expose persisted commit: %+v", revisions)
	}
	var settings struct {
		Source         string `json:"source"`
		ActiveRevision string `json:"active_revision"`
		ConfigVersion  int64  `json:"config_version"`
	}
	if err := json.Unmarshal(getAPIData(t, client2, ts2.URL+"/api/v1/settings"), &settings); err != nil {
		t.Fatal(err)
	}
	if settings.Source != "active-config+bbolt" || settings.ActiveRevision != cs.RevisionID || settings.ConfigVersion != 2 {
		t.Fatalf("settings endpoint did not read active state: %+v", settings)
	}
}

func TestProbesEndpointReadsPersistedResultsAndRedactsIPs(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	result := probe.RouteResult{
		Domain: "example.com", Service: "example", Route: "direct", RouteType: "direct", Status: "OK",
		DNSResolver: "192.0.2.53:53", ResolvedIP: "192.0.2.10", ConnectedIP: "192.0.2.10", LocalIP: "192.0.2.20",
		ExternalIPHash: "sha256:kept", CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Checks: []probe.CheckResult{{Name: "https", DNSResolver: "192.0.2.53:53", ResolvedIPs: []string{"192.0.2.10"}, ConnectedIP: "192.0.2.10", LocalIP: "192.0.2.20"}},
	}
	if err := srv.store.StoreProbeResult(result); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, _ := login(t, ts.URL)
	var payload struct {
		Source string              `json:"source"`
		Status string              `json:"status"`
		Items  []probe.RouteResult `json:"items"`
	}
	if err := json.Unmarshal(getAPIData(t, client, ts.URL+"/api/v1/probes?domain=example.com"), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Source != "bbolt" || payload.Status != "OK" || len(payload.Items) != 1 {
		t.Fatalf("probe endpoint did not read persisted history: %+v", payload)
	}
	item := payload.Items[0]
	if item.ResolvedIP != "" || item.ConnectedIP != "" || item.LocalIP != "" || item.DNSResolver != "" || len(item.Checks[0].ResolvedIPs) != 0 || item.Checks[0].ConnectedIP != "" {
		t.Fatalf("probe endpoint exposed sensitive IP evidence: %+v", item)
	}
	if item.ExternalIPHash != result.ExternalIPHash {
		t.Fatalf("probe endpoint discarded safe egress hash: %+v", item)
	}
}

func TestBackupsEndpointReadsVerifiedStoreMetadata(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, _ := login(t, ts.URL)
	var payload struct {
		Source string `json:"source"`
		Status string `json:"status"`
		Items  []struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			SHA256    string `json:"sha256"`
			SizeBytes int64  `json:"size_bytes"`
		} `json:"items"`
	}
	if err := json.Unmarshal(getAPIData(t, client, ts.URL+"/api/v1/backups"), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Source != "bbolt+verified-files" || payload.Status != "OK" || len(payload.Items) == 0 || payload.Items[0].Status != "OK" || len(payload.Items[0].SHA256) != 64 || payload.Items[0].SizeBytes <= 0 {
		t.Fatalf("backup endpoint returned a stub or unverified data: %+v", payload)
	}
}

func TestSSEStream(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, _ := login(t, ts.URL)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/events/stream", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if epoch := resp.Header.Get("X-Event-Stream-Epoch"); epoch == "" {
		t.Fatal("SSE response did not expose a stream epoch")
	}
	done := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		deadline := time.After(2 * time.Second)
		for {
			select {
			case <-deadline:
				done <- ""
				return
			default:
				if sc.Scan() && strings.HasPrefix(sc.Text(), "event:") {
					done <- sc.Text()
					return
				}
			}
		}
	}()
	if line := <-done; line == "" {
		t.Fatal("no SSE event received")
	}
}

func TestLoginRequiresConfiguredAdmin(t *testing.T) {
	cfg := testAPIConfig(t)
	srv, err := NewServerWithOptions(cfg, Options{Provider: platform.NewOpenWrtProvider(), ProductionAdapter: newFakeAdapter()})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", strings.NewReader(`{"username":"admin","password":"AnythingLongEnough123"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("expected setup_required 428, got %d", resp.StatusCode)
	}
}

func TestUnknownAPIIsJSON404(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/v1/no-such-endpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("expected json content-type, got %s", ct)
	}
}

func login(t *testing.T, base string) (*http.Client, string) {
	t.Helper()
	client := &http.Client{}
	resp, err := client.Post(base+"/api/v1/auth/login", "application/json", strings.NewReader(`{"username":"admin","password":"CorrectHorse123!"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(env.Data)
	var session auth.PublicSession
	if err := json.Unmarshal(data, &session); err != nil {
		t.Fatal(err)
	}
	for _, c := range resp.Cookies() {
		client.Jar = nil
		if c.Name == "rp_session" {
			client.Transport = roundTripWithCookie{cookie: c}
		}
	}
	return client, session.CSRFToken
}

func getAPIData(t *testing.T, client *http.Client, endpoint string) json.RawMessage {
	t.Helper()
	resp, err := client.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned %d", endpoint, resp.StatusCode)
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data
}

func changeActionForTest(t *testing.T, client *http.Client, csrf, base, id, action string) ChangeSet {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/changes/"+id+"/"+action, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s status %d", action, resp.StatusCode)
	}
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(env.Data)
	var cs ChangeSet
	if err := json.Unmarshal(data, &cs); err != nil {
		t.Fatal(err)
	}
	return cs
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := testAPIConfig(t)
	store, err := auth.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := store.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetupAdmin("admin", "CorrectHorse123!", token); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServerWithOptions(cfg, Options{Auth: store, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(), Development: true})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

type roundTripWithCookie struct {
	cookie *http.Cookie
}

func (rt roundTripWithCookie) RoundTrip(req *http.Request) (*http.Response, error) {
	req.AddCookie(rt.cookie)
	return http.DefaultTransport.RoundTrip(req)
}

func testAPIConfig(t *testing.T) *config.Config {
	t.Helper()
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "diagnostics"), 0o700); err != nil {
		t.Fatal(err)
	}
	diagnostics := `{"status":"VERIFIED","source":"api-test-fixture","simulation":true,"wan_interface":"wan","lan_interfaces":["br-lan"],"ipv4_gateway":"192.0.2.1","ipv6_gateway":"2001:db8::1","ipv6_available":true,"transparent_proxy_mode":"tproxy","flow_offloading_status":"VERIFIED","software_flow_offloading":false,"hardware_flow_offloading":false,"collected_at":"2026-01-01T00:00:00Z","expires_at":"2999-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(tmp, "diagnostics", "network.json"), []byte(diagnostics), 0o600); err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		Version:  2,
		Platform: config.Platform{Target: "test"},
		Storage:  config.Storage{StateDir: tmp, RuntimeDir: tmp},
		Policy:   config.Policy{MaxProbeSeconds: 1},
		Xray:     config.Xray{ProbeDNSResolver: "1.1.1.1:53", TransparentPort: 12345},
		OpenWrt: config.OpenWrt{
			WANRouteTable: 100, ZapretRouteTable: 101, XrayRouteTable: 102,
			DirectMark: "0x41", ZapretMark: "0x42", XrayMark: "0x43", XrayTProxyMark: "0x100", XrayBypassMark: "0x200", DropMark: "0x7f",
		},
		Routes: []config.Route{
			{Type: "direct", Tag: "direct"},
			{Type: "smart_dns", Tag: "smart", DNSServer: "203.0.113.53:53", ConnectToResolvedIP: true},
			{Type: "drop", Tag: "drop"},
		},
		Services: map[string]config.Service{
			"github": {
				Category:     "DIRECT_PREFERRED",
				Domains:      []string{"github.com"},
				AllowedPaths: []string{"direct", "smart_dns", "drop"},
				ProbeURLs: []config.ProbeCheck{{
					Name: "web", URL: "https://github.com/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional",
				}},
			},
		},
	}
}
