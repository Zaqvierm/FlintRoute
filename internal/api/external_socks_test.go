package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"router-policy/internal/auth"
	"router-policy/internal/config"
	"router-policy/internal/externalsocks"
	"router-policy/internal/platform"
)

type readyExternalSOCKSChecker struct{}

func (readyExternalSOCKSChecker) Check(_ context.Context, request externalsocks.CheckRequest) (externalsocks.CheckReport, error) {
	return externalsocks.CheckReport{Ready: true, Endpoint: request.Endpoint, TestDomain: request.TestDomain, Dependency: "external_socks", ManagedBy: "external", TCPReachable: true, SOCKS5Handshake: true, RemoteConnect: true, TLSVerified: true, HTTPStatus: http.StatusNoContent}, nil
}

func TestExternalSOCKSCheckIsReadOnlyAndActivateCreatesOneChangeSet(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Xray.ProbeDNSResolver = "1.1.1.1:53"
	cfg.Xray.TransparentPort = 12345
	cfg.Xray.InitScript = "/etc/init.d/router-policy-xray"
	cfg.Routes = append(cfg.Routes, config.Route{Type: "external_socks", Tag: "external-socks", Disabled: true, Status: "NOT_CONFIGURED", SOCKS5: "127.0.0.1:1180", DNSMode: "socks_remote"})
	store, err := auth.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	setupToken, _, err := store.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetupAdmin("admin", "CorrectHorse123!", setupToken); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServerWithOptions(cfg, Options{Auth: store, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(), ExternalSOCKSChecker: readyExternalSOCKSChecker{}, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()
	client, csrf := login(t, httpServer.URL)
	payload := []byte(`{"base_version":1,"endpoint":"127.0.0.1:1180","test_domain":"web.telegram.org"}`)
	post := func(path string) []byte {
		request, _ := http.NewRequest(http.MethodPost, httpServer.URL+path, bytes.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("%s failed: status=%d err=%v", path, response.StatusCode, err)
		}
		return envelope.Data
	}
	post("/api/v1/external-socks/check")
	if len(srv.changes) != 0 {
		t.Fatalf("preflight created a ChangeSet: %d", len(srv.changes))
	}
	raw := post("/api/v1/external-socks/activate")
	var result struct {
		Change ChangeSet `json:"change"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(srv.changes) != 1 || len(result.Change.Operations) != 3 {
		t.Fatalf("activation did not create one three-part ChangeSet: changes=%d ops=%d", len(srv.changes), len(result.Change.Operations))
	}
}

func TestExternalSOCKSSetupBuildsRouteAndServiceWithoutMutatingActiveConfig(t *testing.T) {
	active := testAPIConfig(t)
	active.Xray.ProbeDNSResolver = "1.1.1.1:53"
	active.Routes = append(active.Routes, config.Route{Type: "external_socks", Tag: "external-socks", Disabled: true, Status: "NOT_CONFIGURED", SOCKS5: "127.0.0.1:1180", DNSMode: "socks_remote"})
	routes, err := routesForExternalSOCKS(active, "127.0.0.1:1181")
	if err != nil {
		t.Fatal(err)
	}
	if routes[len(routes)-1].Disabled || routes[len(routes)-1].SOCKS5 != "127.0.0.1:1181" || active.Routes[len(active.Routes)-1].SOCKS5 != "127.0.0.1:1180" {
		t.Fatalf("external SOCKS route update is not isolated: active=%+v candidate=%+v", active.Routes[len(active.Routes)-1], routes[len(routes)-1])
	}
	services, err := servicesForExternalSOCKSTest(active, "web.telegram.org")
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != len(active.Services)+1 || len(active.Services) != 1 {
		t.Fatalf("service candidate mutated active config: active=%d candidate=%d", len(active.Services), len(services))
	}
}
