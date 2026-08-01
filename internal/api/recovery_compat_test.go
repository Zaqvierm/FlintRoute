package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"router-policy/internal/config"
	"router-policy/internal/platform"
)

func TestRestartPreservesLegacyExternalSOCKSCommittedHash(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Routes = append(cfg.Routes, config.Route{
		Type: "tg_ws_proxy", Tag: "tg-ws-proxy", Disabled: true, Status: "NOT_CONFIGURED",
		SOCKS5: "127.0.0.1:1180", DNSMode: "socks_remote",
	})
	service := cfg.Services["github"]
	service.AllowedPaths = append(service.AllowedPaths, "tg_ws_proxy")
	cfg.Services["github"] = service

	fake := newFakeAdapter()
	srv, ts, client, csrf, authStore := newTransactionHTTP(t, cfg, fake)
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusOK || cs.State != "awaiting_confirmation" {
		t.Fatalf("apply status=%d change=%+v", status, cs)
	}
	cs, status = postAction(t, client, csrf, ts.URL, cs.ID, "confirm", `{}`)
	if status != http.StatusOK || cs.State != "committed" {
		t.Fatalf("confirm status=%d change=%+v", status, cs)
	}
	committedHash := cs.CandidateHash
	ts.Close()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}

	restartAdapter := newFakeAdapter()
	srv2, err := NewServerWithOptions(cfg, Options{
		Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: restartAdapter, Development: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv2.Close()
	if recovery := srv2.currentRecoveryStatus(); recovery.Status != "ok" {
		t.Fatalf("legacy committed revision was rejected during recovery: %+v", recovery)
	}
	if got := restartAdapter.callCount("reconcile"); got != 1 {
		t.Fatalf("committed dataplane was not reconciled exactly once: %d", got)
	}
	canonical, err := json.Marshal(srv2.currentConfig())
	if err != nil {
		t.Fatal(err)
	}
	if got := hashBytes(canonical); got != committedHash {
		t.Fatalf("restart changed committed config hash: %s != %s", got, committedHash)
	}
	legacyFound := false
	for _, route := range srv2.currentConfig().Routes {
		if route.Type == "tg_ws_proxy" && route.Tag == "tg-ws-proxy" {
			legacyFound = true
		}
	}
	if !legacyFound {
		t.Fatal("legacy route was silently rewritten outside a ChangeSet")
	}
}
