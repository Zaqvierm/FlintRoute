package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"router-policy/internal/config"
)

func TestRoutesSeparateSystemManagedDirectAndUnclassified(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	recorder := httptest.NewRecorder()
	srv.handleRoutes(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("routes status=%d", recorder.Code)
	}
	var envelope Envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(envelope.Data)
	var items []map[string]any
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatal(err)
	}
	byType := map[string]map[string]any{}
	for _, item := range items {
		byType[item["type"].(string)] = item
	}
	if byType["system_default"]["owner"] != "openwrt" || byType["system_default"]["managed"] != false {
		t.Fatalf("system default route is ambiguous: %+v", byType["system_default"])
	}
	if byType["direct"]["owner"] != "flintroute" || byType["direct"]["scope"] == "" {
		t.Fatalf("managed Direct is ambiguous: %+v", byType["direct"])
	}
	if byType["unclassified"]["effective_path"] != "system-default" || byType["unclassified"]["managed"] != false {
		t.Fatalf("unclassified traffic is ambiguous: %+v", byType["unclassified"])
	}
	if byType["smart_dns"]["vpn"] != false || byType["smart_dns"]["kind"] != "conditional_dns" {
		t.Fatalf("Smart DNS is presented as a tunnel: %+v", byType["smart_dns"])
	}
}

func TestRoutesDoNotClaimManagedDirectOnEmptyBaseline(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	srv.mu.Lock()
	baseline := *srv.activeConfig
	baseline.Services = map[string]config.Service{}
	baseline.Overrides = nil
	srv.activeConfig = &baseline
	srv.mu.Unlock()

	recorder := httptest.NewRecorder()
	srv.handleRoutes(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil))
	var envelope Envelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(envelope.Data)
	var items []map[string]any
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item["type"] == "direct" {
			if item["managed"] != false || item["available"] != true || item["status"] != "NO_MANAGED_POLICIES" {
				t.Fatalf("empty baseline claims managed Direct: %+v", item)
			}
			return
		}
	}
	t.Fatal("Direct route is missing")
}
