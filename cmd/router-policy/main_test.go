package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-policy/internal/auth"
	"router-policy/internal/config"
	"router-policy/internal/state"
	"router-policy/internal/tspu"
)

func TestSetupTokenIfNeededIsIdempotentAfterAdminCreation(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "config", "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.Platform.Target = "test"
	cfg.Storage.StateDir = dir
	cfg.Storage.RuntimeDir = filepath.Join(dir, "runtime")
	cfg.Storage.Database = filepath.Join(dir, "state.bbolt")
	configPath := filepath.Join(dir, "config.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := auth.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := store.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetupAdmin("admin", "correct horse battery staple", token); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ROUTER_POLICY_CONFIG", configPath)
	if err := run([]string{"auth", "setup-token", "--if-needed"}); err != nil {
		t.Fatalf("idempotent setup-token failed after admin creation: %v", err)
	}
	if err := run([]string{"auth", "setup-token"}); err == nil {
		t.Fatal("setup-token without --if-needed must still reject an initialized store")
	}
}

func TestLoadRuntimeConfigUsesFactoryTSPUSourcesForUpgradedConfig(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "config", "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	active := *cfg
	active.TSPUSources = nil
	activeRaw, err := json.Marshal(active)
	if err != nil {
		t.Fatal(err)
	}
	factoryRaw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(dir, "default.json")
	if err := os.WriteFile(activePath, activeRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "factory-default.json"), factoryRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadRuntimeConfig(activePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.TSPUSources) != len(cfg.TSPUSources) || len(loaded.TSPUSources) == 0 {
		t.Fatalf("factory TSPU sources were not inherited: got=%d want=%d", len(loaded.TSPUSources), len(cfg.TSPUSources))
	}
}

func TestSafeListenAddress(t *testing.T) {
	ok := []string{"127.0.0.1:8787", "localhost:8787", "[::1]:8787"}
	for _, addr := range ok {
		if !safeListenAddress(addr) {
			t.Fatalf("expected %s to be safe", addr)
		}
	}
	bad := []string{"0.0.0.0:8787", ":8787", "192.168.8.1:8787", "bad"}
	for _, addr := range bad {
		if safeListenAddress(addr) {
			t.Fatalf("expected %s to be unsafe", addr)
		}
	}
}

func TestServeRefusesUnsafeBind(t *testing.T) {
	t.Setenv("ROUTER_POLICY_ALLOW_UNSAFE_LAN_BIND", "")
	err := run([]string{"serve", "--listen", "0.0.0.0:8787"})
	if err == nil || !strings.Contains(err.Error(), "refusing non-loopback") {
		t.Fatalf("expected unsafe bind refusal, got %v", err)
	}
}

func TestLoadCLIActiveConfigUsesCommittedBboltState(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "config", "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.Platform.Target = "test"
	cfg.Storage.StateDir = dir
	cfg.Storage.Database = filepath.Join(dir, "state.bbolt")
	cfg.Storage.RuntimeDir = filepath.Join(dir, "runtime")
	store, err := state.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	active := *cfg
	active.Routes = append([]config.Route(nil), cfg.Routes...)
	active.Routes[0].Priority = 77
	if err := store.SaveBatch(
		state.Entry{Bucket: "meta", Key: "active_config", Value: &active},
		state.Entry{Bucket: "meta", Key: "active_revision", Value: "rev-committed"},
	); err != nil {
		t.Fatal(err)
	}
	loaded, revision, err := loadCLIActiveConfig(store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if revision != "rev-committed" || loaded.Routes[0].Priority != 77 {
		t.Fatalf("CLI ignored committed state: revision=%q config=%+v", revision, loaded.Routes[0])
	}
}

func TestTSPUMatchForDomainReportsUnavailableMatchAndStaleMatch(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Storage: config.Storage{StateDir: dir}}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

	unavailable, err := tspuMatchForDomain(cfg, "example.com", false, now)
	if err != nil {
		t.Fatal(err)
	}
	if unavailable.Status != "UNAVAILABLE" {
		t.Fatalf("missing cache was reported as a clean miss: %+v", unavailable)
	}

	report := tspu.SourceReport{Name: "source-one", Type: "domains", Accepted: true, Fresh: true, Confidence: 0.9}
	cache := tspu.BuildCache(now, time.Hour, []tspu.SourceReport{report}, map[string][]string{"source-one": {"*.example.com"}})
	if err := tspu.Save(filepath.Join(dir, "tspu-cache.json"), cache); err != nil {
		t.Fatal(err)
	}
	fresh, err := tspuMatchForDomain(cfg, "api.example.com", false, now.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Status != "MATCH" || fresh.Matched != "*.example.com" {
		t.Fatalf("fresh match not returned: %+v", fresh)
	}
	stale, err := tspuMatchForDomain(cfg, "api.example.com", false, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if stale.Status != "STALE_MATCH" {
		t.Fatalf("expired match was treated as fresh: %+v", stale)
	}
}

func TestTSPUMatchForDomainRejectsCorruptCache(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Storage: config.Storage{StateDir: dir}}
	if err := os.WriteFile(filepath.Join(dir, "tspu-cache.json"), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tspuMatchForDomain(cfg, "example.com", false, time.Now()); err == nil {
		t.Fatal("corrupt TSPU cache must not silently become NO_MATCH")
	}
}

func TestParseZapretPorts(t *testing.T) {
	ports, err := parseZapretPorts("80, 443")
	if err != nil || len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Fatalf("unexpected ports: %v err=%v", ports, err)
	}
	for _, raw := range []string{"", "0", "443,", "65536", "https"} {
		if _, err := parseZapretPorts(raw); err == nil {
			t.Fatalf("invalid port list %q was accepted", raw)
		}
	}
}
