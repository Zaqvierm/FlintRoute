package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-policy/internal/auth"
	"router-policy/internal/config"
	"router-policy/internal/state"
	"router-policy/internal/tspu"
	"router-policy/internal/zapret"
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
	cfg.Platform.Target = "test"
	active := *cfg
	active.TSPUSources = nil
	active.Storage.StateDir = dir
	active.Storage.RuntimeDir = filepath.Join(dir, "runtime")
	active.Storage.Database = filepath.Join(dir, "state.bbolt")
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
	bad := []string{"0.0.0.0:8787", ":8787", "192.168.8.1:8787", "127.0.0.1:0", "127.0.0.1:bad", "bad"}
	for _, addr := range bad {
		if safeListenAddress(addr) {
			t.Fatalf("expected %s to be unsafe", addr)
		}
	}
}

func TestServeRefusesUnsafeBind(t *testing.T) {
	t.Setenv("ROUTER_POLICY_ALLOW_FIREWALLED_BIND", "")
	err := run([]string{"serve", "--listen", "0.0.0.0:8787"})
	if err == nil || !strings.Contains(err.Error(), "refusing non-loopback") {
		t.Fatalf("expected unsafe bind refusal, got %v", err)
	}
}

func TestManualImportWritesRedactedPlanWithoutApplyPermission(t *testing.T) {
	dir := t.TempDir()
	xrayPath := filepath.Join(dir, "xray.json")
	planPath := filepath.Join(dir, "adoption-plan.json")
	const uuid = "11111111-1111-4111-8111-111111111111"
	raw := `{
  "inbounds": [{"tag":"socks-proxy-1","listen":"127.0.0.1","port":12000,"protocol":"socks"}],
  "outbounds": [{"tag":"proxy-1","protocol":"vless","settings":{"vnext":[{"address":"vc9.example.com","port":443,"users":[{"id":"` + uuid + `","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}],
  "routing":{"rules":[{"type":"field","inboundTag":["socks-proxy-1"],"outboundTag":"proxy-1"}]}
}`
	if err := os.WriteFile(xrayPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"manual-import", "--xray", xrayPath, "--out-plan", planPath}); err != nil {
		t.Fatalf("manual-import failed: %v", err)
	}
	planRaw, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	var plan struct {
		MigrationState string `json:"migration_state"`
		ApplyAllowed   bool   `json:"apply_allowed"`
	}
	if err := json.Unmarshal(planRaw, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.MigrationState != "blocked_on_ownership_handoff" || plan.ApplyAllowed {
		t.Fatalf("manual adoption plan was not fenced: %+v", plan)
	}
	if strings.Contains(string(planRaw), xrayPath) || strings.Contains(string(planRaw), uuid) {
		t.Fatal("redacted adoption plan leaked an input path or credential")
	}
	if info, err := os.Stat(planPath); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("adoption plan mode = %o, want 600", info.Mode().Perm())
	}
}

func TestFirewalledBindRequiresExplicitOptIn(t *testing.T) {
	t.Setenv("ROUTER_POLICY_ALLOW_FIREWALLED_BIND", "1")
	for _, addr := range []string{"0.0.0.0:8787", "192.168.8.1:8787", "[::]:8787"} {
		if !allowedListenAddress(addr) {
			t.Fatalf("expected explicit firewalled bind %s to be allowed", addr)
		}
	}
	for _, addr := range []string{":8787", "0.0.0.0:0", "0.0.0.0:bad", "bad"} {
		if allowedListenAddress(addr) {
			t.Fatalf("expected invalid bind %s to be rejected", addr)
		}
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

func TestLoadRuntimeConfigIgnoresUncommittedBootstrapCandidate(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "config", "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.Platform.Target = "test"
	cfg.Storage.StateDir = dir
	cfg.Storage.Database = filepath.Join(dir, "state.bbolt")
	cfg.Storage.RuntimeDir = filepath.Join(dir, "runtime")
	bootstrapPath := filepath.Join(dir, "default.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bootstrapPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	active := cfg
	active.Routes = append([]config.Route(nil), cfg.Routes...)
	active.Routes[0].Priority = 91
	if err := store.SaveBatch(
		state.Entry{Bucket: "meta", Key: "active_config", Value: &active},
		state.Entry{Bucket: "meta", Key: "active_revision", Value: "rev-active"},
	); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadRuntimeConfig(bootstrapPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Routes[0].Priority != 91 {
		t.Fatalf("runtime loaded bootstrap instead of committed active config: priority=%d", loaded.Routes[0].Priority)
	}
}

func TestLoadRuntimeConfigRefusesMissingCommittedActiveConfig(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "config", "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.Platform.Target = "test"
	cfg.Storage.StateDir = dir
	cfg.Storage.RuntimeDir = filepath.Join(dir, "runtime")
	cfg.Storage.Database = filepath.Join(dir, "state.bbolt")
	bootstrapPath := filepath.Join(dir, "default.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bootstrapPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveJSON("meta", "active_revision", "rev-committed"); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = loadRuntimeConfig(bootstrapPath)
	var rescue *state.RescueError
	if !errors.As(err, &rescue) {
		t.Fatalf("missing committed active config was not fenced: %v", err)
	}
}

func TestLoadRuntimeConfigRefusesCorruptCommittedActiveConfig(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "config", "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.Platform.Target = "test"
	cfg.Storage.StateDir = dir
	cfg.Storage.RuntimeDir = filepath.Join(dir, "runtime")
	cfg.Storage.Database = filepath.Join(dir, "state.bbolt")
	bootstrapPath := filepath.Join(dir, "default.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bootstrapPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveBatch(
		state.Entry{Bucket: "meta", Key: "active_revision", Value: "rev-committed"},
		state.Entry{Bucket: "meta", Key: "active_config", Value: map[string]any{"not": "a config"}},
	); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = loadRuntimeConfig(bootstrapPath)
	var rescue *state.RescueError
	if !errors.As(err, &rescue) {
		t.Fatalf("corrupt committed active config was not fenced: %v", err)
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

func TestZapretBlockcheckImportWritesValidatedCatalog(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "blockcheck.log")
	binary := filepath.Join(dir, "nfqws")
	catalog := filepath.Join(dir, "adaptive-catalog.json")
	if err := os.WriteFile(report, []byte("curl_test_https_tls12 ipv4 alpha.example : nfqws --dpi-desync=fake --dpi-desync-ttl=3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("reviewed-test-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := run([]string{
		"zapret-blockcheck-import", "--report", report, "--binary", binary,
		"--provider-version", "72.12", "--queue", "200", "--domain", "alpha.example",
		"--bundle-id", "auto-alpha", "--catalog-out", catalog,
	})
	if err != nil {
		t.Fatal(err)
	}
	profiles, bundles, err := zapret.LoadCatalogFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if profiles.Len() != 1 || bundles.Len() != 1 {
		t.Fatalf("written catalog is incomplete: profiles=%d bundles=%d", profiles.Len(), bundles.Len())
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
