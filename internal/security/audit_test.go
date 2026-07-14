package security

import (
	"testing"

	"router-policy/internal/config"
)

func TestAuditFailsWithoutAuthStore(t *testing.T) {
	cfg := auditConfig(t)
	report := Audit(cfg)
	if !hasCheck(report, "auth-users", "fail") {
		t.Fatalf("expected auth-users fail, got %+v", report.Checks)
	}
	if report.Status != "fail" {
		t.Fatalf("expected fail summary, got %s", report.Status)
	}
}

func TestAuditDetectsGeoLockedDirectLeak(t *testing.T) {
	cfg := auditConfig(t)
	cfg.Policy.GeoLockedAllowDirect = true
	cfg.Routes = append(cfg.Routes, config.Route{Type: "direct", Tag: "direct"})
	cfg.Services = map[string]config.Service{
		"geo": {Category: "GEO_LOCKED", Domains: []string{"geo.test"}, AllowedPaths: []string{"direct"}},
	}
	report := Audit(cfg)
	if !hasCheck(report, "geo-locked-policy", "fail") {
		t.Fatalf("expected geo-locked-policy fail, got %+v", report.Checks)
	}
}

func hasCheck(report AuditReport, id, status string) bool {
	for _, check := range report.Checks {
		if check.ID == id && check.Status == status {
			return true
		}
	}
	return false
}

func auditConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Version:  2,
		Storage:  config.Storage{StateDir: t.TempDir()},
		Policy:   config.Policy{},
		Routes:   []config.Route{{Type: "smart_dns", Tag: "smart"}},
		Services: map[string]config.Service{},
	}
}
