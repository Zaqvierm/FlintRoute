package api

import (
	"path/filepath"
	"testing"

	"router-policy/internal/config"
)

func TestZapretProfileStatusUsesCatalogNamesAndDeclaredFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	writeAdaptiveCatalog(t, path)
	cfg := &config.Config{Zapret: config.Zapret{
		Strategy: "legacy-strategy", AdaptiveCatalogFile: path,
		AdaptiveAssignments: []config.ZapretProfileAssignment{{BundleID: "discord", ProfileID: "profile-a"}},
	}}
	active, fallback, assignments := zapretProfileStatus(cfg)
	if active["profile_id"] != "profile-a" || fallback["profile_id"] != "profile-b" || len(assignments) != 1 {
		t.Fatalf("unexpected profile status: active=%#v fallback=%#v assignments=%#v", active, fallback, assignments)
	}
}

func TestZapretProfileStatusDoesNotGuessMissingCatalog(t *testing.T) {
	active, fallback, assignments := zapretProfileStatus(&config.Config{Zapret: config.Zapret{AdaptiveAssignments: []config.ZapretProfileAssignment{{BundleID: "youtube", ProfileID: "missing"}}}})
	if active["profile_id"] != "missing" || active["available"] != false || len(assignments) != 1 || len(fallback) != 0 {
		t.Fatalf("missing catalog was guessed: active=%#v fallback=%#v assignments=%#v", active, fallback, assignments)
	}
}
