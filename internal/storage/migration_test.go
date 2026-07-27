package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMigrationPlanPreservesUnknownFilesAndClassifiesLegacyBackups(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	runtimeDir := filepath.Join(root, "runtime")
	legacyRoot := filepath.Join(root, "root")
	for _, path := range []string{filepath.Join(stateDir, "transactions", "old"), runtimeDir, filepath.Join(legacyRoot, "router-policy-backup-20260722")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	unknown := filepath.Join(stateDir, "user-file.txt")
	if err := os.WriteFile(unknown, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanMigration(stateDir, runtimeDir, legacyRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.DryRun || plan.AmbiguousItems != 1 {
		t.Fatalf("unexpected migration plan: %+v", plan)
	}
	foundLegacy := false
	for _, item := range plan.Items {
		if item.Path == unknown && item.Action != "skip" {
			t.Fatal("unknown user file was selected for mutation")
		}
		foundLegacy = foundLegacy || item.Class == "legacy-backup" && item.Action == "validate-and-register"
	}
	if !foundLegacy {
		t.Fatal("legacy backup was not classified")
	}
}

func TestMigrationRemovesOnlyValidatedStaleTSPUCandidate(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	runtimeDir := filepath.Join(root, "runtime")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "tspu-cache.json"), []byte(`{"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(stateDir, "tspu-cache.previous.json.tmp.test-run")
	unknown := filepath.Join(stateDir, "user.tmp.test-run")
	if err := os.WriteFile(stale, []byte(`{"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unknown, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanMigration(stateDir, runtimeDir, root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reclaimable == 0 {
		t.Fatalf("stale candidate was not reported: %+v", plan)
	}
	plan, err = ApplyMigration(stateDir, runtimeDir, root, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("validated stale candidate survived: %v", err)
	}
	if _, err := os.Lstat(unknown); err != nil {
		t.Fatalf("unknown file was touched: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "router-policy-backups")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty backup registry was created during unrelated cleanup: %v", err)
	}
}

func TestMigrationPreservesStaleTSPUCandidateWhenCurrentIsCorrupt(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "tspu-cache.json"), []byte(`{"entries":`), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(stateDir, "tspu-cache.json.tmp.test-run")
	if err := os.WriteFile(stale, []byte(`{"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := ApplyMigration(stateDir, filepath.Join(root, "runtime"), root, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if plan.AmbiguousItems == 0 {
		t.Fatalf("corrupt current cache was not reported: %+v", plan)
	}
	if _, err := os.Lstat(stale); err != nil {
		t.Fatalf("stale candidate was removed without a valid current cache: %v", err)
	}
}

func TestApplyMigrationRegistersVerifiedCopyBeforeRemovingLegacyBackup(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	runtimeDir := filepath.Join(root, "runtime")
	legacyRoot := filepath.Join(root, "root")
	legacy := filepath.Join(legacyRoot, "router-policy-backup-20260722")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "config.json"), []byte("verified"), 0o600); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(stateDir, "user-file.txt")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unknown, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := ApplyMigration(stateDir, runtimeDir, legacyRoot, time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC))
	if err != nil || plan.DryRun {
		t.Fatalf("migration failed: plan=%+v err=%v", plan, err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy source remains after verified migration: %v", err)
	}
	target := filepath.Join(legacyRoot, "router-policy-backups", filepath.Base(legacy))
	manifest, err := loadAndVerifyManifest(target)
	if err != nil || !manifest.Verified || manifest.TotalSize == 0 {
		t.Fatalf("migrated backup is not verified: manifest=%+v err=%v", manifest, err)
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatal("unknown persistent file was touched")
	}
}

func TestMigrationRetentionUsesLegacyTimestampsAndBoundsBackups(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	runtimeDir := filepath.Join(root, "runtime")
	for _, stamp := range []string{"20260719T003006Z", "20260720T003006Z", "20260721T003006Z"} {
		path := filepath.Join(root, "router-policy-backup-"+stamp)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "config.json"), []byte(stamp), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := ApplyMigration(stateDir, runtimeDir, root, time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Retention == nil || plan.Retention.TotalAfter == 0 {
		t.Fatalf("migration did not apply bounded retention: %+v", plan.Retention)
	}
	registry := filepath.Join(root, "router-policy-backups")
	entries, err := os.ReadDir(registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected two newest verified fallbacks, got %d", len(entries))
	}
	for _, expected := range []string{"router-policy-backup-20260720T003006Z", "router-policy-backup-20260721T003006Z"} {
		if _, err := os.Stat(filepath.Join(registry, expected)); err != nil {
			t.Fatalf("newest fallback %s was not retained: %v", expected, err)
		}
	}
}

func TestApplyMigrationKeepsUnverifiableLegacyBackup(t *testing.T) {
	root := t.TempDir()
	legacyRoot := filepath.Join(root, "root")
	legacy := filepath.Join(legacyRoot, "router-policy-uninstall-backup-empty")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyMigration(filepath.Join(root, "state"), filepath.Join(root, "runtime"), legacyRoot, time.Now().UTC()); err == nil {
		t.Fatal("empty legacy backup was accepted")
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatal("unverifiable legacy backup was removed")
	}
}
