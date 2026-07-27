package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupRetentionKeepsNewestVerifiedFallbacksAndIsBounded(t *testing.T) {
	registry := filepath.Join(t.TempDir(), "router-policy-backups")
	if err := os.MkdirAll(registry, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 22, 9, 0, 0, 0, time.UTC)
	for index := 0; index < 5; index++ {
		id := fmt.Sprintf("install-%d", index)
		root := filepath.Join(registry, id)
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "config.tar"), []byte(fmt.Sprintf("backup-%d", index)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := RegisterDirectory(root, id, "0.2.0-alpha.1", "install", "installer-fallback", now.Add(time.Duration(index)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	dry, err := PlanRetention(registry, 2, 1024, false)
	if err != nil || !dry.DryRun {
		t.Fatalf("dry-run failed: %+v err=%v", dry, err)
	}
	for _, action := range dry.Actions {
		if action.Action == "delete" {
			if _, err := os.Stat(action.Path); err != nil {
				t.Fatal("dry-run deleted a backup")
			}
		}
	}
	applied, err := PlanRetention(registry, 2, 1024, true)
	if err != nil {
		t.Fatal(err)
	}
	kept := 0
	for _, action := range applied.Actions {
		if action.Action == "keep" {
			kept++
			if _, err := os.Stat(action.Path); err != nil {
				t.Fatal("verified fallback was removed")
			}
		} else if action.Action == "delete" {
			if _, err := os.Stat(action.Path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("old verified backup remains")
			}
		}
	}
	if kept != 2 {
		t.Fatalf("kept %d backups, want 2", kept)
	}
}

func TestCorruptNewBackupCannotReplaceKnownGood(t *testing.T) {
	registry := filepath.Join(t.TempDir(), "router-policy-backups")
	good := filepath.Join(registry, "install-good")
	bad := filepath.Join(registry, "install-bad")
	for _, root := range []string{good, bad} {
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "config.tar"), []byte(root), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RegisterDirectory(good, "install-good", "alpha", "install", "installer-fallback", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterDirectory(bad, "install-bad", "alpha", "install", "installer-fallback", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "config.tar"), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanRetention(registry, 1, 1024, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(good); err != nil {
		t.Fatal("known-good backup was removed because a newer backup was corrupt")
	}
	foundSkip := false
	for _, action := range plan.Actions {
		foundSkip = foundSkip || action.OperationID == "install-bad" && action.Action == "skip"
	}
	if !foundSkip {
		t.Fatalf("corrupt backup was not reported: %+v", plan)
	}
}
