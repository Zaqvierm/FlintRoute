package watchdog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMaintenanceLeaseExpiresAndCannotDisableWatchdogForever(t *testing.T) {
	now := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "inhibit.json")
	lease, err := WriteInhibit(path, "installer:upgrade-1", "upgrade", now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, active, err := ReadInhibit(path, now.Add(9*time.Minute)); err != nil || !active {
		t.Fatalf("valid inhibit was ignored: active=%v err=%v", active, err)
	}
	if _, active, err := ReadInhibit(path, lease.ExpiresAt); err != nil || active {
		t.Fatalf("expired inhibit remained active: active=%v err=%v", active, err)
	}
}

func TestWatchdogRespectsStartupAndIntentionalMaintenance(t *testing.T) {
	now := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	controller := Controller{StartedAt: now, StartupGrace: time.Minute, FailureThreshold: 3}
	if got := controller.Observe(now.Add(30*time.Second), false, false); got.Action != "startup-grace" {
		t.Fatalf("got %+v", got)
	}
	if got := controller.Observe(now.Add(2*time.Minute), false, true); got.Action != "inhibited" {
		t.Fatalf("got %+v", got)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		got := controller.Observe(now.Add(3*time.Minute), false, false)
		if attempt < 3 && got.Action != "wait" {
			t.Fatalf("attempt %d: %+v", attempt, got)
		}
		if attempt == 3 && got.Action != "restart" {
			t.Fatalf("attempt %d: %+v", attempt, got)
		}
	}
}

func TestInhibitRefusesSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "inhibit.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := WriteInhibit(link, "installer:1", "upgrade", time.Now(), time.Minute); err == nil {
		t.Fatal("symlink target was accepted")
	}
}
