package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadHotplugEventsBoundsQueueAndReturnsLatest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hotplug-events.log")
	var lines []string
	for i := 0; i < 200; i++ {
		lines = append(lines, "2026-08-22T00:00:00Z\tinterface\tifupdate\tlan"+string(rune('a'+i%26)))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	latest, count, digest, err := readHotplugEvents(path)
	if err != nil {
		t.Fatal(err)
	}
	if count > hotplugEventMaxLines || count == 0 {
		t.Fatalf("unexpected bounded event count: %d", count)
	}
	if latest == "" || digest == "" {
		t.Fatalf("missing latest event or digest: latest=%q digest=%q", latest, digest)
	}
}

func TestReadHotplugEventsReportsMissingFile(t *testing.T) {
	_, _, _, err := readHotplugEvents(filepath.Join(t.TempDir(), "missing.log"))
	if !os.IsNotExist(err) {
		t.Fatalf("expected missing event file, got %v", err)
	}
}
