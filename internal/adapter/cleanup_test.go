package adapter

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"router-policy/internal/config"
)

func TestCleanupCommittedKeepsSmallJournalAndRemovesHeavyFiles(t *testing.T) {
	stateDir := t.TempDir()
	cfg := &config.Config{Storage: config.Storage{StateDir: stateDir}}
	root := filepath.Join(stateDir, "transactions", "rev-1", "tx-1")
	generated := filepath.Join(root, "generated")
	snapshot := filepath.Join(root, "snapshot")
	if err := os.MkdirAll(generated, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(snapshot, 0o700); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(root, "candidate.json")
	capability := filepath.Join(root, "rollback.cap")
	for _, path := range []string{candidate, capability, filepath.Join(generated, "artifact"), filepath.Join(snapshot, "state")} {
		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	journal := filepath.Join(root, "binding.json")
	if err := os.WriteFile(journal, []byte("journal"), 0o600); err != nil {
		t.Fatal(err)
	}
	tx := Transaction{ID: "tx-1", RevisionID: "rev-1", CandidatePath: candidate, CapabilityPath: capability, ArtifactRoot: generated}
	if err := CleanupCommitted(cfg, tx); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{capability, snapshot} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("heavy transaction path remains: %s", path)
		}
	}
	for _, path := range []string{candidate, generated} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("reboot verification artifact was removed: %s", path)
		}
	}
	if _, err := os.Stat(journal); err != nil {
		t.Fatal("small recovery journal was removed")
	}
}
