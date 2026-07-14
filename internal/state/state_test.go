package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/probe"

	bolt "go.etcd.io/bbolt"
)

func TestStorePersistsJSONAcrossReopen(t *testing.T) {
	cfg := &config.Config{Storage: config.Storage{StateDir: t.TempDir()}}
	store, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if store.Mode() != "bbolt" {
		t.Fatalf("expected bbolt mode, got %s", store.Mode())
	}
	if err := store.SaveJSON("changes", "chg_1", map[string]any{"state": "validated"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutInt64("config_version", 7); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var row map[string]string
	if err := store.LoadJSON("changes", "chg_1", &row); err != nil {
		t.Fatal(err)
	}
	if row["state"] != "validated" {
		t.Fatalf("unexpected row: %+v", row)
	}
	version, err := store.GetInt64("config_version", 1)
	if err != nil {
		t.Fatal(err)
	}
	if version != 7 {
		t.Fatalf("expected version 7, got %d", version)
	}
}

func TestMigratesLegacyDatabaseWithoutSchemaVersion(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "legacy.bbolt")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("changes"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("legacy"), []byte(`{"state":"draft"}`))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(&config.Config{Storage: config.Storage{StateDir: tmp, Database: path}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if version, err := store.SchemaVersion(); err != nil || version != CurrentSchemaVersion {
		t.Fatalf("migration version=%d err=%v", version, err)
	}
	if _, err := store.GetRaw("changes", "legacy"); err != nil {
		t.Fatal("migration lost legacy data:", err)
	}
}

func TestSchemaRetentionAndCompactBackup(t *testing.T) {
	tmp := t.TempDir()
	cfg := &config.Config{Storage: config.Storage{
		StateDir: tmp, Database: filepath.Join(tmp, "state.bbolt"), MaxProbeResults: 2,
		EventRetentionDays: 1, ChangeSetRetentionDays: 1, TransactionRetentionDays: 1,
	}}
	store, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if version, err := store.SchemaVersion(); err != nil || version != CurrentSchemaVersion {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
	for i := 0; i < 3; i++ {
		result := probe.RouteResult{Route: "direct", CheckedAt: time.Now().UTC().Add(time.Duration(i) * time.Second).Format(time.RFC3339)}
		if err := store.StoreProbeResult(result); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := store.ListRaw("probes")
	if err != nil || len(rows) != 2 {
		t.Fatalf("probe retention len=%d err=%v", len(rows), err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	if err := store.SaveJSON("events", "old", map[string]any{"time": old}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveJSON("changes", "old", map[string]any{"state": "committed", "updated_at": old}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveJSON("transactions", "old", map[string]any{"state": "rolled_back", "completed_at": old}); err != nil {
		t.Fatal(err)
	}
	stats, err := store.Cleanup(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Events != 1 || stats.ChangeSets != 1 || stats.Transactions != 1 {
		t.Fatalf("bad cleanup stats: %+v", stats)
	}
	backup := filepath.Join(tmp, "backups", "compact.bbolt")
	if err := store.Backup(backup, true); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(backup); err != nil || info.Size() == 0 {
		t.Fatalf("invalid backup info=%v err=%v", info, err)
	}
}

func TestListProbeResultsReturnsNewestFirstAndHonorsLimit(t *testing.T) {
	store, err := Open(&config.Config{Storage: config.Storage{StateDir: t.TempDir(), MaxProbeResults: 10}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	for i, route := range []string{"direct", "smart", "vless"} {
		if err := store.StoreProbeResult(probe.RouteResult{Route: route, CheckedAt: base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := store.ListProbeResults(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Route != "vless" || items[1].Route != "smart" {
		t.Fatalf("probe history is not newest-first and bounded: %+v", items)
	}
}

func TestBackupMetadataSurvivesRestartAndDetectsCorruption(t *testing.T) {
	tmp := t.TempDir()
	cfg := &config.Config{Storage: config.Storage{StateDir: tmp, Database: filepath.Join(tmp, "state.bbolt"), BackupIntervalHours: 24}}
	store, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if store != nil {
			_ = store.Close()
		}
	})
	if err := store.Maintain(time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	items, err := store.ListBackups(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Status != "OK" || len(items[0].SHA256) != 64 || items[0].SizeBytes <= 0 {
		t.Fatalf("backup metadata was not created and verified: %+v", items)
	}
	backupPath := filepath.Join(tmp, "backups", items[0].ID)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	items, err = store.ListBackups(10)
	if err != nil || len(items) != 1 || items[0].Status != "OK" {
		t.Fatalf("backup metadata did not survive restart: items=%+v err=%v", items, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	file, err := os.OpenFile(backupPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("CORRUPTED"), 64); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	items, err = store.ListBackups(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Status != "ERROR" || items[0].ReasonCode != "backup_hash_mismatch" {
		t.Fatalf("corrupted backup was not rejected: %+v", items)
	}
}

func TestRouteHealthPersistsAcrossRestart(t *testing.T) {
	tmp := t.TempDir()
	cfg := &config.Config{Storage: config.Storage{StateDir: tmp, Database: filepath.Join(tmp, "state.bbolt")}}
	store, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	expected := probe.RouteHealth{RouteTag: "smart-primary", RouteType: "smart_dns", State: "unhealthy", Score: 10, ConsecutiveErrors: 3, UpdatedAt: time.Now().UTC()}
	if err := store.SaveRouteHealth(expected); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	health, err := store.ListRouteHealth()
	if err != nil {
		t.Fatal(err)
	}
	if len(health) != 1 || health[0].RouteTag != expected.RouteTag || health[0].ConsecutiveErrors != 3 || health[0].State != "unhealthy" {
		t.Fatalf("route health did not survive restart: %+v", health)
	}
}

func TestMaintainPrunesBackupsAndCompactsActiveDatabase(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "state.bbolt")
	cfg := &config.Config{Storage: config.Storage{
		StateDir: tmp, Database: path, BackupIntervalHours: 1, CompactIntervalDays: 1,
		MaxStateBackups: 2, MaxDatabaseBytes: 1,
	}}
	store, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 3; i++ {
		if err := store.SaveJSON("events", time.Date(2026, 1, i+1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339), map[string]any{
			"time": base.Format(time.RFC3339), "payload": strings.Repeat("x", 32*1024),
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.Maintain(base.Add(time.Duration(i)*25*time.Hour + time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	backupEntries, err := os.ReadDir(filepath.Join(tmp, "backups"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range backupEntries {
		if strings.HasPrefix(entry.Name(), "router-policy-") && strings.HasSuffix(entry.Name(), ".bbolt") {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("backup retention kept %d files instead of 2", count)
	}
	metadata, err := store.ListBackups(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata) != 2 {
		t.Fatalf("backup retention kept %d metadata rows instead of 2", len(metadata))
	}
	var compactedAt time.Time
	if err := store.LoadJSON("meta", "last_active_compact_at", &compactedAt); err != nil || compactedAt.IsZero() {
		t.Fatalf("active database compaction was not recorded: time=%v err=%v", compactedAt, err)
	}
	if err := store.SaveJSON("meta", "after_compaction", "persisted"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var value string
	if err := reopened.LoadJSON("meta", "after_compaction", &value); err != nil || value != "persisted" {
		t.Fatalf("active compact swap lost state: value=%q err=%v", value, err)
	}
}

func TestOpenRecoversInterruptedActiveCompaction(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "state.bbolt")
	cfg := &config.Config{Storage: config.Storage{StateDir: tmp, Database: path}}
	store, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveJSON("meta", "survives", true); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".precompact"); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	var survives bool
	if err := recovered.LoadJSON("meta", "survives", &survives); err != nil || !survives {
		t.Fatalf("interrupted compaction recovery lost state: value=%v err=%v", survives, err)
	}
}
