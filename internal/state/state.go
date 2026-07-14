package state

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"router-policy/internal/config"
	"router-policy/internal/probe"
)

var ErrNotFound = errors.New("state key not found")

const CurrentSchemaVersion = 3

type retentionPolicy struct {
	maxProbeResults      int
	eventRetention       time.Duration
	changeSetRetention   time.Duration
	transactionRetention time.Duration
	backupInterval       time.Duration
	compactInterval      time.Duration
	maxBackups           int
	maxDatabaseBytes     int64
}

type Store struct {
	mode      string
	path      string
	stateDir  string
	retention retentionPolicy
	mu        sync.Mutex
	db        *bolt.DB
}

type Entry struct {
	Bucket string
	Key    string
	Value  any
}

func Open(cfg *config.Config) (*Store, error) {
	path := cfg.Storage.Database
	if path == "" {
		path = filepath.Join(cfg.Storage.StateDir, "router-policy.bbolt")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := recoverInterruptedCompaction(path); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	policy := retentionPolicy{
		maxProbeResults:      positiveOr(cfg.Storage.MaxProbeResults, 5000),
		eventRetention:       days(positiveOr(cfg.Storage.EventRetentionDays, 30)),
		changeSetRetention:   days(positiveOr(cfg.Storage.ChangeSetRetentionDays, 90)),
		transactionRetention: days(positiveOr(cfg.Storage.TransactionRetentionDays, 30)),
		backupInterval:       time.Duration(positiveOr(cfg.Storage.BackupIntervalHours, 24)) * time.Hour,
		compactInterval:      days(positiveOr(cfg.Storage.CompactIntervalDays, 7)),
		maxBackups:           positiveOr(cfg.Storage.MaxStateBackups, 7),
		maxDatabaseBytes:     positiveOr64(cfg.Storage.MaxDatabaseBytes, 64*1024*1024),
	}
	store := &Store{mode: "bbolt", path: path, stateDir: cfg.Storage.StateDir, retention: policy, db: db}
	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := store.Cleanup(time.Now().UTC()); err != nil {
		_ = db.Close()
		return nil, err
	}
	_ = os.Remove(path + ".precompact")
	_ = os.Remove(path + ".compact.tmp")
	return store, nil
}

func (s *Store) init() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists([]byte("meta"))
		if err != nil {
			return err
		}
		version := 0
		if raw := meta.Get([]byte("schema_version")); raw != nil {
			if err := json.Unmarshal(raw, &version); err != nil {
				return fmt.Errorf("invalid schema version: %w", err)
			}
		}
		for version < CurrentSchemaVersion {
			switch version + 1 {
			case 1:
				for _, name := range []string{"probes", "changes", "events", "revisions", "transactions", "candidates", "meta"} {
					if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
						return err
					}
				}
			case 2:
				if _, err := tx.CreateBucketIfNotExists([]byte("route_health")); err != nil {
					return err
				}
			case 3:
				if _, err := tx.CreateBucketIfNotExists([]byte("backups")); err != nil {
					return err
				}
			default:
				return fmt.Errorf("no migration to schema version %d", version+1)
			}
			version++
			raw, _ := json.Marshal(version)
			if err := meta.Put([]byte("schema_version"), raw); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}
func (s *Store) Mode() string { return s.mode }
func (s *Store) Path() string { return s.path }

func (s *Store) StoreProbeResult(result probe.RouteResult) error {
	key := fmt.Sprintf("%s:%s:%d", result.CheckedAt, result.Route, time.Now().UnixNano())
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("probes"))
		if err := bucket.Put([]byte(key), raw); err != nil {
			return err
		}
		return trimBucket(bucket, s.retention.maxProbeResults)
	})
}

func (s *Store) ListProbeResults(limit int) ([]probe.RouteResult, error) {
	if limit <= 0 || limit > s.retention.maxProbeResults {
		limit = s.retention.maxProbeResults
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]probe.RouteResult, 0, limit)
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("probes"))
		if bucket == nil {
			return nil
		}
		cursor := bucket.Cursor()
		for _, raw := cursor.Last(); raw != nil && len(out) < limit; _, raw = cursor.Prev() {
			var result probe.RouteResult
			if err := json.Unmarshal(raw, &result); err != nil {
				return fmt.Errorf("invalid persisted probe result: %w", err)
			}
			out = append(out, result)
		}
		return nil
	})
	return out, err
}

func (s *Store) SaveRouteHealth(health probe.RouteHealth) error {
	if health.RouteTag == "" {
		return fmt.Errorf("route health tag is required")
	}
	return s.SaveJSON("route_health", health.RouteTag, health)
}

func (s *Store) ListRouteHealth() ([]probe.RouteHealth, error) {
	entries, err := s.ListRaw("route_health")
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]probe.RouteHealth, 0, len(entries))
	for _, raw := range entries {
		var health probe.RouteHealth
		if err := json.Unmarshal(raw, &health); err != nil || health.RouteTag == "" {
			return nil, fmt.Errorf("invalid persisted route health")
		}
		result = append(result, health)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RouteTag < result[j].RouteTag })
	return result, nil
}

func (s *Store) SaveJSON(bucket, key string, value any) error {
	if bucket == "" || key == "" {
		return fmt.Errorf("bucket and key are required")
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		bkt, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		return bkt.Put([]byte(key), b)
	})
}

func (s *Store) SaveBatch(entries ...Entry) error {
	encoded := make([][]byte, len(entries))
	for i, entry := range entries {
		if entry.Bucket == "" || entry.Key == "" {
			return fmt.Errorf("bucket and key are required")
		}
		raw, err := json.Marshal(entry.Value)
		if err != nil {
			return err
		}
		encoded[i] = raw
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		for i, entry := range entries {
			bucket, err := tx.CreateBucketIfNotExists([]byte(entry.Bucket))
			if err != nil {
				return err
			}
			if err := bucket.Put([]byte(entry.Key), encoded[i]); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) LoadJSON(bucket, key string, out any) error {
	raw, err := s.GetRaw(bucket, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func (s *Store) GetRaw(bucket, key string) ([]byte, error) {
	if bucket == "" || key == "" {
		return nil, fmt.Errorf("bucket and key are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(bucket))
		if bkt == nil {
			return ErrNotFound
		}
		raw := bkt.Get([]byte(key))
		if raw == nil {
			return ErrNotFound
		}
		out = append([]byte(nil), raw...)
		return nil
	})
	return out, err
}

func (s *Store) ListRaw(bucket string) ([][]byte, error) {
	if bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][]byte
	err := s.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(bucket))
		if bkt == nil {
			return nil
		}
		return bkt.ForEach(func(_, v []byte) error {
			out = append(out, append([]byte(nil), v...))
			return nil
		})
	})
	return out, err
}

func (s *Store) Delete(bucket, key string) error {
	if bucket == "" || key == "" {
		return fmt.Errorf("bucket and key are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(bucket))
		if bkt == nil {
			return nil
		}
		return bkt.Delete([]byte(key))
	})
}

func (s *Store) PutInt64(key string, value int64) error {
	return s.SaveJSON("meta", key, value)
}

func (s *Store) GetInt64(key string, fallback int64) (int64, error) {
	var value int64
	err := s.LoadJSON("meta", key, &value)
	if errors.Is(err, ErrNotFound) {
		return fallback, nil
	}
	return value, err
}

type CleanupStats struct {
	Probes       int `json:"probes"`
	Events       int `json:"events"`
	ChangeSets   int `json:"changesets"`
	Transactions int `json:"transactions"`
}

type BackupMetadata struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	SizeBytes  int64     `json:"size_bytes"`
	SHA256     string    `json:"sha256"`
	Compact    bool      `json:"compact"`
	Status     string    `json:"status"`
	ReasonCode string    `json:"reason_code,omitempty"`
	VerifiedAt time.Time `json:"verified_at,omitempty"`
}

func (s *Store) ListBackups(limit int) ([]BackupMetadata, error) {
	rows, err := s.ListRaw("backups")
	if err != nil {
		return nil, err
	}
	items := make([]BackupMetadata, 0, len(rows))
	for _, raw := range rows {
		var item BackupMetadata
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, fmt.Errorf("invalid backup metadata: %w", err)
		}
		item.Status = "ERROR"
		item.ReasonCode = "backup_file_missing"
		if validBackupID(item.ID) {
			path := filepath.Join(s.stateDir, "backups", item.ID)
			if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
				if info.Size() != item.SizeBytes {
					item.ReasonCode = "backup_size_mismatch"
				} else if digest, hashErr := fileSHA256(path); hashErr != nil {
					item.ReasonCode = "backup_hash_unavailable"
				} else if digest != item.SHA256 {
					item.ReasonCode = "backup_hash_mismatch"
				} else {
					item.Status = "OK"
					item.ReasonCode = ""
					item.VerifiedAt = time.Now().UTC()
				}
			} else if statErr == nil {
				item.ReasonCode = "backup_file_unsafe"
			}
		} else {
			item.ReasonCode = "backup_id_invalid"
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (s *Store) SchemaVersion() (int, error) {
	var version int
	err := s.LoadJSON("meta", "schema_version", &version)
	return version, err
}

func (s *Store) Cleanup(now time.Time) (CleanupStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := CleanupStats{}
	err := s.db.Update(func(tx *bolt.Tx) error {
		probes := tx.Bucket([]byte("probes"))
		before := bucketCount(probes)
		if err := trimBucket(probes, s.retention.maxProbeResults); err != nil {
			return err
		}
		stats.Probes = before - bucketCount(probes)
		var err error
		stats.Events, err = deleteExpired(tx.Bucket([]byte("events")), now.Add(-s.retention.eventRetention), []string{"time"}, nil)
		if err != nil {
			return err
		}
		terminal := map[string]bool{"committed": true, "rolled_back": true, "failed": true, "rollback_failed": true, "expired": true, "requires_device": true}
		changes := tx.Bucket([]byte("changes"))
		candidates := tx.Bucket([]byte("candidates"))
		stats.ChangeSets, err = deleteExpired(changes, now.Add(-s.retention.changeSetRetention), []string{"updated_at"}, terminal)
		if err != nil {
			return err
		}
		if candidates != nil && changes != nil {
			cursor := candidates.Cursor()
			for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
				if changes.Get(key) == nil {
					if err := cursor.Delete(); err != nil {
						return err
					}
				}
			}
		}
		stats.Transactions, err = deleteExpired(tx.Bucket([]byte("transactions")), now.Add(-s.retention.transactionRetention), []string{"completed_at", "updated_at"}, terminal)
		return err
	})
	return stats, err
}

func (s *Store) Backup(path string, compact bool) error {
	if path == "" {
		return fmt.Errorf("backup path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	s.mu.Lock()
	defer s.mu.Unlock()
	if compact {
		dst, err := bolt.Open(tmp, 0o600, nil)
		if err != nil {
			return err
		}
		err = bolt.Compact(dst, s.db, 64*1024)
		closeErr := dst.Close()
		if err != nil {
			_ = os.Remove(tmp)
			return err
		}
		if closeErr != nil {
			_ = os.Remove(tmp)
			return closeErr
		}
	} else if err := s.db.View(func(tx *bolt.Tx) error { return tx.CopyFile(tmp, 0o600) }); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if info, err := os.Stat(tmp); err != nil || info.Size() == 0 {
		_ = os.Remove(tmp)
		if err != nil {
			return err
		}
		return fmt.Errorf("backup is empty")
	}
	_ = os.Remove(path)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (s *Store) CompactActive() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return fmt.Errorf("state database is closed")
	}
	tmp := s.path + ".compact.tmp"
	previous := s.path + ".precompact"
	_ = os.Remove(tmp)
	dst, err := bolt.Open(tmp, 0o600, nil)
	if err != nil {
		return err
	}
	err = bolt.Compact(dst, s.db, 64*1024)
	closeErr := dst.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := validateBoltFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("compacted database validation failed: %w", err)
	}
	if err := s.db.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	s.db = nil
	_ = os.Remove(previous)
	if err := os.Rename(s.path, previous); err != nil {
		reopened, reopenErr := bolt.Open(s.path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
		s.db = reopened
		_ = os.Remove(tmp)
		if reopenErr != nil {
			return fmt.Errorf("move active database for compaction: %v; reopen active database: %w", err, reopenErr)
		}
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		restoreErr := os.Rename(previous, s.path)
		if restoreErr == nil {
			s.db, restoreErr = bolt.Open(s.path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
		}
		_ = os.Remove(tmp)
		if restoreErr != nil {
			return fmt.Errorf("install compacted database: %v; restore active database: %w", err, restoreErr)
		}
		return err
	}
	reopened, err := bolt.Open(s.path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		failed := s.path + ".compact.failed"
		_ = os.Remove(failed)
		_ = os.Rename(s.path, failed)
		restoreErr := os.Rename(previous, s.path)
		if restoreErr == nil {
			s.db, restoreErr = bolt.Open(s.path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
		}
		_ = os.Remove(failed)
		if restoreErr != nil {
			return fmt.Errorf("open compacted database: %v; restore previous database: %w", err, restoreErr)
		}
		return fmt.Errorf("open compacted database: %w", err)
	}
	s.db = reopened
	_ = os.Remove(previous)
	return nil
}

func validateBoltFile(path string) error {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: 2 * time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		for checkErr := range tx.Check() {
			if checkErr != nil {
				return checkErr
			}
		}
		return nil
	})
}

func recoverInterruptedCompaction(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	previous := path + ".precompact"
	if _, err := os.Stat(previous); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return os.Rename(previous, path)
}

func (s *Store) pruneBackups() error {
	backupDir := filepath.Join(s.stateDir, "backups")
	entries, err := os.ReadDir(backupDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	type backupFile struct {
		name string
		path string
	}
	backups := make([]backupFile, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() || !strings.HasPrefix(entry.Name(), "router-policy-") || !strings.HasSuffix(entry.Name(), ".bbolt") {
			continue
		}
		backups = append(backups, backupFile{name: entry.Name(), path: filepath.Join(backupDir, entry.Name())})
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].name < backups[j].name })
	for len(backups) > s.retention.maxBackups {
		name := backups[0].name
		if err := os.Remove(backups[0].path); err != nil {
			return err
		}
		if err := s.Delete("backups", name); err != nil {
			return err
		}
		backups = backups[1:]
	}
	return nil
}

func (s *Store) Maintain(now time.Time) error {
	if _, err := s.Cleanup(now); err != nil {
		return err
	}
	var lastBackup time.Time
	err := s.LoadJSON("meta", "last_backup_at", &lastBackup)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if !lastBackup.IsZero() && now.Sub(lastBackup) < s.retention.backupInterval {
		return s.pruneBackups()
	}
	var lastCompact time.Time
	err = s.LoadJSON("meta", "last_compact_at", &lastCompact)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	compact := lastCompact.IsZero() || now.Sub(lastCompact) >= s.retention.compactInterval
	var lastActiveCompact time.Time
	err = s.LoadJSON("meta", "last_active_compact_at", &lastActiveCompact)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	compactActive := lastActiveCompact.IsZero() || now.Sub(lastActiveCompact) >= s.retention.compactInterval
	backupDir := filepath.Join(s.stateDir, "backups")
	backupPath := filepath.Join(backupDir, "router-policy-"+now.UTC().Format("20060102T150405Z")+".bbolt")
	if err := s.Backup(backupPath, compact); err != nil {
		return err
	}
	info, err := os.Lstat(backupPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 {
		if err != nil {
			return err
		}
		return fmt.Errorf("backup file is unsafe or empty")
	}
	digest, err := fileSHA256(backupPath)
	if err != nil {
		return err
	}
	backup := BackupMetadata{ID: filepath.Base(backupPath), CreatedAt: now.UTC(), SizeBytes: info.Size(), SHA256: digest, Compact: compact, Status: "OK", VerifiedAt: now.UTC()}
	entries := []Entry{
		{Bucket: "meta", Key: "last_backup_at", Value: now.UTC()},
		{Bucket: "backups", Key: backup.ID, Value: backup},
	}
	if compact {
		entries = append(entries, Entry{Bucket: "meta", Key: "last_compact_at", Value: now.UTC()})
	}
	if err := s.SaveBatch(entries...); err != nil {
		return err
	}
	if err := s.pruneBackups(); err != nil {
		return err
	}
	info, err = os.Stat(s.path)
	if err != nil {
		return err
	}
	if compactActive && info.Size() > s.retention.maxDatabaseBytes {
		if err := s.CompactActive(); err != nil {
			return err
		}
		return s.SaveJSON("meta", "last_active_compact_at", now.UTC())
	}
	return nil
}

func trimBucket(bucket *bolt.Bucket, max int) error {
	if bucket == nil || max <= 0 {
		return nil
	}
	count := bucketCount(bucket)
	cursor := bucket.Cursor()
	for count > max {
		key, _ := cursor.First()
		if key == nil {
			break
		}
		if err := cursor.Delete(); err != nil {
			return err
		}
		count--
	}
	return nil
}

func bucketCount(bucket *bolt.Bucket) int {
	if bucket == nil {
		return 0
	}
	count := 0
	cursor := bucket.Cursor()
	for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
		count++
	}
	return count
}

func deleteExpired(bucket *bolt.Bucket, cutoff time.Time, fields []string, terminal map[string]bool) (int, error) {
	if bucket == nil {
		return 0, nil
	}
	deleted := 0
	cursor := bucket.Cursor()
	for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
		var item map[string]any
		if err := json.Unmarshal(value, &item); err != nil {
			return deleted, err
		}
		if terminal != nil {
			stateName, _ := item["state"].(string)
			if !terminal[stateName] {
				continue
			}
		}
		stamp := time.Time{}
		for _, field := range fields {
			if text, ok := item[field].(string); ok {
				parsed, err := time.Parse(time.RFC3339Nano, text)
				if err == nil {
					stamp = parsed
					break
				}
			}
		}
		if !stamp.IsZero() && stamp.Before(cutoff) {
			if err := cursor.Delete(); err != nil {
				return deleted, err
			}
			deleted++
		}
	}
	return deleted, nil
}

func positiveOr(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func positiveOr64(value, fallback int64) int64 {
	if value > 0 {
		return value
	}
	return fallback
}

func validBackupID(id string) bool {
	return id == filepath.Base(id) && strings.HasPrefix(id, "router-policy-") && strings.HasSuffix(id, ".bbolt") && !strings.ContainsAny(id, `/\\`)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func days(value int) time.Duration { return time.Duration(value) * 24 * time.Hour }
