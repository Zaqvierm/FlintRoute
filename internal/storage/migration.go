package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"router-policy/internal/writebudget"
)

type MigrationItem struct {
	Path      string `json:"path"`
	Class     string `json:"class"`
	Action    string `json:"action"`
	Reason    string `json:"reason"`
	Bytes     int64  `json:"bytes"`
	Ambiguous bool   `json:"ambiguous"`
	Applied   bool   `json:"applied"`
}

func ApplyMigration(stateDir, runtimeDir, legacyRoot string, now time.Time) (MigrationPlan, error) {
	plan, err := PlanMigration(stateDir, runtimeDir, legacyRoot)
	if err != nil {
		return plan, err
	}
	plan.DryRun = false
	registryRoot := filepath.Join(legacyRoot, "router-policy-backups")
	registryReady := false
	for index := range plan.Items {
		item := &plan.Items[index]
		if item.Class == "stale-generated" && !item.Ambiguous {
			if err := validateCurrentTSPUCache(stateDir); err != nil {
				item.Action = "skip"
				item.Reason = "current TSPU cache validation failed; stale candidate preserved"
				item.Ambiguous = true
				plan.AmbiguousItems++
				plan.Reclaimable -= item.Bytes
				continue
			}
			if err := removeExactStaleTSPUTemp(stateDir, item.Path); err != nil {
				return plan, err
			}
			writebudget.RecordDelete("remove validated stale TSPU candidate")
			item.Action = "removed"
			item.Reason = "current TSPU cache validated before exact stale candidate removal"
			item.Applied = true
			continue
		}
		if item.Class != "legacy-backup" || item.Ambiguous {
			continue
		}
		if !registryReady {
			if err := os.MkdirAll(registryRoot, 0o700); err != nil {
				return plan, err
			}
			registryReady = true
		}
		operationID := filepath.Base(item.Path)
		target := filepath.Join(registryRoot, operationID)
		if _, err := os.Lstat(target); err == nil {
			item.Action = "skip"
			item.Reason = "managed backup with the same operation ID already exists"
			item.Ambiguous = true
			plan.AmbiguousItems++
			plan.Reclaimable -= item.Bytes
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return plan, err
		}
		temp, err := os.MkdirTemp(registryRoot, ".migrate-"+operationID+"-")
		if err != nil {
			return plan, err
		}
		if err := copyVerifiedTree(item.Path, temp); err != nil {
			_ = os.RemoveAll(temp)
			return plan, fmt.Errorf("stage legacy backup %s: %w", operationID, err)
		}
		createdAt := legacyBackupCreatedAt(item.Path, now)
		if _, err := RegisterDirectory(temp, operationID, "legacy", "migrated legacy backup", "installer-fallback", createdAt); err != nil {
			_ = os.RemoveAll(temp)
			return plan, fmt.Errorf("register legacy backup %s: %w", operationID, err)
		}
		if err := os.Rename(temp, target); err != nil {
			_ = os.RemoveAll(temp)
			return plan, fmt.Errorf("activate migrated backup %s: %w", operationID, err)
		}
		if _, err := loadAndVerifyManifest(target); err != nil {
			return plan, fmt.Errorf("verify migrated backup %s: %w", operationID, err)
		}
		if err := removeExactLegacyBackup(legacyRoot, item.Path); err != nil {
			return plan, err
		}
		item.Action = "migrated"
		item.Reason = "verified copy registered before legacy source removal"
		item.Applied = true
	}
	if registryReady {
		retention, err := PlanRetention(registryRoot, 2, 128*1024*1024, true)
		if err != nil {
			return plan, fmt.Errorf("apply migrated backup retention: %w", err)
		}
		plan.Retention = &retention
	}
	return plan, nil
}

var legacyBackupTimestamp = regexp.MustCompile(`(\d{8}T\d{6}Z|\d{8}-\d{6})$`)

func legacyBackupCreatedAt(path string, fallback time.Time) time.Time {
	match := legacyBackupTimestamp.FindString(filepath.Base(path))
	for _, layout := range []string{"20060102T150405Z", "20060102-150405"} {
		if parsed, err := time.Parse(layout, match); err == nil {
			return parsed.UTC()
		}
	}
	if info, err := os.Lstat(path); err == nil && !info.ModTime().IsZero() {
		return info.ModTime().UTC()
	}
	return fallback.UTC()
}

func validateCurrentTSPUCache(stateDir string) error {
	path := filepath.Join(stateDir, "tspu-cache.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("current TSPU cache is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	var value any
	decoder := json.NewDecoder(io.LimitReader(file, 128<<20))
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("decode current TSPU cache: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("current TSPU cache contains trailing data")
	}
	return nil
}

func removeExactStaleTSPUTemp(stateDir, path string) error {
	cleanState := filepath.Clean(stateDir)
	cleanPath := filepath.Clean(path)
	name := filepath.Base(cleanPath)
	if filepath.Dir(cleanPath) != cleanState || !isStaleTSPUTemp(name) {
		return errors.New("refusing stale TSPU cleanup outside exact allowlist")
	}
	info, err := os.Lstat(cleanPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing non-regular stale TSPU candidate")
	}
	return os.Remove(cleanPath)
}

func isStaleTSPUTemp(name string) bool {
	return strings.HasPrefix(name, "tspu-cache.json.tmp.") || strings.HasPrefix(name, "tspu-cache.previous.json.tmp.")
}

func copyVerifiedTree(source, target string) error {
	sourceInfo, err := os.Lstat(source)
	if err != nil || !sourceInfo.IsDir() || sourceInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("legacy backup is not a regular directory")
	}
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return errors.New("legacy backup path escaped source root")
		}
		if rel == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("legacy backup contains a symlink")
		}
		destination := filepath.Join(target, rel)
		if entry.IsDir() {
			return os.Mkdir(destination, 0o700)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("legacy backup contains a non-regular file")
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeInputErr := input.Close()
		syncErr := output.Sync()
		closeOutputErr := output.Close()
		for _, candidate := range []error{copyErr, closeInputErr, syncErr, closeOutputErr} {
			if candidate != nil {
				return candidate
			}
		}
		return nil
	})
}

func removeExactLegacyBackup(legacyRoot, path string) error {
	cleanRoot := filepath.Clean(legacyRoot)
	cleanPath := filepath.Clean(path)
	name := filepath.Base(cleanPath)
	if filepath.Dir(cleanPath) != cleanRoot || (!strings.HasPrefix(name, "router-policy-backup-") && !strings.HasPrefix(name, "router-policy-uninstall-backup-")) {
		return errors.New("refusing legacy backup cleanup outside allowlisted root")
	}
	return os.RemoveAll(cleanPath)
}

type MigrationPlan struct {
	DryRun         bool            `json:"dry_run"`
	StateDir       string          `json:"state_dir"`
	RuntimeDir     string          `json:"runtime_dir"`
	Items          []MigrationItem `json:"items"`
	Reclaimable    int64           `json:"reclaimable_bytes"`
	AmbiguousItems int             `json:"ambiguous_items"`
	Retention      *RetentionPlan  `json:"retention,omitempty"`
}

func PlanMigration(stateDir, runtimeDir, legacyRoot string) (MigrationPlan, error) {
	plan := MigrationPlan{DryRun: true, StateDir: stateDir, RuntimeDir: runtimeDir}
	knownState := map[string]struct {
		class  string
		action string
		reason string
	}{
		"last-good":      {"durable-recovery", "preserve", "single verified recovery snapshot"},
		"transactions":   {"durable-journal", "validate", "active and committed transaction journals require manifest validation"},
		"backups":        {"bounded-history", "preserve", "managed bbolt backups"},
		"lifecycle":      {"bounded-history", "preserve", "owned test-run manifests"},
		"auth":           {"durable-security", "preserve", "authentication material and session metadata"},
		"xray":           {"durable-recovery", "preserve", "verified provider fallback state"},
		"diagnostics":    {"exported-diagnostics", "review", "diagnostic exports require explicit retention decisions"},
		"recovery-tests": {"exported-diagnostics", "review", "hardware recovery evidence is never removed automatically"},
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return plan, err
	}
	for _, entry := range entries {
		path := filepath.Join(stateDir, entry.Name())
		bytes := treeSize(path)
		if known, ok := knownState[entry.Name()]; ok {
			plan.Items = append(plan.Items, MigrationItem{Path: path, Class: known.class, Action: known.action, Reason: known.reason, Bytes: bytes})
			continue
		}
		if !entry.IsDir() && (entry.Name() == "router-policy.bbolt" || entry.Name() == "active-revision" || entry.Name() == "last-backup-path") {
			plan.Items = append(plan.Items, MigrationItem{Path: path, Class: "durable-committed", Action: "preserve", Reason: "required committed control-plane state", Bytes: bytes})
			continue
		}
		if !entry.IsDir() && (entry.Name() == "tspu-cache.json" || entry.Name() == "tspu-cache.previous.json") {
			plan.Items = append(plan.Items, MigrationItem{Path: path, Class: "bounded-operational-cache", Action: "preserve", Reason: "current and single fallback TSPU cache are bounded", Bytes: bytes})
			continue
		}
		if !entry.IsDir() && isStaleTSPUTemp(entry.Name()) {
			plan.Items = append(plan.Items, MigrationItem{Path: path, Class: "stale-generated", Action: "validate-and-remove", Reason: "interrupted atomic TSPU write left a non-authoritative candidate", Bytes: bytes})
			plan.Reclaimable += bytes
			continue
		}
		plan.Items = append(plan.Items, MigrationItem{Path: path, Class: "unknown", Action: "skip", Reason: "unknown persistent file is never removed automatically", Bytes: bytes, Ambiguous: true})
		plan.AmbiguousItems++
	}
	if info, err := os.Lstat(runtimeDir); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		plan.Items = append(plan.Items, MigrationItem{Path: runtimeDir, Class: "runtime-tmpfs", Action: "preserve-layout", Reason: "transient state already uses the runtime root", Bytes: treeSize(runtimeDir)})
	}
	legacyEntries, err := os.ReadDir(legacyRoot)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return plan, err
	}
	for _, entry := range legacyEntries {
		if !entry.IsDir() || (!strings.HasPrefix(entry.Name(), "router-policy-backup-") && !strings.HasPrefix(entry.Name(), "router-policy-uninstall-backup-")) {
			continue
		}
		path := filepath.Join(legacyRoot, entry.Name())
		bytes := treeSize(path)
		plan.Items = append(plan.Items, MigrationItem{Path: path, Class: "legacy-backup", Action: "validate-and-register", Reason: "legacy backup must be verified before managed retention", Bytes: bytes})
		plan.Reclaimable += bytes
	}
	return plan, nil
}

func treeSize(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !entry.IsDir() {
			if info, err := entry.Info(); err == nil && info.Mode().IsRegular() {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}
