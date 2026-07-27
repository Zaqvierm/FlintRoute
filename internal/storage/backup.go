package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"router-policy/internal/writebudget"
)

const BackupManifestSchemaVersion = 1

type BackupFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type BackupManifest struct {
	SchemaVersion  int          `json:"schema_version"`
	OperationID    string       `json:"operation_id"`
	Version        string       `json:"version"`
	CreatedAt      time.Time    `json:"created_at"`
	Verified       bool         `json:"verified"`
	Files          []BackupFile `json:"files"`
	TotalSize      int64        `json:"total_size"`
	Reason         string       `json:"reason"`
	RetentionClass string       `json:"retention_class"`
}

type RetentionAction struct {
	OperationID string `json:"operation_id"`
	Path        string `json:"path"`
	Bytes       int64  `json:"bytes"`
	Action      string `json:"action"`
	Reason      string `json:"reason"`
	Applied     bool   `json:"applied"`
}

type RetentionPlan struct {
	DryRun      bool              `json:"dry_run"`
	TotalBefore int64             `json:"total_before"`
	TotalAfter  int64             `json:"total_after"`
	Actions     []RetentionAction `json:"actions"`
}

func RegisterDirectory(root, operationID, version, reason, retentionClass string, now time.Time) (BackupManifest, error) {
	if !validBackupRoot(root) || operationID == "" || version == "" || reason == "" || retentionClass == "" {
		return BackupManifest{}, fmt.Errorf("invalid backup registration")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return BackupManifest{}, fmt.Errorf("backup root is not a regular directory")
	}
	manifest := BackupManifest{SchemaVersion: BackupManifestSchemaVersion, OperationID: operationID, Version: version, CreatedAt: now.UTC(), Reason: reason, RetentionClass: retentionClass}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() || entry.Name() == "operation.json" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("backup file escaped operation root")
		}
		digest, bytes, err := hashFile(path)
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, BackupFile{Path: filepath.ToSlash(rel), Bytes: bytes, SHA256: digest})
		manifest.TotalSize += bytes
		return nil
	})
	if err != nil {
		return BackupManifest{}, err
	}
	if len(manifest.Files) == 0 {
		return BackupManifest{}, fmt.Errorf("backup contains no regular files")
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	manifest.Verified = true
	if err := writeManifestAtomic(filepath.Join(root, "operation.json"), manifest); err != nil {
		return BackupManifest{}, err
	}
	writebudget.RecordBackup("verified installer backup")
	return manifest, nil
}

func PlanRetention(registryRoot string, maxVerified int, maxBytes int64, apply bool) (RetentionPlan, error) {
	plan := RetentionPlan{DryRun: !apply}
	if !validRegistryRoot(registryRoot) {
		return plan, fmt.Errorf("backup registry root must be project-owned")
	}
	if maxVerified < 1 {
		maxVerified = 2
	}
	if maxBytes <= 0 {
		maxBytes = 128 * 1024 * 1024
	}
	entries, err := os.ReadDir(registryRoot)
	if errors.Is(err, os.ErrNotExist) {
		return plan, nil
	}
	if err != nil {
		return plan, err
	}
	type registered struct {
		path     string
		manifest BackupManifest
	}
	var verified []registered
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(registryRoot, entry.Name())
		manifest, err := loadAndVerifyManifest(path)
		if err != nil || !manifest.Verified {
			plan.Actions = append(plan.Actions, RetentionAction{OperationID: entry.Name(), Path: path, Action: "skip", Reason: "manifest is missing, invalid, or unverified"})
			continue
		}
		plan.TotalBefore += manifest.TotalSize
		verified = append(verified, registered{path: path, manifest: manifest})
	}
	sort.Slice(verified, func(i, j int) bool { return verified[i].manifest.CreatedAt.After(verified[j].manifest.CreatedAt) })
	keptBytes := int64(0)
	for index, item := range verified {
		keep := index < maxVerified && (index == 0 || keptBytes+item.manifest.TotalSize <= maxBytes)
		action := RetentionAction{OperationID: item.manifest.OperationID, Path: item.path, Bytes: item.manifest.TotalSize}
		if keep {
			action.Action = "keep"
			action.Reason = "verified fallback within count and size limits"
			keptBytes += item.manifest.TotalSize
		} else {
			action.Action = "delete"
			action.Reason = "older verified fallback exceeds bounded retention"
			if apply {
				if err := removeVerifiedBackup(registryRoot, item.path, item.manifest); err != nil {
					return plan, err
				}
				action.Applied = true
			}
		}
		plan.Actions = append(plan.Actions, action)
	}
	plan.TotalAfter = keptBytes
	return plan, nil
}

func loadAndVerifyManifest(root string) (BackupManifest, error) {
	raw, err := os.ReadFile(filepath.Join(root, "operation.json"))
	if err != nil {
		return BackupManifest{}, err
	}
	var manifest BackupManifest
	if json.Unmarshal(raw, &manifest) != nil || manifest.SchemaVersion != BackupManifestSchemaVersion || !manifest.Verified || len(manifest.Files) == 0 {
		return BackupManifest{}, fmt.Errorf("invalid backup manifest")
	}
	total := int64(0)
	for _, file := range manifest.Files {
		path := filepath.Join(root, filepath.FromSlash(file.Path))
		if !withinRoot(path, root) {
			return BackupManifest{}, fmt.Errorf("backup manifest path escaped root")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return BackupManifest{}, fmt.Errorf("backup file is missing or unsafe")
		}
		digest, bytes, err := hashFile(path)
		if err != nil || bytes != file.Bytes || digest != file.SHA256 {
			return BackupManifest{}, fmt.Errorf("backup file verification failed")
		}
		total += bytes
	}
	if total != manifest.TotalSize {
		return BackupManifest{}, fmt.Errorf("backup total size mismatch")
	}
	return manifest, nil
}

func removeVerifiedBackup(registryRoot, path string, manifest BackupManifest) error {
	if manifest.OperationID == "" || !withinRoot(path, registryRoot) || filepath.Dir(path) != filepath.Clean(registryRoot) {
		return fmt.Errorf("refusing backup cleanup outside registry root")
	}
	verified, err := loadAndVerifyManifest(path)
	if err != nil || verified.OperationID != manifest.OperationID {
		return fmt.Errorf("refusing cleanup of unverified backup")
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	writebudget.RecordDelete("verified installer backup retention")
	return nil
}

func validRegistryRoot(path string) bool {
	return filepath.Base(filepath.Clean(path)) == "router-policy-backups"
}

func validBackupRoot(path string) bool {
	return validRegistryRoot(filepath.Dir(filepath.Clean(path)))
}

func withinRoot(path, root string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absRoot, absPath)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	bytes, err := io.Copy(hash, file)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), bytes, err
}

func writeManifestAtomic(path string, manifest BackupManifest) error {
	created := true
	if info, err := os.Lstat(path); err == nil {
		created = false
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular manifest target")
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".operation-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	fsyncCount := uint64(1)
	if parent, err := os.Open(filepath.Dir(path)); err == nil {
		if parent.Sync() == nil {
			fsyncCount++
		}
		_ = parent.Close()
	}
	writebudget.RecordFileWrite(created, uint64(len(raw)), fsyncCount, "backup manifest")
	return nil
}
