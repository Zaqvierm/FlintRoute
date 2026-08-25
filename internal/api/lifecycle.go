package api

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"router-policy/internal/lifecycle"
	"router-policy/internal/writebudget"
)

func (s *Server) handleLifecycle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	manager := lifecycle.Manager{StateDir: s.cfg.Storage.StateDir, RuntimeDir: s.cfg.Storage.RuntimeDir, Inspector: lifecycle.LinuxProcessInspector{}}
	manifests, manifestIssues, err := manager.ListWithIssues()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "lifecycle_manifest_invalid", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	serviceSpecs := []lifecycle.ServiceSpec{
		{Component: "xray", Service: "router-policy-xray", Instance: "router-policy-xray", Executable: s.cfg.Xray.Binary, ConfigPath: s.cfg.Xray.ActiveConfig, SystemServices: []string{"xray"}},
		{Component: "zapret", Service: "router-policy-zapret", Instance: "router-policy-zapret", Executable: s.cfg.Zapret.Binary, ConfigPath: s.cfg.Zapret.ActiveConfig, SystemServices: []string{"zapret", "nfqws"}},
	}
	for _, profile := range s.cfg.Zapret.DeviceProfiles {
		serviceSpecs = append(serviceSpecs, lifecycle.ServiceSpec{
			Component:  "zapret-device:" + profile.ID,
			Service:    "router-policy-zapret-" + profile.ID,
			Instance:   "router-policy-zapret-" + profile.ID,
			Executable: profile.Binary,
			ConfigPath: profile.ActiveConfig,
		})
	}
	services := lifecycle.DiagnoseServices(ctx, lifecycle.ExecRunner{}, lifecycle.LinuxProcessInspector{}, serviceSpecs)
	writeData(w, r, map[string]any{"schema_version": lifecycle.ManifestSchemaVersion, "services": services, "test_runs": manifests, "manifest_issues": manifestIssues})
}

func (s *Server) handleStorage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	dbBytes := int64(0)
	if info, err := os.Stat(s.store.Path()); err == nil && info.Mode().IsRegular() {
		dbBytes = info.Size()
	}
	runtimeBytes, runtimeFiles := boundedTreeSize(s.cfg.Storage.RuntimeDir)
	snapshotBytes, snapshots := boundedTreeSize(filepath.Join(s.cfg.Storage.StateDir, "last-good"))
	backupBytes, backups := boundedTreeSize(filepath.Join(s.cfg.Storage.StateDir, "backups"))
	transactionBytes, transactions := boundedTreeSize(filepath.Join(s.cfg.Storage.StateDir, "transactions"))
	installerBackupBytes, installerBackups := boundedTreeSize("/root/router-policy-backups")
	activeTransaction := readEnvAllowlist(filepath.Join(s.cfg.Storage.RuntimeDir, "active-transaction.env"), map[string]bool{
		"transaction_id": true, "revision_id": true, "candidate_hash": true, "artifact_manifest_hash": true, "transaction_state": true,
	})
	pendingRollback := readEnvAllowlist(filepath.Join(s.cfg.Storage.RuntimeDir, "pending-transaction.env"), map[string]bool{
		"transaction_id": true, "revision_id": true, "deadline": true,
	})
	_, rollbackTimers := boundedTreeSize(filepath.Join(s.cfg.Storage.RuntimeDir, "rollback-timers"))
	var lastCleanup any
	if err := s.store.LoadJSON("meta", "last_cleanup_result", &lastCleanup); err != nil {
		lastCleanup = nil
	}
	var lastRecovery any
	if err := s.store.LoadJSON("meta", "recovery_status", &lastRecovery); err != nil {
		lastRecovery = nil
	}
	writeData(w, r, map[string]any{
		"persistent_database_bytes": dbBytes,
		"runtime":                   map[string]any{"bytes": runtimeBytes, "files": runtimeFiles},
		"snapshots":                 map[string]any{"bytes": snapshotBytes, "files": snapshots},
		"backups":                   map[string]any{"bytes": backupBytes, "files": backups},
		"installer_backups":         map[string]any{"bytes": installerBackupBytes, "files": installerBackups},
		"transactions":              map[string]any{"bytes": transactionBytes, "files": transactions},
		"active_transaction":        activeTransaction,
		"pending_rollback":          pendingRollback,
		"pending_rollback_timers":   rollbackTimers,
		"write_counters":            s.store.WriteMetrics(),
		"file_write_counters":       writebudget.Snapshot(),
		"adapter_write_counters":    readRuntimeWriteEvents(filepath.Join(s.cfg.Storage.RuntimeDir, "write-events.log")),
		"last_cleanup_result":       lastCleanup,
		"last_recovery_result":      lastRecovery,
	})
}

type runtimeWriteCounters struct {
	FilesCreated  uint64 `json:"files_created"`
	FilesReplaced uint64 `json:"files_replaced"`
	BytesWritten  uint64 `json:"bytes_written"`
	Fsyncs        uint64 `json:"fsyncs"`
	Snapshots     uint64 `json:"snapshots"`
	Events        uint64 `json:"events"`
	LastAt        string `json:"last_at,omitempty"`
	LastReason    string `json:"last_reason,omitempty"`
}

func readRuntimeWriteEvents(path string) runtimeWriteCounters {
	result := runtimeWriteCounters{}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 256*1024 {
		return result
	}
	file, err := os.Open(path)
	if err != nil {
		return result
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 4 {
			continue
		}
		value := uint64(0)
		for _, digit := range fields[2] {
			if digit < '0' || digit > '9' {
				value = 0
				break
			}
			value = value*10 + uint64(digit-'0')
		}
		switch fields[1] {
		case "file_created":
			result.FilesCreated++
			result.BytesWritten += value
		case "file_replaced":
			result.FilesReplaced++
			result.BytesWritten += value
		case "fsync":
			result.Fsyncs += value
		case "snapshot":
			result.Snapshots++
		default:
			continue
		}
		result.Events++
		result.LastAt, result.LastReason = fields[0], fields[3]
	}
	return result
}

func readEnvAllowlist(path string, allow map[string]bool) map[string]string {
	result := map[string]string{}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return result
	}
	file, err := os.Open(path)
	if err != nil {
		return result
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok && allow[key] {
			result[key] = value
		}
	}
	return result
}

func boundedTreeSize(root string) (int64, int) {
	var bytes int64
	files := 0
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fs.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err == nil && info.Mode().IsRegular() {
			bytes += info.Size()
			files++
		}
		return nil
	})
	return bytes, files
}
