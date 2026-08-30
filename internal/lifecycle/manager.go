package lifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"router-policy/internal/writebudget"
)

type ProcessInspector interface {
	Inspect(pid int) (ProcessIdentity, error)
	Terminate(pid int) error
}

type ResourceExecutor interface {
	Cleanup(manifest Manifest, resource Resource, apply bool) (checks []string, action string, applied bool, err error)
}

type LinuxProcessInspector struct{}

func (LinuxProcessInspector) Inspect(pid int) (ProcessIdentity, error) {
	if pid <= 0 {
		return ProcessIdentity{}, fmt.Errorf("invalid PID")
	}
	root := filepath.Join("/proc", strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	closeParen := strings.LastIndexByte(string(stat), ')')
	if closeParen < 0 {
		return ProcessIdentity{}, fmt.Errorf("malformed proc stat")
	}
	fields := strings.Fields(string(stat[closeParen+1:]))
	if len(fields) <= 19 {
		return ProcessIdentity{}, fmt.Errorf("proc stat lacks start time")
	}
	pgid, err := strconv.Atoi(fields[2])
	if err != nil || pgid <= 0 {
		return ProcessIdentity{}, fmt.Errorf("parse process group: %w", err)
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("parse process start time: %w", err)
	}
	exe, err := os.Readlink(filepath.Join(root, "exe"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	cmdline, err := os.ReadFile(filepath.Join(root, "cmdline"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	return ProcessIdentity{PID: pid, StartTimeTicks: start, PGID: pgid, Executable: exe, CommandLine: args}, nil
}

func (LinuxProcessInspector) Terminate(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(syscall.SIGTERM)
}

type Manager struct {
	StateDir     string
	RuntimeDir   string
	Inspector    ProcessInspector
	Executor     ResourceExecutor
	Verifier     BaselineVerifier
	Now          func() time.Time
	MaxCompleted int
}

func (m Manager) manifestsDir() string {
	return filepath.Join(m.StateDir, "lifecycle", "test-runs")
}

func (m Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m Manager) Save(manifest Manifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(m.manifestsDir(), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	path := filepath.Join(m.manifestsDir(), manifest.RunID+".json")
	created := true
	if info, err := os.Lstat(path); err == nil {
		created = false
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular manifest target")
		}
		current, readErr := os.ReadFile(path)
		if readErr == nil && string(current) == string(raw) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(m.manifestsDir(), ".manifest-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
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
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	fsyncCount := uint64(1)
	if parent, err := os.Open(m.manifestsDir()); err == nil {
		if parent.Sync() == nil {
			fsyncCount++
		}
		_ = parent.Close()
	}
	writebudget.RecordFileWrite(created, uint64(len(raw)), fsyncCount, "test-run owner manifest")
	return nil
}

func (m Manager) BeginTestRun(runID string, lease time.Duration, baseline Baseline) (Manifest, error) {
	if lease <= 0 || lease > 24*time.Hour {
		return Manifest{}, fmt.Errorf("test-run lease must be between zero and 24 hours")
	}
	now := m.now()
	if baseline.CapturedAt == "" {
		baseline.CapturedAt = now.Format(time.RFC3339)
	}
	manifest := Manifest{
		SchemaVersion: ManifestSchemaVersion,
		RunID:         runID,
		Owner:         Owner{Class: OwnerTestRun, ID: runID},
		CreatedAt:     now.Format(time.RFC3339),
		ExpiresAt:     now.Add(lease).Format(time.RFC3339),
		Baseline:      baseline,
		CleanupState:  "active",
	}
	if err := m.Save(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manager) Load(runID string) (Manifest, error) {
	if !ownerIDPattern.MatchString(runID) {
		return Manifest{}, fmt.Errorf("invalid run ID")
	}
	path := filepath.Join(m.manifestsDir(), runID+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return Manifest{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Manifest{}, fmt.Errorf("refusing non-regular lifecycle manifest")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return Manifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manager) AddResource(runID string, resource Resource) (Manifest, error) {
	manifest, err := m.Load(runID)
	if err != nil {
		return Manifest{}, err
	}
	if manifest.CleanupState != "active" {
		return Manifest{}, fmt.Errorf("test-run is not active")
	}
	resource.Owner = manifest.Owner
	for _, existing := range manifest.Resources {
		if existing.ID == resource.ID {
			return Manifest{}, fmt.Errorf("resource ID already exists")
		}
	}
	manifest.Resources = append(manifest.Resources, resource)
	if err := m.Save(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manager) FinishTestRun(runID, result string) (Manifest, error) {
	manifest, err := m.Load(runID)
	if err != nil {
		return Manifest{}, err
	}
	if cleanupStateTerminal(manifest.CleanupState) {
		return manifest, nil
	}
	manifest.CleanupState = "pending"
	manifest.FinalResult = result
	if err := m.Save(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manager) List() ([]Manifest, error) {
	entries, err := os.ReadDir(m.manifestsDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	manifests := make([]Manifest, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(m.manifestsDir(), entry.Name()))
		if err != nil {
			return nil, err
		}
		var manifest Manifest
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return nil, fmt.Errorf("decode %s: %w", entry.Name(), err)
		}
		if err := manifest.Validate(); err != nil {
			return nil, fmt.Errorf("validate %s: %w", entry.Name(), err)
		}
		manifests = append(manifests, manifest)
	}
	return manifests, nil
}

func (m Manager) ListWithIssues() ([]Manifest, []CleanupAction, error) {
	return m.listForCleanup()
}

func (m Manager) CleanupStale(apply bool) (CleanupReport, error) {
	now := m.now()
	report := CleanupReport{DryRun: !apply, GeneratedAt: now.Format(time.RFC3339)}
	manifests, rejected, err := m.listForCleanup()
	if err != nil {
		return report, err
	}
	for _, action := range rejected {
		report.Actions = append(report.Actions, action)
		report.AmbiguousSkipped++
	}
	for _, manifest := range manifests {
		if cleanupStateTerminal(manifest.CleanupState) {
			continue
		}
		expires, _ := time.Parse(time.RFC3339, manifest.ExpiresAt)
		if now.Before(expires) && manifest.CleanupState != "pending" {
			continue
		}
		report.StaleRuns++
		allClean := true
		for _, resource := range manifest.Resources {
			action := CleanupAction{RunID: manifest.RunID, ResourceID: resource.ID, Kind: resource.Kind, Owner: resource.Owner.String(), Reason: "test-run lease expired"}
			if resource.Owner.Class == OwnerProduction {
				action.Action, action.Skipped = "protect production resource", true
				report.ProtectedProduction++
				allClean = false
				report.Actions = append(report.Actions, action)
				continue
			}
			if resource.Owner != manifest.Owner || !resource.AllowCleanup {
				action.Action, action.Skipped = "skip ambiguous ownership", true
				report.AmbiguousSkipped++
				allClean = false
				report.Actions = append(report.Actions, action)
				continue
			}
			action, err = m.cleanupResource(manifest, resource, action, apply)
			if err != nil {
				action.Skipped = true
				action.Reason = err.Error()
				report.AmbiguousSkipped++
				allClean = false
			}
			report.Actions = append(report.Actions, action)
		}
		baselineDrift := false
		if apply && allClean && m.Verifier != nil {
			comparisons, verifyErr := m.Verifier.Verify(manifest.Baseline)
			if verifyErr != nil {
				allClean = false
				report.AmbiguousSkipped++
				report.Actions = append(report.Actions, CleanupAction{RunID: manifest.RunID, Owner: manifest.Owner.String(), Reason: verifyErr.Error(), Action: "baseline verification failed", Skipped: true})
			} else {
				report.Baseline = append(report.Baseline, comparisons...)
				for _, comparison := range comparisons {
					if !comparison.Matches {
						baselineDrift = true
					}
				}
			}
		}
		if apply && allClean {
			if baselineDrift {
				manifest.CleanupState = "drifted"
				manifest.FinalResult = "owned resources removed; baseline drift detected"
				report.Actions = append(report.Actions, CleanupAction{RunID: manifest.RunID, Owner: manifest.Owner.String(), Reason: "captured baseline differs after owned cleanup", Action: "record terminal baseline drift", Applied: true})
			} else {
				manifest.CleanupState = "complete"
				manifest.FinalResult = "stale resources removed"
			}
			if err := m.Save(manifest); err != nil {
				return report, err
			}
		}
	}
	if apply {
		if err := m.pruneCompleted(); err != nil {
			return report, err
		}
	}
	return report, nil
}

func cleanupStateTerminal(state string) bool {
	return state == "complete" || state == "drifted"
}

func (m Manager) listForCleanup() ([]Manifest, []CleanupAction, error) {
	entries, err := os.ReadDir(m.manifestsDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var manifests []Manifest
	var rejected []CleanupAction
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(m.manifestsDir(), entry.Name())
		info, infoErr := os.Lstat(path)
		if infoErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			rejected = append(rejected, CleanupAction{RunID: strings.TrimSuffix(entry.Name(), ".json"), Owner: "unknown", Reason: "manifest is not a regular owned file", Action: "skip corrupted owner manifest", Skipped: true})
			continue
		}
		raw, readErr := os.ReadFile(path)
		var manifest Manifest
		if readErr != nil || json.Unmarshal(raw, &manifest) != nil || manifest.Validate() != nil {
			rejected = append(rejected, CleanupAction{RunID: strings.TrimSuffix(entry.Name(), ".json"), Owner: "unknown", Reason: "manifest validation failed", Action: "skip corrupted owner manifest", Skipped: true})
			continue
		}
		manifests = append(manifests, manifest)
	}
	return manifests, rejected, nil
}

func (m Manager) pruneCompleted() error {
	limit := m.MaxCompleted
	if limit <= 0 {
		limit = 32
	}
	manifests, _, err := m.listForCleanup()
	if err != nil {
		return err
	}
	completed := make([]Manifest, 0, len(manifests))
	for _, manifest := range manifests {
		if cleanupStateTerminal(manifest.CleanupState) {
			completed = append(completed, manifest)
		}
	}
	if len(completed) <= limit {
		return nil
	}
	sort.Slice(completed, func(i, j int) bool { return completed[i].CreatedAt < completed[j].CreatedAt })
	for _, manifest := range completed[:len(completed)-limit] {
		path := filepath.Join(m.manifestsDir(), manifest.RunID+".json")
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing ambiguous completed manifest cleanup")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		writebudget.RecordDelete("completed test-run manifest retention")
	}
	return nil
}

func (m Manager) cleanupResource(manifest Manifest, resource Resource, action CleanupAction, apply bool) (CleanupAction, error) {
	switch resource.Kind {
	case ResourceProcess:
		if m.Inspector == nil {
			return action, fmt.Errorf("process inspector unavailable")
		}
		actual, err := m.Inspector.Inspect(resource.Process.PID)
		if errors.Is(err, os.ErrNotExist) {
			action.Action = "process already absent"
			action.Applied = apply
			return action, nil
		}
		if err != nil {
			return action, fmt.Errorf("inspect process: %w", err)
		}
		checks, ok := verifyProcessIdentity(*resource.Process, actual, manifest.RunID)
		action.OwnershipChecks = checks
		if !ok {
			return action, fmt.Errorf("process identity is ambiguous")
		}
		action.Action = "terminate exact owned process"
		if apply {
			if err := m.Inspector.Terminate(actual.PID); err != nil {
				return action, fmt.Errorf("terminate owned process: %w", err)
			}
			action.Applied = true
		}
		return action, nil
	case ResourceFile, ResourceArtifact, ResourceLock, ResourceTimer:
		if !withinRoot(resource.Path, m.RuntimeDir) && !withinRoot(resource.Path, filepath.Join(m.StateDir, "lifecycle", "test-runs", manifest.RunID)) {
			return action, fmt.Errorf("path is outside allowlisted test-run roots")
		}
		info, err := os.Lstat(resource.Path)
		if errors.Is(err, os.ErrNotExist) {
			action.Action = "file already absent"
			action.Applied = apply
			return action, nil
		}
		if err != nil {
			return action, err
		}
		if info.Mode()&os.ModeSymlink != 0 || info.IsDir() {
			return action, fmt.Errorf("refusing symlink or directory cleanup")
		}
		action.OwnershipChecks = []string{"owner matches manifest", "path is allowlisted", "target is a regular non-symlink file"}
		action.Action = "remove owned file"
		if apply {
			if err := os.Remove(resource.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return action, err
			}
			writebudget.RecordDelete("owned test-run runtime resource")
			action.Applied = true
		}
		return action, nil
	default:
		if m.Executor == nil {
			return action, fmt.Errorf("resource kind %s requires a namespace-specific cleanup executor", resource.Kind)
		}
		checks, planned, applied, err := m.Executor.Cleanup(manifest, resource, apply)
		action.OwnershipChecks = checks
		action.Action = planned
		action.Applied = applied
		return action, err
	}
}

func verifyProcessIdentity(expected, actual ProcessIdentity, runID string) ([]string, bool) {
	checks := []string{}
	ok := true
	check := func(name string, match bool) {
		if match {
			checks = append(checks, name+" matches")
		} else {
			checks = append(checks, name+" mismatch")
			ok = false
		}
	}
	check("PID", expected.PID > 0 && expected.PID == actual.PID)
	check("start time", expected.StartTimeTicks > 0 && expected.StartTimeTicks == actual.StartTimeTicks)
	check("process group", expected.PGID > 0 && expected.PGID == actual.PGID)
	check("executable", expected.Executable != "" && filepath.Clean(expected.Executable) == filepath.Clean(actual.Executable))
	if expected.ConfigPath != "" {
		check("config", containsArg(actual.CommandLine, expected.ConfigPath))
	}
	check("run identity", containsArg(actual.CommandLine, runID))
	return checks, ok
}

func containsArg(args []string, expected string) bool {
	for _, arg := range args {
		if arg == expected || strings.Contains(arg, expected) {
			return true
		}
	}
	return false
}

func withinRoot(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absRoot, absPath)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
