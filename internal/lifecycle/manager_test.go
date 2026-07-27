package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeInspector struct {
	identities map[int]ProcessIdentity
	terminated []int
}

func (f *fakeInspector) Inspect(pid int) (ProcessIdentity, error) {
	identity, ok := f.identities[pid]
	if !ok {
		return ProcessIdentity{}, os.ErrNotExist
	}
	return identity, nil
}

func (f *fakeInspector) Terminate(pid int) error {
	if _, ok := f.identities[pid]; !ok {
		return errors.New("not found")
	}
	f.terminated = append(f.terminated, pid)
	delete(f.identities, pid)
	return nil
}

func TestStaleCleanupRequiresFullProcessIdentityAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 7, 22, 7, 0, 0, 0, time.UTC)
	inspector := &fakeInspector{identities: map[int]ProcessIdentity{42: {
		PID: 42, StartTimeTicks: 9001, Executable: "/usr/bin/xray",
		CommandLine: []string{"/usr/bin/xray", "run", "-config", "/tmp/router-policy/test-runs/run-1/xray.json", "--owner", "run-1"},
	}}}
	manager := Manager{StateDir: filepath.Join(root, "state"), RuntimeDir: filepath.Join(root, "run"), Inspector: inspector, Now: func() time.Time { return now }}
	manifest := testManifest(now, "run-1")
	manifest.Resources = []Resource{{
		ID: "xray", Kind: ResourceProcess, Owner: manifest.Owner, AllowCleanup: true,
		Process: &ProcessIdentity{PID: 42, StartTimeTicks: 9001, Executable: "/usr/bin/xray", ConfigPath: "/tmp/router-policy/test-runs/run-1/xray.json"},
	}}
	if err := manager.Save(manifest); err != nil {
		t.Fatal(err)
	}
	dry, err := manager.CleanupStale(false)
	if err != nil || len(inspector.terminated) != 0 || len(dry.Actions) != 1 || dry.Actions[0].Skipped {
		t.Fatalf("bad dry-run: report=%+v err=%v terminated=%v", dry, err, inspector.terminated)
	}
	applied, err := manager.CleanupStale(true)
	if err != nil || len(inspector.terminated) != 1 || !applied.Actions[0].Applied {
		t.Fatalf("bad apply: report=%+v err=%v terminated=%v", applied, err, inspector.terminated)
	}
	again, err := manager.CleanupStale(true)
	if err != nil || len(inspector.terminated) != 1 || again.StaleRuns != 0 {
		t.Fatalf("cleanup is not idempotent: report=%+v err=%v terminated=%v", again, err, inspector.terminated)
	}
}

func TestPIDReuseAndForeignNamedProcessAreProtected(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 7, 22, 7, 0, 0, 0, time.UTC)
	inspector := &fakeInspector{identities: map[int]ProcessIdentity{42: {
		PID: 42, StartTimeTicks: 9999, Executable: "/usr/bin/xray",
		CommandLine: []string{"/usr/bin/xray", "run", "-config", "/tmp/foreign.json"},
	}}}
	manager := Manager{StateDir: filepath.Join(root, "state"), RuntimeDir: filepath.Join(root, "run"), Inspector: inspector, Now: func() time.Time { return now }}
	manifest := testManifest(now, "run-2")
	manifest.Resources = []Resource{{
		ID: "xray", Kind: ResourceProcess, Owner: manifest.Owner, AllowCleanup: true,
		Process: &ProcessIdentity{PID: 42, StartTimeTicks: 9001, Executable: "/usr/bin/xray", ConfigPath: "/tmp/router-policy/test-runs/run-2/xray.json"},
	}}
	if err := manager.Save(manifest); err != nil {
		t.Fatal(err)
	}
	report, err := manager.CleanupStale(true)
	if err != nil || len(inspector.terminated) != 0 || report.AmbiguousSkipped != 1 || !report.Actions[0].Skipped {
		t.Fatalf("PID reuse was not protected: report=%+v err=%v", report, err)
	}
}

func TestCleanupOnlyRemovesAllowlistedRegularFiles(t *testing.T) {
	root := t.TempDir()
	runtimeDir := filepath.Join(root, "run")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 22, 7, 0, 0, 0, time.UTC)
	manager := Manager{StateDir: filepath.Join(root, "state"), RuntimeDir: runtimeDir, Inspector: &fakeInspector{}, Now: func() time.Time { return now }}
	owned := filepath.Join(runtimeDir, "run-3.tmp")
	if err := os.WriteFile(owned, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "foreign.tmp")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := testManifest(now, "run-3")
	manifest.Resources = []Resource{
		{ID: "owned", Kind: ResourceFile, Owner: manifest.Owner, Path: owned, AllowCleanup: true},
		{ID: "foreign", Kind: ResourceFile, Owner: manifest.Owner, Path: foreign, AllowCleanup: true},
	}
	if err := manager.Save(manifest); err != nil {
		t.Fatal(err)
	}
	report, err := manager.CleanupStale(true)
	if err != nil || report.AmbiguousSkipped != 1 {
		t.Fatalf("unexpected report: %+v err=%v", report, err)
	}
	if _, err := os.Stat(owned); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned file remains")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("foreign file was removed")
	}
}

func TestHundredSequentialRunsReturnToBaselineAndHistoryIsBounded(t *testing.T) {
	root := t.TempDir()
	runtimeDir := filepath.Join(root, "run")
	now := time.Date(2026, 7, 22, 7, 0, 0, 0, time.UTC)
	manager := Manager{StateDir: filepath.Join(root, "state"), RuntimeDir: runtimeDir, Inspector: &fakeInspector{}, Now: func() time.Time { return now }, MaxCompleted: 16}
	for index := 0; index < 100; index++ {
		runID := fmt.Sprintf("run-%03d", index)
		path := filepath.Join(runtimeDir, runID+".tmp")
		if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("temporary"), 0o600); err != nil {
			t.Fatal(err)
		}
		manifest := testManifest(now.Add(time.Duration(index)*time.Minute), runID)
		manifest.Resources = []Resource{{ID: "file", Kind: ResourceFile, Owner: manifest.Owner, Path: path, AllowCleanup: true}}
		if err := manager.Save(manifest); err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Minute)
		if _, err := manager.CleanupStale(true); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("run %d did not return to file baseline", index)
		}
	}
	manifests, err := manager.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) > 16 {
		t.Fatalf("completed run history is unbounded: %d", len(manifests))
	}
}

func TestCorruptedOwnerManifestIsSkippedWithoutTouchingResource(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	runtimeDir := filepath.Join(root, "run")
	manifestDir := filepath.Join(stateDir, "lifecycle", "test-runs")
	if err := os.MkdirAll(manifestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	resource := filepath.Join(runtimeDir, "foreign.tmp")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resource, []byte("do not remove"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifestDir, "broken.json"), []byte(`{"schema_version":1,"run_id":"broken","owner":{"class":"production"},"resources":[{"id":"file","kind":"file","path":"`+filepath.ToSlash(resource)+`","allow_cleanup":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := Manager{StateDir: stateDir, RuntimeDir: runtimeDir, Inspector: &fakeInspector{}}
	report, err := manager.CleanupStale(true)
	if err != nil || report.AmbiguousSkipped != 1 {
		t.Fatalf("corrupt manifest was not safely skipped: report=%+v err=%v", report, err)
	}
	if _, err := os.Stat(resource); err != nil {
		t.Fatal("resource referenced by corrupt manifest was removed")
	}
}

func TestTestRunRegistrationAndFinishPreserveOwnerIdentity(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	manager := Manager{StateDir: filepath.Join(root, "state"), RuntimeDir: filepath.Join(root, "run"), Inspector: &fakeInspector{}, Now: func() time.Time { return now }}
	manifest, err := manager.BeginTestRun("hardware-1", time.Hour, Baseline{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(manager.RuntimeDir, "hardware-1.tmp")
	if err := os.MkdirAll(manager.RuntimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tmp"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err = manager.AddResource(manifest.RunID, Resource{ID: "working-file", Kind: ResourceFile, Path: path, AllowCleanup: true})
	if err != nil || manifest.Resources[0].Owner.String() != "test-run:hardware-1" {
		t.Fatalf("resource owner was not bound: manifest=%+v err=%v", manifest, err)
	}
	manifest, err = manager.FinishTestRun(manifest.RunID, "passed")
	if err != nil || manifest.CleanupState != "pending" {
		t.Fatalf("finish failed: manifest=%+v err=%v", manifest, err)
	}
	if _, err := manager.CleanupStale(true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("finished run did not clean its registered file")
	}
}

func testManifest(now time.Time, runID string) Manifest {
	owner := Owner{Class: OwnerTestRun, ID: runID}
	return Manifest{
		SchemaVersion: ManifestSchemaVersion, RunID: runID, Owner: owner,
		CreatedAt: now.Add(-2 * time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339),
		Baseline: Baseline{CapturedAt: now.Add(-2 * time.Hour).Format(time.RFC3339)}, CleanupState: "pending",
	}
}
