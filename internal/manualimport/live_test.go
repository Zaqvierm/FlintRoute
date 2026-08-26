package manualimport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-policy/internal/lifecycle"
)

type fakeLiveInspector struct {
	identity lifecycle.ProcessIdentity
	err      error
}

func (f fakeLiveInspector) Inspect(int) (lifecycle.ProcessIdentity, error) {
	return f.identity, f.err
}

func livePlanFixture(t *testing.T) AdoptionPlan {
	t.Helper()
	return AdoptionPlan{
		SchemaVersion:   1,
		GeneratedAt:     time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		CandidateSHA256: handoffHash,
		Resources: []AdoptionResource{
			{Kind: "process", Identifier: "manual-xray", ObservedOwner: "manual"},
			{Kind: "file", Identifier: "manual-dnsmasq-include", ObservedOwner: "manual"},
			{Kind: "listener", Identifier: "127.0.0.1:12345", ObservedOwner: "manual-xray"},
		},
		Blockers: []Conflict{},
		Steps:    []string{"review"},
	}
}

func TestCaptureLiveObservationIsReadOnlyAndRedacted(t *testing.T) {
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.txt")
	if err := os.WriteFile(evidencePath, []byte("manual evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := livePlanFixture(t)
	observation, err := CaptureLiveObservation(LiveObservationOptions{
		Plan: plan,
		ProcessTargets: []LiveProcessTarget{{
			Kind: "process", Identifier: "manual-xray", PID: 42, ConfigPath: evidencePath,
		}},
		EvidenceTargets: []LiveEvidenceTarget{{
			Kind: "file", Identifier: "manual-dnsmasq-include", Path: evidencePath,
		}},
		Inspector: fakeLiveInspector{identity: lifecycle.ProcessIdentity{
			PID: 42, StartTimeTicks: 99, PGID: 41, Executable: "/usr/bin/xray",
			CommandLine: []string{"xray", "--credential=do-not-print"},
		}},
		GeneratedAt: time.Date(2026, 8, 26, 1, 2, 3, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := observation.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(observation.Resources) != 3 {
		t.Fatalf("unexpected resource count: %d", len(observation.Resources))
	}
	var process LiveResourceObservation
	for _, resource := range observation.Resources {
		if resource.Kind == "process" {
			process = resource
			break
		}
	}
	if process.Kind != "process" || process.State != "observed" || process.PGID != 41 || process.ConfigSHA256 == "" {
		t.Fatalf("unexpected process observation: %+v", process)
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "do-not-print") || strings.Contains(string(raw), evidencePath) {
		t.Fatalf("live observation leaked sensitive/raw input: %s", raw)
	}
	after, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "manual evidence" {
		t.Fatal("capture modified evidence file")
	}
}

func TestCaptureLiveObservationKeepsMissingAndUnavailableEvidenceExplicit(t *testing.T) {
	plan := livePlanFixture(t)
	observation, err := CaptureLiveObservation(LiveObservationOptions{
		Plan:           plan,
		ProcessTargets: []LiveProcessTarget{{Kind: "process", Identifier: "manual-xray", PID: 42}},
		Inspector:      fakeLiveInspector{err: os.ErrNotExist},
		GeneratedAt:    time.Date(2026, 8, 26, 1, 2, 3, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	var process LiveResourceObservation
	for _, resource := range observation.Resources {
		if resource.Kind == "process" {
			process = resource
			break
		}
	}
	if process.State != "error" || process.Error != "process_unavailable" {
		t.Fatalf("process failure was not explicit: %+v", process)
	}
	var missing int
	for _, resource := range observation.Resources {
		if resource.State == "missing" {
			missing++
		}
	}
	if missing != 2 {
		t.Fatalf("unprovided resources were not marked missing: %+v", observation.Resources)
	}
}

func TestCaptureLiveObservationRejectsUnknownOrDuplicateTargets(t *testing.T) {
	plan := livePlanFixture(t)
	_, err := CaptureLiveObservation(LiveObservationOptions{
		Plan:           plan,
		ProcessTargets: []LiveProcessTarget{{Kind: "process", Identifier: "not-in-plan", PID: 1}},
	})
	if err == nil || !strings.Contains(err.Error(), "not a process") {
		t.Fatalf("unknown target was accepted: %v", err)
	}
	_, err = CaptureLiveObservation(LiveObservationOptions{
		Plan: plan,
		ProcessTargets: []LiveProcessTarget{
			{Kind: "process", Identifier: "manual-xray", PID: 1},
			{Kind: "process", Identifier: "manual-xray", PID: 2},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate target was accepted: %v", err)
	}
}

func TestCaptureLiveObservationRejectsSymlinkEvidence(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := CaptureLiveObservation(LiveObservationOptions{
		Plan:            livePlanFixture(t),
		EvidenceTargets: []LiveEvidenceTarget{{Kind: "file", Identifier: "manual-dnsmasq-include", Path: link}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The plan still has an explicit observation; the unsafe input is retained
	// as an error state rather than being followed or silently omitted.
	for _, resource := range mustCaptureLiveObservation(t, livePlanFixture(t), link).Resources {
		if resource.Identifier == "manual-dnsmasq-include" {
			if resource.State != "error" || resource.Error != "evidence_unavailable" {
				t.Fatalf("symlink evidence was not fenced: %+v", resource)
			}
		}
	}
}

func mustCaptureLiveObservation(t *testing.T, plan AdoptionPlan, path string) LiveObservation {
	t.Helper()
	observation, err := CaptureLiveObservation(LiveObservationOptions{
		Plan:            plan,
		EvidenceTargets: []LiveEvidenceTarget{{Kind: "file", Identifier: "manual-dnsmasq-include", Path: path}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return observation
}
