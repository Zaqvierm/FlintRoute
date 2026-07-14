package domaincache

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/probe"
	"router-policy/internal/state"
)

func TestBaseDecisionCoversSiblingAndDifferentRouteCreatesExactOverride(t *testing.T) {
	store := openTestStore(t)
	manager, err := New(store, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	base := testDecision(now, "direct", "direct")
	if saved, err := manager.Save("api.example.com", base); err != nil {
		t.Fatal(err)
	} else if saved.Scope != "etld_plus_one" || saved.Key != "base:example.com" {
		t.Fatalf("unexpected base decision: %+v", saved)
	}

	if hit, ok, err := manager.Lookup("cdn.example.com", "rev-1", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	} else if !ok || hit.SelectedRoute != "direct" {
		t.Fatalf("sibling did not reuse eTLD+1 decision: ok=%v hit=%+v", ok, hit)
	}

	override := testDecision(now.Add(2*time.Minute), "vless-a", "vless")
	if saved, err := manager.Save("video.example.com", override); err != nil {
		t.Fatal(err)
	} else if saved.Scope != "exact" || saved.Key != "exact:video.example.com" {
		t.Fatalf("different route must create exact override: %+v", saved)
	}
	if hit, ok, err := manager.Lookup("video.example.com", "rev-1", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	} else if !ok || hit.SelectedRoute != "vless-a" {
		t.Fatalf("exact override did not win: ok=%v hit=%+v", ok, hit)
	}
}

func TestDecisionIsRevisionBoundAndExpires(t *testing.T) {
	store := openTestStore(t)
	manager, err := New(store, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	if _, err := manager.Save("example.com", testDecision(now, "direct", "direct")); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := manager.Lookup("example.com", "rev-2", now.Add(time.Minute)); err != nil || ok {
		t.Fatalf("stale revision returned from cache: ok=%v err=%v", ok, err)
	}
	if _, ok, err := manager.Lookup("example.com", "rev-1", now.Add(25*time.Hour)); err != nil || ok {
		t.Fatalf("expired decision returned from cache: ok=%v err=%v", ok, err)
	}
}

func TestExpiredExactOverrideDoesNotFallBackToBaseDecision(t *testing.T) {
	store := openTestStore(t)
	manager, err := New(store, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	if _, err := manager.Save("api.example.com", testDecision(now, "direct", "direct")); err != nil {
		t.Fatal(err)
	}
	override := testDecision(now.Add(time.Minute), "vless-a", "vless")
	override.ExpiresAt = now.Add(2 * time.Minute)
	if _, err := manager.Save("video.example.com", override); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := manager.Lookup("video.example.com", "rev-1", now.Add(3*time.Minute)); err != nil || ok {
		t.Fatalf("expired exact override resurrected base decision: ok=%v err=%v", ok, err)
	}
	if hit, ok, err := manager.Lookup("cdn.example.com", "rev-1", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	} else if !ok || hit.SelectedRoute != "direct" {
		t.Fatalf("unrelated sibling lost valid base decision: ok=%v hit=%+v", ok, hit)
	}
}

func TestTSPUIdentityDifferenceCreatesExactOverride(t *testing.T) {
	store := openTestStore(t)
	manager, err := New(store, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	base := testDecision(now, "direct", "direct")
	base.TSPUStatus = "NO_MATCH"
	if _, err := manager.Save("api.example.com", base); err != nil {
		t.Fatal(err)
	}
	override := testDecision(now.Add(time.Minute), "direct", "direct")
	override.TSPUStatus = "STALE_MATCH"
	saved, err := manager.Save("video.example.com", override)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Scope != "exact" {
		t.Fatalf("TSPU-specific decision polluted eTLD+1 base: %+v", saved)
	}
}

func TestLRUPrunesOldestDecision(t *testing.T) {
	store := openTestStore(t)
	manager, err := New(store, 2)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	for i, domain := range []string{"one.test", "two.test", "three.test"} {
		decision := testDecision(now.Add(time.Duration(i)*time.Minute), "direct", "direct")
		if _, err := manager.Save(domain, decision); err != nil {
			t.Fatal(err)
		}
	}
	if got := manager.Snapshot(); len(got) != 2 {
		t.Fatalf("expected bounded cache, got %d entries", len(got))
	}
	if _, ok, err := manager.Lookup("one.test", "rev-1", now.Add(10*time.Minute)); err != nil || ok {
		t.Fatalf("oldest entry was not pruned: ok=%v err=%v", ok, err)
	}
}

func TestDecisionSurvivesBboltRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	store, err := state.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := New(store, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	if _, err := manager.Save("api.example.com", testDecision(now, "vless-a", "vless")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = state.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	manager, err = New(store, 10)
	if err != nil {
		t.Fatal(err)
	}
	if hit, ok, err := manager.Lookup("cdn.example.com", "rev-1", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	} else if !ok || hit.SelectedRoute != "vless-a" || len(hit.Results) != 1 {
		t.Fatalf("decision did not survive restart: ok=%v hit=%+v", ok, hit)
	}
}

func TestFailedReplacementRestoresInMemoryDecision(t *testing.T) {
	store := &failingStore{entries: map[string][]byte{}}
	manager, err := New(store, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	if _, err := manager.Save("example.com", testDecision(now, "direct", "direct")); err != nil {
		t.Fatal(err)
	}
	store.failSave = true
	if _, err := manager.Save("example.com", testDecision(now.Add(time.Minute), "vless-a", "vless")); err == nil {
		t.Fatal("expected persistence failure")
	}
	store.failSave = false
	if hit, ok, err := manager.Lookup("example.com", "rev-1", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	} else if !ok || hit.SelectedRoute != "direct" {
		t.Fatalf("failed write replaced live decision: ok=%v hit=%+v", ok, hit)
	}
}

func openTestStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(testConfig(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func testConfig(dir string) *config.Config {
	return &config.Config{Storage: config.Storage{StateDir: dir, Database: filepath.Join(dir, "state.bbolt")}}
}

func testDecision(now time.Time, route, routeType string) Decision {
	reason := "verified"
	return Decision{
		Service:         "UNKNOWN:example.com",
		Category:        "DIRECT_PREFERRED",
		SelectedRoute:   route,
		SelectedType:    routeType,
		Status:          "SELECTED",
		Reason:          "best_verified_route",
		AdapterRevision: "rev-1",
		Confidence:      0.9,
		Results: []probe.RouteResult{{
			Route: route, RouteType: routeType, Status: "OK", PathVerified: true,
			Checks: []probe.CheckResult{{Name: "path", Status: "OK"}}, Reason: &reason,
		}},
		CheckedAt:  now,
		ExpiresAt:  now.Add(24 * time.Hour),
		LastUsedAt: now,
	}
}

type failingStore struct {
	entries  map[string][]byte
	failSave bool
}

func (s *failingStore) SaveJSON(bucket, key string, value any) error {
	if s.failSave {
		return errors.New("write failed")
	}
	data, err := jsonMarshal(value)
	if err != nil {
		return err
	}
	s.entries[bucket+"/"+key] = data
	return nil
}

func (s *failingStore) ListRaw(bucket string) ([][]byte, error) {
	var out [][]byte
	for key, value := range s.entries {
		if len(key) > len(bucket) && key[:len(bucket)+1] == bucket+"/" {
			out = append(out, append([]byte(nil), value...))
		}
	}
	return out, nil
}

func (s *failingStore) Delete(bucket, key string) error {
	delete(s.entries, bucket+"/"+key)
	return nil
}

var jsonMarshal = func(value any) ([]byte, error) {
	return json.Marshal(value)
}
