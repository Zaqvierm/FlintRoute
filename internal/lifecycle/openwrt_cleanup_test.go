package lifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type cleanupCommand struct {
	name string
	args []string
}

type fakeCleanupRunner struct {
	outputs  map[string][]byte
	errors   map[string]error
	commands []cleanupCommand
}

func (f *fakeCleanupRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	f.commands = append(f.commands, cleanupCommand{name: name, args: append([]string(nil), args...)})
	return f.outputs[key], f.errors[key]
}

func TestOpenWrtCleanupDeletesOnlyTestNamespaceResources(t *testing.T) {
	manifest := testManifestForExecutor("run-1")
	runner := &fakeCleanupRunner{outputs: map[string][]byte{
		"nft list table inet router_policy_test_run_1":       []byte("table inet router_policy_test_run_1 {}"),
		"ip -4 rule show pref 30001":                         []byte("30001: from all lookup 30001"),
		"ip -4 route show table 30001 exact 198.51.100.0/24": []byte("198.51.100.0/24 dev lo"),
	}, errors: map[string]error{}}
	executor := OpenWrtResourceExecutor{Runner: runner}
	resources := []Resource{
		{ID: "nft", Kind: ResourceNFTTable, Owner: manifest.Owner, Family: "inet", Table: "router_policy_test_run_1", AllowCleanup: true},
		{ID: "rule", Kind: ResourceIPRule, Owner: manifest.Owner, Family: "ipv4", Table: "30001", Metadata: map[string]string{"priority": "30001"}, AllowCleanup: true},
		{ID: "route", Kind: ResourceRoute, Owner: manifest.Owner, Family: "ipv4", Table: "30001", Address: "198.51.100.0/24", AllowCleanup: true},
	}
	for _, resource := range resources {
		checks, _, applied, err := executor.Cleanup(manifest, resource, true)
		if err != nil || !applied || len(checks) < 3 {
			t.Fatalf("resource %s was not cleaned: checks=%v applied=%t err=%v", resource.ID, checks, applied, err)
		}
	}
	if len(runner.commands) != 6 {
		t.Fatalf("expected inspect+delete per resource, got %d commands", len(runner.commands))
	}
}

func TestOpenWrtCleanupRejectsProductionLikeAndAmbiguousResources(t *testing.T) {
	manifest := testManifestForExecutor("run-2")
	runner := &fakeCleanupRunner{outputs: map[string][]byte{}, errors: map[string]error{}}
	executor := OpenWrtResourceExecutor{Runner: runner}
	cases := []Resource{
		{ID: "production-table", Kind: ResourceNFTTable, Owner: manifest.Owner, Family: "inet", Table: "router_policy", AllowCleanup: true},
		{ID: "production-rule", Kind: ResourceIPRule, Owner: manifest.Owner, Family: "ipv4", Table: "100", Metadata: map[string]string{"priority": "100"}, AllowCleanup: true},
		{ID: "wildcard-route", Kind: ResourceRoute, Owner: manifest.Owner, Family: "ipv4", Table: "30002", Address: "default", AllowCleanup: true},
		{ID: "public-listener", Kind: ResourceListener, Owner: manifest.Owner, Address: "0.0.0.0:12345", AllowCleanup: true},
	}
	for _, resource := range cases {
		if _, _, applied, err := executor.Cleanup(manifest, resource, true); err == nil || applied {
			t.Fatalf("ambiguous resource %s was accepted", resource.ID)
		}
	}
	if len(runner.commands) != 0 {
		t.Fatalf("unsafe resources reached command runner: %+v", runner.commands)
	}
}

func TestOpenWrtCleanupNeverDeletesMismatchedLiveRule(t *testing.T) {
	manifest := testManifestForExecutor("run-3")
	runner := &fakeCleanupRunner{outputs: map[string][]byte{
		"ip -4 rule show pref 30003": []byte("30003: from all lookup 100"),
	}, errors: map[string]error{}}
	resource := Resource{ID: "rule", Kind: ResourceIPRule, Owner: manifest.Owner, Family: "ipv4", Table: "30003", Metadata: map[string]string{"priority": "30003"}, AllowCleanup: true}
	_, _, applied, err := (OpenWrtResourceExecutor{Runner: runner}).Cleanup(manifest, resource, true)
	if err == nil || applied || len(runner.commands) != 1 {
		t.Fatalf("mismatched rule was not protected: applied=%t commands=%+v err=%v", applied, runner.commands, err)
	}
}

func TestOpenWrtCleanupTreatsAbsentNFTTableAsIdempotent(t *testing.T) {
	manifest := testManifestForExecutor("run-4")
	key := "nft list table inet router_policy_test_run_4"
	runner := &fakeCleanupRunner{outputs: map[string][]byte{key: []byte("No such file or directory")}, errors: map[string]error{key: errors.New("exit 1")}}
	resource := Resource{ID: "nft", Kind: ResourceNFTTable, Owner: manifest.Owner, Family: "inet", Table: "router_policy_test_run_4", AllowCleanup: true}
	_, action, applied, err := (OpenWrtResourceExecutor{Runner: runner}).Cleanup(manifest, resource, true)
	if err != nil || !applied || action != "nft table already absent" || len(runner.commands) != 1 {
		t.Fatalf("absent table was not idempotent: action=%q applied=%t err=%v", action, applied, err)
	}
}

func TestOpenWrtListenerCleanupFallsBackToBusyBoxNetstat(t *testing.T) {
	manifest := testManifestForExecutor("run-5")
	ssKey := "ss -H -lntup sport = :18081"
	netstatKey := "netstat -lntup"
	runner := &fakeCleanupRunner{
		outputs: map[string][]byte{netstatKey: []byte("tcp 0 0 127.0.0.1:8787 0.0.0.0:* LISTEN 1/router-policy\n")},
		errors:  map[string]error{ssKey: errors.New("executable file not found")},
	}
	resource := Resource{ID: "listener", Kind: ResourceListener, Owner: manifest.Owner, Address: "127.0.0.1:18081", AllowCleanup: true}
	_, action, applied, err := (OpenWrtResourceExecutor{Runner: runner}).Cleanup(manifest, resource, true)
	if err != nil || !applied || action != "listener already absent" || len(runner.commands) != 2 {
		t.Fatalf("netstat fallback failed: action=%q applied=%t commands=%+v err=%v", action, applied, runner.commands, err)
	}
	runner.outputs[netstatKey] = []byte("tcp 0 0 127.0.0.1:18081 0.0.0.0:* LISTEN 99/test\n")
	_, _, applied, err = (OpenWrtResourceExecutor{Runner: runner}).Cleanup(manifest, resource, true)
	if err == nil || applied {
		t.Fatalf("live fallback listener was not protected: applied=%t err=%v", applied, err)
	}
}

func testManifestForExecutor(runID string) Manifest {
	return Manifest{RunID: runID, Owner: Owner{Class: OwnerTestRun, ID: runID}}
}
