package routeassignment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-policy/internal/artifact"
	"router-policy/internal/config"
)

type recordingRunner struct {
	commands [][]string
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) error {
	r.commands = append(r.commands, append([]string{name}, args...))
	return nil
}

func TestApplyRollbackAndReconcileOnlyTouchOwnedOverlay(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		Version:  2,
		Platform: config.Platform{Target: "test", IPv6Enabled: false},
		Storage:  config.Storage{StateDir: root, RuntimeDir: filepath.Join(root, "runtime")},
		OpenWrt: config.OpenWrt{
			DNSMasqInclude: filepath.Join(root, "dnsmasq.d", "router-policy.conf"),
			NFTFamily:      "inet", NFTTable: "router_policy", WANRouteTable: 100,
			DirectMark: "0x41", ZapretMark: "0x42", XrayMark: "0x43", XrayTProxyMark: "0x100", XrayBypassMark: "0x200", DropMark: "0x7f",
		},
		Routes: []config.Route{
			{Type: "direct", Tag: "direct", Mark: "0x41"},
			{Type: "smart_dns", Tag: "smart", Mark: "0x41", DNSServer: "1.1.1.1:53", ConnectToResolvedIP: true},
			{Type: "drop", Tag: "drop", Mark: "0x7f"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("fixture config invalid: %v", err)
	}
	lastGood := filepath.Join(root, "last-good")
	if err := os.MkdirAll(filepath.Join(lastGood, "generated"), 0o700); err != nil {
		t.Fatal(err)
	}
	configBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	candidateSum := sha256.Sum256(configBytes)
	candidateHash := "sha256:" + hex.EncodeToString(candidateSum[:])
	manifestHash := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	revision := "rev_1_001122334455"
	txID := "tx_0011223344556677"
	if err := os.WriteFile(filepath.Join(lastGood, "router-policy-config.json"), configBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lastGood, "active-transaction.env"), []byte("transaction_id="+txID+"\nrevision_id="+revision+"\ncandidate_hash="+candidateHash+"\nartifact_manifest_hash="+manifestHash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := artifact.IPPlan{Binding: artifact.Binding{TransactionID: txID, RevisionID: revision, CandidateHash: candidateHash}, DeploymentReady: false, BlockReason: "fixture", FlowOffloading: artifact.FlowOffloadingPlan{RequestedPolicy: "preserve", Action: "none", Status: "NOT_APPLICABLE"}}
	planBytes, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lastGood, "generated", artifact.IPPlanFile), planBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	request := Request{
		RequestID: "req_0011223344556677", Generation: revision, RevisionID: revision,
		CandidateHash: candidateHash, ArtifactManifestHash: manifestHash, Domain: "youtube.com",
		RouteTag: "smart", RouteType: "smart_dns", RouteSetID: routeID("smart"), AssignmentID: assignmentID("youtube.com"),
		MappingHash: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	runner := &recordingRunner{}
	if err := Apply(context.Background(), cfg, request, Options{DNSMasqInit: "/sbin/dnsmasq", Runner: runner}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	include := filepath.Join(root, "dnsmasq.d", "router-policy-route-assignments.conf")
	raw, err := os.ReadFile(include)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !contains(text, "nftset=/youtube.com/4#inet#router_policy#route_"+request.RouteSetID+"_v4") || !contains(text, "server=/youtube.com/1.1.1.1#53") {
		t.Fatalf("owned overlay lacks exact mapping: %s", text)
	}
	if len(runner.commands) != 2 || runner.commands[0][0] != "/sbin/dnsmasq" || runner.commands[0][1] != "restart" || runner.commands[1][1] != "running" {
		t.Fatalf("unexpected privileged operations: %#v", runner.commands)
	}
	if err := Rollback(context.Background(), cfg, request, Options{DNSMasqInit: "/sbin/dnsmasq", Runner: runner}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	raw, err = os.ReadFile(include)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(raw), "youtube.com") {
		t.Fatalf("rollback left assignment in owned overlay: %s", raw)
	}
	if err := Apply(context.Background(), cfg, request, Options{DNSMasqInit: "/sbin/dnsmasq", Runner: runner}); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if err := Reconcile(context.Background(), cfg, Options{DNSMasqInit: "/sbin/dnsmasq", Runner: runner}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	raw, err = os.ReadFile(include)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(raw), "youtube.com") {
		t.Fatal("reconcile removed the persistent assignment")
	}

	// If the durable manifest disappears after a crash but the owned include
	// survives, reconcile must not treat that include as active state. It must
	// clear only the owned overlay and recreate a bound empty manifest.
	manifestPath := filepath.Join(root, "route-assignments.json")
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(context.Background(), cfg, Options{DNSMasqInit: "/sbin/dnsmasq", Runner: runner}); err != nil {
		t.Fatalf("reconcile missing manifest: %v", err)
	}
	raw, err = os.ReadFile(include)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(raw), "youtube.com") {
		t.Fatalf("reconcile trusted an owned overlay without a durable manifest: %s", raw)
	}
	if !contains(string(raw), "# FlintRoute owned route-only overlay revision="+revision) {
		t.Fatalf("reconcile did not recreate a bound empty overlay: %s", raw)
	}
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("reconcile did not recreate durable manifest: %v", err)
	}
	if err := Apply(context.Background(), cfg, request, Options{DNSMasqInit: "/sbin/dnsmasq", Runner: runner}); err != nil {
		t.Fatalf("re-apply after missing manifest: %v", err)
	}

	// A subsequent full revision must invalidate the old route-only mapping,
	// not turn a stale overlay into a recovery failure.
	cfg2 := *cfg
	cfg2.Version++
	configBytes2, err := json.Marshal(&cfg2)
	if err != nil {
		t.Fatal(err)
	}
	candidateSum2 := sha256.Sum256(configBytes2)
	candidateHash2 := "sha256:" + hex.EncodeToString(candidateSum2[:])
	revision2 := "rev_2_001122334455"
	if err := os.WriteFile(filepath.Join(lastGood, "router-policy-config.json"), configBytes2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lastGood, "active-transaction.env"), []byte("transaction_id="+txID+"\nrevision_id="+revision2+"\ncandidate_hash="+candidateHash2+"\nartifact_manifest_hash="+manifestHash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan.Binding.RevisionID = revision2
	plan.Binding.CandidateHash = candidateHash2
	planBytes2, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lastGood, "generated", artifact.IPPlanFile), planBytes2, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg2.OpenWrt.DNSMasqInclude = cfg.OpenWrt.DNSMasqInclude
	if err := Reconcile(context.Background(), &cfg2, Options{DNSMasqInit: "/sbin/dnsmasq", Runner: runner}); err != nil {
		t.Fatalf("stale mapping reconcile: %v", err)
	}
	raw, err = os.ReadFile(include)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(raw), "youtube.com") {
		t.Fatalf("stale mapping survived active revision change: %s", raw)
	}
	if err := ReconcileBound(context.Background(), &cfg2, Request{
		Generation: "rev_9_001122334455", RevisionID: "rev_9_001122334455",
		CandidateHash: "sha256:" + strings.Repeat("d", 64), ArtifactManifestHash: manifestHash,
	}, Options{DNSMasqInit: "/sbin/dnsmasq", Runner: runner}); err == nil {
		t.Fatal("reconcile accepted a binding that differs from durable active state")
	}

	// A missing manifest plus a foreign include is ambiguous. Refuse the
	// operation and leave the foreign writer's bytes untouched.
	foreign := []byte("# foreign dnsmasq include\nserver=/foreign.example/9.9.9.9\n")
	if err := os.WriteFile(include, foreign, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(context.Background(), &cfg2, Options{DNSMasqInit: "/sbin/dnsmasq", Runner: runner}); err == nil {
		t.Fatal("reconcile overwrote a foreign include without a durable manifest")
	}
	got, err := os.ReadFile(include)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(foreign) {
		t.Fatalf("foreign include changed after refused reconcile: %q", got)
	}
}

func contains(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}

func TestReadManifestRejectsUntrustedObjectData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route-assignments.json")
	value := manifest{
		Version: manifestVersion, Generation: "rev_1_001122334455", RevisionID: "rev_1_001122334455",
		CandidateHash: "sha256:" + strings.Repeat("a", 64), ArtifactManifestHash: "sha256:" + strings.Repeat("b", 64),
		Assignments: []Assignment{{
			Domain: "youtube.com\nserver=/evil/1.2.3.4", RouteTag: "smart", RouteType: "smart_dns",
			RouteSetID: routeID("smart"), AssignmentID: assignmentID("youtube.com"), MappingHash: "sha256:" + strings.Repeat("c", 64),
		}},
	}
	if err := writeJSONAtomic(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(path); err == nil {
		t.Fatal("manifest accepted newline-bearing domain")
	}

	value.Assignments[0].Domain = "youtube.com"
	value.Assignments[0].AssignmentID = assignmentID("other.example")
	if err := writeJSONAtomic(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(path); err == nil {
		t.Fatal("manifest accepted mismatched deterministic assignment ID")
	}
}
