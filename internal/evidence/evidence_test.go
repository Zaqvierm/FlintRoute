package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"router-policy/internal/artifact"
)

func TestEvidenceRequiresEveryBoundRoute(t *testing.T) {
	root := t.TempDir()
	binding := artifact.Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	plan := artifact.VerificationPlan{Binding: binding, RequireDNSLeakCheck: true, RequireIPv6LeakCheck: true, RequiredRouteProof: []artifact.RouteProof{{
		Tag: "direct", Type: "direct", Mark: "0x41", Table: 100, RulePriority: 10010,
		RequiresIPv4: true, RequiresIPv6: true, RequiresEgress: true,
	}}}
	writeJSON(t, filepath.Join(root, "plan.json"), plan)
	report := Report{Binding: binding, ArtifactManifestHash: "sha256:manifest", DNSLeakFree: true, IPv6LeakFree: true, CheckedAt: time.Now().UTC(), Routes: []RouteResult{{
		RouteTag: "direct", RouteType: "direct", AdapterRevision: binding.RevisionID, CandidateHash: binding.CandidateHash, ArtifactManifestHash: "sha256:manifest",
		NFTMark: "0x41", ConntrackMark: "0x41", IPRulePriority: 10010, RouteTable: 100, Interface: "wan", DNSResolver: "192.0.2.53",
		ResolvedIP: "192.0.2.1", ConnectedIP: "192.0.2.1", ExternalIPHash: "sha256:egress", ExternalCountry: "DE",
		DirectBypassXray: true, DirectBypassZapret: true, InheritedMarkCleared: true, IPv4Verified: true, IPv6Verified: true,
		HTTPResult: "OK", ContentResult: "OK", ReasonCode: "verified", Status: "OK", EvidenceSource: "test", CheckedAt: time.Now().UTC(),
	}}}
	evidencePath := filepath.Join(root, "evidence.json")
	writeJSON(t, evidencePath, report)
	if _, err := LoadAndVerify(filepath.Join(root, "plan.json"), evidencePath, binding, "sha256:manifest"); err != nil {
		t.Fatal(err)
	}
	report.Routes[0].RouteTable = 200
	writeJSON(t, evidencePath, report)
	if _, err := LoadAndVerify(filepath.Join(root, "plan.json"), evidencePath, binding, "sha256:manifest"); err == nil {
		t.Fatal("wrong-route evidence was accepted")
	}
}

func TestSmartDNSProofDoesNotRequireForeignEgress(t *testing.T) {
	binding := artifact.Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	required := artifact.RouteProof{Tag: "smart", Type: "smart_dns", Table: 100, RulePriority: 10010, RequiresIPv4: true, RequiresIPv6: true}
	actual := RouteResult{
		RouteTag: "smart", RouteType: "smart_dns", AdapterRevision: binding.RevisionID, CandidateHash: binding.CandidateHash, ArtifactManifestHash: "sha256:manifest",
		IPRulePriority: 10010, RouteTable: 100, Interface: "wan", DNSResolver: "192.0.2.53:53", DNSResponseSafe: true,
		ResolvedIP: "203.0.113.10", ConnectedIP: "203.0.113.10", HostPreserved: true, SNIPreserved: true,
		IPv4Verified: true, IPv6Verified: true, TLSResult: "OK", HTTPResult: "OK", ContentResult: "OK",
		ReasonCode: "verified", Status: "OK", EvidenceSource: "test", CheckedAt: time.Now().UTC(),
	}
	if err := ValidateRouteProof(required, actual, binding, "sha256:manifest"); err != nil {
		t.Fatalf("Smart DNS must not require a changed external IP: %v", err)
	}
}

func TestZapretNameAloneIsNotProof(t *testing.T) {
	binding := artifact.Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	required := artifact.RouteProof{Tag: "zapret", Type: "zapret", Mark: "0x42", Table: 200, RulePriority: 10010, RequiresEgress: true}
	actual := RouteResult{
		RouteTag: "zapret", RouteType: "zapret", AdapterRevision: binding.RevisionID, CandidateHash: binding.CandidateHash, ArtifactManifestHash: "sha256:manifest",
		NFTMark: "0x42", ConntrackMark: "0x42", IPRulePriority: 10010, RouteTable: 200, Interface: "wan", DNSResolver: "192.0.2.53",
		ResolvedIP: "203.0.113.10", ConnectedIP: "203.0.113.10", ExternalIPHash: "sha256:egress", ExternalCountry: "RU",
		HTTPResult: "OK", ContentResult: "OK", ReasonCode: "route_named_zapret", Status: "OK", EvidenceSource: "test", CheckedAt: time.Now().UTC(),
	}
	if err := ValidateRouteProof(required, actual, binding, "sha256:manifest"); err == nil {
		t.Fatal("a Zapret tag without installed/flow/QUIC evidence was accepted")
	}
}

func TestDropRequiresIPv4IPv6AndDNSProof(t *testing.T) {
	binding := artifact.Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	required := artifact.RouteProof{Tag: "drop", Type: "drop", Mark: "0x43", RulePriority: 10010, RequiresDropProof: true}
	actual := RouteResult{
		RouteTag: "drop", RouteType: "drop", AdapterRevision: binding.RevisionID, CandidateHash: binding.CandidateHash, ArtifactManifestHash: "sha256:manifest",
		NFTMark: "0x43", ConntrackMark: "0x43", IPRulePriority: 10010, ReasonCode: "policy_drop", Status: "OK", EvidenceSource: "test", CheckedAt: time.Now().UTC(),
	}
	if err := ValidateRouteProof(required, actual, binding, "sha256:manifest"); err == nil {
		t.Fatal("partial Drop evidence was accepted")
	}
	actual.DropIPv4Enforced = true
	actual.DropIPv6Enforced = true
	actual.DropDNSEnforced = true
	if err := ValidateRouteProof(required, actual, binding, "sha256:manifest"); err != nil {
		t.Fatalf("complete Drop proof rejected: %v", err)
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
