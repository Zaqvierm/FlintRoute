package probe

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"router-policy/internal/artifact"
	"router-policy/internal/config"
)

type fakeOpenWrtCommands struct {
	counter       uint64
	advance       bool
	routeTable    int
	conntrackMark string
}

func (f *fakeOpenWrtCommands) RouteGet(context.Context, string, string) (KernelRoute, error) {
	return KernelRoute{Table: f.routeTable, Interface: "wan"}, nil
}

func (f *fakeOpenWrtCommands) Rules(context.Context) ([]KernelRule, error) {
	return []KernelRule{
		{Family: "4", Priority: 10010, Mark: "0x41", Table: 100},
		{Family: "6", Priority: 10010, Mark: "0x41", Table: 100},
	}, nil
}

func (f *fakeOpenWrtCommands) HasDefaultRoute(context.Context, string, int) (bool, error) {
	return true, nil
}

func (f *fakeOpenWrtCommands) NFTPolicy(context.Context, string) (NFTPolicy, error) {
	current := f.counter
	if f.advance {
		f.counter++
	}
	return NFTPolicy{Counter: current, Actions: map[string]bool{"direct_bypass": true}}, nil
}

func (f *fakeOpenWrtCommands) ProcessRunning(context.Context, string) (bool, error) {
	return false, nil
}

func (f *fakeOpenWrtCommands) ConntrackMark(string, string) (string, error) {
	if f.conntrackMark == "" {
		return "", fmt.Errorf("missing conntrack mark")
	}
	return f.conntrackMark, nil
}

func TestOpenWrtPathVerifierProvesBoundDirectFlow(t *testing.T) {
	root, activePath, binding, manifestHash := generateDirectArtifacts(t)
	commands := &fakeOpenWrtCommands{counter: 10, advance: true, routeTable: 100, conntrackMark: "0x41"}
	verifier, err := NewOpenWrtPathVerifier(OpenWrtPathOptions{
		ArtifactRoot: root, ActiveBindingPath: activePath, Binding: binding, ManifestHash: manifestHash,
		Commands: commands, AllowSimulation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC()
	session, err := verifier.Begin(context.Background(), PathProofStart{Domain: "example.test", Route: config.Route{Type: "direct", Tag: "direct"}, StartedAt: started})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := verifier.Verify(context.Background(), PathProofRequest{
		Route: config.Route{Type: "direct", Tag: "direct"}, Session: session,
		Observation: PathObservation{
			Domain: "example.test", RouteTag: "direct", RouteType: "direct", DNSResolver: "192.0.2.53", DNSProtocol: "udp",
			ResolvedIPs: []string{"203.0.113.10"}, ConnectedIP: "203.0.113.10", ConnectedPort: 443,
			LocalIP: "192.0.2.2", AddressFamily: "ipv4", Transport: "direct", SocketMark: "0x41",
			HostPreserved: true, SNIPreserved: true, TLSResult: "OK", HTTPResult: "OK", ContentResult: "OK",
			ExternalIPHash: "sha256:egress", ExternalCountry: "DE", StartedAt: started, CompletedAt: started.Add(20 * time.Millisecond),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if proof.Status != "OK" || !proof.DirectBypassXray || !proof.DirectBypassZapret || proof.ConntrackMark != "0x41" || proof.RouteTable != 100 {
		t.Fatalf("incomplete Direct proof: %+v", proof)
	}
}

func TestOpenWrtPathVerifierRejectsCounterThatDidNotAdvance(t *testing.T) {
	root, activePath, binding, manifestHash := generateDirectArtifacts(t)
	commands := &fakeOpenWrtCommands{counter: 10, routeTable: 100, conntrackMark: "0x41"}
	verifier, err := NewOpenWrtPathVerifier(OpenWrtPathOptions{
		ArtifactRoot: root, ActiveBindingPath: activePath, Binding: binding, ManifestHash: manifestHash,
		Commands: commands, AllowSimulation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := verifier.Begin(context.Background(), PathProofStart{Domain: "example.test", Route: config.Route{Type: "direct", Tag: "direct"}, StartedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(context.Background(), PathProofRequest{Route: config.Route{Type: "direct", Tag: "direct"}, Session: session})
	if err == nil {
		t.Fatal("unchanged nft counter was accepted as proof")
	}
}

func TestOpenWrtPathVerifierRejectsSimulationByDefault(t *testing.T) {
	root, activePath, binding, manifestHash := generateDirectArtifacts(t)
	_, err := NewOpenWrtPathVerifier(OpenWrtPathOptions{
		ArtifactRoot: root, ActiveBindingPath: activePath, Binding: binding, ManifestHash: manifestHash,
		Commands: &fakeOpenWrtCommands{},
	})
	if err == nil {
		t.Fatal("simulated artifact set was accepted by production verifier")
	}
}

func TestVerifySOCKSBindingRequiresInboundRuleAndVLESSOutbound(t *testing.T) {
	root := t.TempDir()
	valid := `{"inbounds":[{"tag":"socks-vless-a","listen":"127.0.0.1","port":12000,"protocol":"socks"}],"outbounds":[{"tag":"vless-a","protocol":"vless"}],"routing":{"rules":[{"type":"field","inboundTag":["socks-vless-a"],"outboundTag":"vless-a"}]}}`
	if err := os.WriteFile(filepath.Join(root, artifact.XrayFile), []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	verifier := &OpenWrtPathVerifier{root: root}
	bound, err := verifier.verifySOCKSBinding(config.Route{Type: "vless", Tag: "vless-a", SOCKS5: "127.0.0.1:12000"})
	if err != nil || !bound {
		t.Fatalf("valid inbound/outbound binding was rejected: bound=%t err=%v", bound, err)
	}
	tampered := `{"inbounds":[{"tag":"socks-vless-a","listen":"127.0.0.1","port":12000,"protocol":"socks"}],"outbounds":[{"tag":"vless-a","protocol":"vless"},{"tag":"other","protocol":"vless"}],"routing":{"rules":[{"type":"field","inboundTag":["socks-vless-a"],"outboundTag":"other"}]}}`
	if err := os.WriteFile(filepath.Join(root, artifact.XrayFile), []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.verifySOCKSBinding(config.Route{Type: "vless", Tag: "vless-a", SOCKS5: "127.0.0.1:12000"}); err == nil {
		t.Fatal("tampered SOCKS-to-outbound rule was accepted")
	}
}

func generateDirectArtifacts(t *testing.T) (string, string, artifact.Binding, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "diagnostics"), 0o700); err != nil {
		t.Fatal(err)
	}
	diagnostics := `{"status":"VERIFIED","source":"probe-test","simulation":true,"wan_interface":"wan","lan_interfaces":["br-lan"],"ipv4_gateway":"192.0.2.1","ipv6_gateway":"2001:db8::1","ipv6_available":true,"transparent_proxy_mode":"tproxy","collected_at":"2026-07-12T00:00:00Z","expires_at":"2999-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(root, "diagnostics", "network.json"), []byte(diagnostics), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Version: 2, Storage: config.Storage{StateDir: root},
		OpenWrt: config.OpenWrt{
			FirewallInclude: filepath.Join(root, "active.nft"), DNSMasqInclude: filepath.Join(root, "dnsmasq.conf"),
			WANRouteTable: 100, ZapretRouteTable: 101, XrayRouteTable: 102,
			DirectMark: "0x41", ZapretMark: "0x42", XrayMark: "0x43", DropMark: "0x7f",
		},
		Xray: config.Xray{ActiveConfig: filepath.Join(root, "xray-active.json")},
		Routes: []config.Route{
			{Type: "direct", Tag: "direct", Priority: 10, Mark: "0x41"},
			{Type: "drop", Tag: "drop", Priority: 1000, Mark: "0x7f"},
		},
		Services: map[string]config.Service{
			"example": {Category: "DIRECT_ONLY", Domains: []string{"example.test"}, AllowedPaths: []string{"direct"}},
		},
	}
	binding := artifact.Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	_, manifestHash, err := artifact.Generate(cfg, root, binding, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(root, "active-transaction.env")
	active := fmt.Sprintf("transaction_id=%s\nrevision_id=%s\ncandidate_hash=%s\nartifact_manifest_hash=%s\ntransaction_state=committed\n", binding.TransactionID, binding.RevisionID, binding.CandidateHash, manifestHash)
	if err := os.WriteFile(activePath, []byte(active), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, activePath, binding, manifestHash
}
