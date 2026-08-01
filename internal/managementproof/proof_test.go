package managementproof

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixedResolver struct {
	name   string
	subnet netip.Prefix
}

func (r fixedResolver) Resolve(localIP, clientIP netip.Addr) (string, netip.Prefix, error) {
	return r.name, r.subnet, nil
}

func newTestManager(t *testing.T, now *time.Time) (*Manager, string) {
	t.Helper()
	root := t.TempDir()
	bootPath := filepath.Join(root, "boot-id")
	if err := os.WriteFile(bootPath, []byte("boot-aaaaaaaa\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(root, "state"), filepath.Join(root, "runtime"), Options{
		BootIDPath: bootPath,
		Now:        func() time.Time { return *now },
		Resolver:   fixedResolver{name: "br-lan", subnet: netip.MustParsePrefix("192.0.2.0/24")},
		AdminProbe: func(context.Context, string) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager, bootPath
}

func testBinding() Binding {
	return Binding{TransactionID: "tx_0123456789abcdef", RevisionID: "rev_2_0123456789ab"}
}

func testObservation() Observation {
	return Observation{
		Mode: ModeLAN, ClientIP: netip.MustParseAddr("192.0.2.10"), LocalIP: netip.MustParseAddr("192.0.2.93"),
		Interface: "br-lan", Subnet: netip.MustParsePrefix("192.0.2.0/24"),
		ControlPlaneURL: "http://192.0.2.93:8787/api/v1/health", AdminHTTPURL: "http://192.0.2.93/", AdminHTTPAvailable: true,
	}
}

func TestLANProofIsSignedAndBound(t *testing.T) {
	now := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	manager, _ := newTestManager(t, &now)
	issued, err := manager.Issue(context.Background(), testBinding(), testObservation(), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := manager.Verify(testBinding())
	if err != nil {
		t.Fatal(err)
	}
	if verified.Signature == "" || verified.BootID != "boot-aaaaaaaa" || verified.Interface != "br-lan" || verified.Subnet != "192.0.2.0/24" || verified.TransactionID != issued.TransactionID {
		t.Fatalf("unexpected proof: %+v", verified)
	}
}

func TestAvailableAdminHTTPPathMustRemainReachable(t *testing.T) {
	now := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	manager, _ := newTestManager(t, &now)
	proof, err := manager.Issue(context.Background(), testBinding(), testObservation(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !manager.ProbeAdminHTTP(context.Background(), proof) {
		t.Fatal("available admin HTTP path was not checked")
	}
	manager.adminProbe = func(context.Context, string) bool { return false }
	if manager.ProbeAdminHTTP(context.Background(), proof) {
		t.Fatal("lost admin HTTP path was accepted")
	}
	proof.AdminHTTPAvailable = false
	if !manager.ProbeAdminHTTP(context.Background(), proof) {
		t.Fatal("unavailable optional admin HTTP path became a gate")
	}
}

func TestMissingAndExpiredProofsAreRejected(t *testing.T) {
	now := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	manager, _ := newTestManager(t, &now)
	if _, err := manager.Verify(testBinding()); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing proof was accepted: %v", err)
	}
	if _, err := manager.Issue(context.Background(), testBinding(), testObservation(), time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := manager.Verify(testBinding()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired proof was accepted: %v", err)
	}
}

func TestProofFromAnotherBootOrRevisionIsRejected(t *testing.T) {
	now := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	manager, bootPath := newTestManager(t, &now)
	if _, err := manager.Issue(context.Background(), testBinding(), testObservation(), time.Minute); err != nil {
		t.Fatal(err)
	}
	otherRevision := testBinding()
	otherRevision.RevisionID = "rev_3_aaaaaaaaaaaa"
	sourcePath, _ := manager.ProofPath(testBinding())
	targetPath, _ := manager.ProofPath(otherRevision)
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(otherRevision); err == nil || !strings.Contains(err.Error(), "binding") {
		t.Fatal("proof from another revision was accepted")
	}
	if err := os.WriteFile(bootPath, []byte("boot-bbbbbbbb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(testBinding()); err == nil || !strings.Contains(err.Error(), "another boot") {
		t.Fatalf("proof from another boot was accepted: %v", err)
	}
}

func TestEditingProofInvalidatesSignature(t *testing.T) {
	now := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	manager, _ := newTestManager(t, &now)
	if _, err := manager.Issue(context.Background(), testBinding(), testObservation(), time.Minute); err != nil {
		t.Fatal(err)
	}
	path, _ := manager.ProofPath(testBinding())
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var proof Proof
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	proof.ClientIP = "192.0.2.11"
	raw, _ = json.Marshal(proof)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(testBinding()); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("edited proof was accepted: %v", err)
	}
}

func TestHeadlessSSHProofUsesObservedInterfaceAndSubnet(t *testing.T) {
	now := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	manager, _ := newTestManager(t, &now)
	proof, err := manager.IssueHeadlessSSH(context.Background(), testBinding(), "192.0.2.10 55123 192.0.2.93 22", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Mode != ModeHeadless || proof.ClientIP != "192.0.2.10" || proof.LocalIP != "192.0.2.93" || proof.ControlPlaneURL != "http://127.0.0.1:8787/api/v1/health" {
		t.Fatalf("unexpected headless proof: %+v", proof)
	}
}

func TestLANConfirmationMustUseProvedInterfaceAndSubnet(t *testing.T) {
	now := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	manager, _ := newTestManager(t, &now)
	if _, err := manager.Issue(context.Background(), testBinding(), testObservation(), time.Minute); err != nil {
		t.Fatal(err)
	}
	request := &http.Request{RemoteAddr: "192.0.2.20:54321"}
	request = request.WithContext(context.WithValue(context.Background(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.93"), Port: 8787}))
	if _, err := manager.VerifyLANConfirmation(testBinding(), request); err != nil {
		t.Fatal(err)
	}
	manager.resolver = fixedResolver{name: "guest", subnet: netip.MustParsePrefix("192.0.2.0/24")}
	if _, err := manager.VerifyLANConfirmation(testBinding(), request); err == nil {
		t.Fatal("confirmation through another interface was accepted")
	}
}

func TestLANObservationResolvesWildcardListenerFromValidatedHost(t *testing.T) {
	now := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	manager, _ := newTestManager(t, &now)
	request := &http.Request{RemoteAddr: "192.0.2.20:54321", Host: "192.0.2.93:8787"}
	request = request.WithContext(context.WithValue(context.Background(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.IPv4zero, Port: 8787}))
	observation, err := manager.ObserveLANRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if observation.LocalIP.String() != "192.0.2.93" || observation.Interface != "br-lan" || observation.ControlPlaneURL != "http://192.0.2.93:8787/api/v1/health" {
		t.Fatalf("wildcard listener was not bound to the validated host path: %+v", observation)
	}
}

func TestAutomaticProofDoesNotGuessWANInterface(t *testing.T) {
	if !likelyLANInterface("br-lan") || !likelyLANInterface("lan.10") {
		t.Fatal("known LAN interface was rejected")
	}
	for _, name := range []string{"wan", "eth0", "wwan", "usb0"} {
		if likelyLANInterface(name) {
			t.Fatalf("non-LAN interface %q was accepted", name)
		}
	}
}
