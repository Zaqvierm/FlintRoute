package vpnsub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/probe"
	"router-policy/internal/xraybundle"
)

type fakeXrayRunner struct {
	tests     int
	starts    int
	failTest  bool
	failStart bool
	stops     int
	readiness int
}

func (r *fakeXrayRunner) Test(context.Context, string) error {
	r.tests++
	if r.failTest {
		return errors.New("test failed")
	}
	return nil
}

func (r *fakeXrayRunner) StartCandidate(context.Context, string) (CandidateProcess, error) {
	r.starts++
	if r.failStart {
		return nil, errors.New("start failed")
	}
	return fakeCandidateProcess{runner: r}, nil
}

func (r *fakeXrayRunner) WaitReady(context.Context, []ServerStatus) error {
	r.readiness++
	return nil
}

type fakeCandidateProcess struct{ runner *fakeXrayRunner }

func (p fakeCandidateProcess) Stop(context.Context) error {
	p.runner.stops++
	return nil
}

type sequenceChecker struct {
	checks []OutboundCheck
	index  int
}

func (c *sequenceChecker) Check(_ context.Context, tag, _ string) OutboundCheck {
	if c.index >= len(c.checks) {
		return OutboundCheck{Tag: tag, Status: "FAIL", Reason: "unexpected_extra_check"}
	}
	result := c.checks[c.index]
	c.index++
	result.Tag = tag
	return result
}

func TestManagerStagesVerifiedBundleForTransaction(t *testing.T) {
	root := t.TempDir()
	subscription := writeManagerSubscription(t, root)
	runner := &fakeXrayRunner{}
	checker := &sequenceChecker{checks: []OutboundCheck{{Status: "OK", LatencyMS: 20, ExternalIPHash: "sha256:egress", ExternalCountry: "DE"}}}
	manager := &Manager{StateDir: filepath.Join(root, "xray-state"), Runner: runner, Checker: checker}
	result, err := manager.PrepareBundle(context.Background(), subscription, 12000)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Ready || result.SelectedTag != "good" || runner.tests != 1 || runner.starts != 1 || len(result.Routes) != 1 {
		t.Fatalf("bad prepared bundle result=%+v runner=%+v", result, runner)
	}
	if result.BundleHash == "" || result.BundlePath == "" || xraybundle.Hash(mustRead(t, result.BundlePath)) != result.BundleHash {
		t.Fatalf("prepared bundle is not content-addressed: %+v", result)
	}
	bundle, err := xraybundle.Load(manager.StateDir, result.BundleHash)
	if err != nil {
		t.Fatal(err)
	}
	route := config.Route{Type: "vless", Tag: result.Routes[0].Tag, SOCKS5: result.Routes[0].SOCKS5}
	if err := xraybundle.ValidateRoutes(bundle, []config.Route{route}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(manager.StateDir, "current", "xray.json")); !os.IsNotExist(err) {
		t.Fatal("bundle preparation bypassed the transaction and modified current Xray config")
	}
	encoded, _ := json.Marshal(result)
	for _, secret := range []string{"11111111-1111-4111-8111-111111111111", "good.example", "SECRET_SHORT_ID"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("prepared bundle result leaked secret %q: %s", secret, encoded)
		}
	}
}

func TestManagerXrayTestFailureDoesNotStageBundle(t *testing.T) {
	root := t.TempDir()
	subscription := writeManagerSubscription(t, root)
	stateDir := filepath.Join(root, "xray-state")
	runner := &fakeXrayRunner{failTest: true}
	checker := &sequenceChecker{checks: []OutboundCheck{{Status: "OK", LatencyMS: 20, ExternalIPHash: "sha256:egress", ExternalCountry: "DE"}}}
	manager := &Manager{StateDir: stateDir, Runner: runner, Checker: checker}
	result, err := manager.PrepareBundle(context.Background(), subscription, 12000)
	if err == nil || result.Ready || result.BundlePath != "" {
		t.Fatalf("failed Xray test staged a bundle: result=%+v err=%v", result, err)
	}
	if _, statErr := os.Stat(filepath.Join(stateDir, "xray", "bundles")); !os.IsNotExist(statErr) {
		t.Fatalf("failed candidate created bundle storage: %v", statErr)
	}
}

func TestManagerRefusesRUOnlyCandidate(t *testing.T) {
	root := t.TempDir()
	subscription := writeManagerSubscription(t, root)
	runner := &fakeXrayRunner{}
	checker := &sequenceChecker{checks: []OutboundCheck{{Status: "OK", LatencyMS: 10, ExternalIPHash: "sha256:ru", ExternalCountry: "RU"}}}
	manager := &Manager{StateDir: filepath.Join(root, "xray-state"), Runner: runner, Checker: checker}
	result, err := manager.PrepareBundle(context.Background(), subscription, 12000)
	if err == nil || result.Ready || result.BundlePath != "" {
		t.Fatalf("RU-only candidate was staged: result=%+v err=%v", result, err)
	}
}

func TestCandidateSOCKSVerifierBindsLoopbackInboundToOutboundTag(t *testing.T) {
	request := probe.PathProofRequest{
		Route: config.Route{Type: "vless", Tag: "vless-a", SOCKS5: "127.0.0.1:12000"},
		Observation: probe.PathObservation{
			Domain: "example.com", DNSResolver: "socks5-remote", ResolvedIPs: []string{"203.0.113.10"},
			ConnectedIP: "203.0.113.10", ConnectedPort: 443, LocalIP: "127.0.0.1",
			AddressFamily: "ipv4", Transport: "socks5", HostPreserved: true, SNIPreserved: true,
			TLSResult: "OK", HTTPResult: "OK", ContentResult: "OK",
			ExternalIPHash: "sha256:egress", ExternalCountry: "DE", CompletedAt: time.Now().UTC(),
		},
	}
	proof, err := (candidateSOCKSVerifier{}).Verify(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Status != "OK" || proof.XrayOutboundTag != "vless-a" || !proof.SOCKS5Loopback || !proof.ProxyFlowProcessed || proof.EvidenceSource != "isolated-xray-candidate-socks" {
		t.Fatalf("candidate SOCKS path proof is incomplete: %+v", proof)
	}
	request.Route.SOCKS5 = "0.0.0.0:12000"
	if _, err := (candidateSOCKSVerifier{}).Verify(context.Background(), request); err == nil {
		t.Fatal("non-loopback candidate SOCKS endpoint was accepted")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeManagerSubscription(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, "subscription.json")
	raw := []byte(`{"outbounds":[{"tag":"good","protocol":"vless","settings":{"vnext":[{"address":"good.example","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"good.example","shortId":"SECRET_SHORT_ID","publicKey":"PUBLIC_KEY"}}}]}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
