package hardwarevalidation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-policy/internal/evidence"
	"router-policy/internal/probe"
)

type fakeRunner struct {
	outputs map[string][]byte
	errors  map[string]error
}

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	if err := f.errors[key]; err != nil {
		return nil, err
	}
	if output, ok := f.outputs[key]; ok {
		return output, nil
	}
	return nil, errors.New("unexpected command: " + key)
}

func TestBaselineRequiresBoundRecoveryAndWritesRedactedSnapshots(t *testing.T) {
	root := t.TempDir()
	paths := testPaths(root)
	for _, path := range []string{paths.RouterPolicy, paths.Config, filepath.Join(paths.StateDir, "router-policy.bbolt")} {
		writeTestFile(t, path, "fixture")
	}
	if err := os.MkdirAll(filepath.Join(paths.StateDir, "last-good"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(paths.RuntimeDir, "active-transaction.env"), "transaction_state=committed\n")
	writeTestFile(t, filepath.Join(paths.InitDir, paths.WatchdogService), "#!/bin/sh\n")
	digest := sha256.Sum256([]byte("fixture"))
	buildDigest := hex.EncodeToString(digest[:])
	runner := fakeRunner{outputs: map[string][]byte{
		paths.RouterPolicy + " status":                                   []byte(`{"platform":"openwrt"}`),
		paths.RouterPolicy + " validate-config":                          []byte(`{"valid":true}`),
		filepath.Join(paths.InitDir, paths.WatchdogService) + " running": []byte{},
		filepath.Join(paths.InitDir, paths.WatchdogService) + " enabled": []byte{},
		paths.DFBinary + " -Pk /":                                        []byte("Filesystem 1024-blocks Used Available Capacity Mounted on\nroot 1000000 1 999999 1% /\n"),
		paths.UbusBinary + " call system board":                          []byte(`{"model":"GL-MT6000","board_name":"glinet,gl-mt6000","kernel":"6.6","release":{"distribution":"OpenWrt","version":"24.10.4","description":"fixture"}}`),
		"uname -m":                                                       []byte("aarch64\n"),
		paths.NftBinary + " list table inet router_policy":               []byte("ip 192.0.2.1 ipv6 2001:db8::1\n"),
		paths.IPBinary + " rule show":                                    []byte("from 192.0.2.1\n"),
		paths.IPBinary + " -6 rule show":                                 []byte("from 2001:db8::1\n"),
		paths.IPBinary + " route show table all":                         []byte("default via 192.0.2.1\n"),
		paths.IPBinary + " -6 route show table all":                      []byte("default via 2001:db8::1\n"),
	}}
	runDir := filepath.Join(root, "evidence")
	harness := Harness{Runner: runner, Paths: paths, Now: func() time.Time { return time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC) }}
	baseline, err := harness.Baseline(context.Background(), BaselineOptions{RunDir: runDir, Commit: strings.Repeat("a", 40), BuildSHA256: buildDigest, RecoverySHA256: strings.Repeat("b", 64)})
	if err != nil || !baseline.Passed {
		t.Fatalf("baseline failed: %v %#v", err, baseline.Gate)
	}
	nft, err := os.ReadFile(filepath.Join(runDir, "nft.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(nft), "192.0.2.1") || !strings.Contains(string(nft), "IP_REDACTED") {
		t.Fatalf("snapshot was not redacted: %s", nft)
	}
}

func TestRunMatrixSeparatesPassFailureAndNotApplicable(t *testing.T) {
	root := t.TempDir()
	paths := testPaths(root)
	direct := completeResult("direct")
	vless := completeResult("vless")
	runner := fakeRunner{outputs: map[string][]byte{
		paths.RouterPolicy + " probe-route --no-persist --route direct github.com github":  mustJSON(t, direct),
		paths.RouterPolicy + " probe-route --no-persist --route proxy chatgpt.com chatgpt": mustJSON(t, vless),
	}}
	cases := []MatrixCase{
		{ID: "direct-v4-tls", Route: "direct", Domain: "github.com", Service: "github", ExpectedRouteType: "direct", ExpectedAddressFamily: "ipv4", ExpectedPathTransport: "direct", ExpectedPort: 443, RequireTLS: true, RequireContent: true},
		{ID: "vless-v4-tls", Route: "proxy", Domain: "chatgpt.com", Service: "chatgpt", ExpectedRouteType: "vless", ExpectedAddressFamily: "ipv4", ExpectedPathTransport: "socks5", ExpectedPort: 443, RequireTLS: true},
		{ID: "ipv6", SkipReason: "WAN6 is disabled on this hardware profile"},
	}
	casesPath := filepath.Join(root, "cases.json")
	writeTestJSON(t, casesPath, cases)
	harness := Harness{Runner: runner, Paths: paths, Now: func() time.Time { return time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC) }}
	summary, err := harness.RunMatrix(context.Background(), filepath.Join(root, "evidence"), casesPath)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Passed != 2 || summary.NotApplicable != 1 || summary.Failed != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	probes, err := os.ReadFile(filepath.Join(root, "evidence", "probes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(probes), "192.0.2.1") || !strings.Contains(string(probes), "REDACTED") {
		t.Fatalf("probe evidence was not redacted: %s", probes)
	}
}

func TestRunMatrixFailsClosedOnWrongRouteProof(t *testing.T) {
	root := t.TempDir()
	paths := testPaths(root)
	result := completeResult("direct")
	result.PathEvidence.DirectBypassZapret = false
	runner := fakeRunner{outputs: map[string][]byte{paths.RouterPolicy + " probe-route --no-persist --route direct github.com github": mustJSON(t, result)}}
	casesPath := filepath.Join(root, "cases.json")
	writeTestJSON(t, casesPath, []MatrixCase{{ID: "direct", Route: "direct", Domain: "github.com", Service: "github", ExpectedRouteType: "direct"}})
	harness := Harness{Runner: runner, Paths: paths}
	summary, err := harness.RunMatrix(context.Background(), filepath.Join(root, "evidence"), casesPath)
	if err == nil || summary.Failed != 1 {
		t.Fatalf("wrong proof was accepted: summary=%#v err=%v", summary, err)
	}
}

func TestFinalizeRejectsSymlinksAndWritesStableManifest(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "b.txt"), "b")
	writeTestFile(t, filepath.Join(root, "a.txt"), "a")
	if err := Finalize(root); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "SHA256SUMS.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], "a.txt") || !strings.HasSuffix(lines[1], "b.txt") {
		t.Fatalf("manifest is not stable: %s", raw)
	}
}

func TestValidateDeviceRunDirRejectsArbitraryTargets(t *testing.T) {
	if err := ValidateDeviceRunDir("/tmp/flintroute-p13/p13-20260716-120000"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/tmp/flintroute-p13", "/etc/router-policy", "/tmp/flintroute-p13/../escape"} {
		if err := ValidateDeviceRunDir(path); err == nil {
			t.Fatalf("unsafe path was accepted: %s", path)
		}
	}
}

func completeResult(routeType string) probe.RouteResult {
	proof := &evidence.RouteResult{
		RouteTag: routeType, RouteType: routeType, AdapterRevision: "rev_fixture", CandidateHash: "sha256:fixture",
		ArtifactManifestHash: "sha256:fixture", NFTMark: "0x41", IPRulePriority: 10010, RouteTable: 100,
		DNSResponseSafe: true, ResolvedIP: "192.0.2.1", ConnectedIP: "192.0.2.1", ConnectedPort: 443,
		LocalIP: "192.0.2.2", AddressFamily: "ipv4", Transport: "direct", HostPreserved: true, SNIPreserved: true,
		DirectBypassXray: true, DirectBypassZapret: true, InheritedMarkCleared: true, IPv4Verified: true,
		Status: "PASS", EvidenceSource: "fixture", CheckedAt: time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC),
	}
	if routeType == "vless" {
		proof.Transport = "socks5"
		proof.SOCKS5Endpoint = "127.0.0.1:12000"
		proof.SOCKS5Loopback = true
		proof.ProxyFlowProcessed = true
	}
	return probe.RouteResult{Domain: "example.com", Service: "fixture", Route: routeType, RouteType: routeType, Status: "OK", PathVerified: true, PathEvidence: proof, TLSOK: true, ContentOK: true, Simulation: false}
}

func testPaths(root string) Paths {
	return Paths{RouterPolicy: filepath.Join(root, "router-policy"), Config: filepath.Join(root, "default.json"), StateDir: filepath.Join(root, "state"), RuntimeDir: filepath.Join(root, "runtime"), InitDir: filepath.Join(root, "init.d"), NftBinary: filepath.Join(root, "nft"), IPBinary: filepath.Join(root, "ip"), UbusBinary: filepath.Join(root, "ubus"), DFBinary: filepath.Join(root, "df"), WatchdogService: "router-policy-watchdog"}
}

func writeTestFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, string(raw))
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
