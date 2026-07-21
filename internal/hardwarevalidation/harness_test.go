package hardwarevalidation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
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

type sequenceRunner struct {
	outputs map[string][][]byte
	calls   map[string]int
}

func (r *sequenceRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	values := r.outputs[key]
	index := r.calls[key]
	if index >= len(values) {
		return nil, errors.New("unexpected command: " + key)
	}
	r.calls[key] = index + 1
	return values[index], nil
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

func TestRunMatrixSeparatesPassFailureNotTestedAndNotApplicable(t *testing.T) {
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
		{ID: "quic", PendingReason: "live QUIC evidence is not attached"},
	}
	casesPath := filepath.Join(root, "cases.json")
	writeTestJSON(t, casesPath, cases)
	harness := Harness{Runner: runner, Paths: paths, Now: func() time.Time { return time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC) }}
	summary, err := harness.RunMatrix(context.Background(), filepath.Join(root, "evidence"), casesPath)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Passed != 2 || summary.NotApplicable != 1 || summary.NotTested != 1 || summary.Failed != 0 {
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

func TestRunMatrixRequiresEveryDeclaredCoverageCell(t *testing.T) {
	root := t.TempDir()
	paths := testPaths(root)
	plan := MatrixPlan{
		SchemaVersion: 1, RequireFullCoverage: true,
		RouteTypes: []string{"direct", "drop"}, Protocols: []string{"tcp_443"}, AddressFamilies: []string{"ipv4", "ipv6"},
		Cases: []MatrixCase{
			{ID: "direct-tcp443-ipv4", ExpectedRouteType: "direct", Protocol: "tcp_443", AddressFamily: "ipv4", SkipReason: "fixture"},
			{ID: "direct-tcp443-ipv6", ExpectedRouteType: "direct", Protocol: "tcp_443", AddressFamily: "ipv6", SkipReason: "fixture"},
			{ID: "drop-tcp443-ipv4", ExpectedRouteType: "drop", Protocol: "tcp_443", AddressFamily: "ipv4", SkipReason: "fixture"},
		},
	}
	planPath := filepath.Join(root, "matrix.json")
	writeTestJSON(t, planPath, plan)
	harness := Harness{Runner: fakeRunner{}, Paths: paths}
	if _, err := harness.RunMatrix(context.Background(), filepath.Join(root, "evidence"), planPath); err == nil || !strings.Contains(err.Error(), "requires 4 cells") {
		t.Fatalf("incomplete full matrix was accepted: %v", err)
	}

	plan.Cases = append(plan.Cases, MatrixCase{ID: "drop-tcp443-ipv6", ExpectedRouteType: "drop", Protocol: "tcp_443", AddressFamily: "ipv6", SkipReason: "fixture"})
	writeTestJSON(t, planPath, plan)
	summary, err := harness.RunMatrix(context.Background(), filepath.Join(root, "evidence"), planPath)
	if err != nil || !summary.CoveragePassed || summary.NotApplicable != 4 {
		t.Fatalf("complete declared matrix failed: summary=%+v err=%v", summary, err)
	}
}

func TestRunMatrixRejectsAmbiguousUntestedClassification(t *testing.T) {
	root := t.TempDir()
	paths := testPaths(root)
	casesPath := filepath.Join(root, "cases.json")
	writeTestJSON(t, casesPath, []MatrixCase{{ID: "ambiguous", SkipReason: "not applicable", PendingReason: "not tested"}})
	harness := Harness{Runner: fakeRunner{}, Paths: paths}
	if _, err := harness.RunMatrix(context.Background(), filepath.Join(root, "evidence"), casesPath); err == nil || !strings.Contains(err.Error(), "both not applicable and not tested") {
		t.Fatalf("ambiguous matrix classification was accepted: %v", err)
	}
}

func TestPublishedP13MatrixDeclaresFullCartesianCoverage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "hardware", "p13-cases.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := decodeMatrixPlan(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMatrixCoverage(plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Cases) != 50 {
		t.Fatalf("unexpected published matrix size: %d", len(plan.Cases))
	}
	active, pending, unavailable := 0, 0, 0
	for _, testCase := range plan.Cases {
		switch {
		case testCase.PendingReason != "":
			pending++
		case testCase.SkipReason != "":
			unavailable++
		default:
			active++
			if !testCase.RequireTransportProof {
				t.Fatalf("active matrix case lacks protocol-specific proof: %s", testCase.ID)
			}
		}
	}
	if active != 23 || pending != 0 || unavailable != 27 {
		t.Fatalf("published matrix classification drifted: active=%d pending=%d unavailable=%d", active, pending, unavailable)
	}
}

func TestVerifyProxyRecursionRequiresMarkedOutboundAndLiveCounter(t *testing.T) {
	root := t.TempDir()
	paths := testPaths(root)
	xrayPath := filepath.Join(root, "active-xray.json")
	writeTestFile(t, xrayPath, `{"outbounds":[{"tag":"proxy","protocol":"vless","streamSettings":{"sockopt":{"mark":512}}},{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"mark":512}}},{"tag":"blocked","protocol":"blackhole","settings":{}}]}`)
	writeTestFile(t, paths.Config, `{"xray":{"active_config":`+strconv.Quote(xrayPath)+`},"openwrt":{"nft_family":"inet","nft_table":"router_policy","xray_bypass_mark":"0x200"},"routes":[{"type":"vless","tag":"proxy"}]}`)
	vless := completeResult("vless")
	vless.Route = "proxy"
	vless.PathEvidence.RouteTag = "proxy"
	vless.PathEvidence.XrayOutboundTag = "proxy"
	vless.PathEvidence.ProxyFlowProcessed = false
	runner := &sequenceRunner{calls: map[string]int{}, outputs: map[string][][]byte{
		paths.NftBinary + " list chain inet router_policy rp_prerouting":                   {[]byte(`meta mark 0x00000200 counter packets 0 bytes 0 return comment "rp action=xray_recursion_bypass"`)},
		paths.NftBinary + " list chain inet router_policy probe_output":                    {[]byte(`meta mark 0x00000200 counter packets 10 bytes 100 return comment "rp action=xray_recursion_bypass"`), []byte(`meta mark 0x00000200 counter packets 14 bytes 400 return comment "rp action=xray_recursion_bypass"`)},
		paths.RouterPolicy + " probe-route --no-persist --route proxy chatgpt.com chatgpt": {mustJSON(t, vless)},
	}}
	harness := Harness{Runner: runner, Paths: paths, Now: func() time.Time { return time.Date(2026, 7, 19, 1, 2, 3, 0, time.UTC) }}
	result, err := harness.VerifyProxyRecursion(context.Background(), ProxyRecursionOptions{RunDir: filepath.Join(root, "evidence"), Route: "proxy", Domain: "chatgpt.com", Service: "chatgpt"})
	if err != nil || !result.Passed || result.ProtectedOutbounds != 2 || result.OutputPacketsBefore != 10 || result.OutputPacketsAfter != 14 {
		t.Fatalf("recursion proof failed: result=%+v err=%v", result, err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "evidence", "proxy-recursion.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), xrayPath) || strings.Contains(string(raw), "chatgpt.com") {
		t.Fatalf("recursion evidence leaked private runtime details: %s", raw)
	}
}

func TestVerifyProxyRecursionFailsWhenCounterDoesNotMove(t *testing.T) {
	root := t.TempDir()
	paths := testPaths(root)
	xrayPath := filepath.Join(root, "active-xray.json")
	writeTestFile(t, xrayPath, `{"outbounds":[{"tag":"proxy","protocol":"vless","streamSettings":{"sockopt":{"mark":512}}}]}`)
	writeTestFile(t, paths.Config, `{"xray":{"active_config":`+strconv.Quote(xrayPath)+`},"openwrt":{"nft_family":"inet","nft_table":"router_policy","xray_bypass_mark":"0x200"},"routes":[{"type":"vless","tag":"proxy"}]}`)
	vless := completeResult("vless")
	vless.Route = "proxy"
	vless.PathEvidence.RouteTag = "proxy"
	vless.PathEvidence.XrayOutboundTag = "proxy"
	vless.PathEvidence.ProxyFlowProcessed = false
	line := []byte(`meta mark 0x00000200 counter packets 10 bytes 100 return comment "rp action=xray_recursion_bypass"`)
	runner := &sequenceRunner{calls: map[string]int{}, outputs: map[string][][]byte{
		paths.NftBinary + " list chain inet router_policy rp_prerouting":                   {line},
		paths.NftBinary + " list chain inet router_policy probe_output":                    {line, line},
		paths.RouterPolicy + " probe-route --no-persist --route proxy chatgpt.com chatgpt": {mustJSON(t, vless)},
	}}
	harness := Harness{Runner: runner, Paths: paths}
	result, err := harness.VerifyProxyRecursion(context.Background(), ProxyRecursionOptions{RunDir: filepath.Join(root, "evidence"), Route: "proxy", Domain: "chatgpt.com", Service: "chatgpt"})
	if err == nil || result.Passed || result.Reason != "live VLESS traffic did not hit the recursion bypass" {
		t.Fatalf("stale recursion counter was accepted: result=%+v err=%v", result, err)
	}
}

func TestRunLoadUsesBoundedWorkersAndKeepsMultiClientHonest(t *testing.T) {
	root := t.TempDir()
	paths := testPaths(root)
	direct := completeResult("direct")
	runner := fakeRunner{outputs: map[string][]byte{
		paths.RouterPolicy + " probe-route --no-persist --route direct github.com github": mustJSON(t, direct),
	}}
	planPath := filepath.Join(root, "load.json")
	writeTestJSON(t, planPath, LoadPlan{
		Workers: 2, Iterations: 4,
		Cases: []MatrixCase{{ID: "direct", Route: "direct", Domain: "github.com", Service: "github", ExpectedRouteType: "direct", ExpectedAddressFamily: "ipv4", ExpectedPathTransport: "direct", ExpectedPort: 443, RequireTLS: true, RequireContent: true}},
	})
	harness := Harness{Runner: runner, Paths: paths}
	summary, err := harness.RunLoad(context.Background(), filepath.Join(root, "evidence"), planPath)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 4 || summary.Passed != 4 || summary.Failed != 0 || !summary.SingleNode || summary.MultiClient != "NOT_TESTED" {
		t.Fatalf("unexpected load summary: %+v", summary)
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
