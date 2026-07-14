package artifact_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"router-policy/internal/artifact"
	"router-policy/internal/config"
	"router-policy/internal/vpnsub"
	"router-policy/internal/xraybundle"
)

func TestLiveGeneratedArtifactPassesXrayTest(t *testing.T) {
	xrayPath := os.Getenv("ROUTER_POLICY_TEST_XRAY")
	subscriptionPath := os.Getenv("ROUTER_POLICY_TEST_SUBSCRIPTION")
	bundleSource := os.Getenv("ROUTER_POLICY_TEST_XRAY_BUNDLE")
	if xrayPath == "" || subscriptionPath == "" || bundleSource == "" {
		t.Skip("set live Xray, subscription and bundle paths for artifact validation")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "diagnostics"), 0o700); err != nil {
		t.Fatal(err)
	}
	diagnostics := `{"status":"VERIFIED","source":"live-artifact-test","simulation":true,"wan_interface":"wan","lan_interfaces":["br-lan"],"ipv4_gateway":"192.0.2.1","ipv6_gateway":"2001:db8::1","ipv6_available":true,"transparent_proxy_mode":"tproxy","flow_offloading_status":"VERIFIED","software_flow_offloading":false,"hardware_flow_offloading":false,"collected_at":"1969-01-01T00:00:00Z","expires_at":"2999-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(root, "diagnostics", "network.json"), []byte(diagnostics), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Version: 2, Storage: config.Storage{StateDir: root},
		OpenWrt: config.OpenWrt{
			FirewallInclude: filepath.Join(root, "active", "rules.nft"), DNSMasqInclude: filepath.Join(root, "active", "dnsmasq.conf"),
			WANRouteTable: 100, ZapretRouteTable: 101, XrayRouteTable: 102,
			DirectMark: "0x41", ZapretMark: "0x42", XrayMark: "0x43", XrayTProxyMark: "0x100", XrayBypassMark: "0x200", DropMark: "0x4f",
		},
		Xray: config.Xray{ActiveConfig: filepath.Join(root, "active", "xray.json"), ProbeDNSResolver: "1.1.1.1:53", TransparentPort: 12345},
		Services: map[string]config.Service{
			"control": {Category: "GEO_LOCKED", Domains: []string{"www.gstatic.com"}, AllowedPaths: []string{"vless", "drop"}, RequireNonRUEgress: true, ProbeURLs: []config.ProbeCheck{{Name: "web", URL: "https://www.gstatic.com/generate_204", Required: true, ExpectedCodes: []int{204}, BodyMode: "empty"}}},
		},
	}
	bundleRaw, err := os.ReadFile(bundleSource)
	if err != nil {
		t.Fatal(err)
	}
	bundleHash := xraybundle.Hash(bundleRaw)
	if _, err := xraybundle.Store(root, bundleSource, bundleHash); err != nil {
		t.Fatal(err)
	}
	generatedRoutes, err := vpnsub.GenerateRoutesFile(subscriptionPath, 12000)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Xray.OutboundBundleSHA256 = bundleHash
	cfg.Routes = []config.Route{{Type: "direct", Tag: "direct", Priority: 10, Mark: "0x41"}}
	for _, route := range generatedRoutes {
		cfg.Routes = append(cfg.Routes, config.Route{
			Type: route.Type, Tag: route.Tag, Priority: route.Priority, SOCKS5: route.SOCKS5,
			DNSServer: cfg.Xray.ProbeDNSResolver, DNSMode: route.DNSMode, ExternalIPProbe: route.ExternalIPProbe, RequiresAdapter: true, AdapterMode: "xray", Mark: "0x43",
		})
	}
	cfg.Routes = append(cfg.Routes, config.Route{Type: "drop", Tag: "drop", Priority: 1000, Mark: "0x4f"})
	binding := artifact.Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generatedRoot := filepath.Join(root, "generated")
	manifest, _, err := artifact.Generate(cfg, generatedRoot, binding, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(xrayPath, "run", "-test", "-config", filepath.Join(generatedRoot, artifact.XrayFile))
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		t.Fatal("real Xray rejected the transaction-generated artifact")
	}
	uuid := regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}`)
	if uuid.Match(output.Bytes()) {
		t.Fatal("Xray validation output exposed a VLESS UUID")
	}
	if len(manifest.Artifacts) != 5 {
		t.Fatalf("transaction artifact set is incomplete: %d", len(manifest.Artifacts))
	}
	t.Logf("xray_test_ok=true vless_routes=%d bundle_hash=%s", len(generatedRoutes), bundleHash)
}
