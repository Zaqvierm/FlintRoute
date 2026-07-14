package artifact

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/xraybundle"
)

func TestGenerateVerifyAndRejectTamper(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	manifest, manifestHash, err := Generate(cfg, root, binding, time.Date(2026, 7, 12, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Artifacts) != 6 || manifestHash == "" {
		t.Fatalf("incomplete artifact set: %+v", manifest)
	}
	if manifest.DeploymentReady || manifest.BlockReason != "transparent_activation_unverified" {
		t.Fatalf("candidate-only transparent artifacts were marked deployable: %+v", manifest)
	}
	if _, err := Verify(root, binding, manifestHash); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, DNSMasqFile)
	if err := os.WriteFile(path, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, binding, manifestHash); err == nil {
		t.Fatal("tampered artifact was accepted")
	}
}

func TestManifestBindsCandidateAndRevision(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	_, manifestHash, err := Generate(cfg, root, binding, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	wrong := binding
	wrong.RevisionID = "rev_3_aabbccddeeff"
	if _, err := Verify(root, wrong, manifestHash); err == nil {
		t.Fatal("manifest from another revision was accepted")
	}
}

func TestMissingDiagnosticsProducesBlockedIPPlan(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	if err := os.Remove(filepath.Join(root, "diagnostics", "network.json")); err != nil {
		t.Fatal(err)
	}
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	manifest, _, err := Generate(cfg, filepath.Join(root, "generated"), binding, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if manifest.DeploymentReady || manifest.BlockReason != "network_diagnostics_missing" {
		t.Fatalf("missing diagnostics produced deployable artifacts: %+v", manifest)
	}
	plan, err := LoadIPPlan(filepath.Join(root, "generated", IPPlanFile), binding)
	if err != nil {
		t.Fatal(err)
	}
	if plan.DeploymentReady || len(plan.Routes) != 0 {
		t.Fatalf("blocked plan contains executable routes: %+v", plan)
	}
}

func TestXrayArtifactUsesHashBoundVLESSBundle(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	if _, _, err := Generate(cfg, filepath.Join(root, "generated"), binding, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "generated", XrayFile))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"protocol": "vless"`) || !strings.Contains(text, `"tag": "socks-vless-a"`) {
		t.Fatalf("generated Xray artifact does not contain the real bound VLESS bundle: %s", text)
	}
	if strings.Contains(text, `"_router_policy"`) {
		t.Fatal("generated Xray artifact contains a non-Xray metadata field")
	}
}

func TestXrayArtifactRejectsTamperedBundle(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	bundlePath, err := xraybundle.Path(root, cfg.Xray.OutboundBundleSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	if _, _, err := Generate(cfg, filepath.Join(root, "generated"), binding, time.Unix(1, 0)); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("tampered Xray bundle was not rejected: %v", err)
	}
}

func TestXrayArtifactRejectsRouteBundleMismatch(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Routes[1].Tag = "different-server"
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	if _, _, err := Generate(cfg, filepath.Join(root, "generated"), binding, time.Unix(1, 0)); err == nil || !strings.Contains(err.Error(), "absent from Xray bundle") {
		t.Fatalf("route/bundle mismatch was not rejected: %v", err)
	}
}

func TestTransparentXrayCandidateIsLoopbackBoundMarkedAndFailClosed(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generated := filepath.Join(root, "generated")
	manifest, _, err := Generate(cfg, generated, binding, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.DeploymentReady || manifest.BlockReason != "transparent_activation_unverified" {
		t.Fatalf("transparent preview readiness is dishonest: %+v", manifest)
	}
	plan, err := LoadIPPlan(filepath.Join(generated, IPPlanFile), binding)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.TransparentProxy.Enabled || !plan.TransparentProxy.CapabilityVerified || !plan.TransparentProxy.CandidateOnly || plan.TransparentProxy.Status != "CANDIDATE_ONLY" || len(plan.Routes) != 0 || len(plan.PlannedRoutes) != 4 {
		t.Fatalf("bad transparent preview plan: %+v", plan)
	}

	raw, err := os.ReadFile(filepath.Join(generated, XrayFile))
	if err != nil {
		t.Fatal(err)
	}
	var xray struct {
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Routing   struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &xray); err != nil {
		t.Fatal(err)
	}
	inboundByTag := map[string]map[string]any{}
	for _, inbound := range xray.Inbounds {
		tag, _ := inbound["tag"].(string)
		inboundByTag[tag] = inbound
	}
	for tag, listen := range map[string]string{transparentIPv4InboundTag: "127.0.0.1", transparentIPv6InboundTag: "::1"} {
		inbound := inboundByTag[tag]
		stream, _ := inbound["streamSettings"].(map[string]any)
		sockopt, _ := stream["sockopt"].(map[string]any)
		if inbound["listen"] != listen || inbound["protocol"] != "tunnel" || inbound["port"] != float64(12345) || sockopt["tproxy"] != "tproxy" {
			t.Fatalf("unsafe transparent inbound %s: %#v", tag, inbound)
		}
	}
	outboundByTag := map[string]map[string]any{}
	for _, outbound := range xray.Outbounds {
		tag, _ := outbound["tag"].(string)
		outboundByTag[tag] = outbound
	}
	for _, tag := range []string{"direct", "vless-a"} {
		outbound := outboundByTag[tag]
		stream, _ := outbound["streamSettings"].(map[string]any)
		sockopt, _ := stream["sockopt"].(map[string]any)
		if sockopt["mark"] != float64(0x200) {
			t.Fatalf("outbound %s lacks the recursion bypass mark: %#v", tag, outbound)
		}
	}
	if outboundByTag[transparentFailClosedTag]["protocol"] != "blackhole" {
		t.Fatalf("transparent fallback is not fail-closed: %#v", outboundByTag[transparentFailClosedTag])
	}
	lastRule := xray.Routing.Rules[len(xray.Routing.Rules)-1]
	if lastRule["outboundTag"] != transparentFailClosedTag {
		t.Fatalf("transparent catch-all is not fail-closed: %#v", lastRule)
	}
}

func TestManagedTransparentXrayIsDeploymentReady(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Xray.ActivationMode = "managed"
	cfg.Xray.InitScript = "/etc/init.d/router-policy-xray"
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generated := filepath.Join(root, "generated-managed-xray")
	manifest, _, err := Generate(cfg, generated, binding, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.DeploymentReady || manifest.BlockReason != "" {
		t.Fatalf("managed TPROXY remained candidate-only: %+v", manifest)
	}
	plan, err := LoadIPPlan(filepath.Join(generated, IPPlanFile), binding)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.TransparentProxy.Enabled || plan.TransparentProxy.CandidateOnly || plan.TransparentProxy.Status != "READY" || len(plan.Routes) == 0 || len(plan.PlannedRoutes) != 0 {
		t.Fatalf("managed TPROXY plan is not executable: %+v", plan.TransparentProxy)
	}
}

func TestManagedZapretQueuesOnlyHTTPAndForcesQUICToDrop(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Xray.OutboundBundleSHA256 = ""
	cfg.Routes = []config.Route{
		{Type: "direct", Tag: "direct", Priority: 10, Mark: "0x41"},
		{Type: "zapret", Tag: "zapret", Priority: 20, Mark: "0x42"},
		{Type: "drop", Tag: "drop", Priority: 100, Mark: "0x4f"},
	}
	cfg.Zapret = config.Zapret{
		Binary: "/usr/bin/nfqws", InitScript: "/etc/init.d/router-policy-zapret", ActiveConfig: "/etc/router-policy/zapret/nfqws.conf",
		ActivationMode: "managed", Strategy: "tls-fake-ttl3-v1", QueueNum: 200,
	}
	cfg.Services = map[string]config.Service{
		"blocked": {Category: "TSPU_RESTRICTED", Domains: []string{"blocked.example"}, AllowedPaths: []string{"zapret", "drop"}, ProbeURLs: []config.ProbeCheck{{Name: "web", URL: "https://blocked.example/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}}},
	}
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generated := filepath.Join(root, "generated-zapret")
	manifest, _, err := Generate(cfg, generated, binding, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.DeploymentReady || manifest.BlockReason != "" {
		t.Fatalf("managed Zapret remained blocked: %+v", manifest)
	}
	nftRaw, err := os.ReadFile(filepath.Join(generated, NFTFile))
	if err != nil {
		t.Fatal(err)
	}
	nft := string(nftRaw)
	for _, fragment := range []string{"queue num 200", "nfqueue=required", "udp dport 443", "quic=forced_tcp"} {
		if !strings.Contains(nft, fragment) {
			t.Fatalf("managed Zapret nft lacks %q:\n%s", fragment, nft)
		}
	}
	conf, err := os.ReadFile(filepath.Join(generated, ZapretFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"--qnum=200", "--filter-tcp=443", "--dpi-desync=fake", "--dpi-desync-ttl=3", "--orig-ttl=1", "--orig-mod-start=s1", "--orig-mod-cutoff=d1"} {
		if !strings.Contains(string(conf), fragment) {
			t.Fatalf("nfqws config lacks %q: %s", fragment, conf)
		}
	}
}

func TestTransparentConfigRejectsCollidingMarksAndPorts(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	cfg.OpenWrt.XrayBypassMark = cfg.OpenWrt.XrayTProxyMark
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("colliding marks were accepted: %v", err)
	}
	cfg = testConfig(t, t.TempDir())
	cfg.Xray.TransparentPort = 12000
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "SOCKS endpoint") {
		t.Fatalf("colliding transparent/SOCKS ports were accepted: %v", err)
	}
}

func TestDirectOnlyArtifactsRemainDeploymentReady(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Xray.OutboundBundleSHA256 = ""
	cfg.Routes = []config.Route{cfg.Routes[0], cfg.Routes[2]}
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	manifest, _, err := Generate(cfg, filepath.Join(root, "generated-direct"), binding, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.DeploymentReady || manifest.BlockReason != "" {
		t.Fatalf("direct-only artifacts were unnecessarily blocked: %+v", manifest)
	}
}

func TestUnavailableWANIPv6ProducesFailClosedRoute(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Xray.OutboundBundleSHA256 = ""
	cfg.Routes = []config.Route{cfg.Routes[0], cfg.Routes[2]}
	if _, err := WriteNetworkDiagnostics(cfg, NetworkDiagnostics{
		Status:               "VERIFIED",
		Source:               "ipv4-only-fixture",
		Simulation:           true,
		WANInterface:         "wan",
		LANInterfaces:        []string{"br-lan"},
		IPv4Gateway:          "192.0.2.1",
		IPv6Available:        false,
		TransparentProxyMode: "tproxy",
		FlowOffloadingStatus: "VERIFIED",
		CollectedAt:          time.Unix(0, 0).UTC(),
		ExpiresAt:            time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}

	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generated := filepath.Join(root, "generated-ipv4-only")
	manifest, _, err := Generate(cfg, generated, binding, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.DeploymentReady || manifest.BlockReason != "" {
		t.Fatalf("verified IPv4-only diagnostics were not deployable: %+v", manifest)
	}
	plan, err := LoadIPPlan(filepath.Join(generated, IPPlanFile), binding)
	if err != nil {
		t.Fatal(err)
	}
	want := []IPRoute{
		{Family: "ipv4", Table: 100, Destination: "default", Type: "unicast", Via: "192.0.2.1", Device: "wan"},
		{Family: "ipv6", Table: 100, Destination: "::/0", Type: "unreachable"},
	}
	if !reflect.DeepEqual(plan.Routes, want) {
		t.Fatalf("IPv4-only plan is not fail-closed for IPv6: %+v", plan.Routes)
	}
}

func TestLoadIPPlanRejectsInvalidUnreachableRoute(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Xray.OutboundBundleSHA256 = ""
	cfg.Routes = []config.Route{cfg.Routes[0], cfg.Routes[2]}
	if _, err := WriteNetworkDiagnostics(cfg, NetworkDiagnostics{
		Status:               "VERIFIED",
		Source:               "ipv4-only-fixture",
		Simulation:           true,
		WANInterface:         "wan",
		LANInterfaces:        []string{"br-lan"},
		IPv4Gateway:          "192.0.2.1",
		IPv6Available:        false,
		TransparentProxyMode: "tproxy",
		FlowOffloadingStatus: "VERIFIED",
		CollectedAt:          time.Unix(0, 0).UTC(),
		ExpiresAt:            time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generated := filepath.Join(root, "generated-invalid-unreachable")
	if _, _, err := Generate(cfg, generated, binding, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(generated, IPPlanFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var plan IPPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	plan.Routes[1].Device = "wan"
	raw, err = json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIPPlan(path, binding); err == nil || !strings.Contains(err.Error(), "invalid IPv6 unreachable route") {
		t.Fatalf("tampered unreachable route was accepted: %v", err)
	}
}

func TestGeneratedNFTEnforcesDNSCollisionAndXrayFailClosed(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Services["geo"] = config.Service{
		Category: "GEO_LOCKED", Domains: []string{"geo.example"}, AllowedPaths: []string{"vless", "drop"}, RequireNonRUEgress: true,
		ProbeURLs: []config.ProbeCheck{{Name: "web", URL: "https://geo.example/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}},
	}
	cfg.Services["blocked"] = config.Service{
		Category: "BLOCKED", Domains: []string{"blocked.example"}, AllowedPaths: []string{"drop"},
		ProbeURLs: []config.ProbeCheck{{Name: "web", URL: "https://blocked.example/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}},
	}
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generated := filepath.Join(root, "generated-policy")
	if _, _, err := Generate(cfg, generated, binding, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(generated, NFTFile))
	if err != nil {
		t.Fatal(err)
	}
	nft := string(raw)
	required := []string{
		"type filter hook prerouting priority mangle", `iifname { "br-lan" } jump rp_lan_ingress`,
		"type nat hook prerouting priority dstnat", `iifname { "br-lan" } udp dport 53 counter redirect to :53 comment "rp action=dns_intercept protocol=udp"`,
		`tcp dport 853 counter drop comment "rp action=dot_block protocol=tcp"`,
		"DOMAIN_IP_POLICY_COLLISION", "tproxy ip to 127.0.0.1:12345", "tproxy ip6 to [::1]:12345",
		`meta mark set 0x100`, `meta mark 0x200 counter return comment "rp action=xray_recursion_bypass"`,
		`unsupported_transport=drop`, `inherited_mark=cleared`, "chain rp_forward_guard",
	}
	for _, fragment := range required {
		if !strings.Contains(nft, fragment) {
			t.Fatalf("generated nft lacks %q:\n%s", fragment, nft)
		}
	}
	if strings.Contains(nft, `meta mark 0x43 counter accept`) || strings.Contains(nft, `ct mark 0x43 counter accept`) {
		t.Fatalf("classification mark is still treated as route success:\n%s", nft)
	}
	if invalid := regexp.MustCompile(`comment "[^"\n]*" (?:return|drop|accept|redirect)\b`).FindString(nft); invalid != "" {
		t.Fatalf("terminal nft statement appears after comment and is rejected by nft 1.1.1: %q", invalid)
	}

	plan, err := LoadIPPlan(filepath.Join(generated, IPPlanFile), binding)
	if err != nil {
		t.Fatal(err)
	}
	found4, found6 := false, false
	for _, rule := range plan.IPRules {
		if rule.Purpose == "xray_tproxy" && rule.Mark == "0x100" && rule.Table == 102 {
			found4 = found4 || rule.Family == "ipv4"
			found6 = found6 || rule.Family == "ipv6"
		}
	}
	if !found4 || !found6 {
		t.Fatalf("TPROXY mark has no explicit IPv4/IPv6 ip rules: %+v", plan.IPRules)
	}
}

func TestGeneratedDNSMasqBindsDomainsToRouteSetsAndFormatsResolver(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Routes = append(cfg.Routes, config.Route{
		Type: "smart_dns", Tag: "smart-primary", Priority: 15, DNSServer: "203.0.113.53:5353", ConnectToResolvedIP: true,
	})
	cfg.Services["smart"] = config.Service{
		Category: "GEO_LOCKED", Domains: []string{"smart.example"}, AllowedPaths: []string{"smart_dns", "vless", "drop"}, RequireNonRUEgress: true,
		ProbeURLs: []config.ProbeCheck{{Name: "web", URL: "https://smart.example/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}},
	}
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generated := filepath.Join(root, "generated-dns")
	if _, _, err := Generate(cfg, generated, binding, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(generated, DNSMasqFile))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, fragment := range []string{"stop-dns-rebind", "svc_", "route_", "4#inet#router_policy#", "6#inet#router_policy#", "server=/smart.example/203.0.113.53#5353"} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("generated dnsmasq config lacks %q:\n%s", fragment, text)
		}
	}
	if strings.Contains(text, "server=/smart.example/203.0.113.53:5353") {
		t.Fatalf("dnsmasq resolver uses host:port instead of host#port: %s", text)
	}
}

func TestVLESSDNSListenersScaleWithUniqueUsedRoutesNotDomains(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Xray.DNSProxyBasePort = 14000
	cfg.Routes = []config.Route{
		cfg.Routes[0],
		cfg.Routes[1],
		{Type: "vless", Tag: "vless-b", Priority: 21, Mark: "0x43", SOCKS5: "127.0.0.1:12001", DNSServer: "1.1.1.1:53", DNSMode: "socks_remote"},
		{Type: "vless", Tag: "vless-unused", Priority: 22, Mark: "0x43", SOCKS5: "127.0.0.1:12002", DNSServer: "1.1.1.1:53", DNSMode: "socks_remote"},
		cfg.Routes[2],
	}
	cfg.Xray.OutboundBundleSHA256 = storeTestVLESSBundle(t, root, []string{"vless-a", "vless-b", "vless-unused"})

	domainsA := make([]string, 0, 500)
	domainsB := make([]string, 0, 500)
	for i := 0; i < 1000; i++ {
		domain := fmt.Sprintf("d-%04d.scale.example", i)
		if i%2 == 0 {
			domainsA = append(domainsA, domain)
		} else {
			domainsB = append(domainsB, domain)
		}
	}
	cfg.Services = map[string]config.Service{
		"group-a": {Category: "GEO_LOCKED", Domains: domainsA, AllowedPaths: []string{"vless", "drop"}, RequireNonRUEgress: true},
		"group-b": {Category: "GEO_LOCKED", Domains: domainsB, AllowedPaths: []string{"vless", "drop"}, RequireNonRUEgress: true},
	}
	cfg.Overrides = []config.PolicyOverride{{ID: "group-b-vless", Scope: "service", Service: "group-b", RouteTag: "vless-b"}}

	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generated := filepath.Join(root, "generated-grouped-dns")
	if _, _, err := Generate(cfg, generated, binding, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	plan, err := LoadIPPlan(filepath.Join(generated, IPPlanFile), binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.DNSProxies) != 2 {
		t.Fatalf("1000 domains on two used routes created %d DNS listeners: %+v", len(plan.DNSProxies), plan.DNSProxies)
	}
	listenersByRoute := make(map[string]DNSProxyPlan)
	for _, listener := range plan.DNSProxies {
		listenersByRoute[listener.RouteTag] = listener
	}
	if listenersByRoute["vless-a"].Port != 14000 || listenersByRoute["vless-b"].Port != 14001 {
		t.Fatalf("used routes were not assigned stable shared listeners: %+v", listenersByRoute)
	}
	if _, exists := listenersByRoute["vless-unused"]; exists {
		t.Fatalf("unused VLESS route received a DNS listener: %+v", listenersByRoute)
	}

	dnsRaw, err := os.ReadFile(filepath.Join(generated, DNSMasqFile))
	if err != nil {
		t.Fatal(err)
	}
	endpointCounts := make(map[string]int)
	for _, line := range strings.Split(string(dnsRaw), "\n") {
		if !strings.HasPrefix(line, "server=/d-") {
			continue
		}
		endpointCounts[line[strings.LastIndex(line, "/")+1:]]++
	}
	if len(endpointCounts) != 2 || endpointCounts["127.0.0.1#14000"] != 500 || endpointCounts["127.0.0.1#14001"] != 500 {
		t.Fatalf("dnsmasq did not group domains by route listener: %+v", endpointCounts)
	}

	xrayRaw, err := os.ReadFile(filepath.Join(generated, XrayFile))
	if err != nil {
		t.Fatal(err)
	}
	var xray struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"inbounds"`
		Routing struct {
			Rules []struct {
				InboundTags []string `json:"inboundTag"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(xrayRaw, &xray); err != nil {
		t.Fatal(err)
	}
	dnsInboundCount := 0
	for _, inbound := range xray.Inbounds {
		if !strings.HasPrefix(inbound.Tag, "router-policy-dns-") {
			continue
		}
		dnsInboundCount++
		if inbound.Listen != "127.0.0.1" || inbound.Protocol != "dokodemo-door" {
			t.Fatalf("unsafe grouped DNS inbound: %+v", inbound)
		}
	}
	if dnsInboundCount != 2 {
		t.Fatalf("Xray listener count follows domains instead of unique routes: %d", dnsInboundCount)
	}
	dnsRuleIndex, bundleRuleIndex := -1, -1
	for index, rule := range xray.Routing.Rules {
		if len(rule.InboundTags) != 1 || rule.OutboundTag != "vless-a" {
			continue
		}
		switch rule.InboundTags[0] {
		case "router-policy-dns-" + routeID("vless-a"):
			dnsRuleIndex = index
		case "socks-vless-a":
			bundleRuleIndex = index
		}
	}
	if dnsRuleIndex < 0 || bundleRuleIndex < 0 || dnsRuleIndex >= bundleRuleIndex {
		t.Fatalf("route-bound DNS rule does not precede bundle routing rules: dns=%d bundle=%d", dnsRuleIndex, bundleRuleIndex)
	}
}

func TestDropDNSUsesLocalNXDOMAINWithoutUpstream(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Overrides = []config.PolicyOverride{{ID: "drop-github", Scope: "exact_domain", Domain: "github.com", RouteTag: "drop"}}
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generated := filepath.Join(root, "generated-drop-dns")
	if _, _, err := Generate(cfg, generated, binding, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(generated, DNSMasqFile))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	// A server rule without an address is dnsmasq's local NXDOMAIN/no-forward form.
	if !strings.Contains(text, "server=/github.com/\n") {
		t.Fatalf("DROP domain lacks the explicit local NXDOMAIN rule:\n%s", text)
	}
	for _, forbidden := range []string{"address=/github.com/#", "address=/github.com/0.0.0.0", "address=/github.com/::", "local=/github.com/", "server=/github.com/127."} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("DROP domain uses ambiguous address/upstream form %q:\n%s", forbidden, text)
		}
	}
}

func TestLoadIPPlanRejectsNonLoopbackVLESSDNSListener(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Services["github"] = config.Service{Category: "GEO_LOCKED", Domains: []string{"github.com"}, AllowedPaths: []string{"vless", "drop"}, RequireNonRUEgress: true}
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generated := filepath.Join(root, "generated-invalid-dns-plan")
	if _, _, err := Generate(cfg, generated, binding, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(generated, IPPlanFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var plan IPPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.DNSProxies) != 1 {
		t.Fatalf("expected one VLESS DNS listener, got %+v", plan.DNSProxies)
	}
	plan.DNSProxies[0].Listen = "0.0.0.0"
	raw, err = json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIPPlan(path, binding); err == nil || !strings.Contains(err.Error(), "loopback-bound") {
		t.Fatalf("non-loopback DNS listener was accepted: %v", err)
	}
}

func TestMissingLANInterfacesBlocksOtherwiseValidDirectPlan(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Xray.OutboundBundleSHA256 = ""
	cfg.Routes = []config.Route{cfg.Routes[0], cfg.Routes[2]}
	diagnostics := `{"status":"VERIFIED","source":"missing-lan-fixture","simulation":true,"wan_interface":"wan","ipv4_gateway":"192.0.2.1","ipv6_gateway":"2001:db8::1","ipv6_available":true,"collected_at":"1969-01-01T00:00:00Z","expires_at":"2999-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(root, "diagnostics", "network.json"), []byte(diagnostics), 0o600); err != nil {
		t.Fatal(err)
	}
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	manifest, _, err := Generate(cfg, filepath.Join(root, "generated-no-lan"), binding, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.DeploymentReady || manifest.BlockReason != "lan_interfaces_unverified" {
		t.Fatalf("missing LAN diagnostics did not block DNS/firewall apply: %+v", manifest)
	}
}

func TestEnabledFlowOffloadingBlocksPolicyCandidateWithoutExplicitDisable(t *testing.T) {
	root := t.TempDir()
	cfg := smartDNSPolicyConfig(t, root)
	writeFlowDiagnostics(t, root, "VERIFIED", true, true)
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	manifest, _, err := Generate(cfg, filepath.Join(root, "generated-flow-blocked"), binding, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.DeploymentReady || manifest.BlockReason != "flow_offloading_incompatible" {
		t.Fatalf("enabled flow offloading did not block policy apply: %+v", manifest)
	}
}

func TestExplicitFlowOffloadingDisableProducesBoundApplyPlanAndWarning(t *testing.T) {
	root := t.TempDir()
	cfg := smartDNSPolicyConfig(t, root)
	cfg.OpenWrt.FlowOffloadingPolicy = "disable"
	writeFlowDiagnostics(t, root, "VERIFIED", true, true)
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generated := filepath.Join(root, "generated-flow-disable")
	manifest, _, err := Generate(cfg, generated, binding, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.DeploymentReady || !contains(manifest.Warnings, "flow_offloading_disable_planned") {
		t.Fatalf("explicit flow offloading disable was not a warned deployable plan: %+v", manifest)
	}
	plan, err := LoadIPPlan(filepath.Join(generated, IPPlanFile), binding)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.FlowOffloading.Required || plan.FlowOffloading.Action != "disable" || plan.FlowOffloading.Status != "DISABLE_PLANNED" {
		t.Fatalf("flow offloading action is not bound into the IP plan: %+v", plan.FlowOffloading)
	}
}

func smartDNSPolicyConfig(t *testing.T, root string) *config.Config {
	t.Helper()
	cfg := testConfig(t, root)
	cfg.Routes[1].Disabled = true
	cfg.Routes[1].Status = "NOT_CONFIGURED"
	cfg.Xray.OutboundBundleSHA256 = ""
	cfg.Routes = append(cfg.Routes, config.Route{Type: "smart_dns", Tag: "smart", Priority: 30, Mark: "0x41", DNSServer: "203.0.113.53:53", ConnectToResolvedIP: true})
	cfg.Services["github"] = config.Service{
		Category: "GEO_LOCKED", Domains: []string{"github.com"}, AllowedPaths: []string{"smart_dns", "drop"}, RequireNonRUEgress: true,
		ProbeURLs: []config.ProbeCheck{{Name: "web", URL: "https://github.com/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}},
	}
	return cfg
}

func writeFlowDiagnostics(t *testing.T, root, status string, software, hardware bool) {
	t.Helper()
	diagnostics := fmt.Sprintf(`{"status":"VERIFIED","source":"flow-offload-fixture","simulation":true,"wan_interface":"wan","lan_interfaces":["br-lan"],"ipv4_gateway":"192.0.2.1","ipv6_gateway":"2001:db8::1","ipv6_available":true,"transparent_proxy_mode":"tproxy","flow_offloading_status":%q,"software_flow_offloading":%t,"hardware_flow_offloading":%t,"collected_at":"1969-01-01T00:00:00Z","expires_at":"2999-01-01T00:00:00Z"}`, status, software, hardware)
	if err := os.WriteFile(filepath.Join(root, "diagnostics", "network.json"), []byte(diagnostics), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGlobalExactOverrideChangesDNSNFTAndXrayTogether(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Overrides = []config.PolicyOverride{{ID: "drop-github", Scope: "exact_domain", Domain: "github.com", RouteTag: "drop"}}
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generated := filepath.Join(root, "generated-override")
	if _, _, err := Generate(cfg, generated, binding, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	dnsRaw, err := os.ReadFile(filepath.Join(generated, DNSMasqFile))
	if err != nil {
		t.Fatal(err)
	}
	dropSet := "route_" + routeID("drop")
	if !strings.Contains(string(dnsRaw), "nftset=/github.com/") || !strings.Contains(string(dnsRaw), dropSet+"_v4") {
		t.Fatalf("DNS artifact ignored exact override: %s", dnsRaw)
	}
	nftRaw, err := os.ReadFile(filepath.Join(generated, NFTFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(nftRaw), "chain rp_route_"+routeID("drop")) || !strings.Contains(string(nftRaw), "route=drop action=drop") {
		t.Fatalf("nft artifact ignored exact override: %s", nftRaw)
	}
	xrayRaw, err := os.ReadFile(filepath.Join(generated, XrayFile))
	if err != nil {
		t.Fatal(err)
	}
	var xray struct {
		Routing struct {
			Rules []struct {
				Domains     []string `json:"domain"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(xrayRaw, &xray); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rule := range xray.Routing.Rules {
		if len(rule.Domains) == 1 && rule.Domains[0] == "full:github.com" && rule.OutboundTag == "drop" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Xray artifact ignored exact override: %s", xrayRaw)
	}
}

func TestDeviceOverrideBlocksApplyUntilDeviceMatchingIsProven(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.Overrides = []config.PolicyOverride{{
		ID: "device-github", Scope: "device_service", DeviceMAC: "aa:bb:cc:dd:ee:ff", Service: "github", RouteTag: "direct",
	}}
	binding := Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	generated := filepath.Join(root, "generated-device-override")
	manifest, _, err := Generate(cfg, generated, binding, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.DeploymentReady || manifest.BlockReason != "device_policy_data_plane_unverified" {
		t.Fatalf("device policy was falsely marked deployable: %+v", manifest)
	}
	plan, err := LoadIPPlan(filepath.Join(generated, IPPlanFile), binding)
	if err != nil {
		t.Fatal(err)
	}
	if plan.DeploymentReady || len(plan.Routes) != 0 || plan.BlockReason != "device_policy_data_plane_unverified" {
		t.Fatalf("device policy produced executable unverified plan: %+v", plan)
	}
}

func testConfig(t *testing.T, root string) *config.Config {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "diagnostics"), 0o700); err != nil {
		t.Fatal(err)
	}
	diagnostics := `{"status":"VERIFIED","source":"artifact-unit-fixture","simulation":true,"wan_interface":"wan","lan_interfaces":["br-lan"],"ipv4_gateway":"192.0.2.1","ipv6_gateway":"2001:db8::1","ipv6_available":true,"transparent_proxy_mode":"tproxy","flow_offloading_status":"VERIFIED","software_flow_offloading":false,"hardware_flow_offloading":false,"collected_at":"1969-01-01T00:00:00Z","expires_at":"2999-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(root, "diagnostics", "network.json"), []byte(diagnostics), 0o600); err != nil {
		t.Fatal(err)
	}
	bundleRaw := []byte(`{"log":{"loglevel":"warning"},"inbounds":[{"tag":"socks-vless-a","listen":"127.0.0.1","port":12000,"protocol":"socks","settings":{"auth":"noauth","udp":true,"ip":"127.0.0.1"}}],"outbounds":[{"tag":"vless-a","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["socks-vless-a"],"outboundTag":"vless-a"}]}}`)
	bundleSource := filepath.Join(root, "bundle-source.json")
	if err := os.WriteFile(bundleSource, bundleRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	bundleHash := xraybundle.Hash(bundleRaw)
	if _, err := xraybundle.Store(root, bundleSource, bundleHash); err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		Version: 2,
		Storage: config.Storage{StateDir: root},
		OpenWrt: config.OpenWrt{
			FirewallInclude: filepath.Join(root, "active", "rules.nft"), DNSMasqInclude: filepath.Join(root, "active", "dnsmasq.conf"),
			WANRouteTable: 100, ZapretRouteTable: 101, XrayRouteTable: 102,
			DirectMark: "0x41", ZapretMark: "0x42", XrayMark: "0x43", XrayTProxyMark: "0x100", XrayBypassMark: "0x200", DropMark: "0x4f",
		},
		Xray: config.Xray{ActiveConfig: filepath.Join(root, "active", "xray.json"), ProbeDNSResolver: "1.1.1.1:53", TransparentPort: 12345, OutboundBundleSHA256: bundleHash},
		Routes: []config.Route{
			{Type: "direct", Tag: "direct", Priority: 10, Mark: "0x41"},
			{Type: "vless", Tag: "vless-a", Priority: 20, Mark: "0x43", SOCKS5: "127.0.0.1:12000", DNSServer: "1.1.1.1:53", DNSMode: "socks_remote"},
			{Type: "drop", Tag: "drop", Priority: 100, Mark: "0x4f"},
		},
		Services: map[string]config.Service{
			"github": {Category: "DIRECT_PREFERRED", Domains: []string{"github.com"}, AllowedPaths: []string{"direct", "vless", "drop"}, ProbeURLs: []config.ProbeCheck{{Name: "web", URL: "https://github.com/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}}},
		},
	}
}

func storeTestVLESSBundle(t *testing.T, root string, tags []string) string {
	t.Helper()
	testIDs := []string{
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333",
	}
	if len(tags) > len(testIDs) {
		t.Fatalf("test bundle requires %d deterministic fixture IDs", len(tags))
	}
	inbounds := make([]map[string]any, 0, len(tags))
	outbounds := make([]map[string]any, 0, len(tags))
	rules := make([]map[string]any, 0, len(tags))
	for index, tag := range tags {
		inboundTag := "socks-" + tag
		inbounds = append(inbounds, map[string]any{
			"tag": inboundTag, "listen": "127.0.0.1", "port": 12000 + index, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
		})
		outbounds = append(outbounds, map[string]any{
			"tag": tag, "protocol": "vless",
			"settings": map[string]any{"vnext": []map[string]any{{
				"address": "vless.example.com", "port": 443,
				"users": []map[string]any{{"id": testIDs[index], "encryption": "none"}},
			}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "vless.example.com"}},
		})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{inboundTag}, "outboundTag": tag})
	}
	raw, err := json.Marshal(map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
	})
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, fmt.Sprintf("bundle-source-%d.json", len(tags)))
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	bundleHash := xraybundle.Hash(raw)
	if _, err := xraybundle.Store(root, source, bundleHash); err != nil {
		t.Fatal(err)
	}
	return bundleHash
}
