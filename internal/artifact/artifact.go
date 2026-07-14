package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/platform"
	policyengine "router-policy/internal/policy"
	"router-policy/internal/xraybundle"
)

const ManifestVersion = 6

const networkDiagnosticsMaxBytes = 64 * 1024

const (
	NFTFile          = "router-policy.nft"
	DNSMasqFile      = "router-policy-dnsmasq.conf"
	XrayFile         = "xray.json"
	ZapretFile       = "nfqws.conf"
	IPPlanFile       = "ip-plan.json"
	VerifyPlanFile   = "verification-plan.json"
	ManifestFile     = "manifest.json"
	ManifestHashFile = "manifest.sha256"
)

const (
	transparentIPv4InboundTag = "router-policy-tproxy-v4"
	transparentIPv6InboundTag = "router-policy-tproxy-v6"
	transparentFailClosedTag  = "router-policy-tproxy-drop"
)

type Binding struct {
	TransactionID string `json:"transaction_id"`
	RevisionID    string `json:"revision_id"`
	CandidateHash string `json:"candidate_hash"`
}

type Entry struct {
	Kind         string `json:"kind"`
	Path         string `json:"path"`
	Target       string `json:"target,omitempty"`
	SHA256       string `json:"sha256"`
	Bytes        int64  `json:"bytes"`
	Required     bool   `json:"required"`
	ProjectOwned bool   `json:"project_owned"`
}

type RouteProof struct {
	Tag                  string `json:"tag"`
	Type                 string `json:"type"`
	Mark                 string `json:"mark,omitempty"`
	Table                int    `json:"table,omitempty"`
	RulePriority         int    `json:"rule_priority,omitempty"`
	RequiresDNS          bool   `json:"requires_dns"`
	RequiresIPv4         bool   `json:"requires_ipv4"`
	RequiresIPv6         bool   `json:"requires_ipv6"`
	RequiresEgress       bool   `json:"requires_egress"`
	RequiresXrayOutbound bool   `json:"requires_xray_outbound"`
	RequiresZapretFlow   bool   `json:"requires_zapret_flow"`
	RequiresDropProof    bool   `json:"requires_drop_proof"`
	RequiresAdapter      bool   `json:"requires_adapter"`
	Status               string `json:"status"`
}

type IPRule struct {
	Family   string `json:"family"`
	Priority int    `json:"priority"`
	Mark     string `json:"mark"`
	Mask     string `json:"mask,omitempty"`
	Table    int    `json:"table"`
	Purpose  string `json:"purpose"`
}

type IPPlan struct {
	Binding           Binding              `json:"binding"`
	DeploymentReady   bool                 `json:"deployment_ready"`
	BlockReason       string               `json:"block_reason,omitempty"`
	DiagnosticsHash   string               `json:"diagnostics_hash,omitempty"`
	DiagnosticsSource string               `json:"diagnostics_source,omitempty"`
	Simulation        bool                 `json:"simulation"`
	Routes            []IPRoute            `json:"routes"`
	PlannedRoutes     []IPRoute            `json:"planned_routes,omitempty"`
	Rules             []RouteProof         `json:"rules"`
	IPRules           []IPRule             `json:"ip_rules"`
	TransparentProxy  TransparentProxyPlan `json:"transparent_proxy"`
	Zapret            ZapretPlan           `json:"zapret"`
	FlowOffloading    FlowOffloadingPlan   `json:"flow_offloading"`
	DNSProxies        []DNSProxyPlan       `json:"dns_proxies,omitempty"`
	WANInterface      string               `json:"wan_interface,omitempty"`
	LANInterfaces     []string             `json:"lan_interfaces,omitempty"`
}

type DNSProxyPlan struct {
	RouteTag        string `json:"route_tag"`
	InboundTag      string `json:"inbound_tag"`
	Listen          string `json:"listen"`
	Port            int    `json:"port"`
	Upstream        string `json:"upstream"`
	UpstreamPort    int    `json:"upstream_port"`
	XrayOutboundTag string `json:"xray_outbound_tag"`
}

type FlowOffloadingPlan struct {
	PolicyTraffic     bool   `json:"policy_traffic"`
	Required          bool   `json:"required"`
	DiagnosticsStatus string `json:"diagnostics_status,omitempty"`
	SoftwareEnabled   bool   `json:"software_enabled"`
	HardwareEnabled   bool   `json:"hardware_enabled"`
	RequestedPolicy   string `json:"requested_policy"`
	Action            string `json:"action"`
	Status            string `json:"status"`
}

type TransparentProxyPlan struct {
	Enabled            bool   `json:"enabled"`
	CapabilityVerified bool   `json:"capability_verified"`
	CandidateOnly      bool   `json:"candidate_only"`
	Status             string `json:"status"`
	Mode               string `json:"mode,omitempty"`
	IPv4InboundTag     string `json:"ipv4_inbound_tag,omitempty"`
	IPv6InboundTag     string `json:"ipv6_inbound_tag,omitempty"`
	IPv4Listen         string `json:"ipv4_listen,omitempty"`
	IPv6Listen         string `json:"ipv6_listen,omitempty"`
	Port               int    `json:"port,omitempty"`
	TProxyMark         string `json:"tproxy_mark,omitempty"`
	BypassMark         string `json:"bypass_mark,omitempty"`
	RouteTable         int    `json:"route_table,omitempty"`
}

type ZapretPlan struct {
	Enabled       bool   `json:"enabled"`
	CandidateOnly bool   `json:"candidate_only"`
	Status        string `json:"status"`
	QueueNum      int    `json:"queue_num,omitempty"`
	Strategy      string `json:"strategy,omitempty"`
	Binary        string `json:"binary,omitempty"`
	ActiveConfig  string `json:"active_config,omitempty"`
	InitScript    string `json:"init_script,omitempty"`
}

type IPRoute struct {
	Family      string `json:"family"`
	Table       int    `json:"table"`
	Destination string `json:"destination"`
	Type        string `json:"type"`
	Via         string `json:"via,omitempty"`
	Device      string `json:"device,omitempty"`
}

type NetworkDiagnostics = platform.NetworkDiagnostics

func WriteNetworkDiagnostics(cfg *config.Config, diagnostics NetworkDiagnostics) (string, error) {
	if cfg == nil || strings.TrimSpace(cfg.Storage.StateDir) == "" {
		return "", fmt.Errorf("state directory is required for network diagnostics")
	}
	if diagnostics.Status != "VERIFIED" && diagnostics.Status != "UNVERIFIED" {
		return "", fmt.Errorf("network diagnostics status is invalid")
	}
	if strings.TrimSpace(diagnostics.Source) == "" || len(diagnostics.Source) > 128 {
		return "", fmt.Errorf("network diagnostics source is invalid")
	}
	if diagnostics.CollectedAt.IsZero() || diagnostics.ExpiresAt.IsZero() || !diagnostics.ExpiresAt.After(diagnostics.CollectedAt) {
		return "", fmt.Errorf("network diagnostics timestamps are invalid")
	}
	raw, err := json.Marshal(diagnostics)
	if err != nil {
		return "", err
	}
	raw = append(raw, '\n')
	if len(raw) > networkDiagnosticsMaxBytes {
		return "", fmt.Errorf("network diagnostics exceed size limit")
	}
	path := filepath.Join(cfg.Storage.StateDir, "diagnostics", "network.json")
	if err := writeAtomic(path, raw, 0o600); err != nil {
		return "", err
	}
	return hash(raw), nil
}

type VerificationPlan struct {
	Binding              Binding      `json:"binding"`
	RequiredRouteProof   []RouteProof `json:"required_route_proofs"`
	RequireDNSLeakCheck  bool         `json:"require_dns_leak_check"`
	RequireIPv6LeakCheck bool         `json:"require_ipv6_leak_check"`
	RequireManagementLAN bool         `json:"require_management_lan"`
}

type Manifest struct {
	Version         int          `json:"version"`
	Binding         Binding      `json:"binding"`
	GeneratedAt     time.Time    `json:"generated_at"`
	Artifacts       []Entry      `json:"artifacts"`
	RequiredProof   []RouteProof `json:"required_route_proofs"`
	Capabilities    []string     `json:"capabilities"`
	Warnings        []string     `json:"warnings,omitempty"`
	DeploymentReady bool         `json:"deployment_ready"`
	BlockReason     string       `json:"block_reason,omitempty"`
	Simulation      bool         `json:"simulation"`
}

type generatedFile struct {
	kind         string
	name         string
	target       string
	required     bool
	projectOwned bool
	content      []byte
}

func Generate(cfg *config.Config, root string, binding Binding, generatedAt time.Time) (Manifest, string, error) {
	if cfg == nil {
		return Manifest{}, "", fmt.Errorf("candidate config is required")
	}
	if err := cfg.Validate(); err != nil {
		return Manifest{}, "", fmt.Errorf("candidate config validation failed: %w", err)
	}
	if binding.TransactionID == "" || binding.RevisionID == "" || binding.CandidateHash == "" {
		return Manifest{}, "", fmt.Errorf("complete artifact binding is required")
	}
	if root == "" {
		return Manifest{}, "", fmt.Errorf("artifact root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return Manifest{}, "", err
	}
	routes := enabledRoutes(cfg)
	domainPolicies, err := buildDomainPolicies(cfg, routes)
	if err != nil {
		return Manifest{}, "", err
	}
	proofs := buildProofPlan(cfg, routes)
	ipPlan := buildIPPlan(cfg, binding, proofs, hasPolicyTraffic(domainPolicies), generatedAt.UTC())
	dnsProxies, err := buildDNSProxyPlans(cfg, routes, domainPolicies)
	if err != nil {
		return Manifest{}, "", err
	}
	ipPlan.DNSProxies = dnsProxies
	files, err := renderFiles(cfg, binding, routes, proofs, ipPlan, domainPolicies)
	if err != nil {
		return Manifest{}, "", err
	}
	capabilities := []string{
		"candidate-bound-artifacts", "route-and-service-timeout-sets", "shared-ip-collision-fail-closed",
		"lan-dns-53-intercept", "lan-dot-853-block", "conditional-dns", "xray-routing-candidate",
		"explicit-ip-rule-route-plan", "ipv4-ipv6-policy",
		"flow-offloading-guard",
		"vless-loopback-dns-proxy", "vless-route-grouped-dns-proxy", "drop-domain-dns-fail-closed",
	}
	if ipPlan.TransparentProxy.Enabled {
		if ipPlan.TransparentProxy.CandidateOnly {
			capabilities = append(capabilities, "xray-tproxy-candidate-preview")
		} else {
			capabilities = append(capabilities, "xray-tproxy-managed")
		}
	}
	if ipPlan.Zapret.Enabled {
		capabilities = append(capabilities, "zapret-nfqueue-managed")
	}
	if len(cfg.Overrides) > 0 {
		capabilities = append(capabilities, "global-policy-overrides")
	}
	if policyengine.HasDeviceOverrides(cfg) {
		capabilities = append(capabilities, "device-policy-candidate-only")
	}
	manifest := Manifest{
		Version:         ManifestVersion,
		Binding:         binding,
		GeneratedAt:     generatedAt.UTC(),
		RequiredProof:   proofs,
		Capabilities:    capabilities,
		DeploymentReady: ipPlan.DeploymentReady,
		BlockReason:     ipPlan.BlockReason,
		Simulation:      ipPlan.Simulation,
	}
	if ipPlan.FlowOffloading.Action == "disable" {
		manifest.Capabilities = append(manifest.Capabilities, "flow-offloading-disable-plan")
		manifest.Warnings = append(manifest.Warnings, "flow_offloading_disable_planned")
	}
	for _, file := range files {
		path := filepath.Join(root, file.name)
		if err := writeAtomic(path, file.content, 0o600); err != nil {
			return Manifest{}, "", err
		}
		manifest.Artifacts = append(manifest.Artifacts, Entry{
			Kind: file.kind, Path: file.name, Target: file.target,
			SHA256: hash(file.content), Bytes: int64(len(file.content)), Required: file.required, ProjectOwned: file.projectOwned,
		})
	}
	sort.Slice(manifest.Artifacts, func(i, j int) bool { return manifest.Artifacts[i].Path < manifest.Artifacts[j].Path })
	raw, err := json.Marshal(manifest)
	if err != nil {
		return Manifest{}, "", err
	}
	manifestHash := hash(raw)
	if err := writeAtomic(filepath.Join(root, ManifestFile), append(raw, '\n'), 0o600); err != nil {
		return Manifest{}, "", err
	}
	if err := writeAtomic(filepath.Join(root, ManifestHashFile), []byte(manifestHash+"\n"), 0o600); err != nil {
		return Manifest{}, "", err
	}
	return manifest, manifestHash, nil
}

func Verify(root string, expected Binding, expectedManifestHash string) (Manifest, error) {
	manifestPath := filepath.Join(root, ManifestFile)
	if err := requireRegularFile(manifestPath); err != nil {
		return Manifest{}, err
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("invalid artifact manifest: %w", err)
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return Manifest{}, err
	}
	actualManifestHash := hash(canonical)
	if actualManifestHash != expectedManifestHash {
		return Manifest{}, fmt.Errorf("artifact manifest hash mismatch")
	}
	hashFile, err := os.ReadFile(filepath.Join(root, ManifestHashFile))
	if err != nil || strings.TrimSpace(string(hashFile)) != actualManifestHash {
		return Manifest{}, fmt.Errorf("artifact manifest hash file mismatch")
	}
	if manifest.Version != ManifestVersion || manifest.Binding != expected {
		return Manifest{}, fmt.Errorf("artifact manifest binding mismatch")
	}
	seen := map[string]bool{}
	for _, entry := range manifest.Artifacts {
		if seen[entry.Path] || entry.Path == "" || filepath.IsAbs(entry.Path) || filepath.Clean(entry.Path) != entry.Path || strings.HasPrefix(entry.Path, "..") {
			return Manifest{}, fmt.Errorf("invalid artifact path: %q", entry.Path)
		}
		seen[entry.Path] = true
		path := filepath.Join(root, entry.Path)
		if err := requireRegularFile(path); err != nil {
			return Manifest{}, err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return Manifest{}, err
		}
		if int64(len(content)) != entry.Bytes || hash(content) != entry.SHA256 {
			return Manifest{}, fmt.Errorf("artifact hash mismatch: %s", entry.Path)
		}
	}
	for _, required := range []string{NFTFile, DNSMasqFile, XrayFile, ZapretFile, IPPlanFile, VerifyPlanFile} {
		if !seen[required] {
			return Manifest{}, fmt.Errorf("required artifact missing from manifest: %s", required)
		}
	}
	return manifest, nil
}

func renderFiles(cfg *config.Config, binding Binding, routes []config.Route, proofs []RouteProof, plan IPPlan, domainPolicies []domainPolicy) ([]generatedFile, error) {
	nft, err := renderNFT(cfg, binding, routes, plan, domainPolicies)
	if err != nil {
		return nil, err
	}
	dnsmasq, err := renderDNSMasq(cfg, binding, plan, domainPolicies)
	if err != nil {
		return nil, err
	}
	xray, err := renderXray(cfg, routes, plan, domainPolicies)
	if err != nil {
		return nil, err
	}
	zapret, err := renderZapret(plan.Zapret)
	if err != nil {
		return nil, err
	}
	ipPlan, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, err
	}
	verifyPlan, err := json.MarshalIndent(VerificationPlan{Binding: binding, RequiredRouteProof: proofs, RequireDNSLeakCheck: true, RequireIPv6LeakCheck: true, RequireManagementLAN: true}, "", "  ")
	if err != nil {
		return nil, err
	}
	return []generatedFile{
		{kind: "nft", name: NFTFile, target: cfg.OpenWrt.FirewallInclude, required: true, projectOwned: true, content: []byte(nft)},
		{kind: "dnsmasq", name: DNSMasqFile, target: cfg.OpenWrt.DNSMasqInclude, required: true, projectOwned: true, content: []byte(dnsmasq)},
		{kind: "xray", name: XrayFile, target: cfg.Xray.ActiveConfig, required: true, projectOwned: true, content: append(xray, '\n')},
		{kind: "zapret", name: ZapretFile, target: firstNonEmpty(cfg.Zapret.ActiveConfig, "/etc/router-policy/zapret/nfqws.conf"), required: true, projectOwned: true, content: zapret},
		{kind: "ip_plan", name: IPPlanFile, required: true, projectOwned: false, content: append(ipPlan, '\n')},
		{kind: "verification_plan", name: VerifyPlanFile, required: true, projectOwned: false, content: append(verifyPlan, '\n')},
	}, nil
}

type routeAssignment struct {
	Route    config.Route
	ID       string
	Services []string
}

type domainPolicy struct {
	Domain      string
	ServiceName string
	Route       config.Route
	Exact       bool
	OverrideID  string
}

func renderNFT(cfg *config.Config, binding Binding, routes []config.Route, plan IPPlan, domainPolicies []domainPolicy) (string, error) {
	family, table, err := nftIdentity(cfg)
	if err != nil {
		return "", err
	}
	assignments := buildRouteAssignments(domainPolicies)
	dropMark := markForType(cfg, "drop")
	if _, err := parseMark(dropMark); err != nil {
		return "", fmt.Errorf("invalid drop mark: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# generated transaction=%s revision=%s candidate=%s\n", binding.TransactionID, binding.RevisionID, binding.CandidateHash)
	fmt.Fprintf(&b, "table %s %s {\n", family, table)
	names := sortedServiceNames(cfg)
	for _, serviceName := range names {
		id := serviceID(serviceName)
		fmt.Fprintf(&b, "  set svc_%s_v4 { type ipv4_addr; flags interval,timeout; }\n", id)
		fmt.Fprintf(&b, "  set svc_%s_v6 { type ipv6_addr; flags interval,timeout; }\n", id)
	}
	for _, assignment := range assignments {
		fmt.Fprintf(&b, "  set route_%s_v4 { type ipv4_addr; flags interval,timeout; }\n", assignment.ID)
		fmt.Fprintf(&b, "  set route_%s_v6 { type ipv6_addr; flags interval,timeout; }\n", assignment.ID)
	}

	b.WriteString("  chain rp_prerouting {\n")
	b.WriteString("    type filter hook prerouting priority mangle; policy accept;\n")
	if cfg.OpenWrt.XrayBypassMark != "" {
		fmt.Fprintf(&b, "    meta mark %s counter return comment \"rp action=xray_recursion_bypass\"\n", cfg.OpenWrt.XrayBypassMark)
	}
	if len(plan.LANInterfaces) > 0 {
		fmt.Fprintf(&b, "    iifname %s jump rp_lan_ingress\n", nftStringSet(plan.LANInterfaces))
	} else {
		b.WriteString("    counter return comment \"rp status=UNVERIFIED reason=lan_interfaces_unavailable\"\n")
	}
	b.WriteString("  }\n")

	b.WriteString("  chain rp_dns_redirect {\n")
	b.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n")
	if len(plan.LANInterfaces) > 0 {
		fmt.Fprintf(&b, "    iifname %s udp dport 53 counter redirect to :53 comment \"rp action=dns_intercept protocol=udp\"\n", nftStringSet(plan.LANInterfaces))
		fmt.Fprintf(&b, "    iifname %s tcp dport 53 counter redirect to :53 comment \"rp action=dns_intercept protocol=tcp\"\n", nftStringSet(plan.LANInterfaces))
	}
	b.WriteString("  }\n")

	b.WriteString("  chain rp_lan_ingress {\n")
	b.WriteString("    fib daddr type local counter return comment \"rp action=router_local_bypass\"\n")
	b.WriteString("    udp dport 853 counter drop comment \"rp action=dot_block protocol=udp\"\n")
	b.WriteString("    tcp dport 853 counter drop comment \"rp action=dot_block protocol=tcp\"\n")
	b.WriteString("    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n")
	b.WriteString("    ip6 daddr { ::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8 } return\n")
	b.WriteString("    jump rp_collision_guard\n")
	b.WriteString("    jump rp_classify\n")
	b.WriteString("  }\n")

	b.WriteString("  chain rp_collision_guard {\n")
	for i := 0; i < len(assignments); i++ {
		for j := i + 1; j < len(assignments); j++ {
			left, right := assignments[i], assignments[j]
			comment := fmt.Sprintf("rp event=DOMAIN_IP_POLICY_COLLISION routes=%s,%s", safeComment(left.Route.Tag), safeComment(right.Route.Tag))
			fmt.Fprintf(&b, "    ip daddr @route_%s_v4 ip daddr @route_%s_v4 ct mark set %s meta mark set %s counter drop comment \"%s\"\n", left.ID, right.ID, dropMark, dropMark, comment)
			fmt.Fprintf(&b, "    ip6 daddr @route_%s_v6 ip6 daddr @route_%s_v6 ct mark set %s meta mark set %s counter drop comment \"%s\"\n", left.ID, right.ID, dropMark, dropMark, comment)
		}
	}
	b.WriteString("  }\n")

	b.WriteString("  chain rp_classify {\n")
	for _, assignment := range assignments {
		fmt.Fprintf(&b, "    ip daddr @route_%s_v4 jump rp_route_%s\n", assignment.ID, assignment.ID)
		fmt.Fprintf(&b, "    ip6 daddr @route_%s_v6 jump rp_route_%s\n", assignment.ID, assignment.ID)
	}
	b.WriteString("  }\n")
	for _, assignment := range assignments {
		fmt.Fprintf(&b, "  chain rp_route_%s {\n", assignment.ID)
		if err := renderRouteAction(&b, cfg, assignment.Route, plan); err != nil {
			return "", err
		}
		b.WriteString("  }\n")
	}

	b.WriteString("  chain probe_output {\n")
	b.WriteString("    type route hook output priority mangle; policy accept;\n")
	if cfg.OpenWrt.XrayBypassMark != "" {
		fmt.Fprintf(&b, "    meta mark %s counter return comment \"rp action=xray_recursion_bypass\"\n", cfg.OpenWrt.XrayBypassMark)
	}
	for _, route := range routes {
		mark := route.Mark
		if mark == "" {
			mark = markForType(cfg, route.Type)
		}
		if mark == "" {
			continue
		}
		action, quic := nftProbeAction(route.Type)
		comment := fmt.Sprintf("rp route=%s action=%s", safeComment(route.Tag), action)
		if quic != "" {
			comment += " quic=" + quic
		}
		if route.Type == "drop" {
			fmt.Fprintf(&b, "    meta mark %s ct mark set %s counter drop comment \"%s\"\n", mark, mark, comment)
			continue
		}
		if route.Type == "zapret" {
			dropMark := markForType(cfg, "drop")
			fmt.Fprintf(&b, "    meta mark %s udp dport 443 ct mark set %s meta mark set %s counter drop comment \"%s quic=forced_tcp\"\n", mark, dropMark, dropMark, comment)
			fmt.Fprintf(&b, "    meta mark %s tcp dport { 80, 443 } ct mark set %s counter queue num %d comment \"%s nfqueue=required\"\n", mark, mark, plan.Zapret.QueueNum, comment)
			continue
		}
		fmt.Fprintf(&b, "    meta mark %s ct mark set %s counter comment \"%s\"\n", mark, mark, comment)
	}
	b.WriteString("  }\n")
	b.WriteString("  chain rp_forward_guard {\n")
	b.WriteString("    type filter hook forward priority -5; policy accept;\n")
	fmt.Fprintf(&b, "    meta mark %s counter drop comment \"rp action=drop_guard source=meta\"\n", dropMark)
	fmt.Fprintf(&b, "    ct mark %s counter drop comment \"rp action=drop_guard source=conntrack\"\n", dropMark)
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String(), nil
}

func nftProbeAction(routeType string) (string, string) {
	switch routeType {
	case "direct":
		return "direct_bypass", ""
	case "smart_dns":
		return "smart_dns", ""
	case "drop":
		return "drop_probe", ""
	case "zapret":
		return "zapret", "forced_tcp"
	case "vless":
		return "xray", "processed"
	case "tg_ws_proxy":
		return "tg_proxy", "processed"
	default:
		return "unsupported", ""
	}
}

func renderDNSMasq(cfg *config.Config, binding Binding, plan IPPlan, domainPolicies []domainPolicy) (string, error) {
	family, table, err := nftIdentity(cfg)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# generated transaction=%s revision=%s candidate=%s\n", binding.TransactionID, binding.RevisionID, binding.CandidateHash)
	b.WriteString("# Domain answers populate timeout-bound service and route sets.\n")
	b.WriteString("# DROP domains use local NXDOMAIN and are never forwarded upstream.\n")
	b.WriteString("stop-dns-rebind\n")
	for _, policy := range domainPolicies {
		refs := []string{
			fmt.Sprintf("4#%s#%s#route_%s_v4", family, table, routeID(policy.Route.Tag)),
			fmt.Sprintf("6#%s#%s#route_%s_v6", family, table, routeID(policy.Route.Tag)),
		}
		if policy.ServiceName != "" {
			id := serviceID(policy.ServiceName)
			refs = append([]string{
				fmt.Sprintf("4#%s#%s#svc_%s_v4", family, table, id),
				fmt.Sprintf("6#%s#%s#svc_%s_v6", family, table, id),
			}, refs...)
		}
		fmt.Fprintf(&b, "nftset=/%s/%s\n", policy.Domain, strings.Join(refs, ","))
		switch policy.Route.Type {
		case "smart_dns":
			if policy.Route.DNSServer == "" {
				return "", fmt.Errorf("route %s has no Smart DNS endpoint", policy.Route.Tag)
			}
			server, err := dnsmasqServer(policy.Route.DNSServer)
			if err != nil {
				return "", fmt.Errorf("route %s: %w", policy.Route.Tag, err)
			}
			fmt.Fprintf(&b, "server=/%s/%s\n", policy.Domain, server)
		case "vless":
			proxy, ok := dnsProxyForRoute(plan.DNSProxies, policy.Route.Tag)
			if !ok {
				return "", fmt.Errorf("route %s has no bound Xray DNS proxy", policy.Route.Tag)
			}
			server, err := dnsmasqServer(net.JoinHostPort(proxy.Listen, strconv.Itoa(proxy.Port)))
			if err != nil {
				return "", fmt.Errorf("route %s DNS proxy: %w", policy.Route.Tag, err)
			}
			fmt.Fprintf(&b, "server=/%s/%s\n", policy.Domain, server)
		case "drop":
			fmt.Fprintf(&b, "server=/%s/\n", policy.Domain)
		}
	}
	return b.String(), nil
}

func renderRouteAction(b *strings.Builder, cfg *config.Config, route config.Route, plan IPPlan) error {
	classificationMark := firstNonEmpty(route.Mark, markForType(cfg, route.Type))
	if _, err := parseMark(classificationMark); err != nil {
		return fmt.Errorf("route %s has invalid classification mark: %w", route.Tag, err)
	}
	comment := fmt.Sprintf("rp route=%s action=%s", safeComment(route.Tag), nftAction(route.Type))
	switch route.Type {
	case "direct", "smart_dns":
		fmt.Fprintf(b, "    ct mark set %s meta mark set %s counter return comment \"%s inherited_mark=cleared\"\n", classificationMark, classificationMark, comment)
	case "zapret":
		if !plan.Zapret.Enabled || plan.Zapret.QueueNum < 1 {
			return fmt.Errorf("route %s requires a managed Zapret plan", route.Tag)
		}
		dropMark := markForType(cfg, "drop")
		fmt.Fprintf(b, "    udp dport 443 ct mark set %s meta mark set %s counter drop comment \"%s quic=forced_tcp\"\n", dropMark, dropMark, comment)
		fmt.Fprintf(b, "    tcp dport { 80, 443 } ct mark set %s meta mark set %s counter queue num %d comment \"%s nfqueue=required\"\n", classificationMark, classificationMark, plan.Zapret.QueueNum, comment)
		fmt.Fprintf(b, "    ct mark set %s meta mark set %s counter return comment \"%s non_http=direct\"\n", classificationMark, classificationMark, comment)
	case "vless", "tg_ws_proxy":
		if !plan.TransparentProxy.Enabled || plan.TransparentProxy.Port < 1 {
			return fmt.Errorf("route %s requires a transparent proxy plan", route.Tag)
		}
		tproxyMark := plan.TransparentProxy.TProxyMark
		if _, err := parseMark(tproxyMark); err != nil {
			return fmt.Errorf("route %s has invalid TPROXY mark: %w", route.Tag, err)
		}
		fmt.Fprintf(b, "    meta nfproto ipv4 meta l4proto { tcp, udp } ct mark set %s tproxy ip to %s:%d meta mark set %s counter accept comment \"%s family=ipv4\"\n", classificationMark, plan.TransparentProxy.IPv4Listen, plan.TransparentProxy.Port, tproxyMark, comment)
		fmt.Fprintf(b, "    meta nfproto ipv6 meta l4proto { tcp, udp } ct mark set %s tproxy ip6 to [%s]:%d meta mark set %s counter accept comment \"%s family=ipv6\"\n", classificationMark, plan.TransparentProxy.IPv6Listen, plan.TransparentProxy.Port, tproxyMark, comment)
		fmt.Fprintf(b, "    ct mark set %s meta mark set %s counter drop comment \"%s unsupported_transport=drop\"\n", markForType(cfg, "drop"), markForType(cfg, "drop"), comment)
	case "drop":
		fmt.Fprintf(b, "    ct mark set %s meta mark set %s counter drop comment \"%s\"\n", classificationMark, classificationMark, comment)
	default:
		return fmt.Errorf("unsupported route type in nft renderer: %s", route.Type)
	}
	return nil
}

func nftAction(routeType string) string {
	switch routeType {
	case "direct":
		return "direct_bypass"
	case "smart_dns":
		return "smart_dns"
	case "zapret":
		return "zapret"
	case "vless":
		return "xray_tproxy"
	case "tg_ws_proxy":
		return "tg_proxy_tproxy"
	case "drop":
		return "drop"
	default:
		return "unsupported"
	}
}

func renderXray(cfg *config.Config, routes []config.Route, plan IPPlan, domainPolicies []domainPolicy) ([]byte, error) {
	inbounds := []json.RawMessage{}
	outbounds := []json.RawMessage{}
	rules := []json.RawMessage{}
	bundleRules := []json.RawMessage{}
	usedInboundTags := map[string]bool{}
	usedOutboundTags := map[string]bool{}
	bypassMark := uint64(0)
	if plan.TransparentProxy.Enabled {
		var err error
		bypassMark, err = markNumber(plan.TransparentProxy.BypassMark)
		if err != nil {
			return nil, fmt.Errorf("invalid transparent proxy bypass mark: %w", err)
		}
		for _, inbound := range []map[string]any{
			transparentInbound(plan.TransparentProxy.IPv4InboundTag, plan.TransparentProxy.IPv4Listen, plan.TransparentProxy.Port, false),
			transparentInbound(plan.TransparentProxy.IPv6InboundTag, plan.TransparentProxy.IPv6Listen, plan.TransparentProxy.Port, true),
		} {
			tag, _ := inbound["tag"].(string)
			if usedInboundTags[tag] {
				return nil, fmt.Errorf("duplicate Xray inbound tag: %s", tag)
			}
			raw, err := json.Marshal(inbound)
			if err != nil {
				return nil, err
			}
			inbounds = append(inbounds, raw)
			usedInboundTags[tag] = true
		}
	}
	for _, proxy := range plan.DNSProxies {
		if usedInboundTags[proxy.InboundTag] {
			return nil, fmt.Errorf("duplicate Xray DNS inbound tag: %s", proxy.InboundTag)
		}
		raw, err := json.Marshal(map[string]any{
			"tag": proxy.InboundTag, "listen": proxy.Listen, "port": proxy.Port, "protocol": "dokodemo-door",
			"settings": map[string]any{"address": proxy.Upstream, "port": proxy.UpstreamPort, "network": "tcp,udp"},
		})
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, raw)
		usedInboundTags[proxy.InboundTag] = true
	}
	if cfg.Xray.OutboundBundleSHA256 != "" {
		bundle, err := xraybundle.Load(cfg.Storage.StateDir, cfg.Xray.OutboundBundleSHA256)
		if err != nil {
			return nil, fmt.Errorf("load bound Xray bundle: %w", err)
		}
		if err := xraybundle.ValidateRoutes(bundle, cfg.Routes); err != nil {
			return nil, fmt.Errorf("validate bound Xray bundle: %w", err)
		}
		for _, raw := range bundle.Inbounds {
			var value struct {
				Tag string `json:"tag"`
			}
			if err := json.Unmarshal(raw, &value); err != nil || value.Tag == "" || usedInboundTags[value.Tag] {
				return nil, errors.New("bound Xray bundle has invalid or colliding inbound tags")
			}
			inbounds = append(inbounds, raw)
			usedInboundTags[value.Tag] = true
		}
		bundleRules = append(bundleRules, bundle.Rules...)
		for _, raw := range bundle.Outbounds {
			var value struct {
				Tag string `json:"tag"`
			}
			if err := json.Unmarshal(raw, &value); err != nil || value.Tag == "" || usedOutboundTags[value.Tag] {
				return nil, errors.New("bound Xray bundle has invalid outbound tags")
			}
			if plan.TransparentProxy.Enabled {
				raw, err = withOutboundBypassMark(raw, bypassMark)
				if err != nil {
					return nil, fmt.Errorf("Xray outbound %s: %w", value.Tag, err)
				}
			}
			outbounds = append(outbounds, raw)
			usedOutboundTags[value.Tag] = true
		}
	}
	for _, route := range routes {
		if route.Type == "vless" {
			if !usedOutboundTags[route.Tag] {
				return nil, fmt.Errorf("VLESS route %s is not present in bound Xray bundle", route.Tag)
			}
			continue
		}
		if usedOutboundTags[route.Tag] {
			return nil, fmt.Errorf("duplicate Xray outbound tag: %s", route.Tag)
		}
		outbound := map[string]any{"tag": route.Tag}
		switch route.Type {
		case "drop":
			outbound["protocol"] = "blackhole"
			outbound["settings"] = map[string]any{}
		case "tg_ws_proxy":
			host, port, err := splitProxy(route.SOCKS5)
			if err != nil {
				return nil, fmt.Errorf("route %s: %w", route.Tag, err)
			}
			outbound["protocol"] = "socks"
			outbound["settings"] = map[string]any{"servers": []map[string]any{{"address": host, "port": port}}}
		default:
			outbound["protocol"] = "freedom"
			outbound["settings"] = map[string]any{}
		}
		raw, err := json.Marshal(outbound)
		if err != nil {
			return nil, err
		}
		if plan.TransparentProxy.Enabled {
			raw, err = withOutboundBypassMark(raw, bypassMark)
			if err != nil {
				return nil, fmt.Errorf("Xray outbound %s: %w", route.Tag, err)
			}
		}
		outbounds = append(outbounds, raw)
		usedOutboundTags[route.Tag] = true
	}
	for _, proxy := range plan.DNSProxies {
		if !usedOutboundTags[proxy.XrayOutboundTag] {
			return nil, fmt.Errorf("Xray DNS proxy %s selects missing outbound %s", proxy.RouteTag, proxy.XrayOutboundTag)
		}
		raw, err := json.Marshal(map[string]any{"type": "field", "inboundTag": []string{proxy.InboundTag}, "outboundTag": proxy.XrayOutboundTag})
		if err != nil {
			return nil, err
		}
		rules = append(rules, raw)
	}
	rules = append(rules, bundleRules...)
	if plan.TransparentProxy.Enabled {
		if usedOutboundTags[transparentFailClosedTag] {
			return nil, fmt.Errorf("reserved Xray outbound tag is already used: %s", transparentFailClosedTag)
		}
		failClosed, err := json.Marshal(map[string]any{"tag": transparentFailClosedTag, "protocol": "blackhole", "settings": map[string]any{}})
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, failClosed)
		usedOutboundTags[transparentFailClosedTag] = true
		transparentTags := []string{plan.TransparentProxy.IPv4InboundTag, plan.TransparentProxy.IPv6InboundTag}
		for _, policy := range domainPolicies {
			outboundTag := policy.Route.Tag
			if policy.Route.Type == "drop" && !usedOutboundTags[outboundTag] {
				outboundTag = transparentFailClosedTag
			}
			if !usedOutboundTags[outboundTag] {
				return nil, fmt.Errorf("domain %s selects unknown Xray outbound %s", policy.Domain, outboundTag)
			}
			domainMatch := "domain:" + policy.Domain
			if policy.Exact {
				domainMatch = "full:" + policy.Domain
			}
			raw, err := json.Marshal(map[string]any{"type": "field", "inboundTag": transparentTags, "domain": []string{domainMatch}, "outboundTag": outboundTag})
			if err != nil {
				return nil, err
			}
			rules = append(rules, raw)
		}
		raw, err := json.Marshal(map[string]any{"type": "field", "inboundTag": transparentTags, "outboundTag": transparentFailClosedTag})
		if err != nil {
			return nil, err
		}
		rules = append(rules, raw)
	}
	value := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}
	return json.MarshalIndent(value, "", "  ")
}

func renderZapret(plan ZapretPlan) ([]byte, error) {
	if !plan.Enabled {
		return []byte("# router-policy: zapret disabled\n"), nil
	}
	if plan.QueueNum < 1 || plan.QueueNum > 65535 || plan.Strategy != "tls-fake-ttl3-v1" {
		return nil, fmt.Errorf("invalid managed Zapret plan")
	}
	return []byte(fmt.Sprintf(`--qnum=%d
--filter-tcp=80
--dpi-desync=fake,fakedsplit
--dpi-desync-split-pos=method+2
--dpi-desync-fooling=md5sig
--new
--filter-tcp=443
--dpi-desync=fake
--dpi-desync-ttl=3
--orig-ttl=1
--orig-mod-start=s1
--orig-mod-cutoff=d1
`, plan.QueueNum)), nil
}

func transparentInbound(tag, listen string, port int, v6Only bool) map[string]any {
	sockopt := map[string]any{"tproxy": "tproxy"}
	if v6Only {
		sockopt["V6Only"] = true
	}
	return map[string]any{
		"tag": tag, "listen": listen, "port": port, "protocol": "tunnel",
		"settings":       map[string]any{"allowedNetwork": "tcp,udp", "followRedirect": true},
		"sniffing":       map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}},
		"streamSettings": map[string]any{"sockopt": sockopt},
	}
}

func withOutboundBypassMark(raw json.RawMessage, mark uint64) (json.RawMessage, error) {
	var outbound map[string]any
	if err := json.Unmarshal(raw, &outbound); err != nil {
		return nil, errors.New("invalid outbound JSON")
	}
	protocol, _ := outbound["protocol"].(string)
	if protocol == "" {
		return nil, errors.New("outbound protocol is missing")
	}
	if protocol == "blackhole" {
		return raw, nil
	}
	stream, ok := outbound["streamSettings"].(map[string]any)
	if outbound["streamSettings"] != nil && !ok {
		return nil, errors.New("streamSettings must be an object")
	}
	if !ok {
		stream = map[string]any{}
		outbound["streamSettings"] = stream
	}
	sockopt, ok := stream["sockopt"].(map[string]any)
	if stream["sockopt"] != nil && !ok {
		return nil, errors.New("streamSettings.sockopt must be an object")
	}
	if !ok {
		sockopt = map[string]any{}
		stream["sockopt"] = sockopt
	}
	sockopt["mark"] = mark
	return json.Marshal(outbound)
}

func buildProofPlan(cfg *config.Config, routes []config.Route) []RouteProof {
	proofs := make([]RouteProof, 0, len(routes))
	for i, route := range routes {
		requiresEgress := route.Type == "direct" || route.Type == "zapret" || route.Type == "vless" || route.Type == "tg_ws_proxy"
		proofs = append(proofs, RouteProof{
			Tag: route.Tag, Type: route.Type, Mark: firstNonEmpty(route.Mark, markForType(cfg, route.Type)),
			Table: tableForType(cfg, route.Type), RulePriority: 10010 + i*10,
			RequiresDNS: route.Type != "drop", RequiresIPv4: route.Type != "drop", RequiresIPv6: route.Type != "drop",
			RequiresEgress: requiresEgress, RequiresXrayOutbound: route.Type == "vless",
			RequiresZapretFlow: route.Type == "zapret", RequiresDropProof: route.Type == "drop",
			RequiresAdapter: route.RequiresAdapter, Status: firstNonEmpty(route.Status, "CONFIGURED"),
		})
	}
	return proofs
}

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,32}$`)

func buildIPPlan(cfg *config.Config, binding Binding, proofs []RouteProof, policyTraffic bool, generatedAt time.Time) IPPlan {
	flowPolicy := cfg.OpenWrt.FlowOffloadingPolicy
	if flowPolicy == "" {
		flowPolicy = "preserve"
	}
	flowPlan := FlowOffloadingPlan{
		PolicyTraffic: policyTraffic, RequestedPolicy: flowPolicy, Action: "none", Status: "NOT_APPLICABLE",
	}
	if flowPolicy == "disable" {
		flowPlan.Required = true
		flowPlan.Action = "disable"
		flowPlan.Status = "DISABLE_PLANNED"
	} else if policyTraffic {
		flowPlan.Required = true
		flowPlan.Status = "UNVERIFIED"
	}
	plan := IPPlan{Binding: binding, Rules: proofs, Routes: []IPRoute{}, IPRules: buildIPRules(cfg, proofs), FlowOffloading: flowPlan}
	needsNetwork := false
	for _, proof := range proofs {
		if proof.Type != "drop" {
			needsNetwork = true
		}
		if proof.Type == "vless" || proof.Type == "tg_ws_proxy" {
			managed := cfg.Xray.ActivationMode == "managed"
			plan.TransparentProxy = TransparentProxyPlan{
				Enabled: true, CandidateOnly: !managed, Status: "UNVERIFIED", Mode: "tproxy",
				IPv4InboundTag: transparentIPv4InboundTag, IPv6InboundTag: transparentIPv6InboundTag,
				IPv4Listen: "127.0.0.1", IPv6Listen: "::1", Port: cfg.Xray.TransparentPort,
				TProxyMark: cfg.OpenWrt.XrayTProxyMark, BypassMark: cfg.OpenWrt.XrayBypassMark,
				RouteTable: cfg.OpenWrt.XrayRouteTable,
			}
		}
		if proof.Type == "zapret" {
			plan.Zapret = ZapretPlan{
				Enabled: true, CandidateOnly: cfg.Zapret.ActivationMode != "managed", Status: "UNVERIFIED",
				QueueNum: cfg.Zapret.QueueNum, Strategy: cfg.Zapret.Strategy, Binary: cfg.Zapret.Binary,
				ActiveConfig: cfg.Zapret.ActiveConfig, InitScript: cfg.Zapret.InitScript,
			}
		}
	}
	if !needsNetwork && !plan.FlowOffloading.Required {
		if policyengine.HasDeviceOverrides(cfg) {
			plan.BlockReason = "device_policy_data_plane_unverified"
			return plan
		}
		plan.DeploymentReady = true
		return plan
	}
	diagnostics, diagnosticsHash, reason := loadNetworkDiagnostics(cfg, generatedAt)
	plan.DiagnosticsHash = diagnosticsHash
	plan.DiagnosticsSource = diagnostics.Source
	plan.Simulation = diagnostics.Simulation
	if reason != "" {
		plan.BlockReason = reason
		return plan
	}
	if plan.TransparentProxy.Enabled {
		if diagnostics.TransparentProxyMode != "tproxy" {
			plan.BlockReason = "transparent_proxy_mode_unverified"
			return plan
		}
		plan.TransparentProxy.CapabilityVerified = true
		if plan.TransparentProxy.CandidateOnly {
			plan.TransparentProxy.Status = "CANDIDATE_ONLY"
		} else {
			plan.TransparentProxy.Status = "READY"
		}
	}
	if plan.Zapret.Enabled {
		if plan.Zapret.CandidateOnly {
			plan.Zapret.Status = "CANDIDATE_ONLY"
		} else {
			plan.Zapret.Status = "READY"
		}
	}
	plan.WANInterface = diagnostics.WANInterface
	plan.LANInterfaces = append([]string(nil), diagnostics.LANInterfaces...)
	if len(plan.LANInterfaces) == 0 {
		plan.BlockReason = "lan_interfaces_unverified"
		return plan
	}
	for _, lan := range plan.LANInterfaces {
		if !interfaceNamePattern.MatchString(lan) || lan == diagnostics.WANInterface {
			plan.BlockReason = "lan_interfaces_invalid"
			return plan
		}
	}
	flowBlockReason := ""
	plan.FlowOffloading.DiagnosticsStatus = diagnostics.FlowOffloadingStatus
	plan.FlowOffloading.SoftwareEnabled = diagnostics.SoftwareFlowOffload
	plan.FlowOffloading.HardwareEnabled = diagnostics.HardwareFlowOffload
	if plan.FlowOffloading.PolicyTraffic && plan.FlowOffloading.RequestedPolicy == "preserve" {
		switch {
		case diagnostics.FlowOffloadingStatus != "VERIFIED":
			plan.FlowOffloading.Status = "UNVERIFIED"
			flowBlockReason = "flow_offloading_unverified"
		case diagnostics.SoftwareFlowOffload || diagnostics.HardwareFlowOffload:
			plan.FlowOffloading.Status = "INCOMPATIBLE"
			flowBlockReason = "flow_offloading_incompatible"
		default:
			plan.FlowOffloading.Status = "VERIFIED_DISABLED"
		}
	}
	seen := map[string]bool{}
	add := func(route IPRoute) {
		key := fmt.Sprintf("%s:%d:%s:%s:%s:%s", route.Family, route.Table, route.Destination, route.Type, route.Via, route.Device)
		if !seen[key] {
			seen[key] = true
			plan.Routes = append(plan.Routes, route)
		}
	}
	block := func(reason string) IPPlan {
		plan.BlockReason = reason
		plan.Routes = []IPRoute{}
		return plan
	}
	for _, proof := range proofs {
		if proof.Type == "drop" {
			continue
		}
		if proof.Table < 1 {
			return block("route_table_not_configured")
		}
		switch proof.Type {
		case "direct", "zapret", "smart_dns":
			if !interfaceNamePattern.MatchString(diagnostics.WANInterface) {
				return block("wan_interface_unverified")
			}
			if proof.RequiresIPv4 {
				gateway := net.ParseIP(diagnostics.IPv4Gateway)
				if gateway == nil || gateway.To4() == nil {
					return block("ipv4_gateway_unverified")
				}
				add(IPRoute{Family: "ipv4", Table: proof.Table, Destination: "default", Type: "unicast", Via: diagnostics.IPv4Gateway, Device: diagnostics.WANInterface})
			}
			if proof.RequiresIPv6 {
				if diagnostics.IPv6Available {
					gateway := net.ParseIP(diagnostics.IPv6Gateway)
					if gateway == nil || gateway.To4() != nil {
						return block("ipv6_gateway_unverified")
					}
					add(IPRoute{Family: "ipv6", Table: proof.Table, Destination: "default", Type: "unicast", Via: diagnostics.IPv6Gateway, Device: diagnostics.WANInterface})
				} else {
					add(IPRoute{Family: "ipv6", Table: proof.Table, Destination: "::/0", Type: "unreachable"})
				}
			}
		case "vless", "tg_ws_proxy":
			if proof.RequiresIPv4 {
				add(IPRoute{Family: "ipv4", Table: proof.Table, Destination: "0.0.0.0/0", Type: "local", Device: "lo"})
			}
			if proof.RequiresIPv6 {
				add(IPRoute{Family: "ipv6", Table: proof.Table, Destination: "::/0", Type: "local", Device: "lo"})
			}
		default:
			return block("route_type_unsupported")
		}
	}
	if policyengine.HasDeviceOverrides(cfg) {
		plan.PlannedRoutes = append([]IPRoute(nil), plan.Routes...)
		plan.Routes = []IPRoute{}
		plan.BlockReason = "device_policy_data_plane_unverified"
		return plan
	}
	if plan.TransparentProxy.Enabled && plan.TransparentProxy.CandidateOnly {
		plan.PlannedRoutes = append([]IPRoute(nil), plan.Routes...)
		plan.Routes = []IPRoute{}
		plan.BlockReason = "transparent_activation_unverified"
		return plan
	}
	if plan.Zapret.Enabled && plan.Zapret.CandidateOnly {
		plan.PlannedRoutes = append([]IPRoute(nil), plan.Routes...)
		plan.Routes = []IPRoute{}
		plan.BlockReason = "zapret_activation_unverified"
		return plan
	}
	if flowBlockReason != "" {
		plan.PlannedRoutes = append([]IPRoute(nil), plan.Routes...)
		plan.Routes = []IPRoute{}
		plan.BlockReason = flowBlockReason
		return plan
	}
	plan.DeploymentReady = true
	return plan
}

func hasPolicyTraffic(policies []domainPolicy) bool {
	for _, policy := range policies {
		if policy.Route.Type != "direct" {
			return true
		}
	}
	return false
}

func buildDNSProxyPlans(cfg *config.Config, routes []config.Route, domainPolicies []domainPolicy) ([]DNSProxyPlan, error) {
	usedVLESSRoutes := make(map[string]bool)
	for _, policy := range domainPolicies {
		if policy.Route.Type == "vless" {
			usedVLESSRoutes[policy.Route.Tag] = true
		}
	}
	if len(usedVLESSRoutes) == 0 {
		return nil, nil
	}
	vlessRoutes := make([]config.Route, 0)
	usedPorts := map[int]bool{cfg.Xray.TransparentPort: true}
	for _, route := range routes {
		if route.SOCKS5 != "" {
			_, port, err := splitProxy(route.SOCKS5)
			if err != nil {
				return nil, fmt.Errorf("route %s SOCKS endpoint: %w", route.Tag, err)
			}
			usedPorts[port] = true
		}
		if route.Type == "vless" {
			vlessRoutes = append(vlessRoutes, route)
		}
	}
	upstream, upstreamPort, err := parsePublicDNSResolver(cfg.Xray.ProbeDNSResolver)
	if err != nil {
		return nil, err
	}
	sort.Slice(vlessRoutes, func(i, j int) bool { return vlessRoutes[i].Tag < vlessRoutes[j].Tag })
	basePort := cfg.Xray.DNSProxyBasePort
	if basePort == 0 {
		basePort = 14000
	}
	plans := make([]DNSProxyPlan, 0, len(usedVLESSRoutes))
	for index, route := range vlessRoutes {
		if !usedVLESSRoutes[route.Tag] {
			continue
		}
		port := basePort + index
		if port > 65535 || usedPorts[port] {
			return nil, fmt.Errorf("Xray DNS proxy port %d is unavailable", port)
		}
		usedPorts[port] = true
		plans = append(plans, DNSProxyPlan{
			RouteTag: route.Tag, InboundTag: "router-policy-dns-" + routeID(route.Tag),
			Listen: "127.0.0.1", Port: port, Upstream: upstream, UpstreamPort: upstreamPort, XrayOutboundTag: route.Tag,
		})
	}
	if len(plans) != len(usedVLESSRoutes) {
		return nil, fmt.Errorf("domain policy selects an unavailable VLESS DNS route")
	}
	return plans, nil
}

func parsePublicDNSResolver(value string) (string, int, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, fmt.Errorf("invalid Xray DNS proxy upstream")
	}
	port, err := strconv.Atoi(portText)
	ip := net.ParseIP(host)
	if err != nil || port != 53 || ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return "", 0, fmt.Errorf("invalid Xray DNS proxy upstream")
	}
	return ip.String(), port, nil
}

func dnsProxyForRoute(plans []DNSProxyPlan, routeTag string) (DNSProxyPlan, bool) {
	for _, plan := range plans {
		if plan.RouteTag == routeTag {
			return plan, true
		}
	}
	return DNSProxyPlan{}, false
}

func buildIPRules(cfg *config.Config, proofs []RouteProof) []IPRule {
	type ruleKey struct {
		mark  string
		table int
	}
	seen := map[ruleKey]bool{}
	var rules []IPRule
	add := func(mark string, table, priority int, purpose string) {
		if mark == "" || table <= 0 || priority <= 0 || seen[ruleKey{mark: mark, table: table}] {
			return
		}
		seen[ruleKey{mark: mark, table: table}] = true
		for _, family := range []string{"ipv4", "ipv6"} {
			rules = append(rules, IPRule{Family: family, Priority: priority, Mark: mark, Mask: "0xffffffff", Table: table, Purpose: purpose})
		}
	}
	hasTransparent := false
	for _, proof := range proofs {
		if proof.Type == "vless" || proof.Type == "tg_ws_proxy" {
			hasTransparent = true
			break
		}
	}
	if hasTransparent && cfg.OpenWrt.XrayTProxyMark != "" {
		add(cfg.OpenWrt.XrayTProxyMark, cfg.OpenWrt.XrayRouteTable, 10000, "xray_tproxy")
	}
	for _, proof := range proofs {
		if proof.Type != "drop" {
			add(proof.Mark, proof.Table, proof.RulePriority, "route:"+proof.Tag)
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		if rules[i].Family != rules[j].Family {
			return rules[i].Family < rules[j].Family
		}
		return rules[i].Mark < rules[j].Mark
	})
	return rules
}

func loadNetworkDiagnostics(cfg *config.Config, generatedAt time.Time) (NetworkDiagnostics, string, string) {
	if cfg.Storage.StateDir == "" {
		return NetworkDiagnostics{}, "", "network_diagnostics_missing"
	}
	path := filepath.Join(cfg.Storage.StateDir, "diagnostics", "network.json")
	if err := requireRegularFile(path); err != nil {
		return NetworkDiagnostics{}, "", "network_diagnostics_missing"
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() <= 0 || info.Size() > networkDiagnosticsMaxBytes {
		return NetworkDiagnostics{}, "", "network_diagnostics_invalid"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return NetworkDiagnostics{}, "", "network_diagnostics_invalid"
	}
	var diagnostics NetworkDiagnostics
	if err := json.Unmarshal(raw, &diagnostics); err != nil {
		return NetworkDiagnostics{}, hash(raw), "network_diagnostics_invalid"
	}
	if diagnostics.Status != "VERIFIED" || strings.TrimSpace(diagnostics.Source) == "" || diagnostics.CollectedAt.IsZero() || diagnostics.ExpiresAt.IsZero() || !generatedAt.Before(diagnostics.ExpiresAt) || diagnostics.CollectedAt.After(generatedAt.Add(time.Minute)) {
		return NetworkDiagnostics{}, hash(raw), "network_diagnostics_stale_or_unverified"
	}
	return diagnostics, hash(raw), ""
}

func enabledRoutes(cfg *config.Config) []config.Route {
	routes := make([]config.Route, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		if route.Enabled() {
			routes = append(routes, route)
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Priority != routes[j].Priority {
			return routes[i].Priority < routes[j].Priority
		}
		return routes[i].Tag < routes[j].Tag
	})
	return routes
}

func selectRoute(cfg *config.Config, svc config.Service, routes []config.Route) config.Route {
	for _, allowed := range svc.AllowedPaths {
		for _, route := range routes {
			if route.Type == allowed && config.PathAllowed(svc, route, cfg.Policy) {
				return route
			}
		}
	}
	for _, route := range routes {
		if route.Type == "drop" {
			return route
		}
	}
	return config.Route{Type: "drop", Tag: "drop", Priority: 1000, Mark: cfg.OpenWrt.DropMark}
}

func buildDomainPolicies(cfg *config.Config, routes []config.Route) ([]domainPolicy, error) {
	seen := map[string]bool{}
	var policies []domainPolicy
	add := func(domain, serviceName string, exact bool) error {
		if seen[domain] {
			return nil
		}
		service := cfg.Services[serviceName]
		match, overridden, err := policyengine.Match(cfg, domain, "", serviceName, service.Category)
		if err != nil {
			return err
		}
		route := config.Route{}
		if overridden {
			var ok bool
			route, ok = policyengine.SelectRoute(match, routes)
			if !ok {
				return fmt.Errorf("override %s targets an unavailable route", match.Override.ID)
			}
			exact = match.Override.Scope == "exact_domain"
		} else {
			route = selectRoute(cfg, service, routes)
		}
		policy := domainPolicy{Domain: domain, ServiceName: serviceName, Route: route, Exact: exact}
		if overridden {
			policy.OverrideID = match.Override.ID
		}
		policies = append(policies, policy)
		seen[domain] = true
		return nil
	}
	for _, serviceName := range sortedServiceNames(cfg) {
		domains := append([]string(nil), cfg.Services[serviceName].Domains...)
		sort.Strings(domains)
		for _, domain := range domains {
			if err := add(domain, serviceName, false); err != nil {
				return nil, err
			}
		}
	}
	for _, override := range cfg.Overrides {
		if override.Scope != "exact_domain" || seen[override.Domain] {
			continue
		}
		if err := add(override.Domain, cfg.ServiceForDomain(override.Domain), true); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(policies, func(i, j int) bool {
		if policies[i].Exact != policies[j].Exact {
			return policies[i].Exact
		}
		leftDepth := strings.Count(policies[i].Domain, ".")
		rightDepth := strings.Count(policies[j].Domain, ".")
		if leftDepth != rightDepth {
			return leftDepth > rightDepth
		}
		return policies[i].Domain < policies[j].Domain
	})
	return policies, nil
}

func buildRouteAssignments(policies []domainPolicy) []routeAssignment {
	byTag := map[string]*routeAssignment{}
	for _, policy := range policies {
		assignment := byTag[policy.Route.Tag]
		if assignment == nil {
			assignment = &routeAssignment{Route: policy.Route, ID: routeID(policy.Route.Tag)}
			byTag[policy.Route.Tag] = assignment
		}
		if policy.ServiceName != "" && !contains(assignment.Services, policy.ServiceName) {
			assignment.Services = append(assignment.Services, policy.ServiceName)
		}
	}
	assignments := make([]routeAssignment, 0, len(byTag))
	for _, assignment := range byTag {
		assignments = append(assignments, *assignment)
	}
	sort.Slice(assignments, func(i, j int) bool {
		if assignments[i].Route.Priority != assignments[j].Route.Priority {
			return assignments[i].Route.Priority < assignments[j].Route.Priority
		}
		return assignments[i].Route.Tag < assignments[j].Route.Tag
	})
	return assignments
}

var nftNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,31}$`)

func nftIdentity(cfg *config.Config) (string, string, error) {
	family := firstNonEmpty(cfg.OpenWrt.NFTFamily, "inet")
	table := firstNonEmpty(cfg.OpenWrt.NFTTable, "router_policy")
	if family != "inet" || !nftNamePattern.MatchString(table) {
		return "", "", fmt.Errorf("generated policy requires nft family inet and a safe table name")
	}
	return family, table, nil
}

func nftStringSet(values []string) string {
	unique := map[string]bool{}
	for _, value := range values {
		if interfaceNamePattern.MatchString(value) {
			unique[value] = true
		}
	}
	ordered := make([]string, 0, len(unique))
	for value := range unique {
		ordered = append(ordered, `"`+value+`"`)
	}
	sort.Strings(ordered)
	return "{ " + strings.Join(ordered, ", ") + " }"
}

func dnsmasqServer(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || net.ParseIP(host) == nil {
		return "", fmt.Errorf("invalid DNS endpoint")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid DNS endpoint port")
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]#" + port, nil
	}
	return host + "#" + port, nil
}

func routeID(tag string) string {
	sum := sha256.Sum256([]byte("route:" + strings.ToLower(tag)))
	return hex.EncodeToString(sum[:6])
}

func parseMark(value string) (uint64, error) { return markNumber(value) }

func sortedServiceNames(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.Services))
	for name := range cfg.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func serviceID(name string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(name)))
	return hex.EncodeToString(sum[:6])
}

func markForType(cfg *config.Config, routeType string) string {
	switch routeType {
	case "direct", "smart_dns":
		return cfg.OpenWrt.DirectMark
	case "zapret":
		return cfg.OpenWrt.ZapretMark
	case "vless", "tg_ws_proxy":
		return cfg.OpenWrt.XrayMark
	case "drop":
		return cfg.OpenWrt.DropMark
	default:
		return ""
	}
}

func tableForType(cfg *config.Config, routeType string) int {
	switch routeType {
	case "direct", "smart_dns":
		return cfg.OpenWrt.WANRouteTable
	case "zapret":
		return cfg.OpenWrt.ZapretRouteTable
	case "vless", "tg_ws_proxy":
		return cfg.OpenWrt.XrayRouteTable
	default:
		return 0
	}
}

func splitProxy(value string) (string, int, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, fmt.Errorf("invalid loopback proxy: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", 0, fmt.Errorf("proxy must listen on loopback")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid proxy port")
	}
	return host, port, nil
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func requireRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("artifact is not a regular file: %s", path)
	}
	return nil
}

func LoadIPPlan(path string, expected Binding) (IPPlan, error) {
	if err := requireRegularFile(path); err != nil {
		return IPPlan{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return IPPlan{}, err
	}
	var plan IPPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return IPPlan{}, fmt.Errorf("invalid ip plan: %w", err)
	}
	if plan.Binding != expected {
		return IPPlan{}, fmt.Errorf("ip plan binding mismatch")
	}
	if err := validateTransparentProxyPlan(plan.TransparentProxy); err != nil {
		return IPPlan{}, err
	}
	if err := validateZapretPlan(plan.Zapret); err != nil {
		return IPPlan{}, err
	}
	if err := validateFlowOffloadingPlan(plan.FlowOffloading); err != nil {
		return IPPlan{}, err
	}
	if err := validateDNSProxyPlans(plan.DNSProxies, plan.Rules); err != nil {
		return IPPlan{}, err
	}
	if !plan.DeploymentReady {
		if plan.BlockReason == "" || len(plan.Routes) != 0 {
			return IPPlan{}, fmt.Errorf("blocked ip plan has invalid readiness metadata")
		}
		if len(plan.PlannedRoutes) > 0 {
			routeFamilies, err := validateIPRoutes(plan.PlannedRoutes)
			if err != nil {
				return IPPlan{}, fmt.Errorf("invalid planned route: %w", err)
			}
			if err := validateIPRules(plan.Rules, routeFamilies, true); err != nil {
				return IPPlan{}, err
			}
			if err := validateExplicitIPRules(plan.IPRules, routeFamilies, true); err != nil {
				return IPPlan{}, err
			}
		}
		if plan.BlockReason == "transparent_activation_unverified" && (!plan.TransparentProxy.Enabled || !plan.TransparentProxy.CapabilityVerified || !plan.TransparentProxy.CandidateOnly || len(plan.PlannedRoutes) == 0) {
			return IPPlan{}, fmt.Errorf("transparent candidate plan lacks verified preview metadata")
		}
		if plan.BlockReason == "zapret_activation_unverified" && (!plan.Zapret.Enabled || !plan.Zapret.CandidateOnly || len(plan.PlannedRoutes) == 0) {
			return IPPlan{}, fmt.Errorf("zapret candidate plan lacks preview metadata")
		}
		return plan, nil
	}
	if plan.BlockReason != "" {
		return IPPlan{}, fmt.Errorf("ready ip plan contains a block reason")
	}
	if len(plan.PlannedRoutes) != 0 || plan.TransparentProxy.CandidateOnly || plan.Zapret.CandidateOnly {
		return IPPlan{}, fmt.Errorf("ready ip plan contains candidate-only routes")
	}
	networkRequired := false
	for _, rule := range plan.Rules {
		if rule.Type != "drop" {
			networkRequired = true
			break
		}
	}
	if networkRequired && (plan.DiagnosticsHash == "" || strings.TrimSpace(plan.DiagnosticsSource) == "") {
		return IPPlan{}, fmt.Errorf("ready ip plan lacks diagnostics provenance")
	}
	routeFamilies, err := validateIPRoutes(plan.Routes)
	if err != nil {
		return IPPlan{}, err
	}
	if err := validateIPRules(plan.Rules, routeFamilies, true); err != nil {
		return IPPlan{}, err
	}
	if err := validateExplicitIPRules(plan.IPRules, routeFamilies, networkRequired); err != nil {
		return IPPlan{}, err
	}
	return plan, nil
}

func validateDNSProxyPlans(plans []DNSProxyPlan, rules []RouteProof) error {
	vlessRoutes := make(map[string]bool)
	for _, rule := range rules {
		if rule.Type == "vless" {
			vlessRoutes[rule.Tag] = true
		}
	}
	seenRoutes := make(map[string]bool)
	seenInboundTags := make(map[string]bool)
	seenListeners := make(map[string]bool)
	for _, plan := range plans {
		if plan.RouteTag == "" || !vlessRoutes[plan.RouteTag] || plan.XrayOutboundTag != plan.RouteTag {
			return fmt.Errorf("invalid Xray DNS proxy route binding")
		}
		if plan.InboundTag != "router-policy-dns-"+routeID(plan.RouteTag) || seenInboundTags[plan.InboundTag] || seenRoutes[plan.RouteTag] {
			return fmt.Errorf("duplicate or invalid Xray DNS proxy identity")
		}
		if plan.Listen != "127.0.0.1" || plan.Port < 1024 || plan.Port > 65535 {
			return fmt.Errorf("Xray DNS proxy listener is not loopback-bound")
		}
		listener := net.JoinHostPort(plan.Listen, strconv.Itoa(plan.Port))
		if seenListeners[listener] {
			return fmt.Errorf("duplicate Xray DNS proxy listener")
		}
		upstream := net.JoinHostPort(plan.Upstream, strconv.Itoa(plan.UpstreamPort))
		if _, _, err := parsePublicDNSResolver(upstream); err != nil {
			return err
		}
		seenRoutes[plan.RouteTag] = true
		seenInboundTags[plan.InboundTag] = true
		seenListeners[listener] = true
	}
	return nil
}

func validateIPRoutes(routes []IPRoute) (map[string]bool, error) {
	routeFamilies := map[string]bool{}
	for _, route := range routes {
		if route.Table < 1 {
			return nil, fmt.Errorf("invalid ip route table")
		}
		if route.Type != "unreachable" && !interfaceNamePattern.MatchString(route.Device) {
			return nil, fmt.Errorf("invalid ip route device")
		}
		key := fmt.Sprintf("%s:%d", route.Family, route.Table)
		if routeFamilies[key] {
			return nil, fmt.Errorf("duplicate ip route family/table")
		}
		routeFamilies[key] = true
		switch route.Family {
		case "ipv4":
			if route.Type == "local" {
				if route.Destination != "0.0.0.0/0" || route.Via != "" || route.Device != "lo" {
					return nil, fmt.Errorf("invalid IPv4 local route")
				}
			} else if route.Type != "unicast" || route.Destination != "default" || net.ParseIP(route.Via) == nil || net.ParseIP(route.Via).To4() == nil {
				return nil, fmt.Errorf("invalid IPv4 unicast route")
			}
		case "ipv6":
			switch route.Type {
			case "local":
				if route.Destination != "::/0" || route.Via != "" || route.Device != "lo" {
					return nil, fmt.Errorf("invalid IPv6 local route")
				}
			case "unreachable":
				if route.Destination != "::/0" || route.Via != "" || route.Device != "" {
					return nil, fmt.Errorf("invalid IPv6 unreachable route")
				}
			case "unicast":
				if route.Destination != "default" || net.ParseIP(route.Via) == nil || net.ParseIP(route.Via).To4() != nil {
					return nil, fmt.Errorf("invalid IPv6 unicast route")
				}
			default:
				return nil, fmt.Errorf("invalid IPv6 route type")
			}
		default:
			return nil, fmt.Errorf("invalid ip route family")
		}
	}
	return routeFamilies, nil
}

func validateIPRules(rules []RouteProof, routeFamilies map[string]bool, requireTables bool) error {
	priorities := map[int]bool{}
	for _, rule := range rules {
		if rule.Tag == "" || rule.Type == "" || rule.RulePriority < 1 || priorities[rule.RulePriority] {
			return fmt.Errorf("invalid or duplicate ip rule")
		}
		priorities[rule.RulePriority] = true
		if rule.Type != "drop" && (rule.Table < 1 || !validMark(rule.Mark)) {
			return fmt.Errorf("route %s has invalid mark/table", rule.Tag)
		}
		if requireTables && rule.Type != "drop" {
			if rule.RequiresIPv4 && !routeFamilies[fmt.Sprintf("ipv4:%d", rule.Table)] {
				return fmt.Errorf("route %s has no IPv4 table plan", rule.Tag)
			}
			if rule.RequiresIPv6 && !routeFamilies[fmt.Sprintf("ipv6:%d", rule.Table)] {
				return fmt.Errorf("route %s has no IPv6 table plan", rule.Tag)
			}
		}
	}
	return nil
}

func validateExplicitIPRules(rules []IPRule, routeFamilies map[string]bool, required bool) error {
	if required && len(rules) == 0 {
		return fmt.Errorf("explicit ip rules are missing")
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		if rule.Family != "ipv4" && rule.Family != "ipv6" {
			return fmt.Errorf("invalid explicit ip rule family")
		}
		key := fmt.Sprintf("%s:%d", rule.Family, rule.Priority)
		if seen[key] || rule.Priority < 1 || rule.Table < 1 || rule.Purpose == "" || !validMark(rule.Mark) {
			return fmt.Errorf("invalid or duplicate explicit ip rule")
		}
		seen[key] = true
		if rule.Mask != "" && rule.Mask != "0xffffffff" {
			return fmt.Errorf("unsupported explicit ip rule mask")
		}
		if !routeFamilies[fmt.Sprintf("%s:%d", rule.Family, rule.Table)] {
			return fmt.Errorf("explicit ip rule %s has no route table plan", rule.Purpose)
		}
	}
	return nil
}

func validateTransparentProxyPlan(plan TransparentProxyPlan) error {
	if !plan.Enabled {
		return nil
	}
	if plan.Mode != "tproxy" || plan.IPv4InboundTag != transparentIPv4InboundTag || plan.IPv6InboundTag != transparentIPv6InboundTag || plan.IPv4Listen != "127.0.0.1" || plan.IPv6Listen != "::1" || plan.Port < 1024 || plan.Port > 65535 || plan.RouteTable < 1 {
		return fmt.Errorf("invalid transparent proxy candidate metadata")
	}
	if _, err := markNumber(plan.TProxyMark); err != nil {
		return fmt.Errorf("invalid transparent proxy mark: %w", err)
	}
	if _, err := markNumber(plan.BypassMark); err != nil {
		return fmt.Errorf("invalid transparent bypass mark: %w", err)
	}
	if plan.TProxyMark == plan.BypassMark {
		return fmt.Errorf("transparent proxy and bypass marks collide")
	}
	switch plan.Status {
	case "UNVERIFIED":
	case "CANDIDATE_ONLY":
		if !plan.CandidateOnly {
			return fmt.Errorf("transparent proxy candidate status mismatch")
		}
	case "READY":
		if plan.CandidateOnly || !plan.CapabilityVerified {
			return fmt.Errorf("transparent proxy ready status mismatch")
		}
	default:
		return fmt.Errorf("invalid transparent proxy candidate status")
	}
	return nil
}

func validateZapretPlan(plan ZapretPlan) error {
	if !plan.Enabled {
		return nil
	}
	if plan.QueueNum < 1 || plan.QueueNum > 65535 || plan.Strategy != "tls-fake-ttl3-v1" || plan.Binary != "/usr/bin/nfqws" || plan.ActiveConfig != "/etc/router-policy/zapret/nfqws.conf" || plan.InitScript != "/etc/init.d/router-policy-zapret" {
		return fmt.Errorf("invalid managed Zapret plan")
	}
	switch plan.Status {
	case "UNVERIFIED":
	case "CANDIDATE_ONLY":
		if !plan.CandidateOnly {
			return fmt.Errorf("zapret candidate status mismatch")
		}
	case "READY":
		if plan.CandidateOnly {
			return fmt.Errorf("zapret ready status mismatch")
		}
	default:
		return fmt.Errorf("invalid Zapret status")
	}
	return nil
}

func validateFlowOffloadingPlan(plan FlowOffloadingPlan) error {
	if plan.RequestedPolicy != "preserve" && plan.RequestedPolicy != "disable" {
		return fmt.Errorf("invalid flow offloading policy")
	}
	if !plan.Required {
		if plan.PolicyTraffic || plan.Action != "none" || plan.Status != "NOT_APPLICABLE" {
			return fmt.Errorf("invalid non-applicable flow offloading plan")
		}
		return nil
	}
	if plan.RequestedPolicy == "disable" {
		if plan.Action != "disable" || plan.Status != "DISABLE_PLANNED" {
			return fmt.Errorf("invalid flow offloading disable plan")
		}
		return nil
	}
	if !plan.PolicyTraffic || plan.Action != "none" {
		return fmt.Errorf("invalid policy flow offloading plan")
	}
	switch plan.Status {
	case "UNVERIFIED":
		return nil
	case "INCOMPATIBLE":
		if plan.DiagnosticsStatus != "VERIFIED" || !plan.SoftwareEnabled && !plan.HardwareEnabled {
			return fmt.Errorf("incompatible flow offloading plan lacks evidence")
		}
		return nil
	case "VERIFIED_DISABLED":
		if plan.DiagnosticsStatus != "VERIFIED" || plan.SoftwareEnabled || plan.HardwareEnabled {
			return fmt.Errorf("disabled flow offloading plan lacks evidence")
		}
		return nil
	default:
		return fmt.Errorf("invalid flow offloading status")
	}
}

func LoadVerificationPlan(path string, expected Binding) (VerificationPlan, error) {
	if err := requireRegularFile(path); err != nil {
		return VerificationPlan{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return VerificationPlan{}, err
	}
	var plan VerificationPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return VerificationPlan{}, fmt.Errorf("invalid verification plan: %w", err)
	}
	if plan.Binding != expected {
		return VerificationPlan{}, fmt.Errorf("verification plan binding mismatch")
	}
	return plan, nil
}

func hash(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validMark(value string) bool {
	_, err := markNumber(value)
	return err == nil
}

func markNumber(value string) (uint64, error) {
	if !strings.HasPrefix(value, "0x") || len(value) < 3 || len(value) > 10 {
		return 0, fmt.Errorf("mark must be a 32-bit hexadecimal value")
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, "0x"), 16, 32)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("mark must be a non-zero 32-bit hexadecimal value")
	}
	return parsed, nil
}

func safeComment(value string) string { return strings.ReplaceAll(value, "\"", "") }
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
