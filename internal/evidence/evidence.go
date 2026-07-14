package evidence

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"router-policy/internal/artifact"
)

type RouteResult struct {
	Domain               string    `json:"domain,omitempty"`
	RouteTag             string    `json:"route_tag"`
	RouteType            string    `json:"route_type"`
	AdapterRevision      string    `json:"adapter_revision"`
	CandidateHash        string    `json:"candidate_hash"`
	ArtifactManifestHash string    `json:"artifact_manifest_hash"`
	NFTMark              string    `json:"nft_mark"`
	ConntrackMark        string    `json:"conntrack_mark"`
	IPRulePriority       int       `json:"ip_rule_priority"`
	RouteTable           int       `json:"route_table"`
	Interface            string    `json:"interface,omitempty"`
	DNSResolver          string    `json:"dns_resolver,omitempty"`
	DNSProtocol          string    `json:"dns_protocol,omitempty"`
	DNSResponseSafe      bool      `json:"dns_response_safe"`
	ResolvedIP           string    `json:"resolved_ip,omitempty"`
	ConnectedIP          string    `json:"connected_ip,omitempty"`
	ConnectedPort        int       `json:"connected_port,omitempty"`
	LocalIP              string    `json:"local_ip,omitempty"`
	AddressFamily        string    `json:"address_family,omitempty"`
	Transport            string    `json:"transport,omitempty"`
	SocketMark           string    `json:"socket_mark,omitempty"`
	HostPreserved        bool      `json:"host_preserved"`
	SNIPreserved         bool      `json:"sni_preserved"`
	XrayOutboundTag      string    `json:"xray_outbound_tag,omitempty"`
	SOCKS5Endpoint       string    `json:"socks5_endpoint,omitempty"`
	SOCKS5Loopback       bool      `json:"socks5_loopback"`
	DirectBypassXray     bool      `json:"direct_bypass_xray"`
	DirectBypassZapret   bool      `json:"direct_bypass_zapret"`
	InheritedMarkCleared bool      `json:"inherited_mark_cleared"`
	ZapretInstalled      bool      `json:"zapret_installed"`
	ZapretFlowProcessed  bool      `json:"zapret_flow_processed"`
	TCP443Verified       bool      `json:"tcp_443_verified"`
	QUICPolicy           string    `json:"quic_policy,omitempty"`
	ProxyFlowProcessed   bool      `json:"proxy_flow_processed"`
	IPv4Verified         bool      `json:"ipv4_verified"`
	IPv6Verified         bool      `json:"ipv6_verified"`
	DropIPv4Enforced     bool      `json:"drop_ipv4_enforced"`
	DropIPv6Enforced     bool      `json:"drop_ipv6_enforced"`
	DropDNSEnforced      bool      `json:"drop_dns_enforced"`
	ExternalIPHash       string    `json:"external_ip_hash,omitempty"`
	ExternalCountry      string    `json:"external_country,omitempty"`
	LatencyMS            int64     `json:"latency_ms"`
	TLSResult            string    `json:"tls_result,omitempty"`
	HTTPResult           string    `json:"http_result"`
	ContentResult        string    `json:"content_result"`
	FailureStage         string    `json:"failure_stage,omitempty"`
	ReasonCode           string    `json:"reason_code"`
	Status               string    `json:"status"`
	EvidenceSource       string    `json:"evidence_source,omitempty"`
	Simulation           bool      `json:"simulation"`
	CheckedAt            time.Time `json:"checked_at"`
}

type Report struct {
	Binding              artifact.Binding `json:"binding"`
	ArtifactManifestHash string           `json:"artifact_manifest_hash"`
	DNSLeakFree          bool             `json:"dns_leak_free"`
	IPv6LeakFree         bool             `json:"ipv6_leak_free"`
	GeoLockedKillSwitch  bool             `json:"geo_locked_kill_switch"`
	Routes               []RouteResult    `json:"routes"`
	CheckedAt            time.Time        `json:"checked_at"`
}

func LoadAndVerify(planPath, evidencePath string, binding artifact.Binding, manifestHash string) (Report, error) {
	plan, err := artifact.LoadVerificationPlan(planPath, binding)
	if err != nil {
		return Report{}, err
	}
	raw, err := os.ReadFile(evidencePath)
	if err != nil {
		return Report{}, err
	}
	var report Report
	if err := json.Unmarshal(raw, &report); err != nil {
		return Report{}, fmt.Errorf("invalid data-plane evidence: %w", err)
	}
	if report.Binding != binding || report.ArtifactManifestHash != manifestHash || report.CheckedAt.IsZero() {
		return Report{}, fmt.Errorf("data-plane evidence binding mismatch")
	}
	if plan.RequireDNSLeakCheck && !report.DNSLeakFree {
		return Report{}, fmt.Errorf("DNS leak check is not proven")
	}
	if plan.RequireIPv6LeakCheck && !report.IPv6LeakFree {
		return Report{}, fmt.Errorf("IPv6 leak check is not proven")
	}
	byTag := map[string]RouteResult{}
	for _, route := range report.Routes {
		byTag[route.RouteTag] = route
	}
	for _, required := range plan.RequiredRouteProof {
		actual, ok := byTag[required.Tag]
		if !ok {
			return Report{}, fmt.Errorf("route proof missing: %s", required.Tag)
		}
		if err := ValidateRouteProof(required, actual, binding, manifestHash); err != nil {
			return Report{}, err
		}
	}
	return report, nil
}

func ValidateRouteProof(required artifact.RouteProof, actual RouteResult, binding artifact.Binding, manifestHash string) error {
	if actual.Status != "OK" || actual.RouteTag != required.Tag || actual.RouteType != required.Type || actual.AdapterRevision != binding.RevisionID || actual.CandidateHash != binding.CandidateHash || actual.ArtifactManifestHash != manifestHash {
		return fmt.Errorf("route %s proof binding/status mismatch", required.Tag)
	}
	if actual.CheckedAt.IsZero() || actual.EvidenceSource == "" {
		return fmt.Errorf("route %s lacks timestamp/evidence source", required.Tag)
	}
	if required.Mark != "" && (actual.NFTMark != required.Mark || actual.ConntrackMark != required.Mark) {
		return fmt.Errorf("route %s mark/table proof mismatch", required.Tag)
	}
	if required.RulePriority > 0 && actual.IPRulePriority != required.RulePriority {
		return fmt.Errorf("route %s rule priority proof mismatch", required.Tag)
	}
	if required.Table > 0 && actual.RouteTable != required.Table {
		return fmt.Errorf("route %s route table proof mismatch", required.Tag)
	}
	if required.Type == "drop" {
		if !actual.DropIPv4Enforced || !actual.DropIPv6Enforced || !actual.DropDNSEnforced || actual.ReasonCode == "" {
			return fmt.Errorf("drop route lacks IPv4/IPv6/DNS enforcement proof")
		}
		return nil
	}
	if actual.Interface == "" || actual.DNSResolver == "" || net.ParseIP(actual.ResolvedIP) == nil || net.ParseIP(actual.ConnectedIP) == nil {
		return fmt.Errorf("route %s lacks interface/DNS/IP proof", required.Tag)
	}
	if actual.HTTPResult == "" || actual.ContentResult == "" || actual.ReasonCode == "" {
		return fmt.Errorf("route %s lacks application proof", required.Tag)
	}
	if required.RequiresIPv4 && !actual.IPv4Verified {
		return fmt.Errorf("route %s lacks IPv4 proof", required.Tag)
	}
	if required.RequiresIPv6 && !actual.IPv6Verified {
		return fmt.Errorf("route %s lacks IPv6 proof", required.Tag)
	}
	if required.RequiresEgress && (actual.ExternalIPHash == "" || actual.ExternalCountry == "" || strings.EqualFold(actual.ExternalCountry, "UNKNOWN")) {
		return fmt.Errorf("route %s lacks egress proof", required.Tag)
	}
	if required.RequiresXrayOutbound && strings.TrimSpace(actual.XrayOutboundTag) != required.Tag {
		return fmt.Errorf("route %s lacks bound Xray outbound proof", required.Tag)
	}

	switch required.Type {
	case "direct":
		if !actual.DirectBypassXray || !actual.DirectBypassZapret || !actual.InheritedMarkCleared {
			return fmt.Errorf("route %s lacks direct bypass proof", required.Tag)
		}
	case "zapret":
		if !actual.ZapretInstalled || !actual.ZapretFlowProcessed || !actual.TCP443Verified || !validQUICPolicy(actual.QUICPolicy) {
			return fmt.Errorf("route %s lacks Zapret flow/QUIC proof", required.Tag)
		}
	case "smart_dns":
		if !actual.DNSResponseSafe || !actual.HostPreserved || (actual.TLSOK() && !actual.SNIPreserved) {
			return fmt.Errorf("route %s lacks Smart DNS response/Host/SNI proof", required.Tag)
		}
	case "vless":
		if !actual.SOCKS5Loopback || actual.SOCKS5Endpoint == "" {
			return fmt.Errorf("route %s lacks Xray outbound/SOCKS proof", required.Tag)
		}
	case "tg_ws_proxy":
		if !actual.ProxyFlowProcessed {
			return fmt.Errorf("route %s lacks Telegram proxy flow proof", required.Tag)
		}
	case "drop":
		// Handled before common transport checks.
	default:
		return fmt.Errorf("route %s has unsupported proof type %q", required.Tag, required.Type)
	}
	return nil
}

func (r RouteResult) TLSOK() bool {
	return strings.EqualFold(r.TLSResult, "OK")
}

func validQUICPolicy(value string) bool {
	switch value {
	case "processed", "forced_tcp", "vless_fallback", "not_applicable":
		return true
	default:
		return false
	}
}
