package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"router-policy/internal/artifact"
	"router-policy/internal/config"
	"router-policy/internal/evidence"
)

var (
	activeTransactionPattern = regexp.MustCompile(`^tx_[a-f0-9]{16}$`)
	activeRevisionPattern    = regexp.MustCompile(`^rev_[0-9]+_[a-f0-9]{12}$`)
	activeHashPattern        = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type OpenWrtPathOptions struct {
	ArtifactRoot      string
	ActiveBindingPath string
	Binding           artifact.Binding
	ManifestHash      string
	Commands          OpenWrtCommands
	AllowSimulation   bool
}

type OpenWrtPathVerifier struct {
	root              string
	activeBindingPath string
	binding           artifact.Binding
	manifestHash      string
	plan              artifact.VerificationPlan
	commands          OpenWrtCommands
	simulation        bool
}

type activePathBinding struct {
	Binding      artifact.Binding
	ManifestHash string
	State        string
}

func NewActiveOpenWrtEngine(cfg *config.Config, allowSimulation bool) *Engine {
	verifier, err := NewActiveOpenWrtPathVerifier(cfg, allowSimulation)
	if err != nil {
		return NewEngine(errorProofVerifier{err: err})
	}
	return NewEngine(verifier)
}

func NewActiveOpenWrtPathVerifier(cfg *config.Config, allowSimulation bool) (*OpenWrtPathVerifier, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	runtimeDir := cfg.Storage.RuntimeDir
	if runtimeDir == "" {
		runtimeDir = filepath.Join(cfg.Storage.StateDir, "runtime")
	}
	activePath := filepath.Join(runtimeDir, "active-transaction.env")
	active, err := loadActivePathBinding(activePath)
	if err != nil {
		return nil, err
	}
	commands, err := NewExecOpenWrtCommands()
	if err != nil {
		return nil, err
	}
	root := filepath.Join(cfg.Storage.StateDir, "transactions", active.Binding.RevisionID, active.Binding.TransactionID, "generated")
	return NewOpenWrtPathVerifier(OpenWrtPathOptions{
		ArtifactRoot: root, ActiveBindingPath: activePath, Binding: active.Binding, ManifestHash: active.ManifestHash,
		Commands: commands, AllowSimulation: allowSimulation,
	})
}

func NewOpenWrtPathVerifier(opts OpenWrtPathOptions) (*OpenWrtPathVerifier, error) {
	if opts.ArtifactRoot == "" || opts.ActiveBindingPath == "" || opts.Binding.TransactionID == "" || opts.Binding.RevisionID == "" || opts.Binding.CandidateHash == "" || opts.ManifestHash == "" {
		return nil, errors.New("complete OpenWrt path binding is required")
	}
	if opts.Commands == nil {
		return nil, errors.New("OpenWrt commands are required")
	}
	manifest, err := artifact.Verify(opts.ArtifactRoot, opts.Binding, opts.ManifestHash)
	if err != nil {
		return nil, fmt.Errorf("path artifact verification failed: %w", err)
	}
	if manifest.Simulation && !opts.AllowSimulation {
		return nil, errors.New("simulated path artifacts are forbidden")
	}
	plan, err := artifact.LoadVerificationPlan(filepath.Join(opts.ArtifactRoot, artifact.VerifyPlanFile), opts.Binding)
	if err != nil {
		return nil, err
	}
	return &OpenWrtPathVerifier{
		root: opts.ArtifactRoot, activeBindingPath: opts.ActiveBindingPath, binding: opts.Binding,
		manifestHash: opts.ManifestHash, plan: plan, commands: opts.Commands, simulation: manifest.Simulation,
	}, nil
}

func (v *OpenWrtPathVerifier) Begin(ctx context.Context, start PathProofStart) (PathProofSession, error) {
	if _, ok := v.requiredProof(start.Route.Tag, start.Route.Type); !ok {
		return PathProofSession{}, errors.New("route_not_bound_to_verification_plan")
	}
	if err := v.verifyActiveBinding(); err != nil {
		return PathProofSession{}, err
	}
	policy, err := v.commands.NFTPolicy(ctx, start.Route.Tag)
	if err != nil {
		return PathProofSession{}, fmt.Errorf("nft_policy_begin_failed: %w", err)
	}
	return PathProofSession{StartedAt: start.StartedAt, CounterBefore: policy.Counter}, nil
}

func (v *OpenWrtPathVerifier) Verify(ctx context.Context, request PathProofRequest) (evidence.RouteResult, error) {
	required, ok := v.requiredProof(request.Route.Tag, request.Route.Type)
	if !ok {
		return evidence.RouteResult{}, errors.New("route_not_bound_to_verification_plan")
	}
	if err := v.verifyActiveBinding(); err != nil {
		return evidence.RouteResult{}, err
	}
	policy, err := v.commands.NFTPolicy(ctx, request.Route.Tag)
	if err != nil {
		return evidence.RouteResult{}, fmt.Errorf("nft_policy_finish_failed: %w", err)
	}
	if policy.Counter <= request.Session.CounterBefore {
		return evidence.RouteResult{}, errors.New("route_nft_counter_did_not_advance")
	}

	actual := evidence.RouteResult{
		Domain: request.Observation.Domain, RouteTag: request.Route.Tag, RouteType: request.Route.Type,
		AdapterRevision: v.binding.RevisionID, CandidateHash: v.binding.CandidateHash, ArtifactManifestHash: v.manifestHash,
		NFTMark: required.Mark, IPRulePriority: required.RulePriority, RouteTable: required.Table,
		DNSResolver: request.Observation.DNSResolver, DNSProtocol: request.Observation.DNSProtocol,
		ResolvedIP: firstString(request.Observation.ResolvedIPs), ConnectedIP: request.Observation.ConnectedIP,
		ConnectedPort: request.Observation.ConnectedPort, LocalIP: request.Observation.LocalIP,
		AddressFamily: request.Observation.AddressFamily, Transport: request.Observation.Transport,
		SocketMark: request.Observation.SocketMark, HostPreserved: request.Observation.HostPreserved,
		SNIPreserved: request.Observation.SNIPreserved, TLSResult: request.Observation.TLSResult,
		HTTPResult: request.Observation.HTTPResult, ContentResult: request.Observation.ContentResult,
		ExternalIPHash: request.Observation.ExternalIPHash, ExternalCountry: request.Observation.ExternalCountry,
		LatencyMS:  request.Observation.CompletedAt.Sub(request.Observation.StartedAt).Milliseconds(),
		ReasonCode: "route_path_verified", Status: "OK", EvidenceSource: "openwrt-fixed-commands",
		Simulation: v.simulation, CheckedAt: time.Now().UTC(),
	}

	if request.Route.Type == "drop" {
		if !policy.Actions["drop_probe"] {
			return evidence.RouteResult{}, errors.New("dedicated_drop_probe_rule_missing")
		}
		actual.ConntrackMark = required.Mark
		actual.DropIPv4Enforced = true
		actual.DropIPv6Enforced = true
		actual.DropDNSEnforced = true
		if err := evidence.ValidateRouteProof(required, actual, v.binding, v.manifestHash); err != nil {
			return evidence.RouteResult{}, err
		}
		return actual, nil
	}

	if request.Observation.ConnectedIP == "" || request.Observation.LocalIP == "" {
		return evidence.RouteResult{}, errors.New("connected_socket_observation_missing")
	}
	kernelRoute, err := v.commands.RouteGet(ctx, request.Observation.ConnectedIP, required.Mark)
	if err != nil {
		return evidence.RouteResult{}, fmt.Errorf("route_get_failed: %w", err)
	}
	if kernelRoute.Table != required.Table || kernelRoute.Interface == "" {
		return evidence.RouteResult{}, errors.New("route_get_table_or_interface_mismatch")
	}
	actual.Interface = kernelRoute.Interface
	rules, err := v.commands.Rules(ctx)
	if err != nil {
		return evidence.RouteResult{}, fmt.Errorf("ip_rule_read_failed: %w", err)
	}
	actual.IPv4Verified = matchingRule(rules, "4", required)
	actual.IPv6Verified = matchingRule(rules, "6", required)
	if required.RequiresIPv4 {
		routeOK, err := v.commands.HasDefaultRoute(ctx, "4", required.Table)
		actual.IPv4Verified = actual.IPv4Verified && err == nil && routeOK
	}
	if required.RequiresIPv6 {
		routeOK, err := v.commands.HasDefaultRoute(ctx, "6", required.Table)
		actual.IPv6Verified = actual.IPv6Verified && err == nil && routeOK
	}
	actual.ConntrackMark, err = v.commands.ConntrackMark(request.Observation.LocalIP, request.Observation.ConnectedIP)
	if err != nil {
		return evidence.RouteResult{}, fmt.Errorf("conntrack_proof_failed: %w", err)
	}

	switch request.Route.Type {
	case "direct":
		if !policy.Actions["direct_bypass"] || request.Observation.SocketMark != required.Mark {
			return evidence.RouteResult{}, errors.New("direct_socket_mark_or_bypass_rule_missing")
		}
		actual.DirectBypassXray = true
		actual.DirectBypassZapret = true
		actual.InheritedMarkCleared = true
	case "zapret":
		running, err := v.commands.ProcessRunning(ctx, "nfqws")
		if err != nil || !running || !policy.Actions["zapret"] {
			return evidence.RouteResult{}, pathStatusError("NOT_CONFIGURED", "zapret_not_configured", err)
		}
		if request.Observation.ConnectedPort != 443 || request.Observation.SocketMark != required.Mark {
			return evidence.RouteResult{}, errors.New("zapret_tcp443_socket_mark_missing")
		}
		actual.ZapretInstalled = true
		actual.ZapretFlowProcessed = true
		actual.TCP443Verified = true
		actual.QUICPolicy = policy.QUIC
	case "smart_dns":
		if !policy.Actions["smart_dns"] || request.Observation.SocketMark != required.Mark {
			return evidence.RouteResult{}, errors.New("smart_dns_socket_mark_or_policy_missing")
		}
		actual.DNSResponseSafe = safeDNSAnswers(request.Observation.ResolvedIPs)
	case "vless":
		running, err := v.commands.ProcessRunning(ctx, "xray")
		if err != nil || !running {
			return evidence.RouteResult{}, pathStatusError("NOT_CONFIGURED", "xray_not_running", err)
		}
		if !policy.Actions["xray"] {
			return evidence.RouteResult{}, errors.New("xray_route_policy_missing")
		}
		loopback, err := v.verifySOCKSBinding(request.Route)
		if err != nil {
			return evidence.RouteResult{}, err
		}
		actual.XrayOutboundTag = request.Route.Tag
		actual.SOCKS5Endpoint = request.Route.SOCKS5
		actual.SOCKS5Loopback = loopback
	case "tg_ws_proxy":
		running, err := v.commands.ProcessRunning(ctx, "tg-ws-proxy")
		if err != nil || !running {
			return evidence.RouteResult{}, pathStatusError("NOT_CONFIGURED", "telegram_proxy_not_running", err)
		}
		if !policy.Actions["tg_proxy"] {
			return evidence.RouteResult{}, errors.New("telegram_proxy_route_policy_missing")
		}
		actual.ProxyFlowProcessed = true
	default:
		return evidence.RouteResult{}, errors.New("unsupported_route_type")
	}

	if err := evidence.ValidateRouteProof(required, actual, v.binding, v.manifestHash); err != nil {
		return evidence.RouteResult{}, err
	}
	return actual, nil
}

func (v *OpenWrtPathVerifier) requiredProof(tag, routeType string) (artifact.RouteProof, bool) {
	for _, required := range v.plan.RequiredRouteProof {
		if required.Tag == tag && required.Type == routeType {
			return required, true
		}
	}
	return artifact.RouteProof{}, false
}

func (v *OpenWrtPathVerifier) verifyActiveBinding() error {
	active, err := loadActivePathBinding(v.activeBindingPath)
	if err != nil {
		return fmt.Errorf("active_binding_unavailable: %w", err)
	}
	if active.Binding != v.binding || active.ManifestHash != v.manifestHash {
		return errors.New("active_binding_mismatch")
	}
	return nil
}

func loadActivePathBinding(path string) (activePathBinding, error) {
	raw, err := readBoundedRegular(path, 16<<10)
	if err != nil {
		return activePathBinding{}, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || values[key] != "" {
			return activePathBinding{}, errors.New("active_binding_invalid")
		}
		values[key] = value
	}
	if !activeTransactionPattern.MatchString(values["transaction_id"]) || !activeRevisionPattern.MatchString(values["revision_id"]) || !activeHashPattern.MatchString(values["candidate_hash"]) || !activeHashPattern.MatchString(values["artifact_manifest_hash"]) {
		return activePathBinding{}, errors.New("active_binding_identity_invalid")
	}
	if values["transaction_state"] != "applied" && values["transaction_state"] != "committed" {
		return activePathBinding{}, errors.New("active_binding_state_invalid")
	}
	return activePathBinding{
		Binding:      artifact.Binding{TransactionID: values["transaction_id"], RevisionID: values["revision_id"], CandidateHash: values["candidate_hash"]},
		ManifestHash: values["artifact_manifest_hash"], State: values["transaction_state"],
	}, nil
}

func (v *OpenWrtPathVerifier) verifySOCKSBinding(route config.Route) (bool, error) {
	host, portText, err := net.SplitHostPort(route.SOCKS5)
	if err != nil {
		return false, errors.New("invalid_route_socks_endpoint")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false, errors.New("route_socks_endpoint_not_loopback")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return false, errors.New("invalid_route_socks_port")
	}
	raw, err := readBoundedRegular(filepath.Join(v.root, artifact.XrayFile), 2<<20)
	if err != nil {
		return false, err
	}
	var generated struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"inbounds"`
		Outbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
		} `json:"outbounds"`
		Routing struct {
			Rules []struct {
				InboundTags []string `json:"inboundTag"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &generated); err != nil {
		return false, errors.New("invalid_generated_xray_config")
	}
	outboundFound := false
	for _, outbound := range generated.Outbounds {
		if outbound.Tag == route.Tag && outbound.Protocol == "vless" {
			if outboundFound {
				return false, errors.New("xray_route_outbound_duplicate")
			}
			outboundFound = true
		}
	}
	if !outboundFound {
		return false, errors.New("xray_route_outbound_missing")
	}
	inbounds := map[string]struct {
		listen   string
		port     int
		protocol string
	}{}
	for _, inbound := range generated.Inbounds {
		if inbound.Tag == "" || inbounds[inbound.Tag].protocol != "" {
			return false, errors.New("xray_inbound_tag_invalid_or_duplicate")
		}
		inbounds[inbound.Tag] = struct {
			listen   string
			port     int
			protocol string
		}{listen: inbound.Listen, port: inbound.Port, protocol: inbound.Protocol}
	}
	for _, rule := range generated.Routing.Rules {
		if rule.OutboundTag != route.Tag || len(rule.InboundTags) != 1 {
			continue
		}
		inbound := inbounds[rule.InboundTags[0]]
		if inbound.protocol == "socks" && inbound.listen == host && inbound.port == port {
			return true, nil
		}
	}
	return false, errors.New("xray_route_socks_binding_missing")
}

func matchingRule(rules []KernelRule, family string, expected artifact.RouteProof) bool {
	for _, rule := range rules {
		if rule.Family == family && rule.Priority == expected.RulePriority && rule.Mark == expected.Mark && rule.Table == expected.Table {
			return true
		}
	}
	return false
}

func safeDNSAnswers(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		addr, err := netip.ParseAddr(value)
		if err != nil || isUnsafeAddr(addr) {
			return false
		}
	}
	return true
}
