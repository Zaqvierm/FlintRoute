package probe

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"router-policy/internal/config"
	"router-policy/internal/evidence"
	localgeoip "router-policy/internal/geoip"
)

type RouteResult struct {
	Domain                 string                `json:"domain"`
	Service                string                `json:"service"`
	Route                  string                `json:"route"`
	RouteType              string                `json:"route_type"`
	RoutePriority          int                   `json:"route_priority"`
	Status                 string                `json:"status"`
	ApplicationStatus      string                `json:"application_status"`
	PathVerified           bool                  `json:"path_verified"`
	AdapterRevision        string                `json:"adapter_revision,omitempty"`
	CandidateHash          string                `json:"candidate_hash,omitempty"`
	ArtifactManifestHash   string                `json:"artifact_manifest_hash,omitempty"`
	NFTMark                string                `json:"nft_mark,omitempty"`
	ConntrackMark          string                `json:"conntrack_mark,omitempty"`
	IPRulePriority         int                   `json:"ip_rule_priority,omitempty"`
	RouteTable             int                   `json:"route_table,omitempty"`
	Interface              string                `json:"interface,omitempty"`
	DNSResolver            string                `json:"dns_resolver,omitempty"`
	ResolvedIP             string                `json:"resolved_ip,omitempty"`
	ConnectedIP            string                `json:"connected_ip,omitempty"`
	ConnectedPort          int                   `json:"connected_port,omitempty"`
	LocalIP                string                `json:"local_ip,omitempty"`
	SocketMark             string                `json:"socket_mark,omitempty"`
	XrayOutboundTag        string                `json:"xray_outbound_tag,omitempty"`
	EvidenceSource         string                `json:"evidence_source,omitempty"`
	PathEvidence           *evidence.RouteResult `json:"path_evidence,omitempty"`
	Simulation             bool                  `json:"simulation"`
	DNSOK                  bool                  `json:"dns_ok"`
	TransportOK            bool                  `json:"transport_ok"`
	TLSOK                  bool                  `json:"tls_ok"`
	HTTPOK                 bool                  `json:"http_ok"`
	ContentOK              bool                  `json:"content_ok"`
	ServiceOK              bool                  `json:"service_ok"`
	RegionalBlock          bool                  `json:"regional_block"`
	SuspectedTSPU          bool                  `json:"suspected_tspu"`
	ExternalCountry        string                `json:"external_country,omitempty"`
	ExternalIPHash         string                `json:"external_ip_hash,omitempty"`
	ExternalCountrySources []string              `json:"external_country_sources,omitempty"`
	EgressConsensus        bool                  `json:"egress_consensus"`
	EgressReason           string                `json:"egress_reason,omitempty"`
	LatencyMS              int64                 `json:"latency_ms,omitempty"`
	Checks                 []CheckResult         `json:"checks"`
	FailureStage           string                `json:"failure_stage,omitempty"`
	ReasonCode             string                `json:"reason_code,omitempty"`
	Reason                 *string               `json:"reason"`
	CheckedAt              string                `json:"checked_at"`
}

type CheckResult struct {
	Name                string   `json:"name"`
	URL                 string   `json:"url"`
	Required            bool     `json:"required"`
	Status              string   `json:"status"`
	DNSOK               bool     `json:"dns_ok"`
	DNSResolver         string   `json:"dns_resolver,omitempty"`
	DNSProtocol         string   `json:"dns_protocol,omitempty"`
	ResolvedIPs         []string `json:"resolved_ips,omitempty"`
	ConnectedIP         string   `json:"connected_ip,omitempty"`
	ConnectedPort       int      `json:"connected_port,omitempty"`
	LocalIP             string   `json:"local_ip,omitempty"`
	AddressFamily       string   `json:"address_family,omitempty"`
	Transport           string   `json:"transport,omitempty"`
	SocketMark          string   `json:"socket_mark,omitempty"`
	HostPreserved       bool     `json:"host_preserved"`
	SNIPreserved        bool     `json:"sni_preserved"`
	TransportOK         bool     `json:"transport_ok"`
	TLSOK               bool     `json:"tls_ok"`
	HTTPOK              bool     `json:"http_ok"`
	ContentOK           bool     `json:"content_ok"`
	ExpectedCodeMatched bool     `json:"expected_code_matched"`
	HTTPCode            int      `json:"http_code,omitempty"`
	Redirects           int      `json:"redirects"`
	RegionalBlock       bool     `json:"regional_block"`
	SuspectedTSPU       bool     `json:"suspected_tspu"`
	LatencyMS           int64    `json:"latency_ms,omitempty"`
	Reason              string   `json:"reason,omitempty"`
}

func ProbeRoute(ctx context.Context, cfg *config.Config, domain, serviceName string, svc config.Service, route config.Route) RouteResult {
	return NewEngine(nil).ProbeRoute(ctx, cfg, domain, serviceName, svc, route)
}

func (e *Engine) ProbeRoute(ctx context.Context, cfg *config.Config, domain, serviceName string, svc config.Service, route config.Route) RouteResult {
	startAll := time.Now()
	result := RouteResult{
		Domain:        domain,
		Service:       serviceName,
		Route:         route.Tag,
		RouteType:     route.Type,
		RoutePriority: route.Priority,
		Status:        "FAIL",
		CheckedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	if !route.Enabled() {
		reason := "route_not_configured"
		result.Status = "NOT_CONFIGURED"
		result.ApplicationStatus = "NOT_RUN"
		result.ReasonCode = reason
		result.Reason = &reason
		return result
	}
	proofSession := e.beginPathProof(ctx, domain, route, startAll)

	if route.Type == "drop" {
		if proofSession.BeginError == "" {
			if err := exerciseDropProbe(ctx, cfg, route); err != nil {
				proofSession.BeginError = err.Error()
			}
		}
		result.ApplicationStatus = "DROP"
		result.LatencyMS = time.Since(startAll).Milliseconds()
		return e.finishWithPathProof(ctx, cfg, route, result, startAll, proofSession)
	}

	for _, check := range svc.ProbeURLs {
		checkResult := probeOne(ctx, cfg, route, check)
		result.Checks = append(result.Checks, checkResult)
		result.DNSOK = result.DNSOK || checkResult.DNSOK
		result.TransportOK = result.TransportOK || checkResult.TransportOK
		result.TLSOK = result.TLSOK || checkResult.TLSOK
		result.HTTPOK = result.HTTPOK || checkResult.HTTPOK
		result.ContentOK = result.ContentOK || checkResult.ContentOK
		result.RegionalBlock = result.RegionalBlock || checkResult.RegionalBlock
		result.SuspectedTSPU = result.SuspectedTSPU || checkResult.SuspectedTSPU
	}

	result.LatencyMS = time.Since(startAll).Milliseconds()

	probeEgress := route.ExternalIPProbe || route.Type == "vless"
	if cfg.Platform.Target != "test" && (route.Type == "direct" || route.Type == "zapret" || route.Type == "tg_ws_proxy") {
		probeEgress = true
	}
	if probeEgress {
		ip, country, sources, err := probeExternalIP(ctx, cfg, route)
		if err == nil && ip != "" {
			result.ExternalIPHash = hashIP(ip)
			result.ExternalCountry = country
			result.ExternalCountrySources = sources
			result.EgressConsensus = true
		} else if err != nil {
			result.EgressReason = err.Error()
		}
		if svc.RequireNonRUEgress {
			if country == "RU" {
				reason := "ru_exit_for_geo_locked"
				result.ApplicationStatus = "RU_EXIT"
				result.Status = "RU_EXIT"
				result.Reason = &reason
				return e.finishWithPathProof(ctx, cfg, route, result, startAll, proofSession)
			}
			if country == "" || country == "UNKNOWN" {
				reason := "unknown_exit_country_for_geo_locked"
				if result.EgressReason != "" {
					reason = result.EgressReason
				}
				result.ApplicationStatus = "FAIL"
				result.Status = "FAIL"
				result.Reason = &reason
				return e.finishWithPathProof(ctx, cfg, route, result, startAll, proofSession)
			}
		}
	}

	requiredOK := true
	requiredSeen := false
	optionalOK := false
	var firstReason string
	for _, c := range result.Checks {
		if c.Required {
			requiredSeen = true
			if c.Status != "OK" {
				requiredOK = false
				if firstReason == "" {
					firstReason = c.Reason
				}
			}
		} else if c.Status == "OK" {
			optionalOK = true
		}
	}

	if result.RegionalBlock {
		result.ApplicationStatus = "REGION_BLOCK"
		result.Status = "REGION_BLOCK"
		reason := "regional_block_marker"
		result.Reason = &reason
		return e.finishWithPathProof(ctx, cfg, route, result, startAll, proofSession)
	}
	if result.SuspectedTSPU {
		result.ApplicationStatus = "SUSPECTED_TSPU"
		result.Status = "SUSPECTED_TSPU"
		reason := "tspu_or_block_marker"
		result.Reason = &reason
		return e.finishWithPathProof(ctx, cfg, route, result, startAll, proofSession)
	}
	if requiredSeen && requiredOK {
		result.ServiceOK = true
		result.ApplicationStatus = "OK"
		result.Status = "OK"
		return e.finishWithPathProof(ctx, cfg, route, result, startAll, proofSession)
	}
	if optionalOK {
		result.ApplicationStatus = "DEGRADED"
		result.Status = "DEGRADED"
		reason := "required_checks_failed_optional_ok"
		result.Reason = &reason
		return e.finishWithPathProof(ctx, cfg, route, result, startAll, proofSession)
	}
	if firstReason == "" {
		firstReason = "no_required_probe_succeeded"
	}
	result.ApplicationStatus = "FAIL"
	result.Reason = &firstReason
	return e.finishWithPathProof(ctx, cfg, route, result, startAll, proofSession)
}

func probeOne(ctx context.Context, cfg *config.Config, route config.Route, check config.ProbeCheck) CheckResult {
	start := time.Now()
	res := CheckResult{
		Name:     check.Name,
		URL:      check.URL,
		Required: check.Required,
		Status:   "FAIL",
	}

	parsed, err := url.Parse(check.URL)
	if err != nil {
		res.Reason = "invalid_url"
		return res
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	ips, resolver, protocol, err := resolveForRoute(ctx, cfg, route, host)
	if err != nil {
		res.Reason = "dns_failed:" + err.Error()
		return res
	}
	res.DNSOK = true
	res.DNSResolver = resolver
	res.DNSProtocol = protocol
	for _, ip := range ips {
		res.ResolvedIPs = append(res.ResolvedIPs, ip.String())
	}
	if route.Type == "smart_dns" && !allowPrivateProbe(cfg) {
		for _, ip := range ips {
			if isUnsafeAddr(ip) {
				res.Reason = "smart_dns_unsafe_answer"
				return res
			}
		}
	}

	if len(ips) == 0 {
		res.Reason = "dns_empty"
		return res
	}

	targets := ips

	var lastReason string
	for _, ip := range targets {
		if ip.IsValid() && !allowPrivateProbe(cfg) && isUnsafeAddr(ip) {
			lastReason = "ssrf_private_address_blocked"
			continue
		}
		attempt := runHTTPAttempt(ctx, cfg, route, check, parsed, host, port, ip)
		if attempt.ConnectedIP != "" {
			res.ConnectedIP = attempt.ConnectedIP
			res.ConnectedPort = attempt.ConnectedPort
		}
		if attempt.LocalIP != "" {
			res.LocalIP = attempt.LocalIP
		}
		if attempt.AddressFamily != "" {
			res.AddressFamily = attempt.AddressFamily
		}
		if attempt.Transport != "" {
			res.Transport = attempt.Transport
		}
		if attempt.SocketMark != "" {
			res.SocketMark = attempt.SocketMark
		}
		res.HostPreserved = res.HostPreserved || attempt.HostPreserved
		res.SNIPreserved = res.SNIPreserved || attempt.SNIPreserved
		res.TransportOK = res.TransportOK || attempt.TransportOK
		res.TLSOK = res.TLSOK || attempt.TLSOK
		res.HTTPOK = res.HTTPOK || attempt.HTTPOK
		res.ContentOK = res.ContentOK || attempt.ContentOK
		res.ExpectedCodeMatched = attempt.ExpectedCodeMatched
		res.HTTPCode = attempt.HTTPCode
		res.Redirects = attempt.Redirects
		res.RegionalBlock = attempt.RegionalBlock
		res.SuspectedTSPU = attempt.SuspectedTSPU
		lastReason = attempt.Reason
		if attempt.Status == "OK" || attempt.Status == "REGION_BLOCK" || attempt.Status == "SUSPECTED_TSPU" {
			res.Status = attempt.Status
			res.Reason = attempt.Reason
			res.LatencyMS = time.Since(start).Milliseconds()
			return res
		}
	}
	res.LatencyMS = time.Since(start).Milliseconds()
	if lastReason != "" {
		res.Reason = lastReason
	}
	return res
}

func resolveForRoute(ctx context.Context, cfg *config.Config, route config.Route, host string) ([]netip.Addr, string, string, error) {
	if route.DNSMode == "socks_remote" {
		if route.SOCKS5 == "" || route.DNSServer == "" {
			return nil, "", "", errors.New("socks_dns_not_configured")
		}
		resolver := normalizeDNSServer(route.DNSServer)
		addrs, err := queryDNSTCPViaSOCKS(ctx, cfg, route.SOCKS5, resolver, host)
		return addrs, "socks5:" + resolver, "socks5_tcp", err
	}
	if route.Type == "smart_dns" {
		if route.DNSServer == "" || strings.Contains(route.DNSServer, "PLACEHOLDER") {
			return nil, "", "", errors.New("smart_dns_server_not_configured")
		}
		if !route.ConnectToResolvedIP {
			return nil, "", "", errors.New("smart_dns_connect_to_answer_required")
		}
		addrs, protocol, err := queryDNS(ctx, route.DNSServer, host)
		return addrs, normalizeDNSServer(route.DNSServer), protocol, err
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, "system", "system", err
	}
	return addrs, "system", "system", nil
}

func queryDNSTCPViaSOCKS(ctx context.Context, cfg *config.Config, proxyAddr, server, host string) ([]netip.Addr, error) {
	server = normalizeDNSServer(server)
	resolverHost, resolverPort, err := net.SplitHostPort(server)
	if err != nil || (resolverPort != "53" && !allowPrivateProbe(cfg)) {
		return nil, errors.New("socks_dns_resolver_invalid")
	}
	resolverIP, err := netip.ParseAddr(resolverHost)
	if err != nil || (!allowPrivateProbe(cfg) && isUnsafeAddr(resolverIP)) {
		return nil, errors.New("socks_dns_resolver_unsafe")
	}
	var out []netip.Addr
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), qtype)
		msg.RecursionDesired = true
		connection, err := dialSOCKS5(ctx, proxyAddr, server)
		if err != nil {
			continue
		}
		deadline := time.Now().Add(5 * time.Second)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		_ = connection.SetDeadline(deadline)
		dnsConnection := &dns.Conn{Conn: connection}
		if err := dnsConnection.WriteMsg(msg); err != nil {
			_ = dnsConnection.Close()
			continue
		}
		response, err := dnsConnection.ReadMsg()
		_ = dnsConnection.Close()
		if err != nil {
			continue
		}
		addresses, _, err := validateDNSResponse(msg, response, host, qtype, "socks5_tcp")
		if err == nil {
			out = append(out, addresses...)
		}
	}
	out = uniqueAddrs(out)
	if len(out) == 0 {
		return nil, errors.New("socks_dns_empty")
	}
	if len(out) > 64 {
		return nil, errors.New("dns_answer_limit")
	}
	return out, nil
}

func queryDNS(ctx context.Context, server, host string) ([]netip.Addr, string, error) {
	server = normalizeDNSServer(server)
	var out []netip.Addr
	protocol := "udp"
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		addrs, usedProtocol, err := queryDNSOne(ctx, server, host, qtype)
		if err == nil {
			out = append(out, addrs...)
			if usedProtocol == "tcp" {
				protocol = "tcp"
			}
		}
	}
	out = uniqueAddrs(out)
	if len(out) == 0 {
		return nil, protocol, errors.New("smart_dns_empty")
	}
	if len(out) > 64 {
		return nil, protocol, errors.New("dns_answer_limit")
	}
	return out, protocol, nil
}

func queryDNSOne(ctx context.Context, server, host string, qtype uint16) ([]netip.Addr, string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.RecursionDesired = true
	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		client = &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
		resp, _, err = client.ExchangeContext(ctx, msg, server)
		if err != nil {
			return nil, "tcp", err
		}
		return validateDNSResponse(msg, resp, host, qtype, "tcp")
	}
	protocol := "udp"
	if resp.Truncated {
		client = &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
		resp, _, err = client.ExchangeContext(ctx, msg, server)
		if err != nil {
			return nil, "tcp", err
		}
		protocol = "tcp"
	}
	return validateDNSResponse(msg, resp, host, qtype, protocol)
}

func validateDNSResponse(msg, resp *dns.Msg, host string, qtype uint16, protocol string) ([]netip.Addr, string, error) {
	if resp == nil || resp.Len() > 16*1024 {
		return nil, protocol, errors.New("dns_response_size_limit")
	}
	if resp.Id != msg.Id {
		return nil, protocol, errors.New("dns_transaction_id_mismatch")
	}
	if !resp.Response || resp.Opcode != dns.OpcodeQuery {
		return nil, protocol, errors.New("dns_bad_response_header")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, protocol, fmt.Errorf("dns_rcode_%s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Question) != 1 || !strings.EqualFold(resp.Question[0].Name, dns.Fqdn(host)) || resp.Question[0].Qtype != qtype || resp.Question[0].Qclass != dns.ClassINET {
		return nil, protocol, errors.New("dns_question_mismatch")
	}
	startName := strings.ToLower(dns.Fqdn(host))
	allowedNames := map[string]bool{startName: true}
	cnameTargets := map[string]string{}
	for _, rr := range resp.Answer {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		owner := strings.ToLower(cname.Hdr.Name)
		target := strings.ToLower(cname.Target)
		if owner == "" || target == "" || (cnameTargets[owner] != "" && cnameTargets[owner] != target) {
			return nil, protocol, errors.New("dns_cname_conflict")
		}
		cnameTargets[owner] = target
	}
	current := startName
	for i := 0; i < 8; i++ {
		target, ok := cnameTargets[current]
		if !ok {
			break
		}
		if allowedNames[target] {
			return nil, protocol, errors.New("dns_cname_loop")
		}
		allowedNames[target] = true
		current = target
		if i == 7 && cnameTargets[current] != "" {
			return nil, protocol, errors.New("dns_cname_limit")
		}
	}
	var out []netip.Addr
	addressRecords := 0
	for _, rr := range resp.Answer {
		if len(out) >= 32 {
			return nil, protocol, errors.New("dns_answer_limit")
		}
		switch a := rr.(type) {
		case *dns.A:
			addressRecords++
			if qtype == dns.TypeA && allowedNames[strings.ToLower(a.Hdr.Name)] {
				if addr, ok := netip.AddrFromSlice(a.A); ok {
					out = append(out, addr)
				}
			}
		case *dns.AAAA:
			addressRecords++
			if qtype == dns.TypeAAAA && allowedNames[strings.ToLower(a.Hdr.Name)] {
				if addr, ok := netip.AddrFromSlice(a.AAAA); ok {
					out = append(out, addr)
				}
			}
		}
	}
	if addressRecords > 0 && len(out) == 0 {
		return nil, protocol, errors.New("dns_unrelated_answer")
	}
	return out, protocol, nil
}

func uniqueAddrs(values []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	result := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		if !value.IsValid() || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func normalizeDNSServer(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, "53")
}

func buildDNSQuery(host string, qtype uint16) ([]byte, error) {
	host = strings.TrimSuffix(host, ".")
	msg := []byte{0x12, byte(qtype), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New("invalid_dns_label")
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	return msg, nil
}

func parseDNSResponse(msg []byte, qtype uint16) ([]netip.Addr, error) {
	if len(msg) < 12 {
		return nil, errors.New("short_dns_response")
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		off, err = skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		off += 4
		if off > len(msg) {
			return nil, errors.New("bad_dns_question")
		}
	}
	var out []netip.Addr
	for i := 0; i < an; i++ {
		var err error
		off, err = skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, errors.New("bad_dns_answer")
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		off += 2
		off += 2 // class
		off += 4 // ttl
		rdlen := int(binary.BigEndian.Uint16(msg[off : off+2]))
		off += 2
		if off+rdlen > len(msg) {
			return nil, errors.New("bad_dns_rdata")
		}
		if typ == qtype {
			if typ == 1 && rdlen == 4 {
				if addr, ok := netip.AddrFromSlice(msg[off : off+4]); ok {
					out = append(out, addr)
				}
			}
			if typ == 28 && rdlen == 16 {
				if addr, ok := netip.AddrFromSlice(msg[off : off+16]); ok {
					out = append(out, addr)
				}
			}
		}
		off += rdlen
	}
	return out, nil
}

func skipDNSName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errors.New("dns_name_oob")
		}
		l := int(msg[off])
		off++
		if l == 0 {
			return off, nil
		}
		if l&0xc0 == 0xc0 {
			if off >= len(msg) {
				return 0, errors.New("dns_pointer_oob")
			}
			return off + 1, nil
		}
		off += l
	}
}

type attemptResult struct {
	Status              string
	ConnectedIP         string
	ConnectedPort       int
	LocalIP             string
	AddressFamily       string
	Transport           string
	SocketMark          string
	HostPreserved       bool
	SNIPreserved        bool
	TransportOK         bool
	TLSOK               bool
	HTTPOK              bool
	ContentOK           bool
	ExpectedCodeMatched bool
	HTTPCode            int
	Redirects           int
	RegionalBlock       bool
	SuspectedTSPU       bool
	Reason              string
}

func runHTTPAttempt(ctx context.Context, cfg *config.Config, route config.Route, check config.ProbeCheck, parsed *url.URL, host, port string, ip netip.Addr) attemptResult {
	timeout := time.Duration(cfg.Policy.MaxProbeSeconds) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var connectedIP, localIP, addressFamily, dialTransport string
	var observedSocketMark uint32
	connectedPort, _ := strconv.Atoi(port)
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	installRouteSocketMark(dialer, cfg, route, &observedSocketMark)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
	}
	defer transport.CloseIdleConnections()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		target := address
		if ip.IsValid() {
			if !allowPrivateProbe(cfg) && isUnsafeAddr(ip) {
				return nil, errors.New("ssrf_private_address_blocked")
			}
			target = net.JoinHostPort(ip.String(), port)
			connectedIP = ip.String()
		}
		if route.SOCKS5 != "" {
			dialTransport = "socks5"
			conn, err := dialSOCKS5(ctx, route.SOCKS5, target)
			if err == nil {
				localIP, _ = splitAddr(conn.LocalAddr())
				if ip.IsValid() {
					connectedIP = ip.String()
					addressFamily = familyOf(ip)
				}
			}
			return conn, err
		}
		dialTransport = "direct"
		conn, err := dialer.DialContext(ctx, network, target)
		if err != nil {
			return nil, err
		}
		localIP, _ = splitAddr(conn.LocalAddr())
		if remoteIP, ok := splitAddr(conn.RemoteAddr()); ok {
			connectedIP = remoteIP
			if addr, err := netip.ParseAddr(remoteIP); err == nil {
				addressFamily = familyOf(addr)
			}
		}
		return conn, nil
	}
	transport.DialTLSContext = nil
	client := &http.Client{Transport: transport}
	redirects := 0
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		redirects = len(via)
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return errors.New("redirect_scheme_blocked")
		}
		if !strings.EqualFold(req.URL.Hostname(), host) {
			return errors.New("redirect_cross_host_blocked")
		}
		if addr, err := netip.ParseAddr(req.URL.Hostname()); err == nil && !allowPrivateProbe(cfg) && isUnsafeAddr(addr) {
			return errors.New("redirect_private_address_blocked")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return attemptResult{Status: "FAIL", Reason: "request_create_failed"}
	}
	req.Host = parsed.Host
	req.Header.Set("User-Agent", "router-policy-probe/0.2")

	resp, err := client.Do(req)
	if err != nil {
		return attemptResult{Status: "FAIL", ConnectedIP: connectedIP, ConnectedPort: connectedPort, LocalIP: localIP, AddressFamily: addressFamily, Transport: dialTransport, SocketMark: formatSocketMark(observedSocketMark), Reason: classifyTransportError(err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	bodyText := string(body)

	expectedCode := codeAllowed(resp.StatusCode, check.ExpectedCodes)
	contentOK := bodyAllowed(body, check.BodyMode, check.SuccessMarkers)
	regional := containsAny(bodyText, check.RegionalBlockMarkers) || containsAny(bodyText, defaultRegionalMarkers())
	tspu := resp.StatusCode == 451 || containsAny(bodyText, check.BlockMarkers) || containsAny(bodyText, defaultBlockMarkers())

	status := "FAIL"
	reason := "unexpected_response"
	if regional {
		status = "REGION_BLOCK"
		reason = "regional_block_marker"
	} else if tspu {
		status = "SUSPECTED_TSPU"
		reason = "tspu_or_block_marker"
	} else if !expectedCode {
		reason = fmt.Sprintf("unexpected_http_%d", resp.StatusCode)
	} else if !contentOK {
		reason = "content_check_failed"
	} else {
		status = "OK"
		reason = ""
	}

	return attemptResult{
		Status:              status,
		ConnectedIP:         connectedIP,
		ConnectedPort:       connectedPort,
		LocalIP:             localIP,
		AddressFamily:       addressFamily,
		Transport:           dialTransport,
		SocketMark:          formatSocketMark(observedSocketMark),
		HostPreserved:       req.Host == parsed.Host,
		SNIPreserved:        parsed.Scheme != "https" || transport.TLSClientConfig.ServerName == host,
		TransportOK:         true,
		TLSOK:               parsed.Scheme == "https" && resp.TLS != nil,
		HTTPOK:              expectedCode,
		ContentOK:           contentOK,
		ExpectedCodeMatched: expectedCode,
		HTTPCode:            resp.StatusCode,
		Redirects:           redirects,
		RegionalBlock:       regional,
		SuspectedTSPU:       tspu,
		Reason:              reason,
	}
}

func splitAddr(addr net.Addr) (string, bool) {
	if addr == nil {
		return "", false
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", false
	}
	return host, true
}

func familyOf(addr netip.Addr) string {
	if addr.Is4() {
		return "ipv4"
	}
	if addr.Is6() {
		return "ipv6"
	}
	return ""
}

func codeAllowed(code int, allowed []int) bool {
	for _, c := range allowed {
		if code == c {
			return true
		}
	}
	return false
}

func bodyAllowed(body []byte, mode string, markers []string) bool {
	switch mode {
	case "empty":
		return len(strings.TrimSpace(string(body))) == 0
	case "optional", "ignored":
		return true
	case "required":
		if len(body) == 0 {
			return false
		}
		if len(markers) == 0 {
			return true
		}
		return containsAny(string(body), markers)
	default:
		return false
	}
}

func containsAny(body string, markers []string) bool {
	low := strings.ToLower(body)
	for _, m := range markers {
		if m == "" {
			continue
		}
		if strings.Contains(low, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

func defaultRegionalMarkers() []string {
	return []string{
		"not available in your country",
		"not available in your region",
		"unsupported country",
		"country is not supported",
		"geo-blocked",
	}
}

func defaultBlockMarkers() []string {
	return []string{
		"access to the requested resource is restricted",
		"roskomnadzor",
		"tspu",
	}
}

func classifyTransportError(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "no such host"):
		return "dns_failed"
	case strings.Contains(msg, "tls"):
		return "tls_failed"
	case strings.Contains(msg, "connection reset"):
		return "connection_reset"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline"):
		return "timeout"
	default:
		return "transport_failed"
	}
}

func allowPrivateProbe(cfg *config.Config) bool {
	return cfg != nil && cfg.Platform.Target == "test"
}

func isUnsafeAddr(addr netip.Addr) bool {
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified()
}

func probeExternalIP(ctx context.Context, cfg *config.Config, route config.Route) (ip string, country string, sources []string, err error) {
	return probeExternalIPWithFetcher(ctx, cfg, route, func(ctx context.Context, route config.Route, rawURL string) (string, error) {
		return fetchTextViaRoute(ctx, cfg, route, rawURL)
	})
}

type routeTextFetcher func(context.Context, config.Route, string) (string, error)

func probeExternalIPWithFetcher(ctx context.Context, cfg *config.Config, route config.Route, fetch routeTextFetcher) (ip string, country string, sources []string, err error) {
	if cfg == nil || len(cfg.GeoIP.Endpoints) == 0 {
		return "", "", nil, errors.New("egress_country_sources_not_configured")
	}
	type vote struct {
		ip      netip.Addr
		country string
		source  string
	}
	votes := make([]vote, 0, len(cfg.GeoIP.Endpoints)+1)
	for _, endpoint := range cfg.GeoIP.Endpoints {
		body, fetchErr := fetch(ctx, route, endpoint.URL)
		if fetchErr != nil {
			continue
		}
		observedIP, observedCountry, parseErr := parseGeoIPEndpoint(endpoint.Provider, body)
		if parseErr != nil {
			continue
		}
		votes = append(votes, vote{ip: observedIP, country: observedCountry, source: endpoint.Name})
	}
	if len(votes) == 0 {
		return "", "", nil, errors.New("egress_country_sources_unreachable")
	}
	localCountry := lookupCountry(cfg, votes[0].ip)
	if localCountry != "" && localCountry != "UNKNOWN" {
		votes = append(votes, vote{ip: votes[0].ip, country: localCountry, source: "local_geoip"})
	}
	if len(votes) < 2 {
		return "", "", nil, errors.New("egress_country_consensus_insufficient")
	}
	consensus := votes[0].country
	for _, observed := range votes[1:] {
		if observed.country != consensus {
			return "", "", nil, errors.New("egress_country_consensus_mismatch")
		}
	}
	sources = make([]string, 0, len(votes))
	for _, observed := range votes {
		sources = append(sources, observed.source)
	}
	return votes[0].ip.String(), consensus, sources, nil
}

func parseGeoIPEndpoint(provider, body string) (netip.Addr, string, error) {
	var ipText, country string
	switch provider {
	case "country_is":
		var response struct {
			IP      string `json:"ip"`
			Country string `json:"country"`
		}
		if err := json.Unmarshal([]byte(body), &response); err != nil {
			return netip.Addr{}, "", errors.New("invalid_country_is_response")
		}
		ipText, country = response.IP, response.Country
	case "ipwho_is":
		var response struct {
			Success     bool   `json:"success"`
			IP          string `json:"ip"`
			CountryCode string `json:"country_code"`
		}
		if err := json.Unmarshal([]byte(body), &response); err != nil || !response.Success {
			return netip.Addr{}, "", errors.New("invalid_ipwho_is_response")
		}
		ipText, country = response.IP, response.CountryCode
	default:
		return netip.Addr{}, "", errors.New("unsupported_geoip_provider")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ipText))
	if err != nil || isUnsafeAddr(addr) {
		return netip.Addr{}, "", errors.New("unsafe_geoip_address")
	}
	country = strings.ToUpper(strings.TrimSpace(country))
	if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		return netip.Addr{}, "", errors.New("invalid_geoip_country")
	}
	return addr, country, nil
}

func fetchTextViaRoute(ctx context.Context, cfg *config.Config, route config.Route, rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("invalid_egress_endpoint")
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}

	var target netip.Addr
	ips, _, _, err := resolveForRoute(ctx, cfg, route, host)
	if err == nil && len(ips) > 0 {
		target = ips[0]
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if route.SOCKS5 != "" {
			if target.IsValid() {
				address = net.JoinHostPort(target.String(), port)
			}
			return dialSOCKS5(ctx, route.SOCKS5, address)
		}
		if target.IsValid() {
			address = net.JoinHostPort(target.String(), port)
		}
		return dialer.DialContext(ctx, network, address)
	}
	redirects := 0
	client := http.Client{Timeout: 10 * time.Second, Transport: transport}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		redirects = len(via)
		if redirects > 2 || request.URL.Scheme != "https" || !strings.EqualFold(request.URL.Hostname(), host) {
			return errors.New("unsafe_egress_endpoint_redirect")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Host = host
	req.Header.Set("User-Agent", "router-policy-probe/0.2")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("egress_endpoint_http_error")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024+1))
	if len(body) > 16*1024 {
		return "", errors.New("egress_endpoint_response_too_large")
	}
	return string(body), err
}

func lookupCountry(cfg *config.Config, addr netip.Addr) string {
	if cfg == nil || cfg.GeoIP.Database == "" || cfg.GeoIP.MaxAgeHours <= 0 {
		return "UNKNOWN"
	}
	country, _, err := localgeoip.Lookup(cfg.GeoIP.Database, addr, time.Duration(cfg.GeoIP.MaxAgeHours)*time.Hour, time.Now().UTC())
	if err != nil {
		return "UNKNOWN"
	}
	return country
}

func hashIP(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func dialSOCKS5(ctx context.Context, proxyAddr, targetAddr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(br, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, errors.New("socks5_auth_failed")
	}
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	portNum, err := net.LookupPort("tcp", portStr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(portNum>>8), byte(portNum))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		conn.Close()
		return nil, err
	}
	if header[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5_connect_failed_%d", header[1])
	}
	var skip int
	switch header[3] {
	case 0x01:
		skip = 4
	case 0x03:
		l, err := br.ReadByte()
		if err != nil {
			conn.Close()
			return nil, err
		}
		skip = int(l)
	case 0x04:
		skip = 16
	default:
		conn.Close()
		return nil, errors.New("socks5_bad_atyp")
	}
	if skip > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(skip)); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if _, err := io.CopyN(io.Discard, br, 2); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
