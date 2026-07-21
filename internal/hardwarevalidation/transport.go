package hardwarevalidation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"router-policy/internal/config"
)

type TransportEvidence struct {
	CaseID           string `json:"case_id"`
	Route            string `json:"route"`
	RouteType        string `json:"route_type"`
	Protocol         string `json:"protocol"`
	AddressFamily    string `json:"address_family"`
	CounterBefore    uint64 `json:"counter_before"`
	CounterAfter     uint64 `json:"counter_after"`
	CounterDelta     uint64 `json:"counter_delta"`
	CounterRequired  bool   `json:"counter_required"`
	Connected        bool   `json:"connected,omitempty"`
	ResponseReceived bool   `json:"response_received,omitempty"`
	PacketWritten    bool   `json:"packet_written,omitempty"`
	BlockedExpected  bool   `json:"blocked_expected,omitempty"`
	FailureClass     string `json:"failure_class,omitempty"`
	Passed           bool   `json:"passed"`
	CheckedAt        string `json:"checked_at"`
}

type transportOutcome struct {
	connected        bool
	responseReceived bool
	packetWritten    bool
	err              error
}

func (h Harness) runTransportCase(ctx context.Context, cfg *config.Config, testCase MatrixCase) (TransportEvidence, error) {
	evidence := TransportEvidence{
		CaseID: testCase.ID, Route: testCase.Route, RouteType: testCase.ExpectedRouteType,
		Protocol: testCase.Protocol, AddressFamily: testCase.AddressFamily,
		CheckedAt: h.now().Format(time.RFC3339),
	}
	route, ok := cfg.RouteByTag(testCase.Route)
	if !ok || route.Type != testCase.ExpectedRouteType {
		return evidence, errors.New("transport route is not present in active config")
	}
	markText := route.Mark
	if markText == "" {
		markText = configuredRouteMark(cfg, route.Type)
	}
	mark, err := strconv.ParseUint(markText, 0, 32)
	if err != nil || mark == 0 {
		return evidence, errors.New("transport route mark is invalid")
	}

	before, err := readRouteCounter(ctx, h.Runner, h.Paths.NftBinary, route.Tag)
	if err != nil {
		return evidence, err
	}
	transportDomain := testCase.TransportDomain
	if transportDomain == "" {
		transportDomain = testCase.Domain
	}
	outcome := exerciseMarkedTransport(ctx, cfg, route, uint32(mark), testCase.Protocol, transportDomain)
	time.Sleep(200 * time.Millisecond)
	after, err := readRouteCounter(ctx, h.Runner, h.Paths.NftBinary, route.Tag)
	if err != nil {
		return evidence, err
	}
	evidence.CounterBefore = before
	evidence.CounterAfter = after
	if after >= before {
		evidence.CounterDelta = after - before
	}
	evidence.Connected = outcome.connected
	evidence.ResponseReceived = outcome.responseReceived
	evidence.PacketWritten = outcome.packetWritten
	evidence.BlockedExpected = route.Type == "drop" || (route.Type == "zapret" && testCase.Protocol == "udp_443")
	evidence.CounterRequired = route.Type != "vless"
	evidence.FailureClass = networkFailureClass(outcome.err)
	evidence.Passed = transportPassed(testCase.Protocol, evidence, outcome.err)
	if !evidence.Passed {
		return evidence, errors.New("protocol-specific route evidence failed")
	}
	return evidence, nil
}

func transportPassed(protocol string, evidence TransportEvidence, operationErr error) bool {
	if evidence.CounterRequired && evidence.CounterDelta == 0 {
		return false
	}
	if evidence.BlockedExpected {
		if protocol == "udp_443" {
			return evidence.PacketWritten || operationErr != nil
		}
		return operationErr != nil && !evidence.Connected && !evidence.ResponseReceived
	}
	switch protocol {
	case "dns_udp_53", "dns_tcp_53":
		return operationErr == nil && evidence.ResponseReceived
	case "tcp_80", "tcp_443":
		return operationErr == nil && evidence.Connected
	case "udp_443":
		return operationErr == nil && evidence.PacketWritten
	default:
		return false
	}
}

func exerciseMarkedTransport(ctx context.Context, cfg *config.Config, route config.Route, mark uint32, protocol, domain string) transportOutcome {
	if route.Type == "vless" {
		return exerciseSOCKSTransport(ctx, cfg, route, protocol, domain)
	}
	dialer, err := markedDialer(mark, 4*time.Second)
	if err != nil {
		return transportOutcome{err: err}
	}
	switch protocol {
	case "dns_udp_53", "dns_tcp_53":
		server, err := resolverForRoute(cfg, route)
		if err != nil {
			return transportOutcome{err: err}
		}
		network := "udp4"
		if protocol == "dns_tcp_53" {
			network = "tcp4"
		}
		client := &dns.Client{Net: network, Timeout: 4 * time.Second, Dialer: dialer}
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		response, _, err := client.ExchangeContext(ctx, message, server)
		if err != nil {
			return transportOutcome{err: err}
		}
		if response == nil || response.Rcode != dns.RcodeSuccess || len(response.Answer) == 0 {
			return transportOutcome{err: errors.New("dns response was empty")}
		}
		return transportOutcome{responseReceived: true}
	case "tcp_80", "tcp_443":
		addresses, err := resolveTransportTargets(ctx, cfg, route, domain)
		if err != nil {
			return transportOutcome{err: err}
		}
		port := "80"
		if protocol == "tcp_443" {
			port = "443"
		}
		var lastErr error
		for _, address := range addresses {
			connection, dialErr := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(address.String(), port))
			if dialErr != nil {
				lastErr = dialErr
				continue
			}
			_ = connection.Close()
			return transportOutcome{connected: true}
		}
		return transportOutcome{err: lastErr}
	case "udp_443":
		addresses, err := resolveTransportTargets(ctx, cfg, route, domain)
		if err != nil {
			return transportOutcome{err: err}
		}
		connection, err := dialer.DialContext(ctx, "udp4", net.JoinHostPort(addresses[0].String(), "443"))
		if err != nil {
			return transportOutcome{err: err}
		}
		defer connection.Close()
		payload := make([]byte, 1200)
		payload[0] = 0xc0
		if _, err := connection.Write(payload); err != nil {
			return transportOutcome{err: err}
		}
		return transportOutcome{packetWritten: true}
	default:
		return transportOutcome{err: errors.New("unsupported transport protocol")}
	}
}

func resolverForRoute(cfg *config.Config, route config.Route) (string, error) {
	if route.DNSServer != "" {
		normalized := normalizeResolver(route.DNSServer)
		host, _, splitErr := net.SplitHostPort(normalized)
		address, parseErr := netip.ParseAddr(host)
		if splitErr == nil && parseErr == nil && address.Is4() && !address.IsLoopback() {
			return normalized, nil
		}
	}
	for _, candidate := range cfg.RoutesByType("smart_dns") {
		if candidate.Disabled || candidate.DNSServer == "" {
			continue
		}
		normalized := normalizeResolver(candidate.DNSServer)
		host, _, splitErr := net.SplitHostPort(normalized)
		address, parseErr := netip.ParseAddr(host)
		if splitErr == nil && parseErr == nil && address.Is4() && !address.IsLoopback() {
			return normalized, nil
		}
	}
	for _, path := range []string{"/tmp/resolv.conf.d/resolv.conf.auto", "/etc/resolv.conf"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "nameserver" {
				if address, err := netip.ParseAddr(fields[1]); err == nil && address.Is4() && !address.IsLoopback() {
					return net.JoinHostPort(address.String(), "53"), nil
				}
			}
		}
	}
	return "", errors.New("no non-loopback IPv4 resolver is available")
}

func configuredRouteMark(cfg *config.Config, routeType string) string {
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

func normalizeResolver(value string) string {
	if _, _, err := net.SplitHostPort(value); err == nil {
		return value
	}
	return net.JoinHostPort(strings.Trim(value, "[]"), "53")
}

func resolveTransportTargets(ctx context.Context, cfg *config.Config, route config.Route, domain string) ([]netip.Addr, error) {
	var resolved []netip.Addr
	if route.Type == "smart_dns" && route.DNSServer != "" {
		client := &dns.Client{Net: "udp4", Timeout: 4 * time.Second}
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		response, _, err := client.ExchangeContext(ctx, message, normalizeResolver(route.DNSServer))
		if err == nil && response != nil {
			for _, answer := range response.Answer {
				if record, ok := answer.(*dns.A); ok {
					address, parseErr := netip.ParseAddr(record.A.String())
					if parseErr == nil && address.Is4() {
						resolved = append(resolved, address)
					}
				}
			}
			if len(resolved) > 0 {
				return resolved, nil
			}
		}
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", domain)
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		if address.Is4() {
			resolved = append(resolved, address)
		}
	}
	_ = cfg
	if len(resolved) == 0 {
		return nil, errors.New("no IPv4 transport target")
	}
	return resolved, nil
}

func readRouteCounter(ctx context.Context, runner Runner, nftBinary, route string) (uint64, error) {
	raw, err := runner.Run(ctx, nftBinary, "-j", "list", "chain", "inet", "router_policy", "probe_output")
	if err != nil {
		return 0, errors.New("cannot read protocol proof counters")
	}
	return routeCounterFromJSON(raw, route)
}

func routeCounterFromJSON(raw []byte, route string) (uint64, error) {
	var document struct {
		NFTables []struct {
			Rule *struct {
				Comment string                       `json:"comment"`
				Expr    []map[string]json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return 0, errors.New("invalid nft counter JSON")
	}
	prefix := "rp route=" + route + " "
	var total uint64
	found := false
	for _, item := range document.NFTables {
		if item.Rule == nil || !strings.HasPrefix(item.Rule.Comment, prefix) {
			continue
		}
		for _, expression := range item.Rule.Expr {
			rawCounter, ok := expression["counter"]
			if !ok {
				continue
			}
			var counter struct {
				Packets uint64 `json:"packets"`
			}
			if err := json.Unmarshal(rawCounter, &counter); err != nil {
				return 0, errors.New("invalid nft packet counter")
			}
			total += counter.Packets
			found = true
		}
	}
	if !found {
		return 0, fmt.Errorf("route counter is missing for %s", route)
	}
	return total, nil
}

func networkFailureClass(err error) string {
	if err == nil {
		return ""
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "refused"):
		return "refused"
	case strings.Contains(text, "unreachable"), strings.Contains(text, "no route"):
		return "unreachable"
	default:
		return "transport_error"
	}
}
