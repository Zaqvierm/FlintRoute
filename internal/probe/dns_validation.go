package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"router-policy/internal/config"
	"router-policy/internal/netpolicy"
)

type DNSResolverTransportResult struct {
	Transport   string   `json:"transport"`
	AAnswers    int      `json:"a_answers"`
	AAAAAnswers int      `json:"aaaa_answers"`
	Addresses   []string `json:"addresses"`
	Safe        bool     `json:"safe"`
}

type SmartDNSValidationResult struct {
	Endpoint    string                     `json:"endpoint"`
	Domain      string                     `json:"domain"`
	UDP         DNSResolverTransportResult `json:"udp"`
	TCP         DNSResolverTransportResult `json:"tcp"`
	Addresses   []string                   `json:"addresses"`
	ConnectedIP string                     `json:"connected_ip"`
	HTTPStatus  int                        `json:"http_status"`
	TLSOK       bool                       `json:"tls_ok"`
	HTTPOK      bool                       `json:"http_ok"`
	CheckedAt   time.Time                  `json:"checked_at"`
}

// ValidateDNSResolverTransport checks one resolver over exactly one transport.
// The returned addresses are public DNS answers, not resolver credentials.
func ValidateDNSResolverTransport(ctx context.Context, server, host, network string) (DNSResolverTransportResult, error) {
	return validateDNSResolverTransport(ctx, server, host, network, false)
}

func validateDNSResolverTransport(ctx context.Context, server, host, network string, allowPrivate bool) (DNSResolverTransportResult, error) {
	result := DNSResolverTransportResult{Transport: network}
	if network != "udp" && network != "tcp" {
		return result, errors.New("DNS transport must be udp or tcp")
	}
	server = normalizeDNSServer(server)
	hostPart, _, err := net.SplitHostPort(server)
	if err != nil {
		return result, errors.New("invalid DNS resolver endpoint")
	}
	serverAddr, err := netip.ParseAddr(hostPart)
	if err != nil || (!allowPrivate && !netpolicy.PublicResolverAddr(serverAddr)) {
		return result, errors.New("DNS resolver endpoint must be a public IP")
	}
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" || strings.ContainsAny(host, " /\\") {
		return result, errors.New("invalid DNS validation host")
	}
	for _, query := range []struct {
		qtype uint16
		count *int
	}{{dns.TypeA, &result.AAnswers}, {dns.TypeAAAA, &result.AAAAAnswers}} {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), query.qtype)
		msg.RecursionDesired = true
		client := &dns.Client{Net: network, Timeout: 5 * time.Second}
		response, _, exchangeErr := client.ExchangeContext(ctx, msg, server)
		if exchangeErr != nil {
			return result, fmt.Errorf("%s DNS query failed", network)
		}
		addrs, _, validateErr := validateDNSResponse(msg, response, host, query.qtype, network)
		if validateErr != nil {
			return result, validateErr
		}
		for _, addr := range addrs {
			if !allowPrivate && !netpolicy.PublicResolverAddr(addr) {
				return result, errors.New("DNS resolver returned an unsafe address")
			}
			result.Addresses = append(result.Addresses, addr.Unmap().String())
		}
		*query.count = len(addrs)
	}
	if result.AAnswers+result.AAAAAnswers == 0 {
		return result, errors.New("DNS resolver returned no addresses")
	}
	result.Safe = true
	result.Addresses = uniqueStrings(result.Addresses)
	return result, nil
}

// ValidateSmartDNSCandidate proves both DNS transports and then performs an
// HTTPS request whose TCP connection uses an address returned by that resolver.
// Host and SNI stay bound to domain, so a resolver cannot pass by returning an
// unrelated endpoint with a convenient certificate.
func ValidateSmartDNSCandidate(ctx context.Context, endpoint, domain string) (SmartDNSValidationResult, error) {
	result := SmartDNSValidationResult{Endpoint: endpoint, Domain: strings.TrimSpace(strings.TrimSuffix(domain, ".")), CheckedAt: time.Now().UTC()}
	if result.Domain == "" || strings.ContainsAny(result.Domain, " /\\") || net.ParseIP(result.Domain) != nil {
		return result, errors.New("Smart DNS test domain must be a DNS name")
	}
	udp, err := ValidateDNSResolverTransport(ctx, endpoint, result.Domain, "udp")
	if err != nil {
		return result, fmt.Errorf("UDP resolver check failed: %w", err)
	}
	tcp, err := ValidateDNSResolverTransport(ctx, endpoint, result.Domain, "tcp")
	if err != nil {
		return result, fmt.Errorf("TCP resolver check failed: %w", err)
	}
	result.UDP, result.TCP = udp, tcp
	result.Addresses = uniqueStrings(append(append([]string{}, udp.Addresses...), tcp.Addresses...))
	expectedCodes := smartDNSValidationExpectedCodes()
	routeResult := ProbeRoute(ctx, &config.Config{
		Platform: config.Platform{Target: "generic-openwrt"},
		Policy:   config.Policy{MaxProbeSeconds: 10},
	}, result.Domain, "smart-dns-validation", config.Service{ProbeURLs: []config.ProbeCheck{{
		Name: "https", URL: "https://" + result.Domain + "/", Required: true, ExpectedCodes: expectedCodes, BodyMode: "ignored",
	}}}, config.Route{Type: "smart_dns", Tag: "candidate-smart-dns", DNSServer: endpoint, ConnectToResolvedIP: true})
	if len(routeResult.Checks) != 1 {
		return result, errors.New("Smart DNS HTTP/TLS check did not run")
	}
	check := routeResult.Checks[0]
	result.ConnectedIP = check.ConnectedIP
	result.HTTPStatus = check.HTTPCode
	result.TLSOK = check.TLSOK && check.SNIPreserved
	result.HTTPOK = check.HTTPOK && check.HostPreserved
	if !smartDNSApplicationProofAccepted(routeResult) || !check.DNSOK || !check.TransportOK || !result.TLSOK || !result.HTTPOK || !check.ExpectedCodeMatched || check.ConnectedIP == "" {
		reason := check.Reason
		if reason == "" {
			reason = "HTTP/TLS path was not verified"
		}
		return result, fmt.Errorf("Smart DNS application check failed: %s", reason)
	}
	return result, nil
}

// smartDNSValidationExpectedCodes are responses that prove an HTTP path is
// usable without pretending that authentication, WAF, rate limiting, or a
// missing resource is a successful service check.  In particular, 401/403
// must never be accepted merely because TCP/TLS completed.
func smartDNSValidationExpectedCodes() []int {
	return []int{
		http.StatusOK,
		http.StatusNoContent,
		http.StatusPartialContent,
		http.StatusMultipleChoices,
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	}
}

func smartDNSApplicationProofAccepted(routeResult RouteResult) bool {
	return strings.EqualFold(routeResult.Status, "OK") &&
		routeResult.ServiceOK &&
		!routeResult.RegionalBlock &&
		!routeResult.AuthenticationRequired &&
		!routeResult.WAFOrRateLimit
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
