package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DNSResolverTransportResult struct {
	Transport   string `json:"transport"`
	AAnswers    int    `json:"a_answers"`
	AAAAAnswers int    `json:"aaaa_answers"`
	Safe        bool   `json:"safe"`
}

// ValidateDNSResolverTransport checks one resolver over exactly one transport.
// It deliberately returns counts instead of addresses so hardware evidence can
// prove resolver health without publishing infrastructure details.
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
	if err != nil || (!allowPrivate && isUnsafeAddr(serverAddr)) {
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
			if !allowPrivate && isUnsafeAddr(addr) {
				return result, errors.New("DNS resolver returned an unsafe address")
			}
		}
		*query.count = len(addrs)
	}
	if result.AAnswers+result.AAAAAnswers == 0 {
		return result, errors.New("DNS resolver returned no addresses")
	}
	result.Safe = true
	return result, nil
}
