package hardwarevalidation

import (
	"context"
	"errors"
	"fmt"

	"router-policy/internal/probe"
)

type SmartDNSOptions struct {
	RunDir    string
	Primary   string
	Secondary string
	Domain    string
}

type SmartDNSResolverResult struct {
	Name string                           `json:"name"`
	UDP  probe.DNSResolverTransportResult `json:"udp"`
	TCP  probe.DNSResolverTransportResult `json:"tcp"`
}

type SmartDNSResult struct {
	CheckedAt string                   `json:"checked_at"`
	Resolvers []SmartDNSResolverResult `json:"resolvers"`
	Passed    bool                     `json:"passed"`
	Reason    string                   `json:"reason,omitempty"`
}

func (h Harness) VerifySmartDNSResolvers(ctx context.Context, options SmartDNSOptions) (SmartDNSResult, error) {
	result := SmartDNSResult{CheckedAt: h.now().Format("2006-01-02T15:04:05Z07:00")}
	if err := ensureRunDir(options.RunDir); err != nil {
		return result, err
	}
	finish := func(reason string) (SmartDNSResult, error) {
		result.Reason = reason
		if err := writeJSON(options.RunDir+"/smart-dns-resolvers.json", result); err != nil {
			return result, err
		}
		if reason != "" {
			return result, errors.New(reason)
		}
		return result, nil
	}
	if options.Primary == "" || options.Secondary == "" || options.Primary == options.Secondary {
		return finish("two distinct production Smart DNS resolvers are required")
	}
	if options.Domain == "" {
		return finish("Smart DNS validation domain is required")
	}
	for _, resolver := range []struct {
		name   string
		server string
	}{{"primary", options.Primary}, {"secondary", options.Secondary}} {
		entry := SmartDNSResolverResult{Name: resolver.name}
		udp, err := probe.ValidateDNSResolverTransport(ctx, resolver.server, options.Domain, "udp")
		if err != nil {
			return finish(fmt.Sprintf("%s Smart DNS UDP validation failed", resolver.name))
		}
		entry.UDP = udp
		tcp, err := probe.ValidateDNSResolverTransport(ctx, resolver.server, options.Domain, "tcp")
		if err != nil {
			return finish(fmt.Sprintf("%s Smart DNS TCP validation failed", resolver.name))
		}
		entry.TCP = tcp
		result.Resolvers = append(result.Resolvers, entry)
	}
	result.Passed = true
	return finish("")
}
