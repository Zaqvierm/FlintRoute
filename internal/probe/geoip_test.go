package probe

import (
	"context"
	"errors"
	"testing"

	"router-policy/internal/config"
)

func TestFetchTextViaRouteRejectsPrivateResolvedEndpoint(t *testing.T) {
	cfg := &config.Config{}
	_, err := fetchTextViaRoute(context.Background(), cfg, config.Route{Type: "direct"}, "https://127.0.0.1:443/")
	if err == nil || err.Error() != "ssrf_private_address_blocked" {
		t.Fatalf("private resolved endpoint was not blocked: %v", err)
	}
}

func TestExternalCountryRequiresTwoMatchingSourcesOnSameRoute(t *testing.T) {
	cfg := &config.Config{GeoIP: config.GeoIP{Endpoints: []config.GeoIPEndpoint{
		{Name: "country-a", Provider: "country_is", URL: "https://country-a.example/"},
		{Name: "country-b", Provider: "ipwho_is", URL: "https://country-b.example/"},
	}}}
	route := config.Route{Type: "vless", Tag: "server-a", SOCKS5: "127.0.0.1:12000"}
	seen := 0
	fetcher := func(_ context.Context, observed config.Route, endpoint string) (string, error) {
		if observed.Tag != route.Tag || observed.SOCKS5 != route.SOCKS5 {
			t.Fatalf("GeoIP request escaped the probed route: %+v", observed)
		}
		seen++
		switch endpoint {
		case "https://country-a.example/":
			return `{"ip":"8.8.8.8","country":"DE"}`, nil
		case "https://country-b.example/":
			return `{"success":true,"ip":"8.8.8.8","country_code":"DE"}`, nil
		default:
			return "", errors.New("unexpected endpoint")
		}
	}
	ip, country, sources, err := probeExternalIPWithFetcher(context.Background(), cfg, route, fetcher)
	if err != nil {
		t.Fatal(err)
	}
	if seen != 2 || ip != "8.8.8.8" || country != "DE" || len(sources) != 2 {
		t.Fatalf("bad GeoIP consensus: ip=%s country=%s sources=%v seen=%d", ip, country, sources, seen)
	}
}

func TestExternalCountryMismatchIsUnverified(t *testing.T) {
	cfg := &config.Config{GeoIP: config.GeoIP{Endpoints: []config.GeoIPEndpoint{
		{Name: "country-a", Provider: "country_is", URL: "https://country-a.example/"},
		{Name: "country-b", Provider: "ipwho_is", URL: "https://country-b.example/"},
	}}}
	fetcher := func(_ context.Context, _ config.Route, endpoint string) (string, error) {
		if endpoint == "https://country-a.example/" {
			return `{"ip":"8.8.8.8","country":"DE"}`, nil
		}
		return `{"success":true,"ip":"8.8.8.8","country_code":"NL"}`, nil
	}
	_, _, _, err := probeExternalIPWithFetcher(context.Background(), cfg, config.Route{Type: "vless", Tag: "server-a"}, fetcher)
	if err == nil || err.Error() != "egress_country_consensus_mismatch" {
		t.Fatalf("country mismatch was accepted: %v", err)
	}
}

func TestExternalCountrySingleOrPrivateSourceIsUnverified(t *testing.T) {
	cfg := &config.Config{GeoIP: config.GeoIP{Endpoints: []config.GeoIPEndpoint{
		{Name: "country-a", Provider: "country_is", URL: "https://country-a.example/"},
		{Name: "country-b", Provider: "ipwho_is", URL: "https://country-b.example/"},
	}}}
	fetcher := func(_ context.Context, _ config.Route, endpoint string) (string, error) {
		if endpoint == "https://country-a.example/" {
			return `{"ip":"10.0.0.1","country":"DE"}`, nil
		}
		return `{"success":true,"ip":"8.8.8.8","country_code":"DE"}`, nil
	}
	_, _, _, err := probeExternalIPWithFetcher(context.Background(), cfg, config.Route{Type: "vless", Tag: "server-a"}, fetcher)
	if err == nil || err.Error() != "egress_country_consensus_insufficient" {
		t.Fatalf("single safe country source was accepted: %v", err)
	}
}

func TestExternalCountryRejectsUnvalidatedEndpointFanout(t *testing.T) {
	cfg := &config.Config{GeoIP: config.GeoIP{Endpoints: []config.GeoIPEndpoint{
		{Name: "country-a", Provider: "country_is", URL: "https://country-a.example/"},
		{Name: "country-b", Provider: "ipwho_is", URL: "https://country-b.example/"},
		{Name: "country-c", Provider: "future", URL: "https://country-c.example/"},
	}}}
	seen := 0
	_, _, _, err := probeExternalIPWithFetcher(context.Background(), cfg, config.Route{Type: "vless", Tag: "server-a"}, func(context.Context, config.Route, string) (string, error) {
		seen++
		return `{"ip":"8.8.8.8","country":"DE"}`, nil
	})
	if err == nil || err.Error() != "egress_country_sources_exceed_bound:2" {
		t.Fatalf("unvalidated GeoIP fan-out was not rejected: %v", err)
	}
	if seen != 0 {
		t.Fatalf("probe started remote requests before enforcing the bound: %d", seen)
	}
}
