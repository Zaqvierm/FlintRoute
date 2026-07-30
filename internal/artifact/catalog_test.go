package artifact

import (
	"path/filepath"
	"testing"

	"router-policy/internal/config"
)

func TestDefaultServiceCatalogStartsEmpty(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "config", "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Services) != 0 {
		t.Fatalf("default configuration must not pre-classify user traffic: %#v", cfg.Services)
	}
}

func TestSelectedServiceRouteOverridesPrimaryPathWithoutChangingFallbackOrder(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "config", "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Services["observed_youtube"] = config.Service{
		Category:         "TSPU_RESTRICTED",
		Domains:          []string{"youtube.com"},
		AllowedPaths:     []string{"zapret", "smart_dns", "vless", "direct", "drop"},
		SelectedRouteTag: "proxy-selected",
		ProbeURLs: []config.ProbeCheck{{
			Name: "automatic-web", URL: "https://youtube.com/", Required: true,
			ExpectedCodes: []int{200, 301, 302, 403}, BodyMode: "optional",
		}},
	}
	routes := []config.Route{
		{Type: "direct", Tag: "direct", Priority: 10, Mark: "0x41"},
		{Type: "zapret", Tag: "zapret", Priority: 20, Mark: "0x42"},
		{Type: "vless", Tag: "proxy-selected", Priority: 30, Mark: "0x43", SOCKS5: "127.0.0.1:12000"},
		{Type: "drop", Tag: "drop", Priority: 1000, Mark: "0x7f"},
	}
	policies, err := buildDomainPolicies(cfg, routes)
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range policies {
		if policy.Domain == "youtube.com" && policy.Route.Tag != "proxy-selected" {
			t.Fatalf("selected YouTube fallback route was ignored: %+v", policy.Route)
		}
	}
}
