package config

import (
	"strings"
	"testing"
)

func TestValidateCanonicalizesIDNDomains(t *testing.T) {
	cfg := validConfig()
	service := cfg.Services["site"]
	service.Domains = []string{"Пример.РФ."}
	cfg.Services["site"] = service
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Services["site"].Domains[0]; got != "xn--e1afmkfd.xn--p1ai" {
		t.Fatalf("IDN was not canonicalized: %q", got)
	}
}

func TestValidateRejectsVolatileFlint2State(t *testing.T) {
	cfg := validConfig()
	cfg.Platform.Target = "glinet-flint2"
	cfg.Storage = Storage{StateDir: "/var/lib/router-policy", RuntimeDir: "/tmp/router-policy", Database: "/var/lib/router-policy/router-policy.bbolt"}
	cfg.Xray.LastGoodConfig = "/var/lib/router-policy/last-good/xray.json"
	cfg.GeoIP.Database = "/var/lib/router-policy/geoip/user-country.mmdb"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "persistent") {
		t.Fatalf("volatile Flint 2 state was accepted: %v", err)
	}
	cfg.Storage.StateDir = "/etc/router-policy/state"
	cfg.Storage.Database = "/etc/router-policy/state/router-policy.bbolt"
	cfg.Xray.LastGoodConfig = "/etc/router-policy/state/last-good/xray.json"
	cfg.GeoIP.Database = "/etc/router-policy/state/geoip/user-country.mmdb"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("persistent Flint 2 state was rejected: %v", err)
	}
}

func TestValidateRejectsPrivateSmartDNS(t *testing.T) {
	cfg := validConfig()
	cfg.Routes = append(cfg.Routes, Route{Type: "smart_dns", Tag: "smart", DNSServer: "192.168.1.53:53", ConnectToResolvedIP: true})
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "public resolver") {
		t.Fatalf("private Smart DNS was accepted: %v", err)
	}
}

func TestValidateRejectsDuplicateDomainOwnership(t *testing.T) {
	cfg := validConfig()
	cfg.Services["other"] = Service{
		Category: "DIRECT_PREFERRED", Domains: []string{"EXAMPLE.com"}, AllowedPaths: []string{"direct", "drop"},
		ProbeURLs: []ProbeCheck{{Name: "web", URL: "https://example.com/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "belongs to both") {
		t.Fatalf("duplicate domain ownership was accepted: %v", err)
	}
}

func TestValidateRejectsUnsafeGeoLockedPolicy(t *testing.T) {
	cfg := validConfig()
	service := cfg.Services["site"]
	service.Category = "GEO_LOCKED"
	service.RequireNonRUEgress = true
	service.AllowedPaths = []string{"direct", "drop"}
	cfg.Services["site"] = service
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "forbidden by policy") {
		t.Fatalf("unsafe GEO_LOCKED policy was accepted: %v", err)
	}
}

func TestValidateRejectsPathThatIsAllowedAndForbidden(t *testing.T) {
	cfg := validConfig()
	service := cfg.Services["site"]
	service.ForbiddenPaths = append(service.ForbiddenPaths, service.AllowedPaths[0])
	cfg.Services["site"] = service
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "both allowed and forbidden") {
		t.Fatalf("expected conflicting service path rejection, got %v", err)
	}
}

func TestValidateRejectsDuplicateForbiddenPath(t *testing.T) {
	cfg := validConfig()
	service := cfg.Services["site"]
	service.ForbiddenPaths = []string{"smart_dns", "smart_dns"}
	cfg.Services["site"] = service
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate forbidden path") {
		t.Fatalf("expected duplicate forbidden path rejection, got %v", err)
	}
}

func TestValidateRejectsMarkMappedToDifferentTables(t *testing.T) {
	cfg := validConfig()
	cfg.Routes = append(cfg.Routes, Route{Type: "zapret", Tag: "zapret", Mark: "0x41", Status: "CONFIGURED"})
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "conflicting route tables") {
		t.Fatalf("ambiguous mark/table mapping was accepted: %v", err)
	}
}

func TestValidateRequiresDropRouteAndSafeNFTIdentity(t *testing.T) {
	cfg := validConfig()
	cfg.Routes = cfg.Routes[:1]
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "drop route") {
		t.Fatalf("config without kill switch was accepted: %v", err)
	}
	cfg = validConfig()
	cfg.OpenWrt.NFTTable = "bad;flush"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "nft_table") {
		t.Fatalf("unsafe nft table name was accepted: %v", err)
	}
}

func TestValidateCanonicalizesDeviceDomainOverride(t *testing.T) {
	cfg := validConfig()
	cfg.Overrides = []PolicyOverride{{
		ID: "device-drop", Scope: "device_domain", DeviceMAC: "AA-BB-CC-DD-EE-FF",
		Domain: "API.Example.COM.", RouteType: "drop",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	override := cfg.Overrides[0]
	if override.DeviceMAC != "aa:bb:cc:dd:ee:ff" || override.Domain != "api.example.com" {
		t.Fatalf("override identity was not canonicalized: %+v", override)
	}
}

func TestValidateRejectsOverrideThatViolatesDirectOnly(t *testing.T) {
	cfg := validConfig()
	service := cfg.Services["site"]
	service.Category = "DIRECT_ONLY"
	service.AllowedPaths = []string{"direct"}
	cfg.Services["site"] = service
	cfg.Routes = append(cfg.Routes, Route{
		Type: "smart_dns", Tag: "smart", DNSServer: "203.0.113.53:53", ConnectToResolvedIP: true,
	})
	cfg.Overrides = []PolicyOverride{{ID: "unsafe", Scope: "service", Service: "site", RouteTag: "smart"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "DIRECT_ONLY") {
		t.Fatalf("unsafe DIRECT_ONLY override was accepted: %v", err)
	}
}

func TestValidateRejectsDuplicateOverrideSelector(t *testing.T) {
	cfg := validConfig()
	cfg.Overrides = []PolicyOverride{
		{ID: "one", Scope: "exact_domain", Domain: "api.example.com", RouteType: "direct"},
		{ID: "two", Scope: "exact_domain", Domain: "API.EXAMPLE.COM", RouteType: "drop"},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate policy override selector") {
		t.Fatalf("ambiguous overrides were accepted: %v", err)
	}
}

func TestValidateRejectsUnknownFlowOffloadingPolicy(t *testing.T) {
	cfg := validConfig()
	cfg.OpenWrt.FlowOffloadingPolicy = "auto"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "flow_offloading_policy") {
		t.Fatalf("unknown flow offloading policy was accepted: %v", err)
	}
}

func TestValidateRejectsVLESSDNSProxyPortExhaustion(t *testing.T) {
	cfg := validConfig()
	cfg.Routes = append(cfg.Routes, Route{Type: "vless", Tag: "vless-test", SOCKS5: "127.0.0.1:12000", DNSServer: "1.1.1.1:53", DNSMode: "socks_remote", Mark: "0x43"})
	cfg.Xray.OutboundBundleSHA256 = "sha256:" + strings.Repeat("a", 64)
	cfg.Xray.ProbeDNSResolver = "1.1.1.1:53"
	cfg.Xray.TransparentPort = 12345
	cfg.Xray.DNSProxyBasePort = 65536
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "DNS proxy ports") {
		t.Fatalf("VLESS DNS proxy port exhaustion was accepted: %v", err)
	}
}

func validConfig() *Config {
	return &Config{
		Version: 2,
		OpenWrt: OpenWrt{
			NFTFamily: "inet", NFTTable: "router_policy", WANRouteTable: 100, ZapretRouteTable: 101, XrayRouteTable: 102,
			DirectMark: "0x41", ZapretMark: "0x42", XrayMark: "0x43", XrayTProxyMark: "0x100", XrayBypassMark: "0x200", DropMark: "0x7f",
		},
		Routes: []Route{
			{Type: "direct", Tag: "direct", Mark: "0x41"},
			{Type: "drop", Tag: "drop", Mark: "0x7f"},
		},
		Services: map[string]Service{
			"site": {
				Category: "DIRECT_PREFERRED", Domains: []string{"example.com"}, AllowedPaths: []string{"direct", "drop"},
				ProbeURLs: []ProbeCheck{{Name: "web", URL: "https://example.com/", Required: true, ExpectedCodes: []int{200}, BodyMode: "optional"}},
			},
		},
	}
}
