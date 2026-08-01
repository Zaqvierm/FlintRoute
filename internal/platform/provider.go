package platform

import (
	"time"

	"router-policy/internal/config"
)

type Provider interface {
	Name() string
	Simulation() bool
	Overview(*config.Config) map[string]any
	Topology(*config.Config) map[string]any
	Devices(*config.Config) []map[string]any
	Policies(*config.Config) []map[string]any
	Diagnostics(*config.Config) map[string]any
	System(*config.Config) map[string]any
}

// NetworkDiagnosticsProvider exposes the exact network facts consumed by the
// candidate artifact generator. It is optional so development providers cannot
// accidentally masquerade as hardware evidence.
type NetworkDiagnosticsProvider interface {
	NetworkDiagnostics(*config.Config) NetworkDiagnostics
}

// PrivacyDeviceProvider returns the same device inventory without placing raw
// client addresses in the default response. The API opts into reveal mode only
// for an authenticated, short-lived UI request.
type PrivacyDeviceProvider interface {
	DevicesWithPrivacy(*config.Config, bool) []map[string]any
}

type NetworkDiagnostics struct {
	Status               string    `json:"status"`
	Reason               string    `json:"reason,omitempty"`
	Source               string    `json:"source"`
	Simulation           bool      `json:"simulation"`
	WANInterface         string    `json:"wan_interface"`
	WANInterfaces        []string  `json:"wan_interfaces,omitempty"`
	LANInterfaces        []string  `json:"lan_interfaces"`
	IPv4Gateway          string    `json:"ipv4_gateway"`
	IPv6Gateway          string    `json:"ipv6_gateway"`
	IPv6Available        bool      `json:"ipv6_available"`
	DNSResolvers         []string  `json:"dns_resolvers,omitempty"`
	TransparentProxyMode string    `json:"transparent_proxy_mode"`
	FlowOffloadingStatus string    `json:"flow_offloading_status"`
	SoftwareFlowOffload  bool      `json:"software_flow_offloading"`
	HardwareFlowOffload  bool      `json:"hardware_flow_offloading"`
	CollectedAt          time.Time `json:"collected_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}

type DevelopmentMockProvider struct{}

func (DevelopmentMockProvider) Name() string     { return "development-mock-provider" }
func (DevelopmentMockProvider) Simulation() bool { return true }

func (p DevelopmentMockProvider) Overview(cfg *config.Config) map[string]any {
	return map[string]any{
		"internet":             "simulation",
		"external_ipv4_hash":   "simulation",
		"ipv6":                 "simulation",
		"dns":                  "simulation",
		"zapret":               "simulation",
		"vless_configured":     countRoutes(cfg, "vless"),
		"smart_dns_configured": countRoutes(cfg, "smart_dns"),
		"telegram":             "simulation",
		"cpu_load_1m":          0.18,
		"memory_used_percent":  42.0,
		"temperature_c":        51.0,
		"uptime_seconds":       3600,
		"data_plane":           "simulation-readonly",
		"source":               p.Name(),
		"status":               "simulation",
		"simulation":           true,
		"freshness":            "development",
		"collected_at":         nil,
	}
}

func (p DevelopmentMockProvider) Topology(*config.Config) map[string]any {
	return map[string]any{
		"nodes": []map[string]any{
			{"id": "internet", "label": "Internet", "type": "internet", "status": "simulation"},
			{"id": "router", "label": "OpenWrt development router", "type": "router", "status": "simulation"},
			{"id": "dev-lan", "label": "lan-dev", "type": "bridge", "status": "UP"},
			{"id": "dev-workstation", "label": "Workstation", "type": "device", "kind": "ethernet", "status": "simulation", "ip": "192.0.*.*"},
			{"id": "dev-tv", "label": "TV", "type": "device", "kind": "wifi", "status": "simulation", "ip": "192.0.*.*"},
		},
		"edges": []map[string]any{
			{"from": "internet", "to": "router", "route": "simulation"},
			{"from": "router", "to": "dev-lan", "route": "simulation"},
			{"from": "dev-lan", "to": "dev-workstation", "route": "simulation"},
			{"from": "dev-lan", "to": "dev-tv", "route": "simulation"},
		},
		"source":       p.Name(),
		"status":       "simulation",
		"simulation":   true,
		"freshness":    "development",
		"collected_at": nil,
	}
}

func (DevelopmentMockProvider) Devices(*config.Config) []map[string]any {
	return []map[string]any{
		{"id": "dev-workstation", "name": "Workstation", "kind": "ethernet", "interface": "lan-dev", "connected": true, "ip": "192.0.*.*", "mac": "**:**:**:**:10:01", "policy": "simulation", "status": "simulation", "simulation": true},
		{"id": "dev-tv", "name": "TV", "kind": "wifi", "interface": "radio-dev", "ssid": "Development Wi-Fi", "rssi": -52, "connected": true, "ip": "192.0.*.*", "mac": "**:**:**:**:20:01", "policy": "simulation", "status": "simulation", "simulation": true},
	}
}

func (DevelopmentMockProvider) DevicesWithPrivacy(cfg *config.Config, reveal bool) []map[string]any {
	items := (DevelopmentMockProvider{}).Devices(cfg)
	if reveal {
		items[0]["ip"], items[0]["mac"] = "192.0.2.10", "02:00:00:00:10:01"
		items[1]["ip"], items[1]["mac"] = "192.0.2.20", "02:00:00:00:20:01"
	}
	for _, item := range items {
		item["addresses_revealed"] = reveal
	}
	return items
}

func (DevelopmentMockProvider) Policies(*config.Config) []map[string]any {
	return []map[string]any{
		{"id": "simulation-auto", "name": "Simulation auto", "priority": 8, "status": "simulation", "simulation": true},
		{"id": "simulation-direct", "name": "Simulation direct", "priority": 4, "status": "simulation", "simulation": true},
	}
}

func (p DevelopmentMockProvider) Diagnostics(*config.Config) map[string]any {
	return map[string]any{
		"platform":     "simulation",
		"source":       p.Name(),
		"status":       "simulation",
		"simulation":   true,
		"freshness":    "development",
		"collected_at": nil,
	}
}

func (p DevelopmentMockProvider) System(cfg *config.Config) map[string]any {
	platformTarget := "unknown"
	if cfg != nil {
		platformTarget = cfg.Platform.Target
	}
	return map[string]any{
		"version":             "dev",
		"hostname":            "openwrt-dev",
		"model":               "OpenWrt development router",
		"platform":            platformTarget,
		"uptime_seconds":      3600,
		"cpu_load_1m":         0.18,
		"memory_used_percent": 42.0,
		"temperature_c":       51.0,
		"source":              p.Name(),
		"status":              "simulation",
		"simulation":          true,
		"freshness":           "development",
		"collected_at":        nil,
	}
}

func countRoutes(cfg *config.Config, typ string) int {
	if cfg == nil {
		return 0
	}
	return len(cfg.RoutesByType(typ))
}
