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

type NetworkDiagnostics struct {
	Status               string    `json:"status"`
	Reason               string    `json:"reason,omitempty"`
	Source               string    `json:"source"`
	Simulation           bool      `json:"simulation"`
	WANInterface         string    `json:"wan_interface"`
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
			{"id": "flint2", "label": "Flint 2", "type": "router", "status": "simulation"},
			{"id": "ethernet", "label": "Ethernet", "type": "group", "clients": 4},
			{"id": "wifi24", "label": "Wi-Fi 2.4 GHz", "type": "group", "clients": 7},
			{"id": "wifi5", "label": "Wi-Fi 5 GHz", "type": "group", "clients": 5},
		},
		"edges": []map[string]any{
			{"from": "internet", "to": "flint2", "route": "simulation"},
			{"from": "flint2", "to": "ethernet", "route": "simulation"},
			{"from": "flint2", "to": "wifi24", "route": "simulation"},
			{"from": "flint2", "to": "wifi5", "route": "simulation"},
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
		{"id": "dev-workstation", "name": "Workstation", "kind": "ethernet", "ip": "192.0.2.10", "mac": "masked", "policy": "simulation", "status": "simulation", "simulation": true},
		{"id": "dev-tv", "name": "TV", "kind": "wifi5", "ip": "192.0.2.20", "mac": "masked", "policy": "simulation", "status": "simulation", "simulation": true},
	}
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
