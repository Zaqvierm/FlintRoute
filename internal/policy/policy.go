package policy

import (
	"errors"
	"net"
	"sort"
	"strings"

	"router-policy/internal/config"
	"router-policy/internal/tspu"
)

type MatchResult struct {
	Override config.PolicyOverride `json:"override"`
	Source   string                `json:"source"`
}

func Match(cfg *config.Config, domain, deviceMAC, serviceName, category string) (MatchResult, bool, error) {
	if cfg == nil {
		return MatchResult{}, false, errors.New("config is required")
	}
	normalized, err := tspu.NormalizeDomain(domain)
	if err != nil {
		return MatchResult{}, false, err
	}
	device, err := normalizeDevice(deviceMAC)
	if err != nil {
		return MatchResult{}, false, err
	}
	for _, scope := range []string{"exact_domain", "device_domain", "device_service", "service", "category"} {
		for _, override := range cfg.Overrides {
			if override.Scope != scope {
				continue
			}
			matched := false
			switch scope {
			case "exact_domain":
				matched = override.Domain == normalized
			case "device_domain":
				matched = device != "" && override.DeviceMAC == device && override.Domain == normalized
			case "device_service":
				matched = device != "" && override.DeviceMAC == device && override.Service == serviceName
			case "service":
				matched = serviceName != "" && override.Service == serviceName
			case "category":
				matched = category != "" && override.Category == category
			}
			if matched {
				return MatchResult{Override: override, Source: "manual_override:" + scope}, true, nil
			}
		}
	}
	return MatchResult{}, false, nil
}

func SelectRoute(result MatchResult, routes []config.Route) (config.Route, bool) {
	if result.Override.RouteTag != "" {
		for _, route := range routes {
			if route.Tag == result.Override.RouteTag && route.Enabled() {
				return route, true
			}
		}
		return config.Route{}, false
	}
	candidates := append([]config.Route(nil), routes...)
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority < candidates[j].Priority
		}
		return candidates[i].Tag < candidates[j].Tag
	})
	for _, route := range candidates {
		if route.Type == result.Override.RouteType && route.Enabled() {
			return route, true
		}
	}
	return config.Route{}, false
}

func HasDeviceOverrides(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, override := range cfg.Overrides {
		if override.Scope == "device_domain" || override.Scope == "device_service" {
			return true
		}
	}
	return false
}

func normalizeDevice(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	hardware, err := net.ParseMAC(value)
	if err != nil || len(hardware) != 6 {
		return "", errors.New("invalid device MAC")
	}
	return strings.ToLower(hardware.String()), nil
}
