package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"router-policy/internal/config"
)

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	cfg := s.currentConfig()
	items := make([]map[string]any, 0, len(cfg.Routes)+2)
	overview := s.provider.Overview(cfg)
	defaultStatus := "UNVERIFIED"
	if value, ok := overview["internet"].(string); ok && value != "" {
		defaultStatus = value
	}
	items = append(items, map[string]any{
		"type": "system_default", "tag": "system-default", "owner": "openwrt", "managed": false,
		"status": defaultStatus, "scope": "all traffic not classified by FlintRoute",
		"effective_path": "kernel default route",
	})
	for _, route := range cfg.Routes {
		item := routeMap(route)
		item["owner"] = "flintroute"
		item["managed"] = route.Enabled()
		item["scope"] = "classified domains and explicit policies only"
		if route.Type == "direct" {
			managedDomains := managedDirectDomainCount(cfg, route)
			item["managed"] = route.Enabled() && managedDomains > 0
			item["available"] = route.Enabled()
			item["managed_domains"] = managedDomains
			item["effective_path"] = "FlintRoute mark and WAN policy table"
			if managedDomains == 0 {
				item["status"] = "NO_MANAGED_POLICIES"
			}
		}
		if route.Type == "smart_dns" {
			item["kind"] = "conditional_dns"
			item["vpn"] = false
		}
		items = append(items, item)
	}
	items = append(items, map[string]any{
		"type": "unclassified", "tag": "unclassified", "owner": "system", "managed": false,
		"status": "SYSTEM_DEFAULT", "scope": "domains without a committed FlintRoute policy",
		"effective_path": "system-default", "discovery_mode": cfg.Policy.EffectiveDiscoveryMode(),
	})
	writeData(w, r, items)
}

func routeMap(route config.Route) map[string]any {
	raw, _ := json.Marshal(route)
	item := map[string]any{}
	_ = json.Unmarshal(raw, &item)
	return item
}

func managedDirectDomainCount(cfg *config.Config, route config.Route) int {
	domains := map[string]bool{}
	for _, service := range cfg.Services {
		selected := service.SelectedRouteTag == route.Tag
		if !selected && service.SelectedRouteTag == "" && len(service.AllowedPaths) > 0 {
			selected = service.AllowedPaths[0] == "direct" || service.Category == "DIRECT_ONLY"
		}
		if selected && !containsRouteType(service.ForbiddenPaths, "direct") {
			for _, domain := range service.Domains {
				domains[domain] = true
			}
		}
	}
	for _, override := range cfg.Overrides {
		if override.Domain != "" && (override.RouteTag == route.Tag || override.RouteType == "direct") {
			domains[override.Domain] = true
		}
	}
	return len(domains)
}

func containsRouteType(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
