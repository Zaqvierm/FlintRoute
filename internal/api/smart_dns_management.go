package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"router-policy/internal/config"
)

const maxSmartDNSCards = 16

type smartDNSCard struct {
	Name     string
	Primary  string
	Fallback string
}

type smartDNSRemoveRequest struct {
	BaseVersion int64  `json:"base_version"`
	RouteTag    string `json:"route_tag"`
}

type smartDNSReorderRequest struct {
	BaseVersion int64    `json:"base_version"`
	RouteTags   []string `json:"route_tags"`
}

func smartDNSRouteName(route config.Route, ordinal int) string {
	if name := strings.TrimSpace(route.Name); name != "" {
		return name
	}
	if route.Tag != "" && !strings.HasPrefix(route.Tag, "smart-dns-") {
		return route.Tag
	}
	return fmt.Sprintf("Smart DNS #%d", ordinal)
}

func normalizeSmartDNSName(raw string, route config.Route, ordinal int) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		name = smartDNSRouteName(route, ordinal)
	}
	if name == "" || len([]rune(name)) > 64 || strings.ContainsAny(name, "\r\n") {
		return "", errors.New("Smart DNS name must be 1..64 characters without line breaks")
	}
	return name, nil
}

func smartDNSResolverEndpoint(input smartDNSResolverInput) (string, error) {
	raw := strings.TrimSpace(input.IP)
	if input.Port != 0 {
		raw = net.JoinHostPort(raw, strconv.Itoa(input.Port))
	}
	return normalizeSmartDNSEndpoint(raw)
}

func smartDNSFallbackEndpoint(input smartDNSResolverInput) (string, error) {
	if strings.TrimSpace(input.FallbackIP) == "" {
		if input.FallbackPort != 0 {
			return "", errors.New("fallback resolver IP is required when fallback port is set")
		}
		return "", nil
	}
	raw := strings.TrimSpace(input.FallbackIP)
	if input.FallbackPort != 0 {
		raw = net.JoinHostPort(raw, strconv.Itoa(input.FallbackPort))
	}
	return normalizeSmartDNSEndpoint(raw)
}

func nextSmartDNSTag(routes []config.Route) string {
	used := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		used[route.Tag] = struct{}{}
	}
	for index := 1; ; index++ {
		tag := fmt.Sprintf("smart-dns-%d", index)
		if _, exists := used[tag]; !exists {
			return tag
		}
	}
}

func smartDNSRoutesForInputs(active *config.Config, inputs []smartDNSResolverInput) ([]config.Route, []smartDNSCard, error) {
	if active == nil {
		return nil, nil, errors.New("active config is unavailable")
	}
	if len(inputs) == 0 || len(inputs) > maxSmartDNSCards {
		return nil, nil, fmt.Errorf("provide 1..%d Smart DNS cards", maxSmartDNSCards)
	}
	routes := append([]config.Route(nil), active.Routes...)
	configuredIndexes := make([]int, 0, len(routes))
	unusedIndexes := make([]int, 0, len(routes))
	for index, route := range routes {
		if route.Type == "smart_dns" {
			if route.Enabled() {
				configuredIndexes = append(configuredIndexes, index)
			} else {
				unusedIndexes = append(unusedIndexes, index)
			}
		}
	}
	sort.SliceStable(configuredIndexes, func(i, j int) bool {
		left, right := routes[configuredIndexes[i]], routes[configuredIndexes[j]]
		if left.Priority != right.Priority {
			return left.Priority < right.Priority
		}
		return left.Tag < right.Tag
	})
	indexes := append(configuredIndexes, unusedIndexes...)
	if len(routes)+(len(inputs)-len(indexes)) > 64 {
		return nil, nil, errors.New("configuration route limit leaves no room for another Smart DNS card")
	}
	if len(indexes) < len(inputs) {
		for len(indexes) < len(inputs) {
			routes = append(routes, config.Route{Type: "smart_dns", Tag: nextSmartDNSTag(routes), ConnectToResolvedIP: true})
			indexes = append(indexes, len(routes)-1)
		}
	}

	cards := make([]smartDNSCard, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for ordinal, input := range inputs {
		primary, err := smartDNSResolverEndpoint(input)
		if err != nil {
			return nil, nil, err
		}
		fallback, err := smartDNSFallbackEndpoint(input)
		if err != nil {
			return nil, nil, err
		}
		if _, exists := seen[primary]; exists {
			return nil, nil, fmt.Errorf("duplicate Smart DNS endpoint: %s", primary)
		}
		seen[primary] = struct{}{}
		if fallback != "" {
			if _, exists := seen[fallback]; exists || fallback == primary {
				return nil, nil, fmt.Errorf("duplicate Smart DNS fallback endpoint: %s", fallback)
			}
			seen[fallback] = struct{}{}
		}
		route := routes[indexes[ordinal]]
		name, err := normalizeSmartDNSName(input.Name, route, ordinal+1)
		if err != nil {
			return nil, nil, err
		}
		route.Name = name
		route.DNSServer = primary
		route.DNSFallbackServer = fallback
		route.ConnectToResolvedIP = true
		route.Disabled = false
		route.Status = "CONFIGURED"
		route.Priority = 30 + ordinal
		routes[indexes[ordinal]] = route
		cards = append(cards, smartDNSCard{Name: name, Primary: primary, Fallback: fallback})
	}
	for ordinal := len(inputs); ordinal < len(indexes); ordinal++ {
		route := routes[indexes[ordinal]]
		route.Name = ""
		route.DNSServer = ""
		route.DNSFallbackServer = ""
		route.ConnectToResolvedIP = false
		route.Disabled = true
		route.Status = "NOT_CONFIGURED"
		routes[indexes[ordinal]] = route
	}
	return routes, cards, nil
}

func smartDNSRoutesInOrder(routes []config.Route) []config.Route {
	ordered := append([]config.Route(nil), routes...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority < ordered[j].Priority
		}
		return ordered[i].Tag < ordered[j].Tag
	})
	return ordered
}

func smartDNSConfiguredTags(routes []config.Route) []string {
	ordered := smartDNSRoutesInOrder(routes)
	tags := make([]string, 0, len(ordered))
	for _, route := range ordered {
		if route.Type == "smart_dns" && route.Enabled() {
			tags = append(tags, route.Tag)
		}
	}
	return tags
}

func (s *Server) handleSmartDNSRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	if failure := s.mutationFailureNow(); failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	var request smartDNSRemoveRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if request.BaseVersion <= 0 || strings.TrimSpace(request.RouteTag) == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_smart_dns_remove", "base_version and route_tag are required")
		return
	}
	active := s.currentConfig()
	if active == nil {
		writeError(w, r, http.StatusServiceUnavailable, "active_config_unavailable", "Smart DNS state is unavailable until a committed config is restored")
		return
	}
	routes := append([]config.Route(nil), active.Routes...)
	found := false
	for index, route := range routes {
		if route.Tag != request.RouteTag {
			continue
		}
		if route.Type != "smart_dns" {
			writeError(w, r, http.StatusConflict, "not_smart_dns_route", "route_tag is not a Smart DNS card")
			return
		}
		route.Name = ""
		route.DNSServer = ""
		route.DNSFallbackServer = ""
		route.ConnectToResolvedIP = false
		route.Disabled = true
		route.Status = "NOT_CONFIGURED"
		routes[index] = route
		found = true
		break
	}
	if !found {
		writeError(w, r, http.StatusNotFound, "smart_dns_route_missing", "Smart DNS card was not found")
		return
	}
	change, err := s.createDraftChangeWithOptions("Remove Smart DNS resolver", "Disable and clear the selected owned resolver card", request.BaseVersion, []ChangeOp{{Type: "set", Path: "/routes", Value: routes}}, currentSession(r).User, true)
	if err != nil {
		if errors.Is(err, errBaseVersionConflict) {
			writeError(w, r, http.StatusConflict, "base_version_conflict", "base_version does not match current revision")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "smart_dns_remove_failed", err.Error())
		return
	}
	started := s.startAutoApplyChange(change.ID)
	writeData(w, r, map[string]any{"change": change, "auto_apply_requested": true, "auto_apply_started": started})
}

func (s *Server) handleSmartDNSReorder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	if failure := s.mutationFailureNow(); failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	var request smartDNSReorderRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if request.BaseVersion <= 0 || len(request.RouteTags) == 0 || len(request.RouteTags) > maxSmartDNSCards {
		writeError(w, r, http.StatusBadRequest, "invalid_smart_dns_order", fmt.Sprintf("route_tags must contain 1..%d cards", maxSmartDNSCards))
		return
	}
	active := s.currentConfig()
	if active == nil {
		writeError(w, r, http.StatusServiceUnavailable, "active_config_unavailable", "Smart DNS state is unavailable until a committed config is restored")
		return
	}
	expected := smartDNSConfiguredTags(active.Routes)
	if len(expected) != len(request.RouteTags) {
		writeError(w, r, http.StatusConflict, "smart_dns_order_stale", "the resolver table changed; reload it before reordering")
		return
	}
	expectedSet := make(map[string]struct{}, len(expected))
	for _, tag := range expected {
		expectedSet[tag] = struct{}{}
	}
	seen := make(map[string]struct{}, len(request.RouteTags))
	for _, tag := range request.RouteTags {
		if _, ok := expectedSet[tag]; !ok {
			writeError(w, r, http.StatusBadRequest, "invalid_smart_dns_order", "route_tags contains an unknown or disabled card")
			return
		}
		if _, ok := seen[tag]; ok {
			writeError(w, r, http.StatusBadRequest, "invalid_smart_dns_order", "route_tags contains duplicates")
			return
		}
		seen[tag] = struct{}{}
	}
	routes := append([]config.Route(nil), active.Routes...)
	byTag := make(map[string]int, len(routes))
	for index, route := range routes {
		byTag[route.Tag] = index
	}
	for ordinal, tag := range request.RouteTags {
		routes[byTag[tag]].Priority = 30 + ordinal
	}
	change, err := s.createDraftChangeWithOptions("Reorder Smart DNS resolvers", "Update the explicit Smart DNS failover order", request.BaseVersion, []ChangeOp{{Type: "set", Path: "/routes", Value: routes}}, currentSession(r).User, true)
	if err != nil {
		if errors.Is(err, errBaseVersionConflict) {
			writeError(w, r, http.StatusConflict, "base_version_conflict", "base_version does not match current revision")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "smart_dns_reorder_failed", err.Error())
		return
	}
	started := s.startAutoApplyChange(change.ID)
	writeData(w, r, map[string]any{"change": change, "auto_apply_requested": true, "auto_apply_started": started})
}
