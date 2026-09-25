package api

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"router-policy/internal/config"
	"router-policy/internal/probe"
)

type serviceDeleteRequest struct {
	BaseVersion int64  `json:"base_version"`
	ServiceID   string `json:"service_id"`
}

// serviceCandidateMatrix is deliberately a read model.  It never runs a
// probe; it combines the live route inventory with the newest persisted probe
// evidence so the UI can distinguish eligible, unverified and selected paths.
func (s *Server) serviceCandidateMatrix(serviceID string, service config.Service) []map[string]any {
	cfg := s.currentConfig()
	if cfg == nil {
		return nil
	}
	activeRevision, _ := s.activeIdentity()
	routes := append([]config.Route(nil), cfg.Routes...)
	sort.SliceStable(routes, func(i, j int) bool {
		if routes[i].Priority != routes[j].Priority {
			return routes[i].Priority < routes[j].Priority
		}
		return routes[i].Tag < routes[j].Tag
	})
	var persisted []probeResultView
	if s.store != nil {
		if results, err := s.store.ListProbeResults(500); err == nil {
			persisted = make([]probeResultView, 0, len(results))
			for _, result := range results {
				if result.Service != serviceID && !serviceDomainContains(service, result.Domain) {
					continue
				}
				persisted = append(persisted, probeResultView{result: result})
			}
		}
	}
	items := make([]map[string]any, 0, len(routes))
	seen := map[string]struct{}{}
	for _, route := range routes {
		if !route.Enabled() || !config.PathAllowed(service, route, cfg.Policy) {
			continue
		}
		if _, duplicate := seen[route.Tag]; duplicate {
			continue
		}
		seen[route.Tag] = struct{}{}
		item := map[string]any{
			"route": route.Tag, "route_type": route.Type, "status": "NOT_CHECKED",
			"path_verified": false, "service_ok": false, "eligible": true,
			"selected": route.Tag == service.SelectedRouteTag,
		}
		for _, candidate := range persisted {
			if candidate.result.Route != route.Tag || (activeRevision != "" && candidate.result.AdapterRevision != activeRevision) {
				continue
			}
			item["status"] = candidate.result.Status
			item["path_verified"] = candidate.result.PathVerified
			item["service_ok"] = candidate.result.ServiceOK
			item["reason"] = candidate.result.ReasonCode
			item["selection_score"] = candidate.result.SelectionScore
			item["verification_duration_ms"] = candidate.result.VerificationDurationMS
			item["route_latency_available"] = candidate.result.RouteLatencyAvailable
			item["end_to_end_latency_available"] = candidate.result.EndToEndLatencyAvailable
			if candidate.result.RouteLatencyAvailable {
				item["route_latency_ms"] = candidate.result.RouteLatencyMS
			}
			if candidate.result.EndToEndLatencyAvailable {
				item["end_to_end_latency_ms"] = candidate.result.EndToEndLatencyMS
			}
			break
		}
		items = append(items, item)
	}
	return items
}

type probeResultView struct {
	result probe.RouteResult
}

func uniqueRouteTypes(matrix []map[string]any) []string {
	seen := make(map[string]struct{}, len(matrix))
	result := make([]string, 0, len(matrix))
	for _, item := range matrix {
		typeName, _ := item["route_type"].(string)
		if typeName == "" {
			continue
		}
		if _, ok := seen[typeName]; ok {
			continue
		}
		seen[typeName] = struct{}{}
		result = append(result, typeName)
	}
	sort.Strings(result)
	return result
}

func (s *Server) handleServiceDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	if failure := s.mutationFailureNow(); failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	var request serviceDeleteRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	request.ServiceID = strings.TrimSpace(request.ServiceID)
	if request.BaseVersion <= 0 || request.ServiceID == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_service_delete", "base_version and service_id are required")
		return
	}
	active := s.currentConfig()
	if active == nil {
		writeError(w, r, http.StatusServiceUnavailable, "active_config_unavailable", "active configuration is unavailable")
		return
	}
	if _, ok := active.Services[request.ServiceID]; !ok {
		writeError(w, r, http.StatusNotFound, "service_rule_missing", "service rule was not found")
		return
	}
	services := make(map[string]config.Service, len(active.Services)-1)
	for id, service := range active.Services {
		if id != request.ServiceID {
			services[id] = service
		}
	}
	change, err := s.createDraftChangeWithOptions(
		"Delete service rule",
		"Remove the selected committed service policy through the normal transaction path",
		request.BaseVersion,
		[]ChangeOp{{Type: "set", Path: "/services", Value: services}},
		currentSession(r).User,
		true,
	)
	if err != nil {
		if errors.Is(err, errBaseVersionConflict) {
			writeError(w, r, http.StatusConflict, "base_version_conflict", "base_version does not match current revision")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "service_delete_failed", err.Error())
		return
	}
	started := s.startAutoApplyChange(change.ID)
	writeData(w, r, map[string]any{
		"change": change, "service_id": request.ServiceID,
		"auto_apply_requested": true, "auto_apply_started": started,
	})
}
