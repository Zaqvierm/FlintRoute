package api

import (
	"net/http"
	"strconv"
	"strings"

	"router-policy/internal/component"
	"router-policy/internal/config"
)

func (s *Server) handleComponents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	if s.componentManager == nil {
		writeError(w, r, http.StatusServiceUnavailable, "component_manager_unavailable", "Component Manager is unavailable on this runtime")
		return
	}
	statuses, err := s.componentManager.List(r.Context())
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "component_inventory_failed", err.Error())
		return
	}
	writeData(w, r, map[string]any{"components": statuses})
}

func (s *Server) handleComponentStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	if s.componentManager == nil {
		writeError(w, r, http.StatusServiceUnavailable, "component_manager_unavailable", "Component Manager is unavailable on this runtime")
		return
	}
	kind := component.Kind(strings.TrimPrefix(r.URL.Path, "/api/v1/components/"))
	if !kind.Valid() || strings.Contains(string(kind), "/") {
		writeError(w, r, http.StatusNotFound, "component_not_found", "Unknown component")
		return
	}
	status, err := s.componentManager.Status(r.Context(), kind, r.URL.Query().Get("upstream") == "1")
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "component_status_failed", err.Error())
		return
	}
	writeData(w, r, status)
}

func (s *Server) handleComponentAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	if s.componentManager == nil {
		writeError(w, r, http.StatusServiceUnavailable, "component_manager_unavailable", "Component Manager is unavailable on this runtime")
		return
	}
	var request component.Request
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if !request.Kind.Valid() || !request.Action.Valid() {
		writeError(w, r, http.StatusBadRequest, "component_action_invalid", "Choose a supported component and action")
		return
	}
	usage := componentUsage(s.currentConfig(), request.Kind)
	if request.Action == component.ActionUninstall && usage > 0 && !request.ConfirmDisruption {
		writeError(w, r, http.StatusConflict, "component_in_use", componentUsageMessage(request.Kind, usage))
		return
	}
	release, failure := s.acquireMutationLease()
	if failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	defer release()
	result, err := s.componentManager.Execute(r.Context(), request)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "component_action_failed", err.Error())
		return
	}
	s.publishEvent(Event{
		Type: "component." + string(request.Action), Severity: "info", ReasonCode: "component_action_completed",
		Details: map[string]any{"component": request.Kind, "changed": result.Changed, "rollback": result.Rollback},
	})
	writeData(w, r, result)
}

func componentUsage(cfg *config.Config, kind component.Kind) int {
	if cfg == nil {
		return 0
	}
	count := 0
	for _, route := range cfg.Routes {
		if !route.Enabled() {
			continue
		}
		switch kind {
		case component.KindXray:
			if route.Type == "vless" {
				count++
			}
		case component.KindZapret:
			if route.Type == "zapret" {
				count++
			}
		}
	}
	return count
}

func componentUsageMessage(kind component.Kind, count int) string {
	switch kind {
	case component.KindXray:
		return "Xray is used by " + pluralRules(count) + ". Confirm removal only after reviewing the affected VLESS routes."
	case component.KindZapret:
		return "Zapret is used by " + pluralRules(count) + ". Confirm removal only after reviewing the affected TSPU routes."
	default:
		return "The component is in use by active routes."
	}
}

func pluralRules(count int) string {
	if count == 1 {
		return "1 active route"
	}
	return strconv.Itoa(count) + " active routes"
}
