package api

import (
	"net/http"
	"strings"

	"router-policy/internal/vpnsub"
)

type manualVLESSRequest struct {
	URI string `json:"uri,omitempty"`
	ID  string `json:"id,omitempty"`
}

func (s *Server) handleXrayManualServers(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentConfig()
	if cfg == nil || strings.TrimSpace(cfg.Storage.StateDir) == "" {
		writeError(w, r, http.StatusServiceUnavailable, "xray_not_configured", "Xray state directory is not configured")
		return
	}
	path := vpnsub.ManualServersPath(cfg.Storage.StateDir)
	switch r.Method {
	case http.MethodGet:
		servers, err := vpnsub.ListManualServers(path)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "manual_vless_store_invalid", err.Error())
			return
		}
		writeData(w, r, map[string]any{"servers": servers, "count": len(servers), "capacity": 20})
	case http.MethodPost:
		var request manualVLESSRequest
		if err := readJSON(r, &request); err != nil {
			writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		servers, changed, err := vpnsub.AddManualServer(path, request.URI)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "manual_vless_invalid", err.Error())
			return
		}
		s.publishEvent(Event{
			Type: "xray.manual_server_updated", Severity: "info", ReasonCode: "manual_vless_saved", Durable: true,
			Details: map[string]any{"changed": changed, "server_count": len(servers)},
		})
		writeData(w, r, map[string]any{"servers": servers, "count": len(servers), "capacity": 20, "changed": changed})
	case http.MethodDelete:
		var request manualVLESSRequest
		if err := readJSON(r, &request); err != nil {
			writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		servers, changed, err := vpnsub.DeleteManualServer(path, strings.TrimSpace(request.ID))
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "manual_vless_invalid", err.Error())
			return
		}
		writeData(w, r, map[string]any{"servers": servers, "count": len(servers), "capacity": 20, "changed": changed})
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET, POST or DELETE required")
	}
}
