package api

import (
	"net"
	"net/http"
	"strings"

	"router-policy/internal/component"
)

func (s *Server) handleTGWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	manager, ok := s.componentManager.(TGWSComponentManager)
	if !ok {
		writeError(w, r, http.StatusServiceUnavailable, "tgws_unavailable", "Managed TG WS Proxy is unavailable on this runtime")
		return
	}
	status, err := manager.TGWSStatus(r.Context())
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "tgws_status_failed", err.Error())
		return
	}
	writeData(w, r, status)
}

func (s *Server) handleTGWSConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	manager, ok := s.componentManager.(TGWSComponentManager)
	if !ok {
		writeError(w, r, http.StatusServiceUnavailable, "tgws_unavailable", "Managed TG WS Proxy is unavailable on this runtime")
		return
	}
	var request struct {
		Port          int    `json:"port"`
		FakeTLSDomain string `json:"fake_tls_domain"`
	}
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	linkHost := requestHost(r)
	if linkHost == "" {
		writeError(w, r, http.StatusUnprocessableEntity, "tgws_router_address_unknown", "Open FlintRoute through a router LAN address before generating the Telegram link")
		return
	}
	result, err := manager.ConfigureTGWS(r.Context(), component.TGWSConfigRequest{
		Port: request.Port, FakeTLSDomain: request.FakeTLSDomain, LinkHost: linkHost,
	})
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "tgws_configuration_failed", err.Error())
		return
	}
	s.publishEvent(Event{Type: "component.tgws.configured", Severity: "info", ReasonCode: "tgws_ready_for_client", Details: map[string]any{
		"port": result.Status.Port, "local_listener": result.Status.LocalListener, "upstream_reachable": result.Status.UpstreamReachable,
	}})
	writeData(w, r, result)
}

func requestHost(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return ""
		}
		return host
	}
	if host == "" || strings.EqualFold(host, "localhost") || strings.ContainsAny(host, " /\\:@;\"'`$()<>|&\t\r\n") {
		return ""
	}
	return host
}
