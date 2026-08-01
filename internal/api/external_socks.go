package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"router-policy/internal/config"
	"router-policy/internal/externalsocks"
)

type externalSOCKSRequest struct {
	BaseVersion int64  `json:"base_version"`
	Endpoint    string `json:"endpoint"`
	TestDomain  string `json:"test_domain"`
}

func (s *Server) handleExternalSOCKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	cfg := s.currentConfig()
	routes := filterRoutes(cfg, "external_socks")
	status := "not_configured"
	if len(routes) > 0 && routes[0].Enabled() {
		status = strings.ToLower(routes[0].Status)
		if status == "" {
			status = "configured"
		}
	}
	writeData(w, r, map[string]any{
		"status": status, "routes": routes, "managed_by": "external",
		"lifecycle_managed": false, "dependency": "pre-existing loopback SOCKS5 endpoint",
	})
}

func (s *Server) handleExternalSOCKSCheck(w http.ResponseWriter, r *http.Request) {
	request, report, ok := s.checkExternalSOCKS(w, r)
	if !ok {
		return
	}
	s.publishEvent(Event{Type: "external_socks.checked", Severity: "info", ReasonCode: "external_dependency_verified", Details: map[string]any{"test_domain": report.TestDomain}})
	writeData(w, r, map[string]any{"report": report, "activation": map[string]any{"available": true, "explicit_confirmation_required": true, "managed_by": "external"}, "request": map[string]any{"endpoint": request.Endpoint, "test_domain": request.TestDomain}})
}

func (s *Server) handleExternalSOCKSActivate(w http.ResponseWriter, r *http.Request) {
	request, report, ok := s.checkExternalSOCKS(w, r)
	if !ok {
		return
	}
	active := s.currentConfig()
	routes, err := routesForExternalSOCKS(active, request.Endpoint)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "external_socks_route_invalid", err.Error())
		return
	}
	services, err := servicesForExternalSOCKSTest(active, request.TestDomain)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "external_socks_test_domain_invalid", err.Error())
		return
	}
	operations := []ChangeOp{
		{Type: "set", Path: "/xray/activation_mode", Value: "managed"},
		{Type: "set", Path: "/routes", Value: routes},
		{Type: "set", Path: "/services", Value: services},
	}
	change, err := s.createDraftChange("Activate external SOCKS", "Bind a verified external loopback SOCKS dependency through the normal transaction path", request.BaseVersion, operations, currentSession(r).User)
	if err != nil {
		if errors.Is(err, errBaseVersionConflict) {
			writeError(w, r, http.StatusConflict, "base_version_conflict", "active revision changed while external SOCKS was being checked")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "external_socks_change_failed", err.Error())
		return
	}
	writeData(w, r, map[string]any{"report": report, "change": change})
}

func (s *Server) checkExternalSOCKS(w http.ResponseWriter, r *http.Request) (externalSOCKSRequest, externalsocks.CheckReport, bool) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return externalSOCKSRequest{}, externalsocks.CheckReport{}, false
	}
	var request externalSOCKSRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return externalSOCKSRequest{}, externalsocks.CheckReport{}, false
	}
	_, version := s.activeIdentity()
	if request.BaseVersion < 1 || request.BaseVersion != version {
		writeError(w, r, http.StatusConflict, "base_version_conflict", "base_version does not match current revision")
		return externalSOCKSRequest{}, externalsocks.CheckReport{}, false
	}
	request.Endpoint = strings.TrimSpace(request.Endpoint)
	request.TestDomain = strings.ToLower(strings.TrimSpace(request.TestDomain))
	report, err := s.externalSOCKSChecker.Check(r.Context(), externalsocks.CheckRequest{Endpoint: request.Endpoint, TestDomain: request.TestDomain})
	if err != nil || !report.Ready || !report.SOCKS5Handshake || !report.RemoteConnect || !report.TLSVerified || report.HTTPStatus == 0 {
		message := "external SOCKS verification failed"
		if err != nil {
			message = err.Error()
		}
		writeError(w, r, http.StatusUnprocessableEntity, "external_socks_check_failed", message)
		return externalSOCKSRequest{}, externalsocks.CheckReport{}, false
	}
	return request, report, true
}

func routesForExternalSOCKS(active *config.Config, endpoint string) ([]config.Route, error) {
	if active == nil {
		return nil, errors.New("active config is missing")
	}
	routes := append([]config.Route(nil), active.Routes...)
	found := false
	for index := range routes {
		if routes[index].Type != "external_socks" {
			continue
		}
		if found {
			return nil, errors.New("multiple external SOCKS routes are not supported by setup")
		}
		routes[index].Disabled = false
		routes[index].Status = "CONFIGURED"
		routes[index].SOCKS5 = endpoint
		routes[index].DNSMode = "socks_remote"
		routes[index].DNSServer = active.Xray.ProbeDNSResolver
		routes[index].ExternalIPProbe = true
		found = true
	}
	if !found {
		return nil, errors.New("external SOCKS route is absent from the typed config")
	}
	return routes, nil
}

func servicesForExternalSOCKSTest(active *config.Config, domain string) (map[string]config.Service, error) {
	if active == nil {
		return nil, errors.New("active config is missing")
	}
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	routeTag := ""
	for _, route := range active.Routes {
		if route.Type == "external_socks" {
			if routeTag != "" {
				return nil, errors.New("multiple external SOCKS routes are not supported by setup")
			}
			routeTag = route.Tag
		}
	}
	if routeTag == "" {
		return nil, errors.New("external SOCKS route is absent from the typed config")
	}
	services := make(map[string]config.Service, len(active.Services)+1)
	owner := ""
	for name, service := range active.Services {
		service.Domains = append([]string(nil), service.Domains...)
		service.AllowedPaths = append([]string(nil), service.AllowedPaths...)
		service.ForbiddenPaths = append([]string(nil), service.ForbiddenPaths...)
		service.ProbeURLs = append([]config.ProbeCheck(nil), service.ProbeURLs...)
		services[name] = service
		for _, existing := range service.Domains {
			if strings.EqualFold(strings.TrimSuffix(existing, "."), domain) {
				if owner != "" && owner != name {
					return nil, errors.New("test domain has ambiguous service ownership")
				}
				owner = name
			}
		}
	}
	if owner == "" {
		sum := sha256.Sum256([]byte(domain))
		owner = "external-socks-setup-" + hex.EncodeToString(sum[:6])
		services[owner] = config.Service{
			Category: "TELEGRAM", Domains: []string{domain},
			AllowedPaths: []string{"external_socks", "vless", "drop"}, SelectedRouteTag: routeTag,
			ProbeURLs: []config.ProbeCheck{{Name: "external-socks", URL: "https://" + domain + "/", Required: true, ExpectedCodes: []int{200, 204, 301, 302, 307, 308, 401, 403}, BodyMode: "optional"}},
		}
		return services, nil
	}
	service := services[owner]
	allowed := []string{"external_socks"}
	for _, path := range service.AllowedPaths {
		if path != "external_socks" {
			allowed = append(allowed, path)
		}
	}
	service.AllowedPaths = allowed
	service.SelectedRouteTag = routeTag
	services[owner] = service
	return services, nil
}
