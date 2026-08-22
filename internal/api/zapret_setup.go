package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"path/filepath"
	"strings"

	"router-policy/internal/config"
	"router-policy/internal/zapret"
)

type zapretSetupRequest struct {
	BaseVersion     int64  `json:"base_version"`
	SourceURL       string `json:"source_url"`
	ProviderVersion string `json:"provider_version"`
	BinarySHA256    string `json:"binary_sha256"`
	TestDomain      string `json:"test_domain"`
}

func (s *Server) handleZapretSetupCheck(w http.ResponseWriter, r *http.Request) {
	request, report, ok := s.checkZapretSetup(w, r)
	if !ok {
		return
	}
	s.publishEvent(Event{Type: "zapret.setup_checked", Severity: "info", ReasonCode: "managed_activation_offered", Details: map[string]any{"provider_version": request.ProviderVersion, "test_domain": report.TestDomain}})
	writeData(w, r, map[string]any{"report": report, "activation": map[string]any{"managed_available": true, "explicit_confirmation_required": true}})
}

func (s *Server) handleZapretSetupActivate(w http.ResponseWriter, r *http.Request) {
	if failure := s.mutationFailureNow(); failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	request, report, ok := s.checkZapretSetup(w, r)
	if !ok {
		return
	}
	active := s.currentConfig()
	routes, err := routesForManagedZapret(active)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "zapret_route_invalid", err.Error())
		return
	}
	services, err := servicesForZapretTest(active, request.TestDomain)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "zapret_test_domain_invalid", err.Error())
		return
	}
	operations := []ChangeOp{
		{Type: "set", Path: "/zapret/activation_mode", Value: "managed"},
		{Type: "set", Path: "/zapret/provider_source", Value: request.SourceURL},
		{Type: "set", Path: "/zapret/provider_version", Value: request.ProviderVersion},
		{Type: "set", Path: "/zapret/binary_sha256", Value: request.BinarySHA256},
		{Type: "set", Path: "/routes", Value: routes},
		{Type: "set", Path: "/services", Value: services},
	}
	calibratedProfile := ""
	if s.zapretCalibration != nil {
		status := s.zapretCalibration.Status()
		if status.State == "completed" && strings.EqualFold(strings.TrimSuffix(status.Domain, "."), strings.TrimSuffix(request.TestDomain, ".")) {
			fingerprint, fingerprintErr := s.verifiedCalibrationNetworkFingerprint()
			if fingerprintErr != nil {
				writeError(w, r, http.StatusPreconditionFailed, "zapret_calibration_network_unverified", fingerprintErr.Error())
				return
			}
			adaptiveOps, profileID, adaptiveErr := calibratedZapretActivationOps(active, status, fingerprint, s.zapretCalibration.CatalogPath(), request.TestDomain)
			if adaptiveErr != nil {
				writeError(w, r, http.StatusPreconditionFailed, "zapret_calibration_stale", adaptiveErr.Error())
				return
			}
			operations = append(operations, adaptiveOps...)
			calibratedProfile = profileID
		}
	}
	change, err := s.createDraftChange("Activate managed Zapret", "Bind the verified nfqws component and enable its route in one transaction", request.BaseVersion, operations, currentSession(r).User)
	if err != nil {
		if errors.Is(err, errBaseVersionConflict) {
			writeError(w, r, http.StatusConflict, "base_version_conflict", "active revision changed while Zapret was being checked")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "state_store_failed", err.Error())
		return
	}
	s.publishEvent(Event{Type: "zapret.managed_activation_prepared", Severity: "info", ReasonCode: "transaction_required", Details: map[string]any{"change_id": change.ID, "provider_version": request.ProviderVersion, "test_domain": report.TestDomain}})
	writeData(w, r, map[string]any{"report": report, "change": change, "calibrated_profile_id": calibratedProfile})
}

func calibratedZapretActivationOps(active *config.Config, status zapret.CalibrationStatus, currentFingerprint, catalogPath, domain string) ([]ChangeOp, string, error) {
	if active == nil || status.State != "completed" || !status.ActivationRequired || status.RecommendedProfileID == "" {
		return nil, "", errors.New("completed Zapret calibration is required")
	}
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" || !strings.EqualFold(domain, strings.TrimSuffix(status.Domain, ".")) {
		return nil, "", errors.New("calibration belongs to another domain")
	}
	if currentFingerprint == "" || currentFingerprint != status.NetworkFingerprint {
		return nil, "", errors.New("network changed after calibration; run the strategy check again")
	}
	if catalogPath == "" || !filepath.IsAbs(catalogPath) {
		return nil, "", errors.New("calibration catalog path is unavailable")
	}
	profiles, bundles, err := zapret.LoadCatalogFile(catalogPath)
	if err != nil {
		return nil, "", errors.New("calibration catalog failed validation")
	}
	bundle, ok := bundles.Lookup(status.BundleID)
	if !ok || !containsDomainFold(bundle.RequiredDomains, domain) {
		return nil, "", errors.New("calibration catalog is not bound to the tested domain")
	}
	if _, ok := profiles.Lookup(status.RecommendedProfileID); !ok || !containsStringValue(bundle.AllowedProfiles, status.RecommendedProfileID) {
		return nil, "", errors.New("recommended profile is outside the calibrated bundle")
	}
	assignments := []config.ZapretProfileAssignment{{BundleID: status.BundleID, ProfileID: status.RecommendedProfileID}}
	return []ChangeOp{
		{Type: "set", Path: "/zapret/adaptive_enabled", Value: true},
		{Type: "set", Path: "/zapret/adaptive_catalog_file", Value: catalogPath},
		{Type: "set", Path: "/zapret/adaptive_assignments", Value: assignments},
	}, status.RecommendedProfileID, nil
}

func containsDomainFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(value), "."), target) {
			return true
		}
	}
	return false
}

func containsStringValue(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (s *Server) checkZapretSetup(w http.ResponseWriter, r *http.Request) (zapretSetupRequest, zapret.SetupReport, bool) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return zapretSetupRequest{}, zapret.SetupReport{}, false
	}
	if s.zapretSetupChecker == nil {
		writeError(w, r, http.StatusServiceUnavailable, "zapret_setup_unavailable", "Zapret capability checker is not configured")
		return zapretSetupRequest{}, zapret.SetupReport{}, false
	}
	var request zapretSetupRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return zapretSetupRequest{}, zapret.SetupReport{}, false
	}
	s.mu.Lock()
	version := s.configVersion
	active := s.activeConfig
	s.mu.Unlock()
	if request.BaseVersion <= 0 || request.BaseVersion != version {
		writeError(w, r, http.StatusConflict, "base_version_conflict", "base_version does not match current revision")
		return zapretSetupRequest{}, zapret.SetupReport{}, false
	}
	request.ProviderVersion = strings.TrimSpace(request.ProviderVersion)
	if strings.HasPrefix(request.ProviderVersion, "v") {
		request.ProviderVersion = strings.TrimPrefix(request.ProviderVersion, "v")
	}
	report, err := s.zapretSetupChecker.Check(r.Context(), zapret.SetupRequest{
		Binary: active.Zapret.Binary, SourceURL: strings.TrimSpace(request.SourceURL),
		ProviderVersion: request.ProviderVersion, BinaryDigest: strings.TrimSpace(request.BinarySHA256),
		TestDomain: strings.TrimSpace(request.TestDomain), QueueNum: active.Zapret.QueueNum,
	})
	if err != nil || !report.Ready || !report.DryRun || !report.NFQueueAvailable {
		message := "Zapret capability verification failed"
		if err != nil {
			message = err.Error()
		}
		writeError(w, r, http.StatusUnprocessableEntity, "zapret_preflight_failed", message)
		return zapretSetupRequest{}, zapret.SetupReport{}, false
	}
	request.SourceURL = strings.TrimSpace(request.SourceURL)
	request.BinarySHA256 = strings.TrimSpace(request.BinarySHA256)
	request.TestDomain = strings.TrimSpace(request.TestDomain)
	return request, report, true
}

func routesForManagedZapret(active *config.Config) ([]config.Route, error) {
	if active == nil {
		return nil, errors.New("active config is missing")
	}
	routes := append([]config.Route(nil), active.Routes...)
	found := false
	for index := range routes {
		if routes[index].Type != "zapret" {
			continue
		}
		if found {
			return nil, errors.New("multiple Zapret routes are not supported by setup")
		}
		routes[index].Disabled = false
		routes[index].Status = "CONFIGURED"
		routes[index].RequiresAdapter = true
		routes[index].AdapterMode = "zapret"
		routes[index].Mark = active.OpenWrt.ZapretMark
		routes[index].ForbidProxy = true
		found = true
	}
	if !found {
		return nil, errors.New("Zapret route is absent from the typed config")
	}
	return routes, nil
}

func servicesForZapretTest(active *config.Config, domain string) (map[string]config.Service, error) {
	if active == nil {
		return nil, errors.New("active config is missing")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
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
		owner = "zapret-setup-" + hex.EncodeToString(sum[:6])
		services[owner] = config.Service{
			Category: "TSPU_RESTRICTED", Domains: []string{domain},
			AllowedPaths: []string{"zapret", "direct", "drop"}, SelectedRouteTag: "zapret",
			ProbeURLs: []config.ProbeCheck{{Name: "managed-zapret", URL: "https://" + domain + "/", Required: true, ExpectedCodes: []int{200, 204, 301, 302, 307, 308, 401, 403}, BodyMode: "optional"}},
		}
		return services, nil
	}
	service := services[owner]
	allowed := []string{"zapret"}
	for _, path := range service.AllowedPaths {
		if path != "zapret" {
			allowed = append(allowed, path)
		}
	}
	service.AllowedPaths = allowed
	service.SelectedRouteTag = "zapret"
	services[owner] = service
	return services, nil
}

func zapretSetupStatus(cfg *config.Config) string {
	for _, route := range cfg.RoutesByType("zapret") {
		if route.Enabled() {
			if cfg.Zapret.ProviderSource == "" || cfg.Zapret.ProviderVersion == "" || cfg.Zapret.BinarySHA256 == "" {
				return "legacy_unpinned"
			}
			return "managed"
		}
	}
	return "not_configured"
}
