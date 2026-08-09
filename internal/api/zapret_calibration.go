package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"router-policy/internal/platform"
	"router-policy/internal/zapret"
)

type zapretCalibrationRequest struct {
	Domain              string `json:"domain"`
	AllowManagedRestart bool   `json:"allow_managed_restart,omitempty"`
}

func (s *Server) handleZapretCalibration(w http.ResponseWriter, r *http.Request) {
	if s.zapretCalibration == nil {
		writeError(w, r, http.StatusServiceUnavailable, "zapret_calibration_unavailable", "Zapret calibration is unavailable on this runtime")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeData(w, r, s.zapretCalibration.Status())
	case http.MethodPost:
		var request zapretCalibrationRequest
		if err := readJSON(r, &request); err != nil {
			writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		fingerprint, err := s.verifiedCalibrationNetworkFingerprint()
		if err != nil {
			writeError(w, r, http.StatusPreconditionFailed, "zapret_network_unverified", err.Error())
			return
		}
		bundleID := "auto-" + shortCalibrationHash(strings.ToLower(strings.TrimSpace(request.Domain)))
		status, err := s.zapretCalibration.Start(zapret.CalibrationRequest{
			Domain: request.Domain, BundleID: bundleID, NetworkFingerprint: fingerprint,
			AllowManagedRestart: request.AllowManagedRestart,
		})
		if err != nil {
			writeError(w, r, http.StatusConflict, "zapret_calibration_start_failed", err.Error())
			return
		}
		s.publishEvent(Event{Type: "zapret.calibration_started", Severity: "info", ReasonCode: "provider_calibration_started", Details: map[string]any{"domain": status.Domain, "concurrency": status.Concurrency}})
		writeData(w, r, status)
	case http.MethodDelete:
		status := s.zapretCalibration.Cancel()
		s.publishEvent(Event{Type: "zapret.calibration_cancelled", Severity: "warning", ReasonCode: "operator_cancelled", Details: map[string]any{"run_id": status.ID}})
		writeData(w, r, status)
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET, POST or DELETE required")
	}
}

func (s *Server) verifiedCalibrationNetworkFingerprint() (string, error) {
	provider, ok := s.provider.(platform.NetworkDiagnosticsProvider)
	if !ok || s.provider.Simulation() {
		return "", &calibrationError{"production network diagnostics are unavailable"}
	}
	diagnostics := provider.NetworkDiagnostics(s.currentConfig())
	if diagnostics.Status != "VERIFIED" || diagnostics.Simulation {
		reason := strings.TrimSpace(diagnostics.Reason)
		if reason == "" {
			reason = "network diagnostics are not verified"
		}
		return "", &calibrationError{reason}
	}
	payload := struct {
		WANInterfaces []string `json:"wan_interfaces"`
		LANInterfaces []string `json:"lan_interfaces"`
		IPv4Gateway   string   `json:"ipv4_gateway"`
		IPv6Gateway   string   `json:"ipv6_gateway,omitempty"`
		DNSResolvers  []string `json:"dns_resolvers"`
	}{
		WANInterfaces: diagnostics.WANInterfaces, LANInterfaces: diagnostics.LANInterfaces,
		IPv4Gateway: diagnostics.IPv4Gateway, IPv6Gateway: diagnostics.IPv6Gateway,
		DNSResolvers: diagnostics.DNSResolvers,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

type calibrationError struct{ message string }

func (e *calibrationError) Error() string { return e.message }

func shortCalibrationHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:6])
}
