package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"router-policy/internal/netpolicy"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
	"router-policy/internal/zapret"
)

type zapretCalibrationRequest struct {
	Domain              string `json:"domain"`
	AllowManagedRestart bool   `json:"allow_managed_restart,omitempty"`
	Mode                string `json:"mode,omitempty"`
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
		release, failure := s.acquireMutationLease()
		if failure != nil {
			writeError(w, r, failure.Status, failure.Code, failure.Message)
			return
		}
		defer release()
		var request zapretCalibrationRequest
		if err := readJSON(r, &request); err != nil {
			writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		mode, err := zapret.NormalizeCalibrationMode(request.Mode)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "zapret_calibration_mode_invalid", err.Error())
			return
		}
		fingerprint, err := s.verifiedCalibrationNetworkFingerprint()
		if err != nil {
			writeError(w, r, http.StatusPreconditionFailed, "zapret_network_unverified", err.Error())
			return
		}
		resolvedIPv4, err := s.zapretCalibrationIPv4(r.Context(), request.Domain)
		if err != nil {
			writeError(w, r, http.StatusPreconditionFailed, "zapret_dns_resolution_failed", err.Error())
			return
		}
		bundleID := "auto-" + shortCalibrationHash(strings.ToLower(strings.TrimSpace(request.Domain)))
		status, err := s.zapretCalibration.Start(zapret.CalibrationRequest{
			Domain: request.Domain, BundleID: bundleID, NetworkFingerprint: fingerprint,
			ResolvedIPv4:        resolvedIPv4,
			AllowManagedRestart: request.AllowManagedRestart,
			Mode:                mode,
		})
		if err != nil {
			writeError(w, r, http.StatusConflict, "zapret_calibration_start_failed", err.Error())
			return
		}
		s.publishEvent(Event{Type: "zapret.calibration_started", Severity: "info", ReasonCode: "provider_calibration_started", Details: map[string]any{"domain": status.Domain, "mode": status.Mode, "scan_level": status.ScanLevel, "concurrency": status.Concurrency}})
		writeData(w, r, status)
	case http.MethodDelete:
		release, failure := s.acquireMutationLease()
		if failure != nil {
			writeError(w, r, failure.Status, failure.Code, failure.Message)
			return
		}
		defer release()
		status := s.zapretCalibration.Cancel()
		s.publishEvent(Event{Type: "zapret.calibration_cancelled", Severity: "warning", ReasonCode: "operator_cancelled", Details: map[string]any{"run_id": status.ID}})
		writeData(w, r, status)
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET, POST or DELETE required")
	}
}

func (s *Server) zapretCalibrationIPv4(ctx context.Context, domain string) ([]string, error) {
	active := s.currentConfig()
	if active == nil {
		return nil, nil
	}
	hasSmartDNS := false
	var lastErr error
	for _, route := range active.Routes {
		if route.Type != "smart_dns" || !route.Enabled() || strings.TrimSpace(route.DNSServer) == "" {
			continue
		}
		hasSmartDNS = true
		for _, resolver := range []string{route.DNSServer, route.DNSFallbackServer} {
			if resolver == "" {
				continue
			}
			probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			udp, udpErr := probe.ValidateDNSResolverTransport(probeCtx, resolver, domain, "udp")
			tcp, tcpErr := probe.ValidateDNSResolverTransport(probeCtx, resolver, domain, "tcp")
			cancel()
			if udpErr != nil || tcpErr != nil || !udp.Safe || !tcp.Safe {
				lastErr = fmt.Errorf("Smart DNS resolver %s did not return a verified UDP/TCP answer", route.Tag)
				continue
			}
			values := append(append([]string{}, udp.Addresses...), tcp.Addresses...)
			result := make([]string, 0, len(values))
			seen := make(map[string]struct{}, len(values))
			for _, value := range values {
				addr, parseErr := netip.ParseAddr(value)
				if parseErr != nil || !addr.Is4() || !netpolicy.PublicResolverAddr(addr) {
					continue
				}
				value = addr.String()
				if _, ok := seen[value]; ok {
					continue
				}
				seen[value] = struct{}{}
				result = append(result, value)
				if len(result) == 8 {
					break
				}
			}
			if len(result) > 0 {
				return result, nil
			}
			lastErr = fmt.Errorf("Smart DNS resolver %s returned no safe public IPv4 address", route.Tag)
		}
	}
	if !hasSmartDNS {
		return lookupPublicCalibrationIPv4(ctx, domain)
	}
	if lastErr == nil {
		lastErr = errors.New("configured Smart DNS resolvers could not resolve the calibration domain")
	}
	return nil, lastErr
}

func lookupPublicCalibrationIPv4(ctx context.Context, domain string) ([]string, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip4", domain)
	if err != nil {
		return nil, fmt.Errorf("system DNS could not resolve the calibration domain: %w", err)
	}
	result := make([]string, 0, 4)
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if !address.Is4() || !netpolicy.PublicResolverAddr(address) {
			continue
		}
		value := address.String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
		if len(result) == 4 {
			break
		}
	}
	if len(result) == 0 {
		return nil, errors.New("system DNS returned no safe public IPv4 address")
	}
	return result, nil
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
