package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/vpnsub"
	"router-policy/internal/writebudget"
)

type xraySubscriptionPrepareRequest struct {
	BaseVersion     int64 `json:"base_version"`
	ActivateManaged bool  `json:"activate_managed"`
}

type xraySubscriptionSecretRequest struct {
	URL  string   `json:"url,omitempty"`
	URLs []string `json:"urls,omitempty"`
}

type xraySubscriptionPreparation struct {
	BundleHash        string                  `json:"bundle_hash"`
	SubscriptionHash  string                  `json:"subscription_hash"`
	SubscriptionBytes int                     `json:"subscription_bytes"`
	SelectedTag       string                  `json:"selected_tag"`
	Checks            []vpnsub.OutboundCheck  `json:"checks"`
	Servers           []vpnsub.ServerStatus   `json:"servers"`
	Routes            []vpnsub.GeneratedRoute `json:"routes"`
	Ready             bool                    `json:"ready"`
	SecretsPrinted    bool                    `json:"secrets_printed"`
}

func (s *Server) handleXraySubscriptionSecret(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentConfig()
	path := cfg.Xray.SubscriptionSecretFile
	if path == "" {
		writeError(w, r, http.StatusServiceUnavailable, "xray_not_configured", "VPN subscription secret path is not configured")
		return
	}
	switch r.Method {
	case http.MethodGet:
		present, err := subscriptionSecretPresent(path)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "subscription_secret_invalid", err.Error())
			return
		}
		count := 0
		if present {
			urls, err := vpnsub.ReadSubscriptionURLFiles(path)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "subscription_secret_invalid", err.Error())
				return
			}
			count = len(urls)
		}
		writeData(w, r, subscriptionSecretStatus(present, count))
	case http.MethodPut:
		release, failure := s.acquireMutationLease()
		if failure != nil {
			writeError(w, r, failure.Status, failure.Code, failure.Message)
			return
		}
		defer release()
		var request xraySubscriptionSecretRequest
		if err := readJSON(r, &request); err != nil {
			writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		values := append([]string(nil), request.URLs...)
		if request.URL != "" {
			values = append(values, request.URL)
		}
		normalized, err := normalizeSubscriptionURLs(values)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_subscription_url", err.Error())
			return
		}
		changed, err := storeSubscriptionSecrets(path, normalized)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "subscription_secret_write_failed", err.Error())
			return
		}
		s.publishEvent(Event{
			Type: "xray.subscription_secret_updated", Severity: "info", ReasonCode: "subscription_secret_saved",
			Durable: true, Details: map[string]any{"changed": changed, "source_count": len(normalized)},
		})
		status := subscriptionSecretStatus(true, len(normalized))
		status["changed"] = changed
		writeData(w, r, status)
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET or PUT required")
	}
}

func normalizeSubscriptionURLs(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 5 {
		return nil, errors.New("provide 1..5 subscription URLs")
	}
	normalized := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, raw := range values {
		value, err := normalizeSubscriptionURL(raw)
		if err != nil {
			return nil, err
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		normalized = append(normalized, value)
	}
	if len(normalized) == 0 {
		return nil, errors.New("provide at least one unique subscription URL")
	}
	return normalized, nil
}

func subscriptionSecretStatus(present bool, count int) map[string]any {
	slots := make([]map[string]any, 5)
	for index := range slots {
		slots[index] = map[string]any{"slot": index + 1, "configured": present && index < count}
	}
	return map[string]any{"configured": true, "present": present, "count": count, "capacity": 5, "slots": slots}
}

func normalizeSubscriptionURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > 4096 {
		return "", errors.New("subscription URL must contain 1..4096 characters")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("subscription URL must be an HTTPS URL without user info or fragment")
	}
	return parsed.String(), nil
}

func subscriptionSecretPresent(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, errors.New("subscription secret target is not a regular file")
	}
	return info.Size() > 0, nil
}

func storeSubscriptionSecret(path, value string) (bool, error) {
	return storeSubscriptionSecrets(path, []string{value})
}

func storeSubscriptionSecrets(path string, values []string) (bool, error) {
	if !filepath.IsAbs(path) {
		return false, errors.New("subscription secret path must be absolute")
	}
	if len(values) == 0 || len(values) > 5 {
		return false, errors.New("subscription secret requires 1..5 sources")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return false, err
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return false, err
	}
	if filepath.Clean(resolved) != filepath.Clean(parent) {
		return false, errors.New("subscription secret parent must not contain symlinks")
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return false, err
	}
	raw = append(raw, '\n')
	info, err := os.Lstat(path)
	created := errors.Is(err, os.ErrNotExist)
	if err != nil && !created {
		return false, err
	}
	if !created {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return false, errors.New("subscription secret target is not a regular file")
		}
		existing, err := os.ReadFile(path)
		if err != nil {
			return false, err
		}
		if bytes.Equal(existing, raw) && info.Mode().Perm() == 0o600 {
			return false, nil
		}
	}
	if err := writeFileAtomic(path, raw, 0o600); err != nil {
		return false, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return false, err
	}
	writebudget.RecordFileWrite(created, uint64(len(raw)), 1, "subscription_secret_update")
	return true, nil
}

func (s *Server) handleXraySubscriptionPrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	if failure := s.mutationFailureNow(); failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	if s.subscriptionPreparer == nil {
		writeError(w, r, http.StatusServiceUnavailable, "xray_not_configured", "Xray subscription preparation is not configured")
		return
	}
	var request xraySubscriptionPrepareRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if request.BaseVersion <= 0 {
		writeError(w, r, http.StatusBadRequest, "invalid_base_version", "base_version must be positive")
		return
	}

	s.subscriptionMu.Lock()
	defer s.subscriptionMu.Unlock()
	s.mu.Lock()
	currentVersion := s.configVersion
	active := s.activeConfig
	s.mu.Unlock()
	if request.BaseVersion != currentVersion {
		writeError(w, r, http.StatusConflict, "base_version_conflict", "base_version does not match current revision")
		return
	}
	prepared, err := s.subscriptionPreparer.Prepare(r.Context(), active)
	if err != nil {
		s.publishEvent(Event{Type: "xray.subscription_prepare_failed", Severity: "error", ReasonCode: "xray_candidate_rejected", Details: map[string]any{"reason": err.Error()}})
		writeError(w, r, http.StatusBadGateway, "xray_candidate_rejected", err.Error())
		return
	}
	if !prepared.Ready || prepared.BundleHash == "" || prepared.SelectedTag == "" {
		writeError(w, r, http.StatusUnprocessableEntity, "xray_candidate_unverified", "prepared Xray bundle is not verified")
		return
	}
	routes, err := routesForPreparedBundle(active, prepared)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "xray_routes_invalid", err.Error())
		return
	}
	response := map[string]any{
		"preparation": xraySubscriptionPreparation{
			BundleHash: prepared.BundleHash, SubscriptionHash: prepared.SubscriptionHash, SubscriptionBytes: prepared.SubscriptionBytes,
			SelectedTag: prepared.SelectedTag, Checks: prepared.Checks, Servers: prepared.Servers, Routes: prepared.Routes,
			Ready: prepared.Ready, SecretsPrinted: prepared.SecretsPrinted,
		},
		"activation": map[string]any{
			"current_mode":                   active.Xray.ActivationMode,
			"managed_available":              true,
			"explicit_confirmation_required": true,
			"tproxy_mode":                    "tproxy",
			"tproxy_port":                    active.Xray.TransparentPort,
			"bypass_mark":                    active.OpenWrt.XrayBypassMark,
		},
	}
	if !request.ActivateManaged {
		s.publishEvent(Event{Type: "xray.subscription_prepared", Severity: "info", ReasonCode: "managed_activation_offered", Details: map[string]any{"bundle_hash": prepared.BundleHash, "selected_tag": prepared.SelectedTag}})
		writeData(w, r, response)
		return
	}
	operations := []ChangeOp{
		{Type: "set", Path: "/xray/activation_mode", Value: "managed"},
		{Type: "set", Path: "/xray/outbound_bundle_sha256", Value: prepared.BundleHash},
		{Type: "set", Path: "/routes", Value: routes},
	}
	session := currentSession(r)
	change, err := s.createDraftChange("Activate managed Xray", "Bind verified VLESS routes and transparent proxy activation in one transaction", request.BaseVersion, operations, session.User)
	if err != nil {
		if errors.Is(err, errBaseVersionConflict) {
			writeError(w, r, http.StatusConflict, "base_version_conflict", "active revision changed while the subscription was being checked")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "state_store_failed", err.Error())
		return
	}
	response["change"] = change
	s.publishEvent(Event{Type: "xray.managed_activation_prepared", Severity: "info", ReasonCode: "transaction_required", Details: map[string]any{"change_id": change.ID, "bundle_hash": prepared.BundleHash, "selected_tag": prepared.SelectedTag}})
	writeData(w, r, response)
}

func routesForPreparedBundle(active *config.Config, prepared vpnsub.PreparedBundle) ([]config.Route, error) {
	if active == nil {
		return nil, errors.New("active config is missing")
	}
	routes := make([]config.Route, 0, len(active.Routes)+len(prepared.Routes))
	seen := map[string]bool{}
	maxPriority := 0
	for _, route := range active.Routes {
		if route.Type == "vless" {
			continue
		}
		if route.Tag == "" || seen[route.Tag] {
			return nil, errors.New("active routes contain duplicate or empty tags")
		}
		seen[route.Tag] = true
		routes = append(routes, route)
		if route.Priority > maxPriority {
			maxPriority = route.Priority
		}
	}
	checkByTag := make(map[string]vpnsub.OutboundCheck, len(prepared.Checks))
	for _, check := range prepared.Checks {
		checkByTag[check.Tag] = check
	}
	generated := append([]vpnsub.GeneratedRoute(nil), prepared.Routes...)
	generatedSeen := map[string]bool{}
	for _, route := range generated {
		if route.Type != "vless" || route.Tag == "" || generatedSeen[route.Tag] {
			return nil, errors.New("prepared VLESS routes contain an invalid or duplicate tag")
		}
		generatedSeen[route.Tag] = true
	}
	sort.SliceStable(generated, func(i, j int) bool {
		if generated[i].Tag == prepared.SelectedTag {
			return true
		}
		if generated[j].Tag == prepared.SelectedTag {
			return false
		}
		if generated[i].Priority != generated[j].Priority {
			return generated[i].Priority < generated[j].Priority
		}
		return generated[i].Tag < generated[j].Tag
	})
	selectedFound := false
	for index, generatedRoute := range generated {
		if seen[generatedRoute.Tag] {
			return nil, errors.New("prepared VLESS routes contain an invalid or duplicate tag")
		}
		check, checked := checkByTag[generatedRoute.Tag]
		healthy := checked && check.Status == "OK" && check.ExternalIPHash != "" && check.ExternalCountry != "" && check.ExternalCountry != "UNKNOWN" && check.ExternalCountry != "RU"
		status := "QUARANTINED"
		disabled := true
		if healthy {
			status = "STANDBY"
			disabled = false
		}
		if generatedRoute.Tag == prepared.SelectedTag {
			if !healthy {
				return nil, errors.New("selected VLESS route is not backed by a safe successful check")
			}
			status = "SELECTED"
			selectedFound = true
		}
		routes = append(routes, config.Route{
			Type: "vless", Tag: generatedRoute.Tag, Priority: maxPriority + 10 + index*10,
			Disabled: disabled, Status: status, SOCKS5: generatedRoute.SOCKS5, DNSServer: active.Xray.ProbeDNSResolver, DNSMode: generatedRoute.DNSMode,
			ExternalIPProbe: generatedRoute.ExternalIPProbe, RequiresAdapter: true, AdapterMode: "xray", Mark: active.OpenWrt.XrayMark,
		})
		seen[generatedRoute.Tag] = true
	}
	if !selectedFound {
		return nil, errors.New("selected VLESS route is absent from the prepared bundle")
	}
	return routes, nil
}

var errBaseVersionConflict = errors.New("base version conflict")

func (s *Server) createDraftChange(title, description string, baseVersion int64, operations []ChangeOp, author string) (ChangeSet, error) {
	release, failure := s.acquireMutationLease()
	if failure != nil {
		return ChangeSet{}, &mutationBlockedError{failure: failure}
	}
	defer release()
	s.mu.Lock()
	if baseVersion != s.configVersion {
		s.mu.Unlock()
		return ChangeSet{}, errBaseVersionConflict
	}
	now := time.Now().UTC().Format(time.RFC3339)
	randomID, err := secureRandomHex(8)
	if err != nil {
		s.mu.Unlock()
		return ChangeSet{}, fmt.Errorf("generate change ID: %w", err)
	}
	change := ChangeSet{
		ID: "chg_" + randomID, State: "draft", Title: title, Description: description,
		BaseVersion: baseVersion, Version: 1, Operations: operations, CreatedAt: now, UpdatedAt: now, Author: author,
	}
	s.changes[change.ID] = change
	s.mu.Unlock()
	if err := s.persistChangeSet(change); err != nil {
		s.mu.Lock()
		delete(s.changes, change.ID)
		s.mu.Unlock()
		return ChangeSet{}, err
	}
	s.publishEvent(Event{Type: "change.created", Severity: "info", ReasonCode: "draft_created", Details: map[string]any{"change_id": change.ID}})
	return change, nil
}
