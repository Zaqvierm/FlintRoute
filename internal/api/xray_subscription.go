package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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
	URL   string   `json:"url,omitempty"`
	URLs  []string `json:"urls,omitempty"`
	Index *int     `json:"index,omitempty"`
}

type xraySubscriptionHWIDRequest struct {
	Mode       vpnsub.HWIDMode   `json:"mode,omitempty"`
	Source     vpnsub.HWIDSource `json:"source,omitempty"`
	Preset     string            `json:"preset,omitempty"`
	CustomSeed string            `json:"custom_seed,omitempty"`
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
		var sources []vpnsub.SourceDescription
		if present {
			urls, err := vpnsub.ReadSubscriptionSourceFiles(path)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "subscription_secret_invalid", err.Error())
				return
			}
			count = len(urls)
			sources = make([]vpnsub.SourceDescription, 0, len(urls))
			for _, value := range urls {
				description, describeErr := vpnsub.DescribeSource(value)
				if describeErr != nil {
					writeError(w, r, http.StatusInternalServerError, "subscription_secret_invalid", "subscription source is invalid")
					return
				}
				sources = append(sources, description)
			}
		}
		status := subscriptionSecretStatus(present, count)
		status["sources"] = sources
		writeData(w, r, status)
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
		status["sources"] = describeSubscriptionSources(normalized)
		writeData(w, r, status)
	case http.MethodDelete:
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
		if request.Index == nil || *request.Index < 0 {
			writeError(w, r, http.StatusBadRequest, "invalid_subscription_index", "subscription index is required")
			return
		}
		values, err := vpnsub.ReadSubscriptionSourceFiles(path)
		if err != nil {
			writeError(w, r, http.StatusConflict, "subscription_secret_invalid", "subscription sources could not be read safely")
			return
		}
		if *request.Index >= len(values) {
			writeError(w, r, http.StatusNotFound, "subscription_index_not_found", "subscription source was not found")
			return
		}
		remaining := append([]string(nil), values[:*request.Index]...)
		remaining = append(remaining, values[*request.Index+1:]...)
		changed, err := removeOrStoreSubscriptionSources(path, remaining)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "subscription_secret_write_failed", err.Error())
			return
		}
		status := subscriptionSecretStatus(len(remaining) > 0, len(remaining))
		status["changed"] = changed
		status["sources"] = describeSubscriptionSources(remaining)
		s.publishEvent(Event{Type: "xray.subscription_secret_updated", Severity: "info", ReasonCode: "subscription_source_removed", Durable: true, Details: map[string]any{"changed": changed, "source_count": len(remaining)}})
		writeData(w, r, status)
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET, PUT or DELETE required")
	}
}

func describeSubscriptionSources(values []string) []vpnsub.SourceDescription {
	result := make([]vpnsub.SourceDescription, 0, len(values))
	for _, value := range values {
		description, err := vpnsub.DescribeSource(value)
		if err != nil {
			// Values have already passed normalizeSubscriptionURLs. Keep this
			// defensive branch non-sensitive if a future caller violates that
			// contract.
			continue
		}
		result = append(result, description)
	}
	return result
}

func (s *Server) handleXraySubscriptionHWID(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentConfig()
	path := vpnsub.HWIDSettingsPath(cfg.Xray.SubscriptionSecretFile)
	if path == "" {
		writeError(w, r, http.StatusServiceUnavailable, "xray_not_configured", "VPN subscription secret path is not configured")
		return
	}
	switch r.Method {
	case http.MethodGet:
		settings, err := vpnsub.LoadHWIDSettings(path)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "subscription_hwid_invalid", err.Error())
			return
		}
		payload, err := s.subscriptionHWIDPayload(r.Context(), settings)
		if err != nil && settings.Mode != vpnsub.HWIDModeDisabled {
			writeError(w, r, http.StatusInternalServerError, "subscription_hwid_unavailable", err.Error())
			return
		}
		writeData(w, r, payload)
	case http.MethodPut:
		release, failure := s.acquireMutationLease()
		if failure != nil {
			writeError(w, r, failure.Status, failure.Code, failure.Message)
			return
		}
		defer release()
		var request xraySubscriptionHWIDRequest
		if err := readJSON(r, &request); err != nil {
			writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		settings := vpnsub.NormalizeHWIDSettings(vpnsub.HWIDSettings{Mode: request.Mode, Source: request.Source, Preset: request.Preset, CustomSeed: request.CustomSeed})
		if err := settings.Validate(); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_subscription_hwid", err.Error())
			return
		}
		payload, resolveErr := s.subscriptionHWIDPayload(r.Context(), settings)
		if resolveErr != nil && settings.Mode != vpnsub.HWIDModeDisabled {
			writeError(w, r, http.StatusInternalServerError, "subscription_hwid_unavailable", resolveErr.Error())
			return
		}
		// Resolve and validate the effective HWID before persisting settings. A
		// missing fingerprint source must not replace a previously working
		// configuration with a value that cannot be used after restart.
		if err := vpnsub.StoreHWIDSettings(path, settings); err != nil {
			writeError(w, r, http.StatusInternalServerError, "subscription_hwid_write_failed", err.Error())
			return
		}
		s.publishEvent(Event{Type: "xray.subscription_hwid_updated", Severity: "info", ReasonCode: "subscription_hwid_saved", Durable: true, Details: map[string]any{"mode": settings.Mode, "source": settings.Source}})
		writeData(w, r, payload)
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET or PUT required")
	}
}

func (s *Server) subscriptionHWIDPayload(ctx context.Context, settings vpnsub.HWIDSettings) (map[string]any, error) {
	current, err := vpnsub.ResolveHWID(ctx, settings, s.hwidFingerprintProvider)
	if err != nil && settings.Mode != vpnsub.HWIDModeDisabled {
		return nil, err
	}
	preview, previewErr := vpnsub.PreviewHWIDs(ctx, settings, s.hwidFingerprintProvider)
	if previewErr != nil && settings.Mode != vpnsub.HWIDModeDisabled {
		return nil, previewErr
	}
	return map[string]any{
		"mode": string(settings.Mode), "source": string(settings.Source), "custom_seed": settings.CustomSeed,
		"current_hwid": current, "preset_configured": settings.Mode == vpnsub.HWIDModePreset,
		"preset": func() string {
			if settings.Mode == vpnsub.HWIDModePreset {
				return settings.Preset
			}
			return ""
		}(), "preview": preview,
	}, nil
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
	value, err := vpnsub.NormalizeSource(raw)
	if err != nil {
		return "", err
	}
	info, err := vpnsub.DetectSource(value)
	if err != nil {
		return "", err
	}
	if info.Type == vpnsub.SourceTypeHTTP {
		return "", errors.New("subscription source must be HTTPS or a supported Happ URI")
	}
	return info.Canonical, nil
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

func removeOrStoreSubscriptionSources(path string, values []string) (bool, error) {
	if len(values) > 5 {
		return false, errors.New("subscription secret requires at most 5 sources")
	}
	if len(values) > 0 {
		return storeSubscriptionSecrets(path, values)
	}
	if !filepath.IsAbs(path) {
		return false, errors.New("subscription secret path must be absolute")
	}
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
	if err := os.Remove(path); err != nil {
		return false, err
	}
	writebudget.RecordFileWrite(false, 0, 1, "subscription_secret_remove")
	return true, nil
}

func (s *Server) handleXraySubscriptionPrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	// Preparing a subscription starts a bounded candidate Xray and checks the
	// configured server pool. With the current maximum (15 servers, three
	// attempts, four workers) this can legitimately exceed the HTTP server's
	// short 30-second default write deadline. Extend only this response; SSE
	// and ordinary API requests keep their normal bounded deadline.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
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

	if !s.tryLockSubscription() {
		writeError(w, r, http.StatusConflict, "subscription_operation_busy", "Another subscription operation is still running")
		return
	}
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
		var sourceErr *vpnsub.SourceError
		if errors.As(err, &sourceErr) {
			writeError(w, r, http.StatusBadGateway, sourceErr.Code, sourceErr.Error())
			return
		}
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
