package api

import (
	"errors"
	"net/http"
	"sort"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/vpnsub"
)

type xraySubscriptionPrepareRequest struct {
	BaseVersion int64 `json:"base_version"`
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

func (s *Server) handleXraySubscriptionPrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
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
	operations := []ChangeOp{
		{Type: "set", Path: "/xray/outbound_bundle_sha256", Value: prepared.BundleHash},
		{Type: "set", Path: "/routes", Value: routes},
	}
	session := currentSession(r)
	change, err := s.createDraftChange("VPN subscription refresh", "Prepared and verified VLESS outbound bundle", request.BaseVersion, operations, session.User)
	if err != nil {
		if errors.Is(err, errBaseVersionConflict) {
			writeError(w, r, http.StatusConflict, "base_version_conflict", "active revision changed while the subscription was being checked")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "state_store_failed", err.Error())
		return
	}
	s.publishEvent(Event{Type: "xray.subscription_prepared", Severity: "info", ReasonCode: "transaction_required", Details: map[string]any{"change_id": change.ID, "bundle_hash": prepared.BundleHash, "selected_tag": prepared.SelectedTag}})
	writeData(w, r, map[string]any{
		"change": change,
		"preparation": xraySubscriptionPreparation{
			BundleHash: prepared.BundleHash, SubscriptionHash: prepared.SubscriptionHash, SubscriptionBytes: prepared.SubscriptionBytes,
			SelectedTag: prepared.SelectedTag, Checks: prepared.Checks, Servers: prepared.Servers, Routes: prepared.Routes,
			Ready: prepared.Ready, SecretsPrinted: prepared.SecretsPrinted,
		},
	})
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
	s.mu.Lock()
	if baseVersion != s.configVersion {
		s.mu.Unlock()
		return ChangeSet{}, errBaseVersionConflict
	}
	now := time.Now().UTC().Format(time.RFC3339)
	change := ChangeSet{
		ID: "chg_" + randomHex(8), State: "draft", Title: title, Description: description,
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
