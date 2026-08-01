package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/discovery"
	"router-policy/internal/planner"
)

const (
	discoveryStateKey       = "control"
	maxDiscoverySuggestions = 256
)

type discoveryControlState struct {
	AppliedAt            []time.Time `json:"applied_at"`
	ConsecutiveRollbacks int         `json:"consecutive_rollbacks"`
	PausedReason         string      `json:"paused_reason,omitempty"`
	LastResult           string      `json:"last_result,omitempty"`
	UpdatedAt            time.Time   `json:"updated_at"`
}

type discoverySuggestion struct {
	Domain       string    `json:"domain"`
	Category     string    `json:"category"`
	Route        string    `json:"route,omitempty"`
	RouteType    string    `json:"route_type,omitempty"`
	PathVerified bool      `json:"path_verified"`
	Confidence   float64   `json:"confidence"`
	Reason       string    `json:"reason"`
	QueryType    string    `json:"query_type"`
	ObservedAt   time.Time `json:"observed_at"`
}

type discoveryConfigureRequest struct {
	BaseVersion             int64  `json:"base_version"`
	Mode                    string `json:"mode"`
	MaxNewRulesPerHour      int    `json:"max_new_rules_per_hour"`
	MaxConsecutiveRollbacks int    `json:"max_consecutive_rollbacks"`
	ResetFailures           bool   `json:"reset_failures,omitempty"`
}

type automaticCommitResult struct {
	Applied    bool
	RolledBack bool
	Reason     string
}

type DomainChecker func(context.Context, *config.Config, string, string, planner.Options) (planner.DomainCheck, error)

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	cfg := s.currentConfig()
	state := s.loadDiscoveryState()
	writeData(w, r, map[string]any{
		"mode":                      cfg.Policy.EffectiveDiscoveryMode(),
		"max_new_rules_per_hour":    cfg.Policy.EffectiveDiscoveryMaxNewRulesPerHour(),
		"max_consecutive_rollbacks": cfg.Policy.EffectiveDiscoveryMaxConsecutiveRollbacks(),
		"consecutive_rollbacks":     state.ConsecutiveRollbacks,
		"paused":                    state.PausedReason != "", "paused_reason": state.PausedReason,
		"applied_last_hour": len(pruneDiscoveryTimes(state.AppliedAt, s.discoveryNow().Add(-time.Hour))),
		"suggestions":       s.discoverySuggestions(100),
	})
}

func (s *Server) handleDiscoveryConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	var request discoveryConfigureRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	request.Mode = strings.ToLower(strings.TrimSpace(request.Mode))
	if request.Mode != "observe_only" && request.Mode != "suggest" && request.Mode != "auto_apply_verified" && request.Mode != "locked" {
		writeError(w, r, http.StatusBadRequest, "invalid_discovery_mode", "mode must be observe_only, suggest, auto_apply_verified or locked")
		return
	}
	if request.BaseVersion < 1 || request.MaxNewRulesPerHour < 1 || request.MaxNewRulesPerHour > 1000 || request.MaxConsecutiveRollbacks < 1 || request.MaxConsecutiveRollbacks > 100 {
		writeError(w, r, http.StatusBadRequest, "invalid_discovery_limits", "base_version and positive bounded discovery limits are required")
		return
	}
	operations := []ChangeOp{
		{Type: "set", Path: "/policy/discovery_mode", Value: request.Mode},
		{Type: "set", Path: "/policy/discovery_max_new_rules_per_hour", Value: request.MaxNewRulesPerHour},
		{Type: "set", Path: "/policy/discovery_max_consecutive_rollbacks", Value: request.MaxConsecutiveRollbacks},
	}
	if err := validateDiscoveryOperations(operations); err != nil {
		writeError(w, r, http.StatusBadRequest, "unsafe_discovery_change", err.Error())
		return
	}
	change, err := s.createDraftChange("Configure domain discovery", "Change observation and verified auto-apply policy", request.BaseVersion, operations, currentSession(r).User)
	if err != nil {
		if errors.Is(err, errBaseVersionConflict) {
			writeError(w, r, http.StatusConflict, "base_version_conflict", "base_version does not match current revision")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "discovery_change_failed", err.Error())
		return
	}
	if request.ResetFailures {
		state := s.loadDiscoveryState()
		state.ConsecutiveRollbacks = 0
		state.PausedReason = ""
		state.LastResult = "manually_reset"
		state.UpdatedAt = s.discoveryNow()
		_ = s.store.SaveJSON("discovery", discoveryStateKey, state)
	}
	writeData(w, r, map[string]any{"change": change})
}

func validateDiscoveryOperations(operations []ChangeOp) error {
	for _, operation := range operations {
		if operation.Type != "set" || (!strings.HasPrefix(operation.Path, "/services/") && !strings.HasPrefix(operation.Path, "/policy/discovery_")) {
			return fmt.Errorf("discovery may only change service rules and discovery limits")
		}
		if strings.Contains(operation.Path, "/openwrt/") || strings.Contains(operation.Path, "/platform/") || strings.Contains(operation.Path, "firewall") || strings.Contains(operation.Path, "management") {
			return fmt.Errorf("discovery cannot change management or firewall settings")
		}
	}
	return nil
}

func (s *Server) discoveryAutoAllowed(cfg *config.Config, check planner.DomainCheck) error {
	if check.Selected == nil || !check.Selected.PathVerified {
		return errors.New("selected route has no PathVerified evidence")
	}
	if check.Selected.RouteType == "direct" || check.Selected.RouteType == "drop" {
		return errors.New("Direct and Drop observations are not automatically persisted")
	}
	if cfg.OpenWrt.RollbackTimeoutSeconds <= 0 {
		return errors.New("automatic apply requires a rollback timer")
	}
	if active := s.activeTransaction(""); active != "" {
		return fmt.Errorf("transaction %s is already active", active)
	}
	state := s.loadDiscoveryState()
	limit := cfg.Policy.EffectiveDiscoveryMaxConsecutiveRollbacks()
	if state.ConsecutiveRollbacks >= limit {
		return fmt.Errorf("automatic apply paused after %d consecutive rollbacks", state.ConsecutiveRollbacks)
	}
	recent := pruneDiscoveryTimes(state.AppliedAt, s.discoveryNow().Add(-time.Hour))
	if len(recent) >= cfg.Policy.EffectiveDiscoveryMaxNewRulesPerHour() {
		return errors.New("hourly automatic rule limit reached")
	}
	return nil
}

func (s *Server) recordDiscoveryAutoResult(result automaticCommitResult) {
	state := s.loadDiscoveryState()
	now := s.discoveryNow()
	state.AppliedAt = pruneDiscoveryTimes(state.AppliedAt, now.Add(-time.Hour))
	state.LastResult = result.Reason
	state.UpdatedAt = now
	if result.Applied {
		state.AppliedAt = append(state.AppliedAt, now)
		state.ConsecutiveRollbacks = 0
		state.PausedReason = ""
	} else if result.RolledBack {
		state.ConsecutiveRollbacks++
		limit := s.currentConfig().Policy.EffectiveDiscoveryMaxConsecutiveRollbacks()
		if state.ConsecutiveRollbacks >= limit {
			state.PausedReason = "consecutive_rollbacks"
			s.publishEvent(Event{Type: "discovery.auto_apply_paused", Severity: "error", ReasonCode: "consecutive_rollbacks", Details: map[string]any{"count": state.ConsecutiveRollbacks, "limit": limit}})
		}
	}
	_ = s.store.SaveJSON("discovery", discoveryStateKey, state)
}

func (s *Server) loadDiscoveryState() discoveryControlState {
	var state discoveryControlState
	if err := s.store.LoadJSON("discovery", discoveryStateKey, &state); err != nil {
		return discoveryControlState{}
	}
	return state
}

func pruneDiscoveryTimes(values []time.Time, cutoff time.Time) []time.Time {
	out := make([]time.Time, 0, len(values))
	for _, value := range values {
		if value.After(cutoff) {
			out = append(out, value)
		}
	}
	return out
}

func (s *Server) saveDiscoverySuggestion(observation discovery.Observation, check planner.DomainCheck) {
	suggestion := discoverySuggestion{
		Domain: check.Domain, Category: check.Category, Confidence: check.Confidence,
		QueryType: observation.QueryType, ObservedAt: s.discoveryNow(), Reason: "no verified route selected",
	}
	if check.Selected != nil {
		suggestion.Route = check.Selected.Route
		suggestion.RouteType = check.Selected.RouteType
		suggestion.PathVerified = check.Selected.PathVerified
		suggestion.Reason = check.Selected.ReasonCode
		if suggestion.Reason == "" && check.Selected.Reason != nil {
			suggestion.Reason = *check.Selected.Reason
		}
		if suggestion.Reason == "" {
			suggestion.Reason = "route selected by verified planner evidence"
		}
	}
	s.mu.Lock()
	s.discoverySuggestionMap[check.Domain] = suggestion
	if len(s.discoverySuggestionMap) > maxDiscoverySuggestions {
		oldestDomain := ""
		var oldestTime time.Time
		for domain, item := range s.discoverySuggestionMap {
			if oldestDomain == "" || item.ObservedAt.Before(oldestTime) {
				oldestDomain = domain
				oldestTime = item.ObservedAt
			}
		}
		delete(s.discoverySuggestionMap, oldestDomain)
	}
	s.mu.Unlock()
}

func (s *Server) discoverySuggestions(limit int) []discoverySuggestion {
	s.mu.Lock()
	items := make([]discoverySuggestion, 0, len(s.discoverySuggestionMap))
	for _, item := range s.discoverySuggestionMap {
		items = append(items, item)
	}
	s.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ObservedAt.After(items[j].ObservedAt) })
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}
