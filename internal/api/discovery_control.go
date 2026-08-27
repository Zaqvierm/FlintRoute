package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/discovery"
	"router-policy/internal/planner"
	"router-policy/internal/probe"
	"router-policy/internal/tspu"
)

const (
	discoveryStateKey        = "control"
	maxDiscoverySuggestions  = 256
	maxDiscoveryObservations = 1000
	discoverySuggestionKey   = "suggestions"
	// A DNS cache miss can be reported repeatedly by several clients.  Treat
	// the eTLD+1 as one discovery subject for a bounded observation window;
	// ordinary repeat queries must not restart route probes.
	discoveryDedupeWindow = 30 * time.Minute
)

func (s *Server) beginDiscoveryObservation(domain string, now time.Time) bool {
	key := discoveryDedupeKey(domain)
	if key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.discoveryInFlight[key] {
		return false
	}
	if last := s.discoveryRecent[key]; !last.IsZero() && now.Sub(last) < discoveryDedupeWindow {
		return false
	}
	s.discoveryInFlight[key] = true
	return true
}

func (s *Server) finishDiscoveryObservation(domain string, observedAt time.Time) {
	key := discoveryDedupeKey(domain)
	s.mu.Lock()
	delete(s.discoveryInFlight, key)
	s.discoveryRecent[key] = observedAt
	if len(s.discoveryRecent) > maxDiscoverySuggestions*2 {
		cutoff := observedAt.Add(-discoveryDedupeWindow)
		for name, seenAt := range s.discoveryRecent {
			if seenAt.Before(cutoff) {
				delete(s.discoveryRecent, name)
			}
		}
	}
	s.mu.Unlock()
}

func discoveryDedupeKey(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}
	if etld := tspu.ETLDPlusOne(domain); etld != "" {
		return etld
	}
	return domain
}

func discoveryCandidateDetails(results []probe.RouteResult) []map[string]any {
	items := make([]map[string]any, 0, len(results))
	for _, result := range results {
		item := map[string]any{
			"route": result.Route, "route_type": result.RouteType, "status": result.Status,
			"path_verified": result.PathVerified, "service_ok": result.ServiceOK,
			"reason":                   result.ReasonCode,
			"route_latency_available":  result.RouteLatencyAvailable,
			"verification_duration_ms": result.VerificationDurationMS,
			"dns_resolver":             result.DNSResolver, "resolved_ip": result.ResolvedIP,
			"connected_ip": result.ConnectedIP, "interface": result.Interface,
		}
		if result.RouteLatencyAvailable {
			item["latency_ms"] = result.RouteLatencyMS
			item["route_latency_ms"] = result.RouteLatencyMS
		}
		items = append(items, item)
	}
	return items
}

func discoveryRouteLabel(result probe.RouteResult) string {
	if result.Route == "system-default" {
		return "Direct (системный маршрут)"
	}
	switch result.RouteType {
	case "direct":
		return "Direct"
	case "smart_dns":
		return "Smart DNS"
	case "vless":
		return "VLESS"
	case "zapret":
		return "Zapret"
	case "drop":
		return "Блокировка"
	default:
		return result.Route
	}
}

func discoveryHTTPStatus(result probe.RouteResult) string {
	for _, check := range result.Checks {
		if check.HTTPCode > 0 {
			return fmt.Sprintf("HTTP %d", check.HTTPCode)
		}
	}
	return ""
}

func checkVerificationDuration(check planner.DomainCheck) int64 {
	if check.Cached {
		// A cache hit does not run a verification job. Reuse the stored full
		// decision duration, falling back to the selected candidate's legacy
		// evidence; never report cache lookup time as path verification.
		if check.VerificationDurationMS > 0 {
			return check.VerificationDurationMS
		}
		if check.Selected != nil {
			return check.Selected.VerificationDurationMS
		}
		return 0
	}
	if check.VerificationDurationMS > 0 {
		return check.VerificationDurationMS
	}
	// A missing planner measurement is not permission to substitute the
	// caller's wall-clock time. That would include queue/cache/orchestration
	// delay and mislabel it as path verification duration.
	return 0
}

type discoveryControlState struct {
	Configured           bool        `json:"configured,omitempty"`
	Mode                 string      `json:"mode,omitempty"`
	MaxNewRulesPerHour   int         `json:"max_new_rules_per_hour,omitempty"`
	MaxRollbacks         int         `json:"max_consecutive_rollbacks,omitempty"`
	AppliedAt            []time.Time `json:"applied_at"`
	ConsecutiveRollbacks int         `json:"consecutive_rollbacks"`
	PausedReason         string      `json:"paused_reason,omitempty"`
	LastResult           string      `json:"last_result,omitempty"`
	UpdatedAt            time.Time   `json:"updated_at"`
}

type discoverySuggestion struct {
	Domain                 string           `json:"domain"`
	Category               string           `json:"category"`
	Route                  string           `json:"route,omitempty"`
	RouteType              string           `json:"route_type,omitempty"`
	PathVerified           bool             `json:"path_verified"`
	Candidates             []map[string]any `json:"candidates,omitempty"`
	VerificationDurationMS int64            `json:"verification_duration_ms,omitempty"`
	// Confidence is retained as a compatibility alias for route-decision
	// confidence. New clients must use the explicit fields below.
	Confidence               float64   `json:"confidence"`
	DecisionConfidence       float64   `json:"decision_confidence"`
	ClassificationConfidence float64   `json:"classification_confidence"`
	ClassificationSource     string    `json:"classification_source,omitempty"`
	ClassificationEvidence   string    `json:"classification_evidence,omitempty"`
	Reason                   string    `json:"reason"`
	QueryType                string    `json:"query_type"`
	ObservedAt               time.Time `json:"observed_at"`
	ClassificationState      string    `json:"classification_state"`
	ProbeState               string    `json:"probe_state"`
	PolicyState              string    `json:"policy_state"`
	Client                   string    `json:"client,omitempty"`
	LastSeen                 time.Time `json:"last_seen"`
	Count                    uint64    `json:"count"`
}

type discoveryObservation struct {
	Domain     string    `json:"domain"`
	QueryType  string    `json:"query_type"`
	Client     string    `json:"client,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

func plannerProbeState(check planner.DomainCheck) string {
	if check.VerificationState != "" {
		switch check.VerificationState {
		case "in_progress":
			return "verifying"
		case "verified":
			if check.Selected != nil && check.Selected.PathVerified {
				return "verified_candidate"
			}
			return "verifying"
		case "terminal_no_safe_route":
			return "no_safe_route"
		}
	}
	switch check.Status {
	case "SELECTED", "DROP":
		if check.Selected != nil && check.Selected.PathVerified {
			return "verified_candidate"
		}
		return "verifying"
	case "NO_SAFE_ROUTE":
		// A bare status is not enough evidence for terminal exhaustion. The
		// planner must explicitly mark the candidate set terminal first.
		return "verifying"
	case "VERIFYING":
		return "verifying"
	default:
		if check.Selected != nil {
			return "verifying"
		}
		return "unknown"
	}
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

type discoverySuggestionActionRequest struct {
	Route string `json:"route,omitempty"`
}

// handleDiscoverySuggestionAction is the human-facing bounded action for a
// verified suggestion. It intentionally reuses the route-only assignment
// path and never invokes a full ChangeSet/dataplane rebuild.
func (s *Server) handleDiscoverySuggestionAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/discovery/suggestions/"), "/")
	if len(parts) != 2 || parts[0] == "" || (parts[1] != "apply" && parts[1] != "ignore") {
		writeError(w, r, http.StatusNotFound, "not_found", "suggestion action not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	domain, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(domain) == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_domain", "domain is invalid")
		return
	}
	release, failure := s.acquireMutationLease()
	if failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	defer release()
	s.mu.Lock()
	suggestion, ok := s.discoverySuggestionMap[domain]
	s.mu.Unlock()
	if !ok {
		writeError(w, r, http.StatusNotFound, "suggestion_not_found", "suggestion has expired or was removed")
		return
	}
	if parts[1] == "ignore" {
		s.mu.Lock()
		suggestion.PolicyState = "ignored"
		suggestion.Reason = "ignored by administrator"
		s.discoverySuggestionMap[domain] = suggestion
		s.mu.Unlock()
		s.persistDiscoverySuggestions()
		writeData(w, r, map[string]any{"applied": false, "ignored": true, "domain": domain})
		return
	}
	if !suggestion.PathVerified || suggestion.Route == "" {
		writeError(w, r, http.StatusConflict, "suggestion_not_verified", "only a PathVerified suggestion can be applied")
		return
	}
	var request discoverySuggestionActionRequest
	if r.Body != nil {
		if err := readJSON(r, &request); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
	}
	if request.Route != "" && request.Route != suggestion.Route {
		writeError(w, r, http.StatusConflict, "route_mismatch", "requested route differs from verified suggestion")
		return
	}
	check := planner.DomainCheck{
		Domain: suggestion.Domain, ETLDPlusOne: tspu.ETLDPlusOne(suggestion.Domain),
		Category: suggestion.Category, Confidence: suggestion.DecisionConfidence,
		ClassificationConfidence: suggestion.ClassificationConfidence,
		ClassificationSource:     suggestion.ClassificationSource, ClassificationEvidence: suggestion.ClassificationEvidence,
		Status: "SELECTED", VerificationState: "verified", Selected: &probe.RouteResult{
			Route: suggestion.Route, RouteType: suggestion.RouteType, PathVerified: true, Status: "OK", ServiceOK: true,
		},
	}
	result := s.commitAutomaticDomain(r.Context(), check)
	if !result.Applied {
		writeError(w, r, http.StatusConflict, "suggestion_apply_failed", result.Reason)
		return
	}
	s.recordDiscoveryAutoResult(result)
	writeData(w, r, map[string]any{
		"applied": true, "domain": domain, "route": suggestion.Route, "route_type": suggestion.RouteType,
		// Route-only assignment does not rerun the network probe.  The proof is
		// the PathVerified evidence already bound to the current active revision
		// plus the successful durable assignment write.
		"post_apply_proof": true, "post_apply_proof_kind": "revision_bound_path_evidence",
	})
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	cfg := s.currentConfig()
	mode, maxRules, maxRollbacks, state := s.effectiveDiscoverySettings(cfg)
	queueDepth, queueCapacity, activeProbes := 0, 0, 0
	if s.discoveryQueue != nil {
		queueDepth, queueCapacity = len(s.discoveryQueue), cap(s.discoveryQueue)
	}
	if s.probeBudget != nil {
		activeProbes = len(s.probeBudget)
	}
	writeData(w, r, map[string]any{
		"mode":                      mode,
		"max_new_rules_per_hour":    maxRules,
		"max_consecutive_rollbacks": maxRollbacks,
		"consecutive_rollbacks":     state.ConsecutiveRollbacks,
		"paused":                    state.PausedReason != "", "paused_reason": state.PausedReason,
		"applied_last_hour":  len(pruneDiscoveryTimes(state.AppliedAt, s.discoveryNow().Add(-time.Hour))),
		"suggestions":        s.discoverySuggestions(100),
		"observations":       s.discoveryObservationsSnapshot(100),
		"applied_count":      s.discoveryCounter("applied"),
		"failed_count":       s.discoveryCounter("failed"),
		"queue_depth":        queueDepth,
		"queue_capacity":     queueCapacity,
		"active_probe_jobs":  activeProbes,
		"observation_source": s.discoveryObservationStatus(),
	})
}

func (s *Server) discoveryObservationStatus() map[string]any {
	// Discovery observes dnsmasq query records; it is not a packet counter.
	// Report a disabled observer separately from a missing or stale log so the
	// UI cannot suggest that DNS interception is broken when the feature is
	// simply turned off.
	base := map[string]any{"source": "dnsmasq_query_log"}
	cfg := s.currentConfig()
	if cfg == nil || !cfg.Policy.UnknownDomainBackgroundCheck {
		base["status"] = "disabled"
		base["enabled"] = false
		base["reason"] = "dns_observation_disabled"
		return base
	}
	if strings.TrimSpace(s.dnsObservationPath) == "" {
		base["status"] = "unavailable"
		base["enabled"] = true
		base["reason"] = "dns_observation_path_not_configured"
		return base
	}
	info, err := os.Stat(s.dnsObservationPath)
	if err != nil {
		if os.IsNotExist(err) {
			base["status"] = "waiting"
			base["enabled"] = true
			base["reason"] = "dns_observation_log_not_created"
			return base
		}
		base["status"] = "unavailable"
		base["enabled"] = true
		base["reason"] = "dns_observation_log_unreadable"
		return base
	}
	status := "listening"
	if info.Size() > 0 {
		status = "stale"
		if time.Since(info.ModTime()) <= 5*time.Minute {
			status = "receiving"
		}
	}
	base["status"] = status
	base["enabled"] = true
	base["bytes"] = info.Size()
	base["last_updated"] = info.ModTime().UTC()
	s.mu.Lock()
	base["cursor"] = s.discoveryCursor
	base["lag_bytes"] = s.discoveryLagBytes
	base["emitted"] = s.discoveryEmitted
	base["dropped"] = s.discoveryDropped
	emitted := s.discoveryEmitted
	s.mu.Unlock()
	if status == "receiving" && emitted == 0 {
		base["status"] = "listening"
		base["status_reason"] = "file_changed_but_no_record_emitted"
	}
	return base
}

func (s *Server) handleDiscoveryConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	release, failure := s.acquireMutationLease()
	if failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	defer release()
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
	_, currentVersion := s.activeIdentity()
	if request.BaseVersion != currentVersion {
		writeError(w, r, http.StatusConflict, "base_version_conflict", "base_version does not match current revision")
		return
	}
	state := s.loadDiscoveryState()
	state.Configured = true
	state.Mode = request.Mode
	state.MaxNewRulesPerHour = request.MaxNewRulesPerHour
	state.MaxRollbacks = request.MaxConsecutiveRollbacks
	if request.ResetFailures {
		state.ConsecutiveRollbacks = 0
		state.PausedReason = ""
		state.LastResult = "manually_reset"
	}
	state.UpdatedAt = s.discoveryNow()
	if err := s.store.SaveJSON("discovery", discoveryStateKey, state); err != nil {
		writeError(w, r, http.StatusInternalServerError, "discovery_settings_failed", "discovery settings could not be saved")
		return
	}
	s.publishEvent(Event{Type: "discovery.settings.updated", Severity: "info", ReasonCode: "discovery_runtime_policy_updated", Details: map[string]any{"mode": request.Mode, "max_new_rules_per_hour": request.MaxNewRulesPerHour, "max_consecutive_rollbacks": request.MaxConsecutiveRollbacks}})
	writeData(w, r, map[string]any{
		"applied": true, "dataplane_changed": false, "config_version": currentVersion,
		"mode": request.Mode, "max_new_rules_per_hour": request.MaxNewRulesPerHour,
		"max_consecutive_rollbacks": request.MaxConsecutiveRollbacks,
		"paused":                    state.PausedReason != "", "paused_reason": state.PausedReason,
	})
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
	// Auto-apply is deliberately a narrow route-assignment operation. It may
	// persist a revision-bound domain decision for an already enabled route, but
	// it must never be allowed to fall through to the full ChangeSet/adapter
	// path. All dataplane topology and component changes stay explicit.
	if cfg == nil {
		return errors.New("active configuration is unavailable")
	}
	mode, maxRules, _, state := s.effectiveDiscoverySettings(cfg)
	if mode != "auto_apply_verified" {
		return errors.New("automatic_route_assignment_disabled")
	}
	if state.PausedReason != "" {
		return fmt.Errorf("automatic_route_assignment_paused:%s", state.PausedReason)
	}
	if len(pruneDiscoveryTimes(state.AppliedAt, s.discoveryNow().Add(-time.Hour))) >= maxRules {
		return errors.New("automatic_route_assignment_rate_limited")
	}
	if check.Selected == nil || !check.Selected.PathVerified || !check.Selected.ServiceOK || check.Confidence < 0.8 {
		return errors.New("automatic_route_assignment_requires_verified_evidence")
	}
	route, ok := cfg.RouteByTag(check.Selected.Route)
	if !ok || !route.Enabled() {
		return errors.New("automatic_route_not_active")
	}
	service, _, allowed := automaticServiceForDecision(check)
	if !allowed || !config.PathAllowed(service, route, cfg.Policy) {
		return errors.New("automatic_route_not_allowed")
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
		s.mu.Lock()
		s.discoveryApplied++
		s.mu.Unlock()
		state.AppliedAt = append(state.AppliedAt, now)
		state.ConsecutiveRollbacks = 0
		state.PausedReason = ""
	} else if result.RolledBack {
		s.mu.Lock()
		s.discoveryFailed++
		s.mu.Unlock()
		state.ConsecutiveRollbacks++
		_, _, limit, _ := s.effectiveDiscoverySettings(s.currentConfig())
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

func (s *Server) effectiveDiscoverySettings(cfg *config.Config) (string, int, int, discoveryControlState) {
	state := s.loadDiscoveryState()
	mode := "observe_only"
	maxRules := 4
	maxRollbacks := 3
	if cfg != nil {
		mode = cfg.Policy.EffectiveDiscoveryMode()
		maxRules = cfg.Policy.EffectiveDiscoveryMaxNewRulesPerHour()
		maxRollbacks = cfg.Policy.EffectiveDiscoveryMaxConsecutiveRollbacks()
	}
	if state.Configured {
		if state.Mode == "observe_only" || state.Mode == "suggest" || state.Mode == "auto_apply_verified" || state.Mode == "locked" {
			mode = state.Mode
		}
		if state.MaxNewRulesPerHour >= 1 && state.MaxNewRulesPerHour <= 1000 {
			maxRules = state.MaxNewRulesPerHour
		}
		if state.MaxRollbacks >= 1 && state.MaxRollbacks <= 100 {
			maxRollbacks = state.MaxRollbacks
		}
	}
	return mode, maxRules, maxRollbacks, state
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
	s.saveDiscoverySuggestionState(observation, check)
	s.persistDiscoverySuggestions()
}

// saveDiscoverySuggestionTransient keeps an in-progress verification visible
// to the current UI without treating it as a durable, verified suggestion.
// A restart must never resurrect a probe that was still running.
func (s *Server) saveDiscoverySuggestionTransient(observation discovery.Observation, check planner.DomainCheck) {
	s.saveDiscoverySuggestionState(observation, check)
}

func (s *Server) saveDiscoverySuggestionState(observation discovery.Observation, check planner.DomainCheck) {
	probeState := plannerProbeState(check)
	suggestion := discoverySuggestion{
		Domain: check.Domain, Category: check.Category, Confidence: check.Confidence,
		DecisionConfidence: check.Confidence, ClassificationConfidence: check.ClassificationConfidence,
		ClassificationSource: check.ClassificationSource, ClassificationEvidence: check.ClassificationEvidence,
		QueryType: observation.QueryType, ObservedAt: s.discoveryNow(), Reason: "verification is still in progress",
		ClassificationState: "unresolved", ProbeState: probeState, PolicyState: "suggested",
		Candidates: discoveryCandidateDetails(check.Results), VerificationDurationMS: check.VerificationDurationMS,
	}
	if probeState == "no_safe_route" {
		suggestion.Reason = "no verified route selected"
	}
	if check.ClassificationConfidence > 0 || (check.ClassificationEvidence != "" && check.ClassificationEvidence != "none" && check.ClassificationEvidence != "unavailable") || check.Category == "GEO_LOCKED" || check.Category == "TSPU_RESTRICTED" {
		suggestion.ClassificationState = "classified"
	}
	if check.Selected != nil {
		suggestion.Route = check.Selected.Route
		suggestion.RouteType = check.Selected.RouteType
		suggestion.PathVerified = check.Selected.PathVerified
		suggestion.ProbeState = "verified_candidate"
		suggestion.Reason = check.Selected.ReasonCode
		if suggestion.Reason == "" && check.Selected.Reason != nil {
			suggestion.Reason = *check.Selected.Reason
		}
		if suggestion.Reason == "" {
			suggestion.Reason = "route selected by verified planner evidence"
		}
	}
	suggestion.Client = strings.TrimSpace(observation.Client)
	suggestion.LastSeen = suggestion.ObservedAt
	s.mu.Lock()
	if previous, ok := s.discoverySuggestionMap[check.Domain]; ok {
		suggestion.Count = previous.Count + 1
		if suggestion.Count == 0 {
			suggestion.Count = 1
		}
	} else {
		suggestion.Count = 1
	}
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

func (s *Server) recordDiscoveryObservation(observation discovery.Observation) {
	now := s.discoveryNow()
	item := discoveryObservation{Domain: observation.Domain, QueryType: observation.QueryType, Client: observation.Client, ObservedAt: now}
	s.mu.Lock()
	s.discoveryObservations = append(s.discoveryObservations, item)
	cutoff := now.Add(-time.Hour)
	first := 0
	for first < len(s.discoveryObservations) && (len(s.discoveryObservations)-first > maxDiscoveryObservations || s.discoveryObservations[first].ObservedAt.Before(cutoff)) {
		first++
	}
	if first > 0 {
		s.discoveryObservations = append([]discoveryObservation(nil), s.discoveryObservations[first:]...)
	}
	s.mu.Unlock()
}

func (s *Server) discoveryObservationsSnapshot(limit int) []discoveryObservation {
	if limit <= 0 || limit > maxDiscoveryObservations {
		limit = maxDiscoveryObservations
	}
	s.mu.Lock()
	items := append([]discoveryObservation(nil), s.discoveryObservations...)
	s.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ObservedAt.After(items[j].ObservedAt) })
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func (s *Server) discoveryCounter(kind string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if kind == "applied" {
		return s.discoveryApplied
	}
	return s.discoveryFailed
}

func (s *Server) loadPersistedDiscoverySuggestions() {
	var items []discoverySuggestion
	if err := s.store.LoadJSON("discovery", discoverySuggestionKey, &items); err != nil {
		return
	}
	now := s.discoveryNow()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range items {
		if item.Domain == "" || (!item.LastSeen.IsZero() && now.Sub(item.LastSeen) > 7*24*time.Hour) {
			continue
		}
		if item.Count == 0 {
			item.Count = 1
		}
		s.discoverySuggestionMap[item.Domain] = item
	}
}

func (s *Server) persistDiscoverySuggestions() {
	items := s.discoverySuggestions(maxDiscoverySuggestions)
	_ = s.store.SaveJSON("discovery", discoverySuggestionKey, items)
}
