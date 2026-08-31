package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"sync"
	"time"

	"router-policy/internal/adapter"
	"router-policy/internal/config"
	"router-policy/internal/state"
	"router-policy/internal/zapret"
)

type adaptiveRuntime struct {
	profiles            *zapret.Catalog
	bundles             *zapret.BundleCatalog
	controller          *zapret.SwitchController
	ranker              *zapret.Ranker
	scheduler           *zapret.ProbeScheduler
	store               *state.Store
	catalogDigest       string
	probeMu             sync.Mutex
	lastProbeCheckpoint time.Time
}

type adaptiveEvaluateRequest struct {
	Key     zapret.DecisionKey      `json:"key"`
	Ranking []zapret.CandidateScore `json:"ranking"`
}

type adaptiveEvaluateResponse struct {
	Decision zapret.SwitchDecision `json:"decision"`
	Change   *ChangeSet            `json:"change,omitempty"`
}

type adaptiveStateRequest struct {
	Key zapret.DecisionKey `json:"key"`
}

type adaptivePinRequest struct {
	Key zapret.DecisionKey `json:"key"`
	Pin zapret.ManualPin   `json:"pin"`
}

func newAdaptiveRuntime(cfg *config.Config, store *state.Store) (*adaptiveRuntime, error) {
	if cfg == nil || store == nil || !cfg.Zapret.AdaptiveEnabled {
		return nil, errors.New("adaptive Zapret config and state store are required")
	}
	profiles, bundles, err := zapret.LoadCatalogFile(cfg.Zapret.AdaptiveCatalogFile)
	if err != nil {
		return nil, err
	}
	if err := validateAdaptiveAssignments(cfg, profiles, bundles); err != nil {
		return nil, err
	}
	controller, err := zapret.NewSwitchController(zapret.DefaultSwitchingPolicy())
	if err != nil {
		return nil, err
	}
	ranker, err := zapret.NewRanker(bundles, profiles, zapret.DefaultRankingPolicy())
	if err != nil {
		return nil, err
	}
	scheduler, err := zapret.NewProbeScheduler(zapret.DefaultProbeSchedulePolicy())
	if err != nil {
		return nil, err
	}
	catalogDigest, err := adaptiveCatalogDigest(cfg, profiles, bundles)
	if err != nil {
		return nil, err
	}
	runtime := &adaptiveRuntime{profiles: profiles, bundles: bundles, controller: controller, ranker: ranker, scheduler: scheduler, store: store, catalogDigest: catalogDigest}
	if err := restoreAdaptiveProbeRuntime(runtime, time.Now().UTC()); err != nil {
		return nil, err
	}
	return runtime, nil
}

func buildAdaptiveRuntime(cfg *config.Config, store *state.Store) (*adaptiveRuntime, error) {
	if cfg == nil || !cfg.Zapret.AdaptiveEnabled {
		return nil, nil
	}
	return newAdaptiveRuntime(cfg, store)
}

func adaptiveBindingRequired(active, candidate *config.Config) bool {
	if candidate == nil || !candidate.Zapret.AdaptiveEnabled {
		return false
	}
	if active == nil || !active.Zapret.AdaptiveEnabled {
		return true
	}
	return candidate.Zapret.AdaptiveCatalogFile != active.Zapret.AdaptiveCatalogFile ||
		!reflect.DeepEqual(candidate.Zapret.AdaptiveAssignments, active.Zapret.AdaptiveAssignments) ||
		!reflect.DeepEqual(candidate.Zapret.DeviceProfiles, active.Zapret.DeviceProfiles)
}

func bindAdaptiveCandidate(tx *adapter.Transaction, active, candidate *config.Config) error {
	if candidate == nil || !candidate.Zapret.AdaptiveEnabled {
		return nil
	}
	// Ordinary service/route edits inherit the already-bound adaptive artifact.
	// Rebinding it here would incorrectly require a new deployment-ready
	// transaction even though no Zapret profile changed.
	if !adaptiveBindingRequired(active, candidate) {
		return nil
	}
	profiles, bundles, err := zapret.LoadCatalogFile(candidate.Zapret.AdaptiveCatalogFile)
	if err != nil {
		return fmt.Errorf("load adaptive catalog: %w", err)
	}
	if err := validateAdaptiveAssignments(candidate, profiles, bundles); err != nil {
		return err
	}
	assignments := make([]zapret.BundleProfileAssignment, 0, len(candidate.Zapret.AdaptiveAssignments))
	for _, assignment := range candidate.Zapret.AdaptiveAssignments {
		assignments = append(assignments, zapret.BundleProfileAssignment{BundleID: assignment.BundleID, ProfileID: assignment.ProfileID})
	}
	return zapret.BindBundleProfiles(tx, bundles, profiles, assignments)
}

func validateAdaptiveAssignments(cfg *config.Config, profiles *zapret.Catalog, bundles *zapret.BundleCatalog) error {
	assignments := make([]zapret.BundleProfileAssignment, 0, len(cfg.Zapret.AdaptiveAssignments))
	for _, assignment := range cfg.Zapret.AdaptiveAssignments {
		assignments = append(assignments, zapret.BundleProfileAssignment{BundleID: assignment.BundleID, ProfileID: assignment.ProfileID})
	}
	if _, err := zapret.RenderBundleProfiles(bundles, profiles, assignments); err != nil {
		return err
	}
	runtime := &adaptiveRuntime{bundles: bundles}
	for _, assignment := range cfg.Zapret.AdaptiveAssignments {
		bundle, ok := bundles.Lookup(assignment.BundleID)
		if !ok {
			return fmt.Errorf("adaptive bundle %s is unavailable", assignment.BundleID)
		}
		if !adaptiveRouteAllowed(cfg, runtime, bundle.ID, bundle.FailureRoute) {
			return fmt.Errorf("adaptive bundle %s has unavailable failure route %s", bundle.ID, bundle.FailureRoute)
		}
		if bundle.DirectFallback {
			directAllowed := false
			for _, route := range cfg.RoutesByType("direct") {
				if adaptiveRouteAllowed(cfg, runtime, bundle.ID, route.Tag) {
					directAllowed = true
					break
				}
			}
			if !directAllowed {
				return fmt.Errorf("adaptive bundle %s enables direct fallback without an allowed direct route", bundle.ID)
			}
		}
	}
	return nil
}

func (s *Server) handleAdaptiveZapretEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	if failure := s.mutationFailureNow(); failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	if s.currentAdaptiveRuntime() == nil {
		writeError(w, r, http.StatusConflict, "adaptive_zapret_disabled", "adaptive Zapret is not configured")
		return
	}
	var request adaptiveEvaluateRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	response, failure := s.evaluateAdaptiveZapret(r.Context(), request, time.Now().UTC())
	if failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	writeData(w, r, response)
}

func (s *Server) handleAdaptiveZapretState(w http.ResponseWriter, r *http.Request) {
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
	var request adaptiveStateRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	runtime, stateKey, failure := s.restoreAdaptiveState(request.Key, time.Now().UTC())
	if failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	state := runtime.controller.Snapshot(request.Key, time.Now().UTC())
	if err := runtime.store.SaveJSON("zapret_switch", stateKey, state); err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	writeData(w, r, state)
}

func (s *Server) handleAdaptiveZapretPin(w http.ResponseWriter, r *http.Request) {
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
	var request adaptivePinRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	runtime, stateKey, failure := s.restoreAdaptiveState(request.Key, time.Now().UTC())
	if failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	if err := validateAdaptivePin(runtime, request.Key, request.Pin); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "adaptive_pin_invalid", err.Error())
		return
	}
	if err := runtime.controller.SetPin(request.Key, request.Pin); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "adaptive_pin_invalid", err.Error())
		return
	}
	now := time.Now().UTC()
	state := runtime.controller.Snapshot(request.Key, now)
	if err := runtime.store.SaveJSON("zapret_switch", stateKey, state); err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	s.publishEvent(Event{Type: "zapret.adaptive_pin", Severity: "info", ReasonCode: "manual_pin_set", Details: map[string]any{"bundle_id": request.Key.BundleID, "profile_id": request.Pin.ProfileID, "mode": request.Pin.Mode}})
	writeData(w, r, state)
}

func validateAdaptivePin(runtime *adaptiveRuntime, key zapret.DecisionKey, pin zapret.ManualPin) error {
	if runtime == nil || runtime.bundles == nil {
		return errors.New("adaptive Zapret is not configured")
	}
	bundle, ok := runtime.bundles.Lookup(key.BundleID)
	if !ok {
		return errors.New("service bundle is absent from the adaptive catalog")
	}
	allowed := make(map[string]bool, len(bundle.AllowedProfiles))
	for _, profileID := range bundle.AllowedProfiles {
		allowed[profileID] = true
	}
	if !allowed[pin.ProfileID] {
		return errors.New("pinned profile is not allowed for the service bundle")
	}
	for _, profileID := range pin.AllowedFallbacks {
		if !allowed[profileID] {
			return errors.New("pinned fallback is not allowed for the service bundle")
		}
	}
	return nil
}

func (s *Server) handleAdaptiveZapretUnpin(w http.ResponseWriter, r *http.Request) {
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
	var request adaptiveStateRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	runtime, stateKey, failure := s.restoreAdaptiveState(request.Key, time.Now().UTC())
	if failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	runtime.controller.ClearPin(request.Key)
	now := time.Now().UTC()
	state := runtime.controller.Snapshot(request.Key, now)
	if err := runtime.store.SaveJSON("zapret_switch", stateKey, state); err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	s.publishEvent(Event{Type: "zapret.adaptive_pin", Severity: "info", ReasonCode: "manual_pin_cleared", Details: map[string]any{"bundle_id": request.Key.BundleID}})
	writeData(w, r, state)
}

func (s *Server) currentAdaptiveRuntime() *adaptiveRuntime {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.adaptiveZapret
}

func (s *Server) restoreAdaptiveState(key zapret.DecisionKey, now time.Time) (*adaptiveRuntime, string, *actionFailure) {
	runtime := s.currentAdaptiveRuntime()
	if runtime == nil {
		return nil, "", conflict("adaptive_zapret_disabled", "adaptive Zapret is not configured")
	}
	active := s.currentConfig()
	if active == nil {
		return nil, "", &actionFailure{Status: 503, Code: "active_config_unavailable", Message: "adaptive state cannot be restored without an active config"}
	}
	currentProfile := profileForBundle(active.Zapret.AdaptiveAssignments, key.BundleID)
	if currentProfile == "" {
		return nil, "", conflict("adaptive_assignment_missing", "service bundle has no active profile")
	}
	stateKey, err := adaptiveStateKey(key)
	if err != nil {
		return nil, "", &actionFailure{Status: 400, Code: "adaptive_key_invalid", Message: err.Error()}
	}
	var persisted zapret.SwitchState
	if err := runtime.store.LoadJSON("zapret_switch", stateKey, &persisted); err == nil {
		if persisted.ActiveProfileID != currentProfile {
			return nil, "", conflict("adaptive_state_conflict", "persisted profile does not match the active config")
		}
		if err := runtime.controller.Restore(persisted); err != nil {
			return nil, "", internalFailure(err)
		}
	} else if errors.Is(err, state.ErrNotFound) {
		if err := runtime.controller.SetActive(key, currentProfile, now); err != nil {
			return nil, "", &actionFailure{Status: 400, Code: "adaptive_key_invalid", Message: err.Error()}
		}
	} else {
		return nil, "", internalFailure(err)
	}
	return runtime, stateKey, nil
}

func (s *Server) evaluateAdaptiveZapret(ctx context.Context, request adaptiveEvaluateRequest, now time.Time) (adaptiveEvaluateResponse, *actionFailure) {
	if failure := s.mutationFailureNow(); failure != nil {
		return adaptiveEvaluateResponse{}, failure
	}
	runtime, stateKey, failure := s.restoreAdaptiveState(request.Key, now)
	if failure != nil {
		return adaptiveEvaluateResponse{}, failure
	}
	active := s.currentConfig()
	decision, err := runtime.controller.Evaluate(request.Key, request.Ranking, now)
	if err != nil {
		return adaptiveEvaluateResponse{}, &actionFailure{Status: 422, Code: "adaptive_ranking_invalid", Message: err.Error()}
	}
	if decision.Action == zapret.SwitchFallback {
		change, fallbackFailure := s.applyAdaptiveFallback(ctx, active, runtime, request.Key.BundleID, decision)
		if err := persistAdaptiveState(runtime, stateKey, request.Key, now); err != nil {
			return adaptiveEvaluateResponse{}, internalFailure(err)
		}
		if fallbackFailure != nil {
			return adaptiveEvaluateResponse{}, fallbackFailure
		}
		return adaptiveEvaluateResponse{Decision: decision, Change: change}, nil
	}
	if decision.Action != zapret.SwitchProfile {
		if activeAdaptiveFallback(active, runtime, request.Key.BundleID) && profileProductionReady(request.Ranking, decision.FromProfile) {
			change, recoveryFailure := s.commitAdaptiveRouteSelection(ctx, active, runtime, request.Key.BundleID, "", "Restore Zapret service route", "adaptive_profile_recovered")
			if recoveryFailure != nil {
				return adaptiveEvaluateResponse{}, recoveryFailure
			}
			if err := persistAdaptiveState(runtime, stateKey, request.Key, now); err != nil {
				return adaptiveEvaluateResponse{}, internalFailure(err)
			}
			s.publishEvent(Event{Type: "zapret.adaptive_recovery", Severity: "info", ReasonCode: "adaptive_profile_recovered", Details: map[string]any{"bundle_id": request.Key.BundleID, "profile_id": decision.FromProfile, "revision_id": change.RevisionID}})
			return adaptiveEvaluateResponse{Decision: decision, Change: change}, nil
		}
		if err := persistAdaptiveState(runtime, stateKey, request.Key, now); err != nil {
			return adaptiveEvaluateResponse{}, internalFailure(err)
		}
		return adaptiveEvaluateResponse{Decision: decision}, nil
	}
	updated, err := replaceBundleProfile(active.Zapret.AdaptiveAssignments, request.Key.BundleID, decision.ToProfile)
	if err != nil {
		return adaptiveEvaluateResponse{}, conflict("adaptive_assignment_invalid", err.Error())
	}
	s.mu.Lock()
	baseVersion := s.configVersion
	s.mu.Unlock()
	operations := []ChangeOp{{Type: "update", Path: "/zapret/adaptive_assignments", Value: updated}}
	operations = append(operations, adaptiveRouteSelectionOps(active, runtime, request.Key.BundleID, "")...)
	change, err := s.createDraftChange("Switch Zapret service profile", decision.Reason, baseVersion, operations, "adaptive-controller")
	if err != nil {
		return adaptiveEvaluateResponse{}, internalFailure(err)
	}
	change, failure = s.validateChangeSet(change)
	if failure == nil {
		change, failure = s.applyChangeSet(withAutomaticManagementProof(ctx), change)
	}
	if failure == nil && change.State != "awaiting_confirmation" {
		failure = conflict("adaptive_apply_unverified", "adaptive candidate did not reach confirmation")
	}
	if failure == nil {
		change, failure = s.confirmChangeSet(ctx, change)
	}
	if failure != nil {
		_ = runtime.controller.RecordRollback(decision, now)
		if change.TransactionID != "" && change.State != "rolled_back" && change.State != "expired" {
			_, _ = s.rollbackChangeSet(context.WithoutCancel(ctx), change, false)
		}
		_ = persistAdaptiveState(runtime, stateKey, request.Key, now)
		return adaptiveEvaluateResponse{}, failure
	}
	if err := runtime.controller.RecordApplied(decision, now); err != nil {
		return adaptiveEvaluateResponse{}, internalFailure(err)
	}
	if err := persistAdaptiveState(runtime, stateKey, request.Key, now); err != nil {
		return adaptiveEvaluateResponse{}, internalFailure(err)
	}
	s.publishEvent(Event{Type: "zapret.adaptive_switch", Severity: "info", ReasonCode: decision.Reason, Details: map[string]any{"bundle_id": request.Key.BundleID, "from_profile": decision.FromProfile, "to_profile": decision.ToProfile, "revision_id": change.RevisionID}})
	return adaptiveEvaluateResponse{Decision: decision, Change: &change}, nil
}

func (s *Server) applyAdaptiveFallback(ctx context.Context, active *config.Config, runtime *adaptiveRuntime, bundleID string, decision zapret.SwitchDecision) (*ChangeSet, *actionFailure) {
	bundle, ok := runtime.bundles.Lookup(bundleID)
	if !ok {
		return nil, conflict("adaptive_bundle_missing", "service bundle is absent from the adaptive catalog")
	}
	if activeAdaptiveFallback(active, runtime, bundleID) {
		return nil, nil
	}
	tags := []string{bundle.FailureRoute}
	if bundle.DirectFallback {
		for _, route := range active.RoutesByType("direct") {
			if route.Enabled() {
				tags = append(tags, route.Tag)
				break
			}
		}
	}
	var lastFailure *actionFailure
	for _, tag := range tags {
		if !adaptiveRouteAllowed(active, runtime, bundleID, tag) {
			continue
		}
		change, failure := s.commitAdaptiveRouteSelection(ctx, active, runtime, bundleID, tag, "Use fallback route for Zapret service", decision.Reason)
		if failure == nil {
			s.publishEvent(Event{Type: "zapret.adaptive_fallback", Severity: "warning", ReasonCode: decision.Reason, Details: map[string]any{"bundle_id": bundleID, "route_tag": tag, "revision_id": change.RevisionID}})
			return change, nil
		}
		lastFailure = failure
		active = s.currentConfig()
	}
	if lastFailure != nil {
		return nil, lastFailure
	}
	return nil, conflict("adaptive_fallback_unavailable", "no allowed fallback route is available for the service bundle")
}

func (s *Server) commitAdaptiveRouteSelection(ctx context.Context, active *config.Config, runtime *adaptiveRuntime, bundleID, routeTag, title, reason string) (*ChangeSet, *actionFailure) {
	operations := adaptiveRouteSelectionOps(active, runtime, bundleID, routeTag)
	if len(operations) == 0 {
		return nil, nil
	}
	s.mu.Lock()
	baseVersion := s.configVersion
	s.mu.Unlock()
	change, err := s.createDraftChange(title, reason, baseVersion, operations, "adaptive-controller")
	if err != nil {
		return nil, internalFailure(err)
	}
	change, failure := s.validateChangeSet(change)
	if failure == nil {
		change, failure = s.applyChangeSet(withAutomaticManagementProof(ctx), change)
	}
	if failure == nil && change.State != "awaiting_confirmation" {
		failure = conflict("adaptive_apply_unverified", "adaptive route candidate did not reach confirmation")
	}
	if failure == nil {
		change, failure = s.confirmChangeSet(ctx, change)
	}
	if failure != nil {
		if change.TransactionID != "" && change.State != "rolled_back" && change.State != "expired" {
			_, _ = s.rollbackChangeSet(context.WithoutCancel(ctx), change, false)
		}
		return nil, failure
	}
	return &change, nil
}

func adaptiveRouteSelectionOps(cfg *config.Config, runtime *adaptiveRuntime, bundleID, routeTag string) []ChangeOp {
	var operations []ChangeOp
	for _, name := range adaptiveBundleServiceNames(cfg, runtime, bundleID) {
		service := cfg.Services[name]
		if service.SelectedRouteTag == routeTag {
			continue
		}
		operations = append(operations, ChangeOp{Type: "set", Path: "/services/" + escapeJSONPointer(name) + "/selected_route_tag", Value: routeTag})
	}
	return operations
}

func adaptiveBundleServiceNames(cfg *config.Config, runtime *adaptiveRuntime, bundleID string) []string {
	var names []string
	for name, service := range cfg.Services {
		for _, domain := range service.Domains {
			bundle, ok := runtime.bundles.LookupDomain(domain)
			if ok && bundle.ID == bundleID {
				names = append(names, name)
				break
			}
		}
	}
	sort.Strings(names)
	return names
}

func adaptiveRouteAllowed(cfg *config.Config, runtime *adaptiveRuntime, bundleID, routeTag string) bool {
	route, ok := cfg.RouteByTag(routeTag)
	if !ok || !route.Enabled() {
		return false
	}
	names := adaptiveBundleServiceNames(cfg, runtime, bundleID)
	if len(names) == 0 {
		return false
	}
	for _, name := range names {
		if !config.PathAllowed(cfg.Services[name], route, cfg.Policy) {
			return false
		}
	}
	return true
}

func activeAdaptiveFallback(cfg *config.Config, runtime *adaptiveRuntime, bundleID string) bool {
	for _, name := range adaptiveBundleServiceNames(cfg, runtime, bundleID) {
		if cfg.Services[name].SelectedRouteTag != "" {
			return true
		}
	}
	return false
}

func profileProductionReady(ranking []zapret.CandidateScore, profileID string) bool {
	for _, score := range ranking {
		if score.ProfileID == profileID {
			return score.ProductionReady && score.SafetyGate && score.RequiredChecksPassed && !score.RecentHardFailure
		}
	}
	return false
}

func persistAdaptiveState(runtime *adaptiveRuntime, key string, decisionKey zapret.DecisionKey, now time.Time) error {
	return runtime.store.SaveJSON("zapret_switch", key, runtime.controller.Snapshot(decisionKey, now))
}

func adaptiveStateKey(key zapret.DecisionKey) (string, error) {
	raw, err := json.Marshal(key)
	if err != nil {
		return "", err
	}
	return zapret.Digest(raw), nil
}

func profileForBundle(assignments []config.ZapretProfileAssignment, bundleID string) string {
	for _, assignment := range assignments {
		if assignment.BundleID == bundleID {
			return assignment.ProfileID
		}
	}
	return ""
}

func replaceBundleProfile(assignments []config.ZapretProfileAssignment, bundleID, profileID string) ([]config.ZapretProfileAssignment, error) {
	updated := append([]config.ZapretProfileAssignment(nil), assignments...)
	found := false
	for index := range updated {
		if updated[index].BundleID == bundleID {
			updated[index].ProfileID = profileID
			found = true
		}
	}
	if !found {
		return nil, errors.New("bundle assignment not found")
	}
	sort.Slice(updated, func(i, j int) bool { return updated[i].BundleID < updated[j].BundleID })
	return updated, nil
}
