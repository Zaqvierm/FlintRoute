package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"router-policy/internal/adapter"
	"router-policy/internal/config"
	"router-policy/internal/state"
	"router-policy/internal/zapret"
)

type adaptiveRuntime struct {
	profiles   *zapret.Catalog
	bundles    *zapret.BundleCatalog
	controller *zapret.SwitchController
	store      *state.Store
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
	return &adaptiveRuntime{profiles: profiles, bundles: bundles, controller: controller, store: store}, nil
}

func buildAdaptiveRuntime(cfg *config.Config, store *state.Store) (*adaptiveRuntime, error) {
	if cfg == nil || !cfg.Zapret.AdaptiveEnabled {
		return nil, nil
	}
	return newAdaptiveRuntime(cfg, store)
}

func bindAdaptiveCandidate(tx *adapter.Transaction, candidate *config.Config) error {
	if candidate == nil || !candidate.Zapret.AdaptiveEnabled {
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
	_, err := zapret.RenderBundleProfiles(bundles, profiles, assignments)
	return err
}

func (s *Server) handleAdaptiveZapretEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
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
	runtime, stateKey, failure := s.restoreAdaptiveState(request.Key, now)
	if failure != nil {
		return adaptiveEvaluateResponse{}, failure
	}
	active := s.currentConfig()
	decision, err := runtime.controller.Evaluate(request.Key, request.Ranking, now)
	if err != nil {
		return adaptiveEvaluateResponse{}, &actionFailure{Status: 422, Code: "adaptive_ranking_invalid", Message: err.Error()}
	}
	if decision.Action != zapret.SwitchProfile {
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
	change, err := s.createDraftChange("Switch Zapret service profile", decision.Reason, baseVersion, []ChangeOp{{Type: "update", Path: "/zapret/adaptive_assignments", Value: updated}}, "adaptive-controller")
	if err != nil {
		return adaptiveEvaluateResponse{}, internalFailure(err)
	}
	change, failure = s.validateChangeSet(change)
	if failure == nil {
		change, failure = s.applyChangeSet(ctx, change)
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
