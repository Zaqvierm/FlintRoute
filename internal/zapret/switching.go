package zapret

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	SwitchHold     = "HOLD"
	SwitchProfile  = "SWITCH"
	SwitchFallback = "FALLBACK"
	SwitchDrop     = "DROP"

	PinFailClosed   = "fail_closed"
	PinSafeFallback = "safe_fallback"
	PinHoldLast     = "hold_last"
)

type SwitchingPolicy struct {
	FailureThreshold        int
	FailedWindowThreshold   int
	ChallengerStableWindows int
	LatencyImprovement      float64
	Cooldown                time.Duration
	Quarantine              time.Duration
}

type ManualPin struct {
	ProfileID        string   `json:"profile_id"`
	Mode             string   `json:"mode"`
	AllowedFallbacks []string `json:"allowed_fallbacks,omitempty"`
}

type SwitchState struct {
	Key              DecisionKey          `json:"key"`
	ActiveProfileID  string               `json:"active_profile_id"`
	LastSwitchAt     time.Time            `json:"last_switch_at,omitempty"`
	CooldownUntil    time.Time            `json:"cooldown_until,omitempty"`
	Pin              *ManualPin           `json:"pin,omitempty"`
	QuarantinedUntil map[string]time.Time `json:"quarantined_until,omitempty"`
}

type SwitchDecision struct {
	Key         DecisionKey `json:"key"`
	Action      string      `json:"action"`
	FromProfile string      `json:"from_profile,omitempty"`
	ToProfile   string      `json:"to_profile,omitempty"`
	Reason      string      `json:"reason"`
	Emergency   bool        `json:"emergency"`
	EvaluatedAt time.Time   `json:"evaluated_at"`
}

type SwitchController struct {
	mu     sync.Mutex
	policy SwitchingPolicy
	states map[string]SwitchState
}

func DefaultSwitchingPolicy() SwitchingPolicy {
	return SwitchingPolicy{
		FailureThreshold: 3, FailedWindowThreshold: 2, ChallengerStableWindows: 3,
		LatencyImprovement: 0.20, Cooldown: 30 * time.Minute, Quarantine: 6 * time.Hour,
	}
}

func NewSwitchController(policy SwitchingPolicy) (*SwitchController, error) {
	if err := validateSwitchingPolicy(policy); err != nil {
		return nil, err
	}
	return &SwitchController{policy: policy, states: make(map[string]SwitchState)}, nil
}

func (c *SwitchController) SetActive(key DecisionKey, profileID string, now time.Time) error {
	if c == nil || profileID == "" || now.IsZero() {
		return errors.New("complete active profile state is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.stateLocked(key)
	state.ActiveProfileID = profileID
	state.LastSwitchAt = now.UTC()
	c.states[decisionKeyString(key)] = state
	return nil
}

func (c *SwitchController) SetPin(key DecisionKey, pin ManualPin) error {
	if c == nil {
		return errors.New("valid pinned profile is required")
	}
	if err := validateManualPin(pin); err != nil {
		return err
	}
	copyPin := pin
	copyPin.AllowedFallbacks = append([]string(nil), pin.AllowedFallbacks...)
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.stateLocked(key)
	state.Pin = &copyPin
	c.states[decisionKeyString(key)] = state
	return nil
}

func (c *SwitchController) ClearPin(key DecisionKey) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.stateLocked(key)
	state.Pin = nil
	c.states[decisionKeyString(key)] = state
}

func (c *SwitchController) Evaluate(key DecisionKey, ranking []CandidateScore, now time.Time) (SwitchDecision, error) {
	if c == nil || now.IsZero() {
		return SwitchDecision{}, errors.New("switch controller and evaluation time are required")
	}
	now = now.UTC()
	if err := validateRankingForKey(key, ranking); err != nil {
		return SwitchDecision{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.stateLocked(key)
	c.purgeQuarantineLocked(&state, now)
	decision := SwitchDecision{Key: key, Action: SwitchHold, FromProfile: state.ActiveProfileID, Reason: "current_profile_retained", EvaluatedAt: now}
	byID := make(map[string]CandidateScore, len(ranking))
	for _, score := range ranking {
		byID[score.ProfileID] = score
	}
	current, hasCurrent := byID[state.ActiveProfileID]

	if state.Pin != nil {
		decision = c.evaluatePinLocked(state, byID, ranking, now)
		c.states[decisionKeyString(key)] = state
		return decision, nil
	}

	if !hasCurrent || state.ActiveProfileID == "" {
		if candidate, ok := bestAvailable(ranking, state.QuarantinedUntil, "", now); ok {
			decision.Action, decision.ToProfile, decision.Reason = SwitchProfile, candidate.ProfileID, "no_active_profile"
		} else {
			decision.Action, decision.Reason = SwitchFallback, "no_eligible_profile"
		}
		c.states[decisionKeyString(key)] = state
		return decision, nil
	}

	emergency := current.RecentHardFailure || !current.SafetyGate
	degraded := emergency || current.FailureStreak >= c.policy.FailureThreshold || current.FailedWindows >= c.policy.FailedWindowThreshold
	if degraded {
		if candidate, ok := bestAvailable(ranking, state.QuarantinedUntil, state.ActiveProfileID, now); ok {
			decision.Action, decision.ToProfile, decision.Emergency = SwitchProfile, candidate.ProfileID, emergency
			if emergency {
				decision.Reason = "active_profile_hard_failure"
			} else {
				decision.Reason = "active_profile_degraded"
			}
		} else {
			decision.Action, decision.Emergency, decision.Reason = SwitchFallback, emergency, "active_profile_failed_without_safe_backup"
		}
		c.states[decisionKeyString(key)] = state
		return decision, nil
	}

	if now.Before(state.CooldownUntil) {
		decision.Reason = "cooldown_active"
		c.states[decisionKeyString(key)] = state
		return decision, nil
	}
	challenger, ok := bestAvailable(ranking, state.QuarantinedUntil, state.ActiveProfileID, now)
	if !ok || challenger.StableWindows < c.policy.ChallengerStableWindows {
		decision.Reason = "no_stable_challenger"
		c.states[decisionKeyString(key)] = state
		return decision, nil
	}
	reliabilityBetter := challenger.WilsonLowerBound > current.WilsonUpperBound
	reliabilityOverlap := challenger.WilsonLowerBound <= current.WilsonUpperBound && current.WilsonLowerBound <= challenger.WilsonUpperBound
	latencyBetter := current.MedianLatencyMS > 0 && challenger.MedianLatencyMS > 0 &&
		challenger.MedianLatencyMS <= current.MedianLatencyMS*(1-c.policy.LatencyImprovement)
	if reliabilityBetter || reliabilityOverlap && latencyBetter {
		decision.Action, decision.ToProfile = SwitchProfile, challenger.ProfileID
		if reliabilityBetter {
			decision.Reason = "challenger_more_reliable"
		} else {
			decision.Reason = "challenger_lower_latency"
		}
	} else {
		decision.Reason = "challenger_improvement_too_small"
	}
	c.states[decisionKeyString(key)] = state
	return decision, nil
}

func (c *SwitchController) RecordApplied(decision SwitchDecision, now time.Time) error {
	if c == nil || decision.Action != SwitchProfile || decision.ToProfile == "" || now.IsZero() {
		return errors.New("completed profile switch is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.stateLocked(decision.Key)
	if state.ActiveProfileID != decision.FromProfile {
		return errors.New("active profile changed while switch was running")
	}
	state.ActiveProfileID = decision.ToProfile
	state.LastSwitchAt = now.UTC()
	state.CooldownUntil = now.UTC().Add(c.policy.Cooldown)
	c.states[decisionKeyString(decision.Key)] = state
	return nil
}

func (c *SwitchController) RecordRollback(decision SwitchDecision, now time.Time) error {
	if c == nil || decision.ToProfile == "" || now.IsZero() {
		return errors.New("rolled back profile switch is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.stateLocked(decision.Key)
	state.QuarantinedUntil[decision.ToProfile] = now.UTC().Add(c.policy.Quarantine)
	c.states[decisionKeyString(decision.Key)] = state
	return nil
}

func (c *SwitchController) Snapshot(key DecisionKey, now time.Time) SwitchState {
	if c == nil {
		return SwitchState{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.stateLocked(key)
	c.purgeQuarantineLocked(&state, now.UTC())
	c.states[decisionKeyString(key)] = state
	return cloneSwitchState(state)
}

// Restore loads a previously persisted decision state. The caller remains
// responsible for binding it to the current network fingerprint.
func (c *SwitchController) Restore(state SwitchState) error {
	if c == nil || state.Key.BundleID == "" || state.ActiveProfileID == "" {
		return errors.New("complete persisted switch state is required")
	}
	if !profileIDPattern.MatchString(state.ActiveProfileID) {
		return errors.New("persisted active profile is invalid")
	}
	if state.Pin != nil {
		if err := validateManualPin(*state.Pin); err != nil {
			return err
		}
	}
	for profileID, until := range state.QuarantinedUntil {
		if !profileIDPattern.MatchString(profileID) || until.IsZero() {
			return errors.New("persisted quarantine state is invalid")
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.states[decisionKeyString(state.Key)] = cloneSwitchState(state)
	return nil
}

type SwitchApplier interface {
	Prepare(context.Context, SwitchDecision) error
	Validate(context.Context, SwitchDecision) error
	Snapshot(context.Context, SwitchDecision) error
	Apply(context.Context, SwitchDecision) error
	Verify(context.Context, SwitchDecision) error
	Commit(context.Context, SwitchDecision) error
	Rollback(context.Context, SwitchDecision) error
}

type SwitchResult struct {
	Decision      SwitchDecision `json:"decision"`
	Status        string         `json:"status"`
	FailedStep    string         `json:"failed_step,omitempty"`
	Reason        string         `json:"reason,omitempty"`
	RollbackTried bool           `json:"rollback_tried"`
	RollbackOK    bool           `json:"rollback_ok"`
}

type SwitchExecutor struct {
	mu         sync.Mutex
	controller *SwitchController
}

func NewSwitchExecutor(controller *SwitchController) (*SwitchExecutor, error) {
	if controller == nil {
		return nil, errors.New("switch controller is required")
	}
	return &SwitchExecutor{controller: controller}, nil
}

func (e *SwitchExecutor) Execute(ctx context.Context, decision SwitchDecision, applier SwitchApplier, now time.Time) SwitchResult {
	result := SwitchResult{Decision: decision, Status: "REJECTED"}
	if e == nil || applier == nil || decision.Action != SwitchProfile || decision.ToProfile == "" || now.IsZero() {
		result.Reason = "invalid_switch_request"
		return result
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.controller.Snapshot(decision.Key, now)
	if state.ActiveProfileID != decision.FromProfile {
		result.Reason = "stale_switch_decision"
		return result
	}
	steps := []struct {
		name string
		run  func(context.Context, SwitchDecision) error
	}{
		{"prepare", applier.Prepare}, {"validate", applier.Validate}, {"snapshot", applier.Snapshot},
		{"apply", applier.Apply}, {"verify", applier.Verify}, {"commit", applier.Commit},
	}
	snapshotComplete := false
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return e.failSwitch(ctx, result, decision, applier, step.name, err, snapshotComplete, now)
		}
		if err := step.run(ctx, decision); err != nil {
			return e.failSwitch(ctx, result, decision, applier, step.name, err, snapshotComplete, now)
		}
		if step.name == "snapshot" {
			snapshotComplete = true
		}
	}
	if err := e.controller.RecordApplied(decision, now); err != nil {
		return e.failSwitch(ctx, result, decision, applier, "record", err, true, now)
	}
	result.Status = "COMMITTED"
	return result
}

func (e *SwitchExecutor) failSwitch(ctx context.Context, result SwitchResult, decision SwitchDecision, applier SwitchApplier, step string, cause error, rollback bool, now time.Time) SwitchResult {
	result.Status = "FAILED"
	result.FailedStep = step
	result.Reason = cause.Error()
	if !rollback {
		return result
	}
	result.RollbackTried = true
	_ = e.controller.RecordRollback(decision, now)
	rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := applier.Rollback(rollbackContext, decision); err != nil {
		result.Status = "ROLLBACK_FAILED"
		result.Reason = fmt.Sprintf("%s; rollback: %v", cause, err)
		return result
	}
	result.RollbackOK = true
	return result
}

func (c *SwitchController) evaluatePinLocked(state SwitchState, byID map[string]CandidateScore, ranking []CandidateScore, now time.Time) SwitchDecision {
	pin := state.Pin
	decision := SwitchDecision{Key: state.Key, Action: SwitchHold, FromProfile: state.ActiveProfileID, Reason: "manual_pin_held", EvaluatedAt: now}
	pinned, exists := byID[pin.ProfileID]
	pinnedSafe := exists && pinned.SafetyGate && !pinned.RecentHardFailure
	if state.ActiveProfileID != pin.ProfileID && pinned.Eligible && !quarantined(state.QuarantinedUntil, pin.ProfileID, now) {
		decision.Action, decision.ToProfile, decision.Reason = SwitchProfile, pin.ProfileID, "manual_pin_requested"
		return decision
	}
	if state.ActiveProfileID == pin.ProfileID && pinnedSafe {
		return decision
	}
	switch pin.Mode {
	case PinHoldLast:
		if pinnedSafe {
			return decision
		}
		decision.Action, decision.Emergency, decision.Reason = SwitchDrop, true, "pinned_profile_unsafe"
	case PinSafeFallback:
		allowed := make(map[string]bool, len(pin.AllowedFallbacks))
		for _, profileID := range pin.AllowedFallbacks {
			allowed[profileID] = true
		}
		for _, score := range ranking {
			if allowed[score.ProfileID] && score.Eligible && !quarantined(state.QuarantinedUntil, score.ProfileID, now) {
				decision.Action, decision.ToProfile, decision.Emergency, decision.Reason = SwitchProfile, score.ProfileID, true, "pinned_safe_fallback"
				return decision
			}
		}
		decision.Action, decision.Emergency, decision.Reason = SwitchDrop, true, "pinned_fallback_unavailable"
	default:
		decision.Action, decision.Emergency, decision.Reason = SwitchDrop, true, "pinned_profile_failed_closed"
	}
	return decision
}

func (c *SwitchController) stateLocked(key DecisionKey) SwitchState {
	state, ok := c.states[decisionKeyString(key)]
	if !ok {
		state = SwitchState{Key: key, QuarantinedUntil: make(map[string]time.Time)}
	}
	if state.QuarantinedUntil == nil {
		state.QuarantinedUntil = make(map[string]time.Time)
	}
	return state
}

func (c *SwitchController) purgeQuarantineLocked(state *SwitchState, now time.Time) {
	for profileID, until := range state.QuarantinedUntil {
		if !now.Before(until) {
			delete(state.QuarantinedUntil, profileID)
		}
	}
}

func bestAvailable(ranking []CandidateScore, quarantine map[string]time.Time, exclude string, now time.Time) (CandidateScore, bool) {
	for _, score := range ranking {
		if score.ProfileID != exclude && score.Eligible && !quarantined(quarantine, score.ProfileID, now) {
			return score, true
		}
	}
	return CandidateScore{}, false
}

func quarantined(values map[string]time.Time, profileID string, now time.Time) bool {
	until, ok := values[profileID]
	return ok && now.Before(until)
}

func validateRankingForKey(key DecisionKey, ranking []CandidateScore) error {
	if len(ranking) == 0 || len(ranking) > MaxProfiles {
		return errors.New("bounded candidate ranking is required")
	}
	seen := make(map[string]bool, len(ranking))
	for _, score := range ranking {
		if decisionKeyString(score.Key) != decisionKeyString(key) || !profileIDPattern.MatchString(score.ProfileID) || seen[score.ProfileID] {
			return errors.New("candidate ranking does not match the decision key")
		}
		seen[score.ProfileID] = true
	}
	if !sort.SliceIsSorted(ranking, func(i, j int) bool { return BetterCandidate(ranking[i], ranking[j]) }) {
		return errors.New("candidate ranking is not sorted")
	}
	return nil
}

func validateSwitchingPolicy(policy SwitchingPolicy) error {
	if policy.FailureThreshold < 1 || policy.FailureThreshold > 10 ||
		policy.FailedWindowThreshold < 1 || policy.FailedWindowThreshold > 10 ||
		policy.ChallengerStableWindows < 1 || policy.ChallengerStableWindows > 10 {
		return errors.New("switching thresholds are outside the bounded range")
	}
	if policy.LatencyImprovement < 0.05 || policy.LatencyImprovement > 0.75 ||
		policy.Cooldown < time.Minute || policy.Cooldown > 24*time.Hour ||
		policy.Quarantine < time.Minute || policy.Quarantine > 7*24*time.Hour {
		return errors.New("switching timing policy is outside the bounded range")
	}
	return nil
}

func validateManualPin(pin ManualPin) error {
	if !profileIDPattern.MatchString(pin.ProfileID) {
		return errors.New("valid pinned profile is required")
	}
	if pin.Mode != PinFailClosed && pin.Mode != PinSafeFallback && pin.Mode != PinHoldLast {
		return errors.New("unsupported pin mode")
	}
	seen := make(map[string]bool, len(pin.AllowedFallbacks))
	for _, profileID := range pin.AllowedFallbacks {
		if !profileIDPattern.MatchString(profileID) || profileID == pin.ProfileID || seen[profileID] {
			return errors.New("invalid pinned fallback list")
		}
		seen[profileID] = true
	}
	if pin.Mode != PinSafeFallback && len(pin.AllowedFallbacks) > 0 {
		return errors.New("fallbacks are only valid for safe_fallback pins")
	}
	return nil
}

func cloneSwitchState(state SwitchState) SwitchState {
	clone := state
	if state.Pin != nil {
		pin := *state.Pin
		pin.AllowedFallbacks = append([]string(nil), state.Pin.AllowedFallbacks...)
		clone.Pin = &pin
	}
	clone.QuarantinedUntil = make(map[string]time.Time, len(state.QuarantinedUntil))
	for profileID, until := range state.QuarantinedUntil {
		clone.QuarantinedUntil[profileID] = until
	}
	return clone
}
