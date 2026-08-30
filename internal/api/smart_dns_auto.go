package api

import (
	"context"
	"time"
)

const smartDNSAutoApplyTimeout = 5 * time.Minute

// startAutoApplyChange continues the one-click Smart DNS operation in the
// backend. It is deliberately keyed by ChangeSet ID so retries from multiple
// UI tabs cannot start overlapping transactions. The ChangeSet journal remains
// authoritative; this goroutine is only an execution trigger.
func (s *Server) startAutoApplyChange(id string) bool {
	if s == nil || id == "" {
		return false
	}
	s.autoApplyMu.Lock()
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		s.autoApplyMu.Unlock()
		return false
	}
	if s.autoApplyInFlight == nil {
		s.autoApplyInFlight = make(map[string]bool)
	}
	if s.autoApplyInFlight[id] {
		s.mu.Unlock()
		s.autoApplyMu.Unlock()
		return false
	}
	s.autoApplyInFlight[id] = true
	s.mu.Unlock()
	s.autoApplyWG.Add(1)
	s.autoApplyMu.Unlock()

	go func() {
		defer s.autoApplyWG.Done()
		defer func() {
			s.autoApplyMu.Lock()
			delete(s.autoApplyInFlight, id)
			s.autoApplyMu.Unlock()
		}()
		s.runAutoApplyChange(id)
	}()
	return true
}

func (s *Server) runAutoApplyChange(id string) {
	// Do not inherit the request context: the user is allowed to navigate away
	// while the bounded transaction continues. The timeout prevents a stuck
	// adapter/provider from leaking a goroutine indefinitely.
	parent := s.autoApplyCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, smartDNSAutoApplyTimeout)
	defer cancel()

	release := s.acquireChangeActionLock(id)
	defer release()

	s.mu.Lock()
	change, ok := s.changes[id]
	s.mu.Unlock()
	if !ok || !change.AutoApply {
		return
	}
	if failure := s.mutationFailureNow(); failure != nil {
		s.publishEvent(Event{Type: "change.auto_apply", Severity: "warning", ReasonCode: "smart_dns_auto_apply_fenced", Details: map[string]any{
			"change_id": id, "code": failure.Code,
		}})
		return
	}

	if change.State == "draft" {
		var failure *actionFailure
		change, failure = s.validateChangeSet(change)
		if failure != nil {
			s.publishEvent(Event{Type: "change.auto_apply", Severity: "warning", ReasonCode: "smart_dns_auto_validate_failed", Details: map[string]any{
				"change_id": id, "code": failure.Code,
			}})
			return
		}
	}
	if change.State == "validated" {
		var failure *actionFailure
		change, failure = s.applyChangeSet(withAutomaticManagementProof(ctx), change)
		if failure != nil {
			s.publishEvent(Event{Type: "change.auto_apply", Severity: "warning", ReasonCode: "smart_dns_auto_apply_failed", Details: map[string]any{
				"change_id": id, "code": failure.Code,
			}})
			return
		}
	}
	if change.State != "awaiting_confirmation" {
		// requires_device, rolled_back and recovery_required are persisted by the
		// transaction engine. Do not invent a success state for them.
		return
	}

	if _, failure := s.confirmChangeSet(ctx, change); failure != nil {
		s.publishEvent(Event{Type: "change.auto_apply", Severity: "warning", ReasonCode: "smart_dns_auto_confirm_failed", Details: map[string]any{
			"change_id": id, "code": failure.Code,
		}})
		return
	}
	s.publishEvent(Event{Type: "change.auto_apply", Severity: "info", ReasonCode: "smart_dns_auto_apply_committed", Details: map[string]any{
		"change_id": id,
	}})
}

func (s *Server) resumeAutoApplyChanges() {
	if s == nil {
		return
	}
	s.mu.Lock()
	ids := make([]string, 0)
	for id, change := range s.changes {
		if change.AutoApply && (change.State == "draft" || change.State == "validated" || change.State == "awaiting_confirmation") {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.startAutoApplyChange(id)
	}
}
