package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"router-policy/internal/adapter"
)

type recoveryStatus struct {
	Status               string    `json:"status"`
	ReasonCode           string    `json:"reason_code,omitempty"`
	Reason               string    `json:"reason,omitempty"`
	TransactionID        string    `json:"transaction_id,omitempty"`
	RevisionID           string    `json:"revision_id,omitempty"`
	CandidateHash        string    `json:"candidate_hash,omitempty"`
	ArtifactManifestHash string    `json:"artifact_manifest_hash,omitempty"`
	CommitPhase          string    `json:"commit_phase,omitempty"`
	StartedAt            time.Time `json:"started_at"`
	FinishedAt           time.Time `json:"finished_at"`
}

type mutationBlockedError struct{ failure *actionFailure }

func (e *mutationBlockedError) Error() string {
	if e == nil || e.failure == nil {
		return "mutation blocked by recovery fence"
	}
	return e.failure.Message
}

func mutationFailureFromError(err error) *actionFailure {
	blocked, ok := err.(*mutationBlockedError)
	if !ok || blocked == nil {
		return nil
	}
	return blocked.failure
}

func (s *Server) recoverCommittedDataplane(ctx context.Context) {
	started := time.Now().UTC()
	result := recoveryStatus{Status: "not_required", StartedAt: started, FinishedAt: started}

	s.mu.Lock()
	activeRevision := s.activeRevision
	configVersion := s.configVersion
	s.mu.Unlock()
	if activeRevision == "" {
		if configVersion > 1 {
			result = failedRecovery(started, "active_revision_missing", "committed config version has no active revision", adapter.RecoveryTarget{})
		}
		s.setRecoveryStatus(result)
		return
	}

	var revision revisionRecord
	if err := s.store.LoadJSON("revisions", activeRevision, &revision); err != nil {
		result = failedRecovery(started, "active_revision_load_failed", err.Error(), adapter.RecoveryTarget{RevisionID: activeRevision})
		s.setRecoveryStatus(result)
		return
	}
	if revision.Kind == baselineRevisionKind {
		if err := validateBaselineRevision(revision, activeRevision, s.currentConfig()); err != nil {
			result = failedRecovery(started, "active_baseline_invalid", err.Error(), adapter.RecoveryTarget{RevisionID: activeRevision, CandidateHash: revision.CandidateHash})
		} else {
			// A boot guard may have been armed before the controller created or
			// re-opened the baseline. Clear it through a dedicated baseline-bound
			// adapter operation; the generic unbound clear is never sufficient.
			if clearer, ok := s.adapter.(adapter.BaselineBootGuardClearer); ok {
				clearResult := clearer.ClearBootGuardForBaseline(ctx, activeRevision, revision.CandidateHash)
				if !stepOK(clearResult) {
					reason := clearResult.Reason
					if reason == "" {
						reason = "baseline boot guard removal was not proven"
					}
					result = failedRecovery(started, "baseline_boot_guard_clear_failed", reason, adapter.RecoveryTarget{RevisionID: activeRevision, CandidateHash: revision.CandidateHash})
					s.setRecoveryStatus(result)
					return
				}
			}
			result = recoveryStatus{
				Status: "not_required", RevisionID: activeRevision, CandidateHash: revision.CandidateHash,
				CommitPhase: "baseline_confirmed", StartedAt: started, FinishedAt: time.Now().UTC(),
			}
		}
		s.setRecoveryStatus(result)
		return
	}
	target := adapter.RecoveryTarget{
		TransactionID: revision.TransactionID, RevisionID: revision.RevisionID,
		CandidateHash: revision.CandidateHash, ArtifactManifestHash: revision.ArtifactManifestHash,
	}
	if revision.State == "control_plane_committed" {
		result = recoveryRequired(started, "active_revision_pending_finalize", "active revision is durable but adapter finalization is not proven", target, "control_plane_committed")
		s.setRecoveryStatus(result)
		return
	}
	if revision.State != "committed" || revision.RevisionID != activeRevision || revision.TransactionID == "" || revision.CandidateHash == "" || revision.ArtifactManifestHash == "" {
		result = failedRecovery(started, "active_revision_invalid", "active revision record is incomplete or not committed", target)
		s.setRecoveryStatus(result)
		return
	}

	var txRecord transactionRecord
	if err := s.store.LoadJSON("transactions", revision.TransactionID, &txRecord); err != nil {
		result = failedRecovery(started, "active_transaction_load_failed", err.Error(), target)
		s.setRecoveryStatus(result)
		return
	}
	tx := txRecord.Transaction
	if txRecord.State != "committed" || tx.ID != target.TransactionID || tx.RevisionID != target.RevisionID || !constantEqual(tx.CandidateHash, target.CandidateHash) || !constantEqual(tx.ArtifactManifestHash, target.ArtifactManifestHash) {
		result = failedRecovery(started, "active_transaction_mismatch", "active revision and transaction bindings differ", target)
		s.setRecoveryStatus(result)
		return
	}

	s.mu.Lock()
	cs, ok := s.changes[revision.ChangeID]
	s.mu.Unlock()
	if !ok || cs.State != "committed" || cs.TransactionID != target.TransactionID || cs.RevisionID != target.RevisionID {
		result = failedRecovery(started, "active_changeset_mismatch", "committed ChangeSet is missing or does not match the active revision", target)
		s.setRecoveryStatus(result)
		return
	}
	candidate, failure := s.loadVerifiedCandidate(cs, tx)
	if failure != nil {
		result = failedRecovery(started, "active_candidate_verification_failed", failure.Message, target)
		s.setRecoveryStatus(result)
		return
	}
	activeCanonical, _ := json.Marshal(s.currentConfig())
	candidateCanonical, _ := json.Marshal(candidate)
	if !constantEqual(hashBytes(activeCanonical), target.CandidateHash) || !constantEqual(hashBytes(candidateCanonical), target.CandidateHash) {
		result = failedRecovery(started, "active_config_mismatch", "persisted active config differs from committed candidate", target)
		s.setRecoveryStatus(result)
		return
	}

	reconcile := s.reconcileCommittedTarget(ctx, target)
	if !stepOK(reconcile) {
		reason := reconcile.Reason
		if reason == "" {
			reason = "adapter reconcile failed"
		}
		result = failedRecovery(started, "adapter_reconcile_failed", reason, target)
		s.setRecoveryStatus(result)
		return
	}
	status := s.adapter.Status(ctx)
	if !stepOK(status) || evidenceString(status, "active_revision") != target.RevisionID || evidenceString(status, "active_transaction") != target.TransactionID || evidenceString(status, "active_candidate_hash") != target.CandidateHash || evidenceString(status, "active_artifact_manifest_hash") != target.ArtifactManifestHash || evidenceString(status, "transaction_state") != "committed" {
		result = failedRecovery(started, "adapter_recovery_binding_mismatch", "adapter status does not match committed recovery target", target)
		s.setRecoveryStatus(result)
		return
	}

	result = recoveryStatus{
		Status: "ok", TransactionID: target.TransactionID, RevisionID: target.RevisionID,
		CandidateHash: target.CandidateHash, ArtifactManifestHash: target.ArtifactManifestHash,
		StartedAt: started, FinishedAt: time.Now().UTC(),
	}
	s.setRecoveryStatus(result)
}

func (s *Server) reconcileCommittedTarget(ctx context.Context, target adapter.RecoveryTarget) adapter.StepResult {
	const maxAttempts = 31
	for attempt := 1; ; attempt++ {
		result := s.adapter.Reconcile(ctx, target)
		busy, _ := result.Evidence["adapter_busy"].(bool)
		if stepOK(result) || !busy || attempt >= maxAttempts {
			return result
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return result
		case <-timer.C:
		}
	}
}

func failedRecovery(started time.Time, code, reason string, target adapter.RecoveryTarget) recoveryStatus {
	if reason == "" {
		reason = fmt.Sprintf("recovery failed: %s", code)
	}
	return recoveryStatus{
		Status: "error", ReasonCode: code, Reason: reason,
		TransactionID: target.TransactionID, RevisionID: target.RevisionID,
		CandidateHash: target.CandidateHash, ArtifactManifestHash: target.ArtifactManifestHash,
		StartedAt: started, FinishedAt: time.Now().UTC(),
	}
}

func recoveryRequired(started time.Time, code, reason string, target adapter.RecoveryTarget, phase string) recoveryStatus {
	return recoveryStatus{
		Status: "recovery_required", ReasonCode: code, Reason: reason,
		TransactionID: target.TransactionID, RevisionID: target.RevisionID,
		CandidateHash: target.CandidateHash, ArtifactManifestHash: target.ArtifactManifestHash,
		CommitPhase: phase, StartedAt: started, FinishedAt: time.Now().UTC(),
	}
}

func (s *Server) markRecoveryRequired(target adapter.RecoveryTarget, code, reason, phase string) {
	// The caller is normally inside a mutation lease. Taking the write side of
	// mutationGate here would self-deadlock; the lease already excludes new
	// readers, and the status is published before the lease is released.
	_ = s.setRecoveryStatusDuringMutation(recoveryRequired(time.Now().UTC(), code, reason, target, phase))
}

func (s *Server) mutationFailure() *actionFailure {
	status := s.currentRecoveryStatus()
	if recoveryStatusAllowsMutation(status) {
		return nil
	}
	message := status.Reason
	if message == "" {
		message = fmt.Sprintf("recovery status %q is not safe for network changes", status.Status)
	}
	code := "recovery_not_safe"
	if status.Status == "recovery_required" {
		code = "recovery_required"
	}
	return &actionFailure{Status: 503, Code: code, Message: message}
}

func recoveryStatusAllowsMutation(status recoveryStatus) bool {
	switch status.Status {
	case "ok":
		return true
	case "not_required":
		// not_required is only an allowlisted baseline after the recovery path
		// has validated the committed baseline revision. Merely supplying an
		// arbitrary revision/hash pair must not open the mutation gate.
		return status.CommitPhase == "baseline_confirmed" && status.RevisionID != "" && status.CandidateHash != ""
	default:
		return false
	}
}

func (s *Server) acquireMutationLease() (func(), *actionFailure) {
	s.mutationGate.RLock()
	if failure := s.mutationFailure(); failure != nil {
		s.mutationGate.RUnlock()
		return nil, failure
	}
	return s.mutationGate.RUnlock, nil
}

func (s *Server) mutationFailureNow() *actionFailure {
	s.mutationGate.RLock()
	defer s.mutationGate.RUnlock()
	return s.mutationFailure()
}

func (s *Server) setRecoveryStatus(status recoveryStatus) error {
	s.mutationGate.Lock()
	defer s.mutationGate.Unlock()
	return s.setRecoveryStatusDuringMutation(status)
}

func (s *Server) setRecoveryStatusDuringMutation(status recoveryStatus) error {
	s.mu.Lock()
	s.recovery = status
	s.mu.Unlock()
	if err := s.store.SaveJSON("meta", "recovery_status", status); err != nil {
		// A status that was not durably recorded cannot be treated as a safe
		// status. Keep a visible in-memory fence so this process cannot admit
		// writes while the durable state is uncertain.
		fenced := status
		fenced.Status = "recovery_required"
		fenced.ReasonCode = "recovery_status_persist_failed"
		fenced.Reason = fmt.Sprintf("could not persist recovery status %q: %v", status.Status, err)
		fenced.FinishedAt = time.Now().UTC()
		s.mu.Lock()
		s.recovery = fenced
		s.mu.Unlock()
		s.publishEvent(Event{Type: "recovery.status_persist_failed", Severity: "critical", ReasonCode: fenced.ReasonCode, Details: map[string]any{"requested_status": status.Status}})
		return err
	}
	if status.Status == "ok" {
		s.publishEvent(Event{Type: "recovery.completed", Severity: "info", ReasonCode: "committed_dataplane_recovered", Details: map[string]any{"revision_id": status.RevisionID}})
	} else if status.Status == "error" {
		s.publishEvent(Event{Type: "recovery.failed", Severity: "error", ReasonCode: status.ReasonCode, Details: map[string]any{"revision_id": status.RevisionID}})
	} else if status.Status == "recovery_required" {
		s.publishEvent(Event{Type: "recovery.required", Severity: "critical", ReasonCode: status.ReasonCode, Details: map[string]any{"revision_id": status.RevisionID, "transaction_id": status.TransactionID, "commit_phase": status.CommitPhase}})
	}
	return nil
}

func (s *Server) currentRecoveryStatus() recoveryStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recovery
}
