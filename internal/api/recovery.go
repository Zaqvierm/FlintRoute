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
	StartedAt            time.Time `json:"started_at"`
	FinishedAt           time.Time `json:"finished_at"`
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
	target := adapter.RecoveryTarget{
		TransactionID: revision.TransactionID, RevisionID: revision.RevisionID,
		CandidateHash: revision.CandidateHash, ArtifactManifestHash: revision.ArtifactManifestHash,
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

	reconcile := s.adapter.Reconcile(ctx, target)
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

func (s *Server) setRecoveryStatus(status recoveryStatus) {
	s.mu.Lock()
	s.recovery = status
	s.mu.Unlock()
	_ = s.store.SaveJSON("meta", "recovery_status", status)
}

func (s *Server) currentRecoveryStatus() recoveryStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recovery
}
