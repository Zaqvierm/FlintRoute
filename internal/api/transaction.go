package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"router-policy/internal/adapter"
	"router-policy/internal/artifact"
	"router-policy/internal/config"
	"router-policy/internal/platform"
	"router-policy/internal/state"
)

type actionFailure struct {
	Status  int
	Code    string
	Message string
}

type candidateRecord struct {
	ChangeID             string          `json:"change_id"`
	BaseVersion          int64           `json:"base_version"`
	CandidateVersion     int64           `json:"candidate_version"`
	Hash                 string          `json:"hash"`
	ArtifactManifestHash string          `json:"artifact_manifest_hash"`
	ArtifactsReady       bool            `json:"artifacts_ready"`
	ArtifactBlockReason  string          `json:"artifact_block_reason,omitempty"`
	ArtifactsSimulation  bool            `json:"artifacts_simulation"`
	Config               config.Config   `json:"config"`
	Canonical            json.RawMessage `json:"canonical"`
	CreatedAt            time.Time       `json:"created_at"`
}

type transactionRecord struct {
	Transaction adapter.Transaction  `json:"transaction"`
	State       string               `json:"state"`
	Steps       []adapter.StepResult `json:"steps"`
	UpdatedAt   time.Time            `json:"updated_at"`
	CompletedAt *time.Time           `json:"completed_at,omitempty"`
}

type revisionRecord struct {
	RevisionID           string     `json:"revision_id"`
	ChangeID             string     `json:"change_id"`
	TransactionID        string     `json:"transaction_id"`
	BaseVersion          int64      `json:"base_version"`
	Version              int64      `json:"version"`
	CandidateHash        string     `json:"candidate_hash"`
	ArtifactManifestHash string     `json:"artifact_manifest_hash"`
	State                string     `json:"state"`
	CreatedAt            time.Time  `json:"created_at"`
	CommittedAt          *time.Time `json:"committed_at,omitempty"`
}

func loadActiveConfig(store *state.Store, fallback *config.Config) (*config.Config, string, error) {
	active := fallback
	var persisted config.Config
	if err := store.LoadJSON("meta", "active_config", &persisted); err == nil {
		if err := persisted.Validate(); err != nil {
			return nil, "", fmt.Errorf("persisted active config is invalid: %w", err)
		}
		active = &persisted
	} else if !errors.Is(err, state.ErrNotFound) {
		return nil, "", err
	}
	var revision string
	if err := store.LoadJSON("meta", "active_revision", &revision); err != nil && !errors.Is(err, state.ErrNotFound) {
		return nil, "", err
	}
	return active, revision, nil
}

func (s *Server) currentConfig() *config.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeConfig
}

func (s *Server) acquireChangeActionLock(id string) func() {
	s.mu.Lock()
	entry := s.actionLocks[id]
	if entry == nil {
		entry = &actionLockEntry{}
		s.actionLocks[id] = entry
	}
	entry.refs++
	s.mu.Unlock()
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		s.mu.Lock()
		entry.refs--
		if entry.refs == 0 && s.actionLocks[id] == entry {
			delete(s.actionLocks, id)
		}
		s.mu.Unlock()
	}
}

func (s *Server) refreshCandidateNetworkDiagnostics(candidate *config.Config) error {
	reporter, ok := s.provider.(platform.NetworkDiagnosticsProvider)
	if !ok {
		if s.development {
			return nil
		}
		now := time.Now().UTC()
		_, err := artifact.WriteNetworkDiagnostics(candidate, platform.NetworkDiagnostics{
			Status:      "UNVERIFIED",
			Reason:      "provider_does_not_supply_network_diagnostics",
			Source:      "provider-network-diagnostics-unavailable",
			Simulation:  false,
			CollectedAt: now,
			ExpiresAt:   now.Add(time.Minute),
		})
		return err
	}
	diagnostics := reporter.NetworkDiagnostics(candidate)
	if !s.development && diagnostics.Simulation {
		diagnostics.Status = "UNVERIFIED"
		diagnostics.Reason = "simulation_not_allowed_in_production"
	}
	_, err := artifact.WriteNetworkDiagnostics(candidate, diagnostics)
	return err
}

func (s *Server) validateChangeSet(cs ChangeSet) (ChangeSet, *actionFailure) {
	if cs.State != "draft" {
		return cs, conflict("invalid_transition", "change cannot be validated from "+cs.State)
	}
	s.mu.Lock()
	currentVersion := s.configVersion
	active := s.activeConfig
	s.mu.Unlock()
	if cs.BaseVersion != currentVersion {
		return cs, conflict("base_version_conflict", "base_version does not match current revision")
	}
	candidate, canonical, diff, validations := buildCandidate(active, cs.Operations)
	cs.Validation = validations
	if hasValidationError(validations) {
		if err := s.saveChange(&cs, "draft"); err != nil {
			return cs, internalFailure(err)
		}
		return cs, &actionFailure{Status: 422, Code: "candidate_invalid", Message: "candidate config validation failed"}
	}
	candidateVersion := currentVersion + 1
	revisionID := fmt.Sprintf("rev_%d_%s", candidateVersion, randomHex(6))
	tx, err := adapter.NewTransaction(s.cfg, cs.ID, revisionID, cs.BaseVersion, candidateVersion, canonical)
	if err != nil {
		return cs, internalFailure(err)
	}
	if err := writeFileAtomic(tx.CandidatePath, append(canonical, '\n'), 0o600); err != nil {
		return cs, internalFailure(err)
	}
	if err := adapter.PersistCapability(tx); err != nil {
		return cs, internalFailure(err)
	}
	if err := s.refreshCandidateNetworkDiagnostics(candidate); err != nil {
		_ = adapter.RetireCapability(tx)
		return cs, internalFailure(err)
	}
	generatedAt := time.Now().UTC()
	manifest, manifestHash, err := artifact.Generate(candidate, tx.ArtifactRoot, artifact.Binding{TransactionID: tx.ID, RevisionID: tx.RevisionID, CandidateHash: tx.CandidateHash}, generatedAt)
	if err != nil {
		_ = adapter.RetireCapability(tx)
		return cs, internalFailure(err)
	}
	tx.ArtifactManifestHash = manifestHash
	tx.ArtifactsReady = manifest.DeploymentReady
	tx.ArtifactBlockReason = manifest.BlockReason
	tx.ArtifactsSimulation = manifest.Simulation
	if err := bindAdaptiveCandidate(&tx, candidate); err != nil {
		_ = adapter.RetireCapability(tx)
		return cs, &actionFailure{Status: 422, Code: "adaptive_candidate_invalid", Message: err.Error()}
	}
	manifestHash = tx.ArtifactManifestHash
	if err := adapter.PersistBinding(tx); err != nil {
		_ = adapter.RetireCapability(tx)
		return cs, internalFailure(err)
	}
	record := candidateRecord{ChangeID: cs.ID, BaseVersion: cs.BaseVersion, CandidateVersion: candidateVersion, Hash: tx.CandidateHash, ArtifactManifestHash: manifestHash, ArtifactsReady: manifest.DeploymentReady, ArtifactBlockReason: manifest.BlockReason, ArtifactsSimulation: manifest.Simulation, Config: *candidate, Canonical: canonical, CreatedAt: generatedAt}
	cs.State = "validated"
	cs.CandidateVersion = candidateVersion
	cs.CandidateHash = tx.CandidateHash
	cs.CandidatePath = tx.CandidatePath
	cs.ArtifactManifestHash = manifestHash
	cs.ArtifactsReady = manifest.DeploymentReady
	cs.ArtifactBlockReason = manifest.BlockReason
	cs.ArtifactsSimulation = manifest.Simulation
	if !manifest.DeploymentReady {
		cs.Validation = append(cs.Validation, Validation{Level: "warning", Code: manifest.BlockReason, Message: "generated data-plane artifacts require verified device diagnostics"})
	}
	for _, warning := range manifest.Warnings {
		cs.Validation = append(cs.Validation, Validation{Level: "warning", Code: warning, Message: "candidate changes OpenWrt flow offloading and requires explicit apply confirmation"})
	}
	cs.RevisionID = tx.RevisionID
	cs.TransactionID = tx.ID
	cs.ExpiresAt = tx.ExpiresAt.Format(time.RFC3339)
	cs.Diff = diff
	cs.AdapterStatus = "NOT_STARTED"
	cs.Version++
	cs.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	txRecord := transactionRecord{Transaction: tx, State: cs.State, UpdatedAt: time.Now().UTC()}
	revision := revisionRecord{RevisionID: tx.RevisionID, ChangeID: cs.ID, TransactionID: tx.ID, BaseVersion: cs.BaseVersion, Version: candidateVersion, CandidateHash: tx.CandidateHash, ArtifactManifestHash: manifestHash, State: cs.State, CreatedAt: tx.CreatedAt}
	if err := s.store.SaveBatch(
		state.Entry{Bucket: "candidates", Key: cs.ID, Value: record},
		state.Entry{Bucket: "transactions", Key: tx.ID, Value: txRecord},
		state.Entry{Bucket: "revisions", Key: tx.RevisionID, Value: revision},
		state.Entry{Bucket: "changes", Key: cs.ID, Value: cs},
	); err != nil {
		return cs, internalFailure(err)
	}
	s.setChange(cs)
	s.publishChangeEvent(cs, "candidate_validated")
	return cs, nil
}

func (s *Server) applyChangeSet(ctx context.Context, cs ChangeSet) (ChangeSet, *actionFailure) {
	if cs.State != "validated" {
		return cs, conflict("invalid_transition", "change cannot be applied from "+cs.State)
	}
	s.transactionMu.Lock()
	defer s.transactionMu.Unlock()
	if other := s.activeTransaction(cs.ID); other != "" {
		return cs, conflict("transaction_busy", "another transaction is active: "+other)
	}
	if !s.baseVersionCurrent(cs) {
		return cs, conflict("base_version_conflict", "candidate was built from a stale config version")
	}
	tx, failure := s.loadVerifiedTransaction(cs)
	if failure != nil {
		return cs, failure
	}
	if !tx.ArtifactsReady {
		cs.AdapterStatus = "REQUIRES_DEVICE"
		if err := s.saveProgress(&cs, tx, "requires_device"); err != nil {
			return cs, internalFailure(err)
		}
		return cs, nil
	}
	if tx.ArtifactsSimulation && !s.development {
		cs.AdapterStatus = "REQUIRES_DEVICE"
		cs.Validation = append(cs.Validation, Validation{Level: "warning", Code: "simulated_diagnostics_refused", Message: "production apply requires non-simulated device diagnostics"})
		if err := s.saveProgress(&cs, tx, "requires_device"); err != nil {
			return cs, internalFailure(err)
		}
		return cs, nil
	}
	type stepSpec struct {
		before string
		call   func(context.Context, adapter.Transaction) adapter.StepResult
	}
	steps := []stepSpec{
		{call: s.adapter.Prepare},
		{before: "prepared", call: s.adapter.ValidateCandidate},
		{before: "prepared", call: s.adapter.SnapshotCurrent},
		{before: "applying", call: s.adapter.ApplyCandidate},
		{before: "verifying", call: s.adapter.VerifyManagementPath},
		{before: "verifying", call: s.adapter.VerifyDataPlane},
	}
	dataPlaneApplied := false
	for index, step := range steps {
		if step.before != "" && cs.State != step.before {
			if err := s.saveProgress(&cs, tx, step.before); err != nil {
				return cs, internalFailure(err)
			}
		}
		if failure := validateTransactionBinding(cs, tx); failure != nil {
			return cs, failure
		}
		result := step.call(ctx, tx)
		cs.Steps = append(cs.Steps, result)
		cs.AdapterStatus = result.Status
		if index == 0 && stepOK(result) {
			cs.State = "prepared"
		}
		if err := s.saveProgress(&cs, tx, cs.State); err != nil {
			return cs, internalFailure(err)
		}
		if !stepOK(result) {
			if result.Status == "SKIPPED" || result.Status == "UNVERIFIED" {
				cs.ManagementVerified = false
				cs.DataPlaneVerified = false
				cs.AdapterStatus = "REQUIRES_DEVICE"
				if dataPlaneApplied {
					return s.rollbackLocked(ctx, cs, tx, "requires_device", "verification_requires_device")
				}
				if err := s.saveProgress(&cs, tx, "requires_device"); err != nil {
					return cs, internalFailure(err)
				}
				return cs, nil
			}
			finalState := "failed"
			if result.Step == "verify_management_path" || result.Step == "verify_data_plane" {
				finalState = "rolled_back"
			}
			return s.rollbackLocked(ctx, cs, tx, finalState, "adapter_step_failed")
		}
		if result.Step == "apply_candidate" && !artifactEvidenceMatches(result, tx) {
			return s.rollbackLocked(ctx, cs, tx, "failed", "applied_artifact_binding_mismatch")
		}
		if result.Step == "apply_candidate" {
			dataPlaneApplied = true
		}
		if result.Step == "verify_management_path" {
			cs.ManagementVerified = result.ManagementVerified
		}
		if result.Step == "verify_data_plane" {
			cs.DataPlaneVerified = result.DataPlaneVerified
		}
	}
	if !cs.ManagementVerified || !cs.DataPlaneVerified {
		return s.rollbackLocked(ctx, cs, tx, "rolled_back", "verification_flags_missing")
	}
	cs.AdapterStatus = "OK"
	if err := s.saveProgress(&cs, tx, "awaiting_confirmation"); err != nil {
		return cs, internalFailure(err)
	}
	s.scheduleExpiry(cs)
	return cs, nil
}

func (s *Server) confirmChangeSet(ctx context.Context, cs ChangeSet) (ChangeSet, *actionFailure) {
	if cs.State != "awaiting_confirmation" {
		return cs, conflict("invalid_transition", "change cannot be confirmed from "+cs.State)
	}
	if !cs.ManagementVerified || !cs.DataPlaneVerified {
		return cs, conflict("data_plane_not_verified", "management and data plane verification are required")
	}
	s.transactionMu.Lock()
	defer s.transactionMu.Unlock()
	tx, failure := s.loadVerifiedTransaction(cs)
	if failure != nil {
		return cs, failure
	}
	if time.Now().UTC().After(tx.ExpiresAt) {
		rolled, _ := s.rollbackLocked(ctx, cs, tx, "expired", "confirmation_expired")
		return rolled, conflict("transaction_expired", "transaction expired and was rolled back")
	}
	status := s.adapter.Status(ctx)
	cs.Steps = append(cs.Steps, status)
	if !stepOK(status) || evidenceString(status, "active_revision") != tx.RevisionID || evidenceString(status, "active_transaction") != tx.ID || evidenceString(status, "active_candidate_hash") != tx.CandidateHash || evidenceString(status, "active_artifact_manifest_hash") != tx.ArtifactManifestHash {
		return s.rollbackLocked(ctx, cs, tx, "failed", "adapter_revision_mismatch")
	}
	if err := s.saveProgress(&cs, tx, "committing"); err != nil {
		return cs, internalFailure(err)
	}
	commit := s.adapter.Commit(ctx, tx)
	cs.Steps = append(cs.Steps, commit)
	cs.AdapterStatus = commit.Status
	if err := s.saveProgress(&cs, tx, "committing"); err != nil {
		return cs, internalFailure(err)
	}
	if !stepOK(commit) {
		return s.rollbackLocked(ctx, cs, tx, "failed", "commit_failed")
	}
	candidate, failure := s.loadVerifiedCandidate(cs, tx)
	if failure != nil {
		return s.rollbackLocked(ctx, cs, tx, "failed", "candidate_recheck_failed")
	}
	adaptiveRuntime, err := buildAdaptiveRuntime(candidate, s.store)
	if err != nil {
		return s.rollbackLocked(ctx, cs, tx, "failed", "adaptive_runtime_invalid")
	}
	now := time.Now().UTC()
	cs.State = "committed"
	cs.Version++
	cs.UpdatedAt = now.Format(time.RFC3339)
	revision := revisionRecord{RevisionID: tx.RevisionID, ChangeID: cs.ID, TransactionID: tx.ID, BaseVersion: tx.BaseVersion, Version: tx.CandidateVersion, CandidateHash: tx.CandidateHash, ArtifactManifestHash: tx.ArtifactManifestHash, State: "committed", CreatedAt: tx.CreatedAt, CommittedAt: &now}
	txRecord := transactionRecord{Transaction: tx, State: "committed", Steps: cs.Steps, UpdatedAt: now, CompletedAt: &now}
	if err := s.store.SaveBatch(
		state.Entry{Bucket: "meta", Key: "active_config", Value: candidate},
		state.Entry{Bucket: "meta", Key: "active_revision", Value: tx.RevisionID},
		state.Entry{Bucket: "meta", Key: "config_version", Value: tx.CandidateVersion},
		state.Entry{Bucket: "revisions", Key: tx.RevisionID, Value: revision},
		state.Entry{Bucket: "transactions", Key: tx.ID, Value: txRecord},
		state.Entry{Bucket: "changes", Key: cs.ID, Value: cs},
	); err != nil {
		return cs, internalFailure(err)
	}
	s.mu.Lock()
	s.activeConfig = candidate
	s.adaptiveZapret = adaptiveRuntime
	s.activeRevision = tx.RevisionID
	s.configVersion = tx.CandidateVersion
	s.changes[cs.ID] = cs
	s.cancelExpiryLocked(cs.ID)
	s.mu.Unlock()
	_ = adapter.RetireCapability(tx)
	s.publishChangeEvent(cs, "adapter_commit_succeeded")
	return cs, nil
}

func (s *Server) rollbackChangeSet(ctx context.Context, cs ChangeSet, expired bool) (ChangeSet, *actionFailure) {
	if cs.State == "rolled_back" || cs.State == "expired" {
		return cs, nil
	}
	switch cs.State {
	case "validated", "prepared", "applying", "verifying", "awaiting_confirmation", "committing", "failed", "requires_device":
	default:
		return cs, conflict("invalid_transition", "change cannot be rolled back from "+cs.State)
	}
	s.transactionMu.Lock()
	defer s.transactionMu.Unlock()
	tx, failure := s.loadTransaction(cs)
	if failure != nil {
		return cs, failure
	}
	if !capabilityMatches(tx) {
		if err := s.saveProgress(&cs, tx, "rollback_failed"); err != nil {
			return cs, internalFailure(err)
		}
		return cs, &actionFailure{Status: 403, Code: "rollback_capability_invalid", Message: "stored rollback capability failed verification"}
	}
	final := "rolled_back"
	if expired {
		final = "expired"
	}
	return s.rollbackLocked(ctx, cs, tx, final, "rollback_requested")
}

func (s *Server) rollbackLocked(ctx context.Context, cs ChangeSet, tx adapter.Transaction, finalState, reason string) (ChangeSet, *actionFailure) {
	if err := s.saveProgress(&cs, tx, "rolling_back"); err != nil {
		return cs, internalFailure(err)
	}
	result := s.adapter.Rollback(ctx, tx)
	cs.Steps = append(cs.Steps, result)
	cs.AdapterStatus = result.Status
	if !stepOK(result) {
		if err := s.saveProgress(&cs, tx, "rollback_failed"); err != nil {
			return cs, internalFailure(err)
		}
		return cs, &actionFailure{Status: 500, Code: "rollback_failed", Message: result.Reason}
	}
	cs.ManagementVerified = false
	cs.DataPlaneVerified = false
	cs.Validation = append(cs.Validation, Validation{Level: "info", Code: reason, Message: "adapter rollback completed"})
	if err := s.saveProgress(&cs, tx, finalState); err != nil {
		return cs, internalFailure(err)
	}
	s.mu.Lock()
	s.cancelExpiryLocked(cs.ID)
	s.mu.Unlock()
	_ = adapter.RetireCapability(tx)
	return cs, nil
}

func (s *Server) saveProgress(cs *ChangeSet, tx adapter.Transaction, nextState string) error {
	if failure := validateTransactionBinding(*cs, tx); failure != nil {
		return errors.New(failure.Message)
	}
	cs.State = nextState
	cs.Version++
	cs.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	now := time.Now().UTC()
	record := transactionRecord{Transaction: tx, State: nextState, Steps: cs.Steps, UpdatedAt: now}
	if isTerminalState(nextState) {
		record.CompletedAt = &now
	}
	if err := s.store.SaveBatch(
		state.Entry{Bucket: "transactions", Key: tx.ID, Value: record},
		state.Entry{Bucket: "changes", Key: cs.ID, Value: *cs},
	); err != nil {
		return err
	}
	s.setChange(*cs)
	s.publishChangeEvent(*cs, "transaction_step")
	return nil
}

func (s *Server) saveChange(cs *ChangeSet, stateName string) error {
	cs.State = stateName
	cs.Version++
	cs.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.persistChangeSet(*cs); err != nil {
		return err
	}
	s.setChange(*cs)
	return nil
}

func (s *Server) setChange(cs ChangeSet) {
	s.mu.Lock()
	s.changes[cs.ID] = cs
	s.mu.Unlock()
}

func (s *Server) publishChangeEvent(cs ChangeSet, reason string) {
	s.publishEvent(Event{Type: "change." + cs.State, Severity: "info", ReasonCode: reason, Details: map[string]any{"change_id": cs.ID, "state": cs.State, "transaction_id": cs.TransactionID, "revision_id": cs.RevisionID}})
}

func (s *Server) loadTransaction(cs ChangeSet) (adapter.Transaction, *actionFailure) {
	var record transactionRecord
	if err := s.store.LoadJSON("transactions", cs.TransactionID, &record); err != nil {
		return adapter.Transaction{}, internalFailure(err)
	}
	if failure := validateTransactionBinding(cs, record.Transaction); failure != nil {
		return adapter.Transaction{}, failure
	}
	return record.Transaction, nil
}

func (s *Server) loadVerifiedTransaction(cs ChangeSet) (adapter.Transaction, *actionFailure) {
	tx, failure := s.loadTransaction(cs)
	if failure != nil {
		return tx, failure
	}
	if _, failure := s.loadVerifiedCandidate(cs, tx); failure != nil {
		return tx, failure
	}
	if !capabilityMatches(tx) {
		return tx, conflict("rollback_token_invalid", "stored rollback token failed verification")
	}
	return tx, nil
}

func (s *Server) loadVerifiedCandidate(cs ChangeSet, tx adapter.Transaction) (*config.Config, *actionFailure) {
	var record candidateRecord
	if err := s.store.LoadJSON("candidates", cs.ID, &record); err != nil {
		return nil, internalFailure(err)
	}
	canonical, err := json.Marshal(record.Config)
	if err != nil {
		return nil, internalFailure(err)
	}
	hash := hashBytes(canonical)
	if !constantEqual(hash, record.Hash) || !constantEqual(hash, cs.CandidateHash) || !constantEqual(hash, tx.CandidateHash) {
		return nil, conflict("candidate_hash_mismatch", "candidate hash does not match the full canonical config")
	}
	candidatePath, artifactRoot, failure := s.currentTransactionPaths(tx)
	if failure != nil {
		return nil, failure
	}
	fileRaw, err := os.ReadFile(candidatePath)
	if err != nil {
		return nil, internalFailure(err)
	}
	var fileConfig config.Config
	if err := json.Unmarshal(fileRaw, &fileConfig); err != nil {
		return nil, conflict("candidate_file_invalid", "candidate file is invalid")
	}
	fileCanonical, _ := json.Marshal(fileConfig)
	if !constantEqual(hashBytes(fileCanonical), hash) {
		return nil, conflict("candidate_file_hash_mismatch", "candidate file differs from bbolt candidate")
	}
	if err := fileConfig.Validate(); err != nil {
		return nil, conflict("candidate_invalid", err.Error())
	}
	binding := artifact.Binding{TransactionID: tx.ID, RevisionID: tx.RevisionID, CandidateHash: tx.CandidateHash}
	manifest, err := artifact.Verify(artifactRoot, binding, tx.ArtifactManifestHash)
	if err != nil {
		return nil, conflict("artifact_manifest_mismatch", err.Error())
	}
	if record.ArtifactManifestHash != tx.ArtifactManifestHash || cs.ArtifactManifestHash != tx.ArtifactManifestHash {
		return nil, conflict("artifact_manifest_mismatch", "candidate, transaction and ChangeSet artifact hashes differ")
	}
	if manifest.DeploymentReady != tx.ArtifactsReady || manifest.DeploymentReady != record.ArtifactsReady || manifest.DeploymentReady != cs.ArtifactsReady || manifest.BlockReason != tx.ArtifactBlockReason || manifest.BlockReason != record.ArtifactBlockReason || manifest.BlockReason != cs.ArtifactBlockReason || manifest.Simulation != tx.ArtifactsSimulation || manifest.Simulation != record.ArtifactsSimulation || manifest.Simulation != cs.ArtifactsSimulation {
		return nil, conflict("artifact_readiness_mismatch", "candidate, manifest, transaction and ChangeSet readiness differ")
	}
	return &fileConfig, nil
}

func (s *Server) currentTransactionPaths(tx adapter.Transaction) (string, string, *actionFailure) {
	if !safePathComponent(tx.RevisionID) || !safePathComponent(tx.ID) {
		return "", "", conflict("transaction_path_invalid", "transaction or revision id cannot form a state path")
	}
	root := filepath.Join(s.cfg.Storage.StateDir, "transactions", tx.RevisionID, tx.ID)
	return filepath.Join(root, "candidate.json"), filepath.Join(root, "generated"), nil
}

func safePathComponent(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func validateTransactionBinding(cs ChangeSet, tx adapter.Transaction) *actionFailure {
	if tx.ID == "" || tx.RevisionID == "" || tx.ID != cs.TransactionID || tx.RevisionID != cs.RevisionID || tx.ChangeID != cs.ID {
		return conflict("transaction_binding_mismatch", "transaction id or revision id does not match ChangeSet")
	}
	if tx.RevisionID == "rev-manual" || tx.CandidateHash != cs.CandidateHash || tx.CandidatePath != cs.CandidatePath || tx.ArtifactManifestHash != cs.ArtifactManifestHash || tx.ArtifactsReady != cs.ArtifactsReady || tx.ArtifactBlockReason != cs.ArtifactBlockReason || tx.ArtifactsSimulation != cs.ArtifactsSimulation {
		return conflict("transaction_binding_mismatch", "transaction metadata does not match candidate")
	}
	return nil
}

func (s *Server) baseVersionCurrent(cs ChangeSet) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cs.BaseVersion == s.configVersion
}

func (s *Server) activeTransaction(exceptID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, cs := range s.changes {
		if id == exceptID {
			continue
		}
		switch cs.State {
		case "prepared", "applying", "verifying", "awaiting_confirmation", "committing", "rolling_back":
			return id
		}
	}
	return ""
}

func (s *Server) scheduleExpiry(cs ChangeSet) {
	expires, err := time.Parse(time.RFC3339, cs.ExpiresAt)
	if err != nil {
		return
	}
	delay := time.Until(expires)
	if delay < 0 {
		delay = 0
	}
	s.mu.Lock()
	s.cancelExpiryLocked(cs.ID)
	s.timers[cs.ID] = time.AfterFunc(delay, func() {
		release := s.acquireChangeActionLock(cs.ID)
		defer release()
		s.mu.Lock()
		current, ok := s.changes[cs.ID]
		s.mu.Unlock()
		if !ok || current.State != "awaiting_confirmation" || current.TransactionID != cs.TransactionID || current.RevisionID != cs.RevisionID {
			return
		}
		_, _ = s.rollbackChangeSet(context.Background(), current, true)
	})
	s.mu.Unlock()
}

func (s *Server) cancelExpiryLocked(changeID string) {
	if timer := s.timers[changeID]; timer != nil {
		timer.Stop()
		delete(s.timers, changeID)
	}
}

func (s *Server) recoverTransactions(ctx context.Context) error {
	ids := make([]string, 0)
	s.mu.Lock()
	for id, cs := range s.changes {
		switch cs.State {
		case "prepared", "applying", "verifying", "awaiting_confirmation", "committing", "rolling_back":
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	sort.Strings(ids)
	for _, id := range ids {
		release := s.acquireChangeActionLock(id)
		s.mu.Lock()
		cs := s.changes[id]
		s.mu.Unlock()
		tx, failure := s.loadTransaction(cs)
		if failure != nil {
			release()
			return errors.New(failure.Message)
		}
		status := s.adapter.Status(ctx)
		activeMatches := stepOK(status) && evidenceString(status, "active_revision") == tx.RevisionID && evidenceString(status, "active_transaction") == tx.ID && evidenceString(status, "active_candidate_hash") == tx.CandidateHash && evidenceString(status, "active_artifact_manifest_hash") == tx.ArtifactManifestHash
		if cs.State == "committing" && activeMatches && evidenceString(status, "transaction_state") == "committed" {
			if err := s.finalizeRecoveredCommit(&cs, tx); err != nil {
				release()
				return err
			}
			s.publishChangeEvent(cs, "recovery_commit_finalized")
			release()
			continue
		}
		if cs.State == "awaiting_confirmation" && activeMatches && time.Now().UTC().Before(tx.ExpiresAt) {
			s.scheduleExpiry(cs)
			s.publishChangeEvent(cs, "recovery_awaiting_confirmation")
			release()
			continue
		}
		s.transactionMu.Lock()
		finalState := "rolled_back"
		if cs.State == "awaiting_confirmation" && !time.Now().UTC().Before(tx.ExpiresAt) {
			finalState = "expired"
		}
		_, rollbackFailure := s.rollbackLocked(ctx, cs, tx, finalState, "recovery_fail_closed")
		s.transactionMu.Unlock()
		release()
		if rollbackFailure != nil {
			return errors.New(rollbackFailure.Message)
		}
	}
	return nil
}

func (s *Server) finalizeRecoveredCommit(cs *ChangeSet, tx adapter.Transaction) error {
	candidate, failure := s.loadVerifiedCandidate(*cs, tx)
	if failure != nil {
		return errors.New(failure.Message)
	}
	now := time.Now().UTC()
	cs.State = "committed"
	cs.Version++
	cs.UpdatedAt = now.Format(time.RFC3339)
	revision := revisionRecord{RevisionID: tx.RevisionID, ChangeID: cs.ID, TransactionID: tx.ID, BaseVersion: tx.BaseVersion, Version: tx.CandidateVersion, CandidateHash: tx.CandidateHash, ArtifactManifestHash: tx.ArtifactManifestHash, State: "committed", CreatedAt: tx.CreatedAt, CommittedAt: &now}
	record := transactionRecord{Transaction: tx, State: "committed", Steps: cs.Steps, UpdatedAt: now, CompletedAt: &now}
	if err := s.store.SaveBatch(
		state.Entry{Bucket: "meta", Key: "active_config", Value: candidate},
		state.Entry{Bucket: "meta", Key: "active_revision", Value: tx.RevisionID},
		state.Entry{Bucket: "meta", Key: "config_version", Value: tx.CandidateVersion},
		state.Entry{Bucket: "revisions", Key: tx.RevisionID, Value: revision},
		state.Entry{Bucket: "transactions", Key: tx.ID, Value: record},
		state.Entry{Bucket: "changes", Key: cs.ID, Value: *cs},
	); err != nil {
		return err
	}
	s.mu.Lock()
	s.activeConfig = candidate
	s.activeRevision = tx.RevisionID
	s.configVersion = tx.CandidateVersion
	s.changes[cs.ID] = *cs
	s.cancelExpiryLocked(cs.ID)
	s.mu.Unlock()
	_ = adapter.RetireCapability(tx)
	return nil
}

func buildCandidate(active *config.Config, operations []ChangeOp) (*config.Config, []byte, []ChangeOp, []Validation) {
	if active == nil {
		return nil, nil, nil, []Validation{{Level: "error", Code: "active_config_missing", Message: "active config is missing"}}
	}
	if len(operations) == 0 {
		return nil, nil, nil, []Validation{{Level: "error", Code: "empty_operations", Message: "at least one operation is required"}}
	}
	raw, err := json.Marshal(active)
	if err != nil {
		return nil, nil, nil, []Validation{{Level: "error", Code: "candidate_clone_failed", Message: err.Error()}}
	}
	var activeMap map[string]any
	var candidateMap map[string]any
	if err := json.Unmarshal(raw, &activeMap); err != nil {
		return nil, nil, nil, []Validation{{Level: "error", Code: "candidate_clone_failed", Message: err.Error()}}
	}
	if err := json.Unmarshal(raw, &candidateMap); err != nil {
		return nil, nil, nil, []Validation{{Level: "error", Code: "candidate_clone_failed", Message: err.Error()}}
	}
	validations := make([]Validation, 0, len(operations)+1)
	for _, op := range operations {
		if !supportedOperation(op.Type) {
			validations = append(validations, Validation{Level: "error", Code: "operation_type_denied", Message: "unsupported operation: " + op.Type})
			continue
		}
		if !operationRootAllowed(op.Path) {
			validations = append(validations, Validation{Level: "error", Code: "operation_path_denied", Message: "immutable or unsupported config path: " + op.Path})
			continue
		}
		if op.Type != "delete" && op.Value == nil {
			validations = append(validations, Validation{Level: "error", Code: "operation_value_required", Message: op.Path})
			continue
		}
		applied, err := applyConfigOperation(candidateMap, op)
		if err != nil || !applied {
			message := "operation was not applied"
			if err != nil {
				message = err.Error()
			}
			validations = append(validations, Validation{Level: "error", Code: "operation_not_applied", Message: op.Path + ": " + message})
		}
	}
	if hasValidationError(validations) {
		return nil, nil, nil, validations
	}
	candidateRaw, err := json.Marshal(candidateMap)
	if err != nil {
		return nil, nil, nil, append(validations, Validation{Level: "error", Code: "candidate_marshal_failed", Message: err.Error()})
	}
	var typed config.Config
	if err := json.Unmarshal(candidateRaw, &typed); err != nil {
		return nil, nil, nil, append(validations, Validation{Level: "error", Code: "candidate_type_failed", Message: err.Error()})
	}
	if err := typed.Validate(); err != nil {
		return nil, nil, nil, append(validations, Validation{Level: "error", Code: "candidate_semantic_failed", Message: err.Error()})
	}
	canonical, err := json.Marshal(typed)
	if err != nil {
		return nil, nil, nil, append(validations, Validation{Level: "error", Code: "candidate_marshal_failed", Message: err.Error()})
	}
	var canonicalMap map[string]any
	_ = json.Unmarshal(canonical, &canonicalMap)
	diff := diffJSON(activeMap, canonicalMap, "")
	if len(diff) == 0 {
		return nil, nil, nil, append(validations, Validation{Level: "error", Code: "candidate_noop", Message: "operations produced no config change"})
	}
	validations = append(validations, Validation{Level: "info", Code: "candidate_semantic_ok", Message: "all operations were applied and the full typed candidate validates"})
	return &typed, canonical, diff, validations
}

func diffJSON(before, after any, path string) []ChangeOp {
	if reflect.DeepEqual(before, after) {
		return nil
	}
	bm, bok := before.(map[string]any)
	am, aok := after.(map[string]any)
	if bok && aok {
		keys := make([]string, 0, len(bm)+len(am))
		seen := map[string]bool{}
		for key := range bm {
			seen[key] = true
			keys = append(keys, key)
		}
		for key := range am {
			if !seen[key] {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		var out []ChangeOp
		for _, key := range keys {
			child := path + "/" + escapeJSONPointer(key)
			bv, beforeOK := bm[key]
			av, afterOK := am[key]
			switch {
			case !afterOK:
				out = append(out, ChangeOp{Type: "delete", Path: child, Before: bv})
			case !beforeOK:
				out = append(out, ChangeOp{Type: "add", Path: child, Value: av})
			default:
				out = append(out, diffJSON(bv, av, child)...)
			}
		}
		return out
	}
	return []ChangeOp{{Type: "update", Path: path, Value: after, Before: before}}
}

func supportedOperation(op string) bool {
	return op == "set" || op == "add" || op == "update" || op == "delete"
}

func operationRootAllowed(path string) bool {
	parts, err := splitJSONPointer(path)
	if err != nil || len(parts) == 0 {
		return false
	}
	switch parts[0] {
	case "policy", "routes", "services", "overrides":
		return true
	case "storage":
		return len(parts) == 2 && (parts[1] == "state_dir" || parts[1] == "database")
	case "xray":
		if len(parts) != 2 {
			return false
		}
		switch parts[1] {
		case "outbound_bundle_sha256", "activation_mode", "subscription_secret_file", "last_good_config":
			return true
		default:
			return false
		}
	case "zapret":
		if len(parts) != 2 {
			return false
		}
		switch parts[1] {
		case "adaptive_enabled", "adaptive_catalog_file", "adaptive_assignments":
			return true
		default:
			return false
		}
	case "openwrt":
		return len(parts) == 2 && parts[1] == "flow_offloading_policy"
	case "geoip":
		return len(parts) == 2 && parts[1] == "database"
	default:
		return false
	}
}

func hasValidationError(items []Validation) bool {
	for _, item := range items {
		if item.Level == "error" {
			return true
		}
	}
	return false
}

func stepOK(result adapter.StepResult) bool { return result.OK && result.Status == "OK" }

func evidenceString(result adapter.StepResult, key string) string {
	value, _ := result.Evidence[key].(string)
	return value
}

func artifactEvidenceMatches(result adapter.StepResult, tx adapter.Transaction) bool {
	return evidenceString(result, "transaction_id") == tx.ID &&
		evidenceString(result, "revision_id") == tx.RevisionID &&
		evidenceString(result, "candidate_hash") == tx.CandidateHash &&
		evidenceString(result, "artifact_manifest_hash") == tx.ArtifactManifestHash
}

func capabilityMatches(tx adapter.Transaction) bool {
	_, err := adapter.ReadCapability(tx)
	return err == nil
}

func hashBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeFileAtomic(path string, raw []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp." + randomHex(6)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	cleanup := func() { _ = f.Close(); _ = os.Remove(tmp) }
	if _, err := f.Write(raw); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func escapeJSONPointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func isTerminalState(value string) bool {
	switch value {
	case "committed", "rolled_back", "failed", "rollback_failed", "expired", "requires_device":
		return true
	default:
		return false
	}
}

func conflict(code, message string) *actionFailure {
	return &actionFailure{Status: 409, Code: code, Message: message}
}
func internalFailure(err error) *actionFailure {
	return &actionFailure{Status: 500, Code: "state_store_failed", Message: err.Error()}
}
