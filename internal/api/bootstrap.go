package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/state"
)

const baselineRevisionKind = "baseline"

func ensureBaselineRevision(store *state.Store, cfg *config.Config, now time.Time) (bool, error) {
	if store == nil || cfg == nil {
		return false, fmt.Errorf("state store and config are required")
	}
	if err := cfg.Validate(); err != nil {
		return false, fmt.Errorf("baseline config is invalid: %w", err)
	}
	canonical, err := json.Marshal(cfg)
	if err != nil {
		return false, fmt.Errorf("encode baseline config: %w", err)
	}
	digest := sha256.Sum256(canonical)
	candidateHash := "sha256:" + hex.EncodeToString(digest[:])
	revisionID := fmt.Sprintf("rev_1_%s", hex.EncodeToString(digest[:6]))
	now = now.UTC()
	revision := revisionRecord{
		RevisionID:    revisionID,
		Kind:          baselineRevisionKind,
		Version:       1,
		CandidateHash: candidateHash,
		State:         "committed",
		CreatedAt:     now,
		CommittedAt:   &now,
	}
	created, err := store.InitializeIfEmpty(
		state.Entry{Bucket: "meta", Key: "active_config", Value: cfg},
		state.Entry{Bucket: "meta", Key: "active_revision", Value: revisionID},
		state.Entry{Bucket: "meta", Key: "config_version", Value: int64(1)},
		state.Entry{Bucket: "revisions", Key: revisionID, Value: revision},
	)
	if err != nil {
		return false, fmt.Errorf("initialize baseline revision: %w", err)
	}
	return created, nil
}

func validateBaselineRevision(revision revisionRecord, activeRevision string, active *config.Config) error {
	if revision.Kind != baselineRevisionKind || revision.State != "committed" || revision.Version != 1 ||
		revision.BaseVersion != 0 || revision.RevisionID == "" || revision.RevisionID != activeRevision ||
		revision.ChangeID != "" || revision.TransactionID != "" || revision.ArtifactManifestHash != "" ||
		revision.CandidateHash == "" || revision.CreatedAt.IsZero() || revision.CommittedAt == nil || active == nil {
		return fmt.Errorf("baseline revision record is incomplete")
	}
	canonical, err := json.Marshal(active)
	if err != nil {
		return fmt.Errorf("encode active baseline config: %w", err)
	}
	digest := sha256.Sum256(canonical)
	expectedHash := "sha256:" + hex.EncodeToString(digest[:])
	expectedRevision := fmt.Sprintf("rev_1_%s", hex.EncodeToString(digest[:6]))
	if !constantEqual(revision.CandidateHash, expectedHash) || revision.RevisionID != expectedRevision {
		return fmt.Errorf("baseline config hash does not match revision")
	}
	return nil
}
