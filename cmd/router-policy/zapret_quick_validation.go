package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"router-policy/internal/artifact"
	"router-policy/internal/config"
	"router-policy/internal/helper"
)

func validateZapretQuickRuntime(cfgPath string, args []string) error {
	bootstrap, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	binding, err := helper.CalibrationBinding(bootstrap.Storage.StateDir, bootstrap.Storage.RuntimeDir)
	if err != nil {
		return err
	}
	if binding.RevisionID != args[0] || binding.TransactionID != args[1] || binding.CandidateHash != args[2] || binding.ArtifactManifestHash != args[3] || binding.RollbackTokenHash != args[4] {
		return errors.New("quick runtime binding mismatch")
	}
	dir := filepath.Join(bootstrap.Storage.StateDir, "transactions", binding.RevisionID, binding.TransactionID)
	_, err = artifact.Verify(filepath.Join(dir, "generated"), artifact.Binding{RevisionID: binding.RevisionID, TransactionID: binding.TransactionID, CandidateHash: binding.CandidateHash}, binding.ArtifactManifestHash)
	if err != nil {
		return errors.New("quick runtime artifact verification failed")
	}
	cfg, err := config.Load(filepath.Join(dir, "candidate.json"))
	if err != nil {
		return err
	}
	raw, err := json.Marshal(cfg)
	sum := sha256.Sum256(raw)
	if err != nil || "sha256:"+hex.EncodeToString(sum[:]) != binding.CandidateHash {
		return errors.New("quick runtime candidate hash mismatch")
	}
	if cfg.Zapret.Binary != "/usr/bin/nfqws" || cfg.Storage.RuntimeDir != "/tmp/router-policy" || cfg.Zapret.QueueNum < 1 || cfg.Zapret.QueueNum > 65535 {
		return errors.New("quick runtime owned paths/queue are invalid")
	}
	return printJSON(map[string]any{"validated": true, "revision_id": binding.RevisionID, "transaction_id": binding.TransactionID, "candidate_hash": binding.CandidateHash, "artifact_manifest_hash": binding.ArtifactManifestHash, "rollback_token_hash": binding.RollbackTokenHash, "queue": cfg.Zapret.QueueNum})
}
