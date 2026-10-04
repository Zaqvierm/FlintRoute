package helper

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// CalibrationBinding contains only a previously committed transaction identity.
// Paths are supplied by the local bootstrap, never by a socket request.
func CalibrationBinding(stateDir, runtimeDir string) (Request, error) {
	values, err := readQuickEnv(filepath.Join(runtimeDir, "active-transaction.env"))
	if err != nil || values["transaction_state"] != "committed" {
		return Request{}, errors.New("quick test requires a committed active binding")
	}
	r := Request{ProtocolVersion: ProtocolVersion, Generation: values["revision_id"], RevisionID: values["revision_id"], TransactionID: values["transaction_id"], CandidateHash: values["candidate_hash"], ArtifactManifestHash: values["artifact_manifest_hash"]}
	if !safeObjectName(r.RevisionID) || !safeObjectName(r.TransactionID) || !safeHash(r.CandidateHash) || !safeHash(r.ArtifactManifestHash) {
		return Request{}, errors.New("active calibration binding is invalid")
	}
	binding, err := readQuickEnv(filepath.Join(stateDir, "transactions", r.RevisionID, r.TransactionID, "binding.env"))
	if err != nil {
		return Request{}, errors.New("committed calibration transaction is unavailable")
	}
	for key, want := range map[string]string{"revision_id": r.RevisionID, "transaction_id": r.TransactionID, "candidate_hash": r.CandidateHash, "artifact_manifest_hash": r.ArtifactManifestHash} {
		if binding[key] != want {
			return Request{}, errors.New("calibration transaction binding mismatch")
		}
	}
	r.RollbackTokenHash = binding["rollback_token_hash"]
	if !safeHash(r.RollbackTokenHash) {
		return Request{}, errors.New("calibration transaction token is invalid")
	}
	return r, nil
}

func readQuickEnv(path string) (map[string]string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 64<<10 {
		return nil, errors.New("calibration metadata is unavailable or unsafe")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errors.New("malformed calibration metadata")
		}
		if _, exists := values[key]; exists {
			return nil, errors.New("duplicate calibration metadata")
		}
		values[key] = value
	}
	return values, nil
}
