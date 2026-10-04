package helper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCalibrationBindingComparesBothSidesAndRejectsCorruption(t *testing.T) {
	root := t.TempDir()
	runtimeDir := filepath.Join(root, "runtime")
	stateDir := filepath.Join(root, "state")
	r := validRequest("zapret.quick_check")
	r.Generation = r.RevisionID
	txDir := filepath.Join(stateDir, "transactions", r.RevisionID, r.TransactionID)
	for _, dir := range []string{runtimeDir, txDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	identity := "transaction_id=" + r.TransactionID + "\nrevision_id=" + r.RevisionID + "\ncandidate_hash=" + r.CandidateHash + "\nartifact_manifest_hash=" + r.ArtifactManifestHash + "\n"
	activePath := filepath.Join(runtimeDir, "active-transaction.env")
	bindingPath := filepath.Join(txDir, "binding.env")
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(activePath, identity+"transaction_state=committed\n")
	write(bindingPath, identity+"rollback_token_hash="+r.RollbackTokenHash+"\n")
	got, err := CalibrationBinding(stateDir, runtimeDir)
	if err != nil || got.CandidateHash != r.CandidateHash || got.RollbackTokenHash != r.RollbackTokenHash {
		t.Fatalf("valid binding failed: %v", err)
	}
	for _, bad := range []string{identity + "transaction_state=applied\n", identity + "transaction_state=committed\nrevision_id=duplicate\n", strings.ReplaceAll(identity, r.CandidateHash, "sha256:"+strings.Repeat("a", 64)) + "transaction_state=committed\n"} {
		write(activePath, bad)
		if _, err := CalibrationBinding(stateDir, runtimeDir); err == nil {
			t.Fatal("ambiguous binding accepted")
		}
	}
	write(activePath, identity+"transaction_state=committed\n")
	write(bindingPath, identity+"rollback_token_hash=invalid\n")
	if _, err := CalibrationBinding(stateDir, runtimeDir); err == nil {
		t.Fatal("invalid rollback capability accepted")
	}
}
