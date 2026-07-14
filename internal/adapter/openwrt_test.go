package adapter

import "testing"

func TestValidateRecoveryTarget(t *testing.T) {
	valid := RecoveryTarget{
		TransactionID:        "tx_0011223344556677",
		RevisionID:           "rev_10_001122334455",
		CandidateHash:        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ArtifactManifestHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	if err := validateRecoveryTarget(valid); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*RecoveryTarget)
	}{
		{name: "transaction", mutate: func(target *RecoveryTarget) { target.TransactionID = "tx_bad" }},
		{name: "revision", mutate: func(target *RecoveryTarget) { target.RevisionID = "rev-manual" }},
		{name: "candidate hash", mutate: func(target *RecoveryTarget) { target.CandidateHash = "sha256:abc" }},
		{name: "artifact hash", mutate: func(target *RecoveryTarget) { target.ArtifactManifestHash = "SHA256:" + valid.ArtifactManifestHash[7:] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := valid
			test.mutate(&target)
			if err := validateRecoveryTarget(target); err == nil {
				t.Fatal("invalid recovery target accepted")
			}
		})
	}
}

func TestOpenWrtStepNamesMatchTransactionContract(t *testing.T) {
	tests := map[string]string{
		"prepare":            "prepare",
		"validate-candidate": "validate_candidate",
		"snapshot-current":   "snapshot_current",
		"apply-candidate":    "apply_candidate",
		"verify-management":  "verify_management_path",
		"verify-data-plane":  "verify_data_plane",
		"commit":             "commit",
		"rollback":           "rollback",
	}
	for command, expected := range tests {
		if actual := stepName(command); actual != expected {
			t.Errorf("stepName(%q) = %q, want %q", command, actual, expected)
		}
	}
}
