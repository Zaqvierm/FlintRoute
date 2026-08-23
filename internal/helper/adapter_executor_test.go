package helper

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAdapterExecutorUsesOnlyOwnedOperationExecutor(t *testing.T) {
	executor := AdapterExecutor{
		AdapterPath: filepath.Join(t.TempDir(), "adapter.sh"),
		ConfigPath:  filepath.Join(t.TempDir(), "default.json"),
		InitDir:     t.TempDir(),
	}
	request := validRequest("nft.replace_owned_table")
	request.NFT = &NFTRequest{Family: "inet", Table: "router_policy", Generation: request.Generation, ArtifactHash: request.ArtifactManifestHash}
	response := executor.Execute(context.Background(), request)
	if response.Accepted || response.ErrorCode != "adapter_exit_nonzero" {
		t.Fatalf("owned operation did not reach the fixed adapter executor: %+v", response)
	}
}

func TestAdapterExecutorTransactionVerbsAreClosed(t *testing.T) {
	for command, want := range map[string]string{
		"transaction.prepare":         "prepare",
		"transaction.apply_candidate": "apply-candidate",
		"transaction.commit_prepared": "commit-prepared",
		"transaction.finalize_commit": "finalize-commit",
		"transaction.rollback":        "rollback",
	} {
		got, ok := transactionVerb(command)
		if !ok || got != want {
			t.Fatalf("%s mapped to %q/%v, want %q/true", command, got, ok, want)
		}
	}
	if _, ok := transactionVerb("transaction.exec"); ok {
		t.Fatal("unknown transaction verb was accepted")
	}
}

func TestParseEvidenceIsBoundedToKeyValueLines(t *testing.T) {
	evidence := parseEvidence([]byte("transaction_state=adapter_activated\ncommitted=false\nnot evidence\n"))
	if evidence["transaction_state"] != "adapter_activated" || evidence["committed"] != "false" {
		t.Fatalf("evidence was not parsed: %#v", evidence)
	}
	if _, ok := evidence["not evidence"]; ok {
		t.Fatal("invalid evidence key was accepted")
	}
}
