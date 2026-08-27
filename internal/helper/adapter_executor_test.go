package helper

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
		"transaction.prepare":          "prepare",
		"transaction.apply_candidate":  "apply-candidate",
		"transaction.commit_prepared":  "commit-prepared",
		"transaction.finalize_commit":  "finalize-commit",
		"transaction.clear_boot_guard": "clear-boot-guard-bound",
		"transaction.rollback":         "rollback",
		"transaction.reconcile":        "reconcile",
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

func TestAdapterExecutorAcceptsOnlySemanticallyProvenReconcile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exec adapter fixture requires a POSIX shell")
	}
	dir := t.TempDir()
	adapterPath := filepath.Join(dir, "adapter.sh")
	request := validRequest("transaction.reconcile")
	request.RollbackTokenHash = ""
	request.Generation = request.RevisionID
	request.Transaction = &TransactionRequest{Operation: "reconcile"}
	script := "#!/bin/sh\n" + strings.Join([]string{
		"echo protocol_version=1",
		"echo operation=reconcile",
		"echo reconcile=ok",
		"echo generation=" + request.Generation,
		"echo transaction_id=" + request.TransactionID,
		"echo active_transaction=" + request.TransactionID,
		"echo active_revision=" + request.RevisionID,
		"echo active_candidate_hash=" + request.CandidateHash,
		"echo active_artifact_manifest_hash=" + request.ArtifactManifestHash,
		"echo transaction_state=committed",
	}, "\n") + "\n"
	if err := os.WriteFile(adapterPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	executor := AdapterExecutor{AdapterPath: adapterPath, ConfigPath: filepath.Join(dir, "default.json"), InitDir: dir}
	response := executor.Execute(context.Background(), request)
	if !response.Accepted || response.ErrorCode != "" {
		t.Fatalf("semantic reconcile proof was rejected: %+v", response)
	}
}

func TestAdapterExecutorAcceptsOnlyGenerationBoundBootGuardClear(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exec adapter fixture requires a POSIX shell")
	}
	dir := t.TempDir()
	adapterPath := filepath.Join(dir, "adapter.sh")
	request := validRequest("transaction.clear_boot_guard")
	request.Transaction = &TransactionRequest{Operation: "clear-boot-guard"}
	script := "#!/bin/sh\n" + strings.Join([]string{
		"echo protocol_version=1",
		"echo operation=clear-boot-guard",
		"echo boot_guard=cleared",
		"echo generation=" + request.Generation,
		"echo transaction_id=" + request.TransactionID,
		"echo active_transaction=" + request.TransactionID,
		"echo active_revision=" + request.RevisionID,
		"echo active_candidate_hash=" + request.CandidateHash,
		"echo active_artifact_manifest_hash=" + request.ArtifactManifestHash,
		"echo transaction_state=committed",
	}, "\n") + "\n"
	if err := os.WriteFile(adapterPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	executor := AdapterExecutor{AdapterPath: adapterPath, ConfigPath: filepath.Join(dir, "default.json"), InitDir: dir}
	response := executor.Execute(context.Background(), request)
	if !response.Accepted || response.ErrorCode != "" {
		t.Fatalf("generation-bound boot guard proof was rejected: %+v", response)
	}

	badScript := strings.Replace(script, "echo active_revision="+request.RevisionID, "echo active_revision=rev_9_deadbeef0000", 1)
	if err := os.WriteFile(adapterPath, []byte(badScript), 0o700); err != nil {
		t.Fatal(err)
	}
	response = executor.Execute(context.Background(), request)
	if response.Accepted || response.ErrorCode != "boot_guard_binding_mismatch" {
		t.Fatalf("mismatched boot guard binding was accepted: %+v", response)
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
