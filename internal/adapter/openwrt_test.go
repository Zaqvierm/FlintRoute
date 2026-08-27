package adapter

import (
	"context"
	"encoding/json"
	"net"
	"runtime"
	"testing"

	"router-policy/internal/helper"
)

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

func TestOpenWrtRecoveryUsesTypedHelperWhenConfigured(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix helper boundary is only exercised on Linux")
	}
	listener, err := net.Listen("unix", t.TempDir()+"/helper.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	target := RecoveryTarget{
		TransactionID:        "tx_0011223344556677",
		RevisionID:           "rev_10_001122334455",
		CandidateHash:        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ArtifactManifestHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	requestSeen := make(chan helper.Request, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var request helper.Request
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			return
		}
		requestSeen <- request
		response := helper.ResponseFrom(request, true, "", "")
		response.SemanticState = "committed"
		response.Evidence = map[string]string{"operation": "reconcile", "reconcile": "noop", "transaction_state": "committed"}
		_ = json.NewEncoder(connection).Encode(response)
	}()
	a := &OpenWrt{helperSocket: listener.Addr().String()}
	result := a.Reconcile(context.Background(), target)
	if !result.OK || result.Status != "OK" {
		t.Fatalf("helper reconcile was not accepted: %+v", result)
	}
	select {
	case request := <-requestSeen:
		if request.Command != "transaction.reconcile" || request.Transaction == nil || request.Transaction.Operation != "reconcile" {
			t.Fatalf("unexpected recovery helper request: %+v", request)
		}
		if request.RollbackTokenHash != "" {
			t.Fatalf("recovery request unexpectedly carried rollback capability: %+v", request)
		}
	default:
		t.Fatal("recovery did not reach the typed helper")
	}
}

func TestOpenWrtGlobalUsesTypedHelperWhenConfigured(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix helper boundary is only exercised on Linux")
	}
	listener, err := net.Listen("unix", t.TempDir()+"/helper.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requestSeen := make(chan helper.Request, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var request helper.Request
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			return
		}
		requestSeen <- request
		response := helper.ResponseFrom(request, true, "", "")
		response.Operation = "status"
		response.Evidence = map[string]string{"operation": "status", "healthy": "true"}
		_ = json.NewEncoder(connection).Encode(response)
	}()
	a := &OpenWrt{helperSocket: listener.Addr().String()}
	result := a.Status(context.Background())
	if !result.OK || result.Status != "OK" {
		t.Fatalf("helper status was not accepted: %+v", result)
	}
	select {
	case request := <-requestSeen:
		if request.Command != "global.status" || request.Global == nil || request.Global.Operation != "status" {
			t.Fatalf("unexpected global helper request: %+v", request)
		}
		if request.Generation != "global" || request.CandidateHash != "" {
			t.Fatalf("global request was not narrowly bound: %+v", request)
		}
	default:
		t.Fatal("status did not reach the typed helper")
	}
}
