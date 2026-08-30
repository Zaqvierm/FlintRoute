package adapter

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"router-policy/internal/config"
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

func TestNewOpenWrtRequiresFixedHelperSocket(t *testing.T) {
	adapterPath, err := filepath.Abs(filepath.Join(t.TempDir(), "adapter.sh"))
	if err != nil {
		t.Fatal(err)
	}
	configPath, err := filepath.Abs(filepath.Join(t.TempDir(), "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	stateDir, err := filepath.Abs(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		OpenWrt: config.OpenWrt{Adapter: adapterPath},
		Storage: config.Storage{StateDir: stateDir},
	}
	for _, test := range []struct {
		name   string
		socket string
		wantOK bool
	}{
		{name: "missing", wantOK: false},
		{name: "foreign absolute", socket: "/tmp/other-helper.sock", wantOK: false},
		{name: "fixed production socket", socket: "/var/run/router-policy/helper.sock", wantOK: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("ROUTER_POLICY_HELPER_SOCKET", test.socket)
			adapter, err := NewOpenWrt(cfg, configPath)
			if test.wantOK {
				if err != nil || adapter == nil {
					t.Fatalf("fixed helper socket rejected: adapter=%v err=%v", adapter, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("unsafe helper socket accepted: %+v", adapter)
			}
		})
	}
}

func TestOpenWrtLegacyExecutionRejectsUnverifiedCandidate(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("legacy adapter execution fixture requires a POSIX shell")
	}
	dir := t.TempDir()
	adapterPath := filepath.Join(dir, "adapter.sh")
	script := "#!/bin/sh\n" +
		"echo transaction_state=candidate_requires_device\n" +
		"echo candidate_valid=false\n" +
		"echo verification_status=UNVERIFIED\n" +
		"echo reason=missing_device_diagnostics\n"
	if err := os.WriteFile(adapterPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	executor := &OpenWrt{helperPath: adapterPath}
	result := executor.execute(context.Background(), "validate-candidate", time.Now().UTC(), "default.json")
	if result.OK || result.Status != "UNVERIFIED" || result.Reason != "missing_device_diagnostics" {
		t.Fatalf("unverified candidate was accepted by legacy execution path: %+v", result)
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

func TestOpenWrtBaselineBootGuardUsesTypedBoundHelper(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix helper boundary is only exercised on Linux")
	}
	listener, err := net.Listen("unix", t.TempDir()+"/helper.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	revision := "rev_1_001122334455"
	candidateHash := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
		response.Operation = "clear-boot-guard-baseline"
		response.SemanticState = "baseline_confirmed"
		response.Evidence = map[string]string{
			"operation":             "clear-boot-guard-baseline",
			"generation":            revision,
			"transaction_id":        "baseline",
			"revision_id":           revision,
			"candidate_hash":        candidateHash,
			"active_revision":       revision,
			"active_candidate_hash": candidateHash,
			"boot_guard":            "cleared",
			"transaction_state":     "baseline_confirmed",
		}
		_ = json.NewEncoder(connection).Encode(response)
	}()
	a := &OpenWrt{helperSocket: listener.Addr().String()}
	result := a.ClearBootGuardForBaseline(context.Background(), revision, candidateHash)
	if !result.OK || result.Status != "OK" {
		t.Fatalf("typed baseline boot-guard clear was not accepted: %+v", result)
	}
	select {
	case request := <-requestSeen:
		if request.Command != "recovery.clear_boot_guard_baseline" || request.Baseline == nil || request.Baseline.Operation != "clear-boot-guard" {
			t.Fatalf("unexpected baseline helper request: %+v", request)
		}
		if request.TransactionID != "baseline" || request.RevisionID != revision || request.CandidateHash != candidateHash || request.ArtifactManifestHash != "" || request.RollbackTokenHash != "" {
			t.Fatalf("baseline request was not narrowly bound: %+v", request)
		}
	default:
		t.Fatal("baseline clear did not reach the typed helper")
	}
}
