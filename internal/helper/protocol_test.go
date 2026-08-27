package helper

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func validRequest(command string) Request {
	return Request{
		ProtocolVersion:      ProtocolVersion,
		RequestID:            "req_1",
		Command:              command,
		Generation:           "gen_1",
		RevisionID:           "rev_1",
		TransactionID:        "tx_1",
		CandidateHash:        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ArtifactManifestHash: "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		RollbackTokenHash:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

func TestValidateRequestRejectsUnknownCommandsAndObjects(t *testing.T) {
	request := validRequest("shell.exec")
	if err := ValidateRequest(request); err != ErrUnknownCommand {
		t.Fatalf("unknown command returned %v", err)
	}
	request = validRequest("service.start")
	request.Service = &ServiceRequest{Name: "dnsmasq", Operation: "start"}
	if err := ValidateRequest(request); err == nil {
		t.Fatal("foreign service was accepted")
	}
	request = validRequest("service.start")
	request.Service = &ServiceRequest{Name: "router-policy-zapret-tv-q208", Operation: "start"}
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("owned device-scoped Zapret service was rejected: %v", err)
	}
	request.Service.Name = "router-policy-zapret-tv/q208"
	if err := ValidateRequest(request); err == nil {
		t.Fatal("profile service path traversal was accepted")
	}
}

func TestValidateRequestBindsGenerationAndHashes(t *testing.T) {
	request := validRequest("nft.replace_owned_table")
	request.NFT = &NFTRequest{Family: "inet", Table: "router_policy", Generation: "different", ArtifactHash: request.ArtifactManifestHash}
	if err := ValidateRequest(request); err == nil {
		t.Fatal("mismatched generation was accepted")
	}
	request.NFT.Generation = request.Generation
	request.NFT.Table = "../../etc"
	if err := ValidateRequest(request); err == nil {
		t.Fatal("path traversal table was accepted")
	}
}

func TestValidateRequestRequiresTypedOperationAndAllBindings(t *testing.T) {
	request := validRequest("transaction.commit_prepared")
	request.Transaction = &TransactionRequest{Operation: "commit"}
	if err := ValidateRequest(request); err == nil {
		t.Fatal("transaction accepted an operation that did not match its command")
	}
	request.Transaction.Operation = "commit-prepared"
	request.CandidateHash = ""
	if err := ValidateRequest(request); err == nil {
		t.Fatal("transaction accepted without candidate binding")
	}
}

func TestValidateRequestAllowsBoundRecoveryWithoutRollbackCapability(t *testing.T) {
	request := validRequest("transaction.reconcile")
	request.RollbackTokenHash = ""
	request.Generation = request.RevisionID
	request.Transaction = &TransactionRequest{Operation: "reconcile"}
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("recovery reconcile rejected without rollback capability: %v", err)
	}
	request.CandidateHash = ""
	if err := ValidateRequest(request); err == nil {
		t.Fatal("recovery reconcile accepted without candidate binding")
	}
}

func TestOwnedVerbMappingIsClosed(t *testing.T) {
	for command, want := range map[string]string{
		"nft.replace_owned_table": "replace-owned-nft",
		"ip_plan.apply":           "apply-ip-plan",
		"ip_plan.rollback":        "rollback-ip-plan",
		"artifact.install":        "artifact-install",
		"artifact.remove":         "artifact-remove",
	} {
		request := validRequest(command)
		switch command {
		case "nft.replace_owned_table":
			request.NFT = &NFTRequest{Family: "inet", Table: "router_policy", Generation: request.Generation, ArtifactHash: request.ArtifactManifestHash}
		case "ip_plan.apply", "ip_plan.rollback":
			request.IPPlan = &IPPlanRequest{Generation: request.Generation, PlanHash: request.ArtifactManifestHash, Operation: strings.TrimPrefix(command, "ip_plan.")}
		case "artifact.install", "artifact.remove":
			request.Artifact = &ArtifactRequest{Kind: "xray_config", Hash: request.ArtifactManifestHash, Operation: strings.TrimPrefix(command, "artifact.")}
		}
		if err := ValidateRequest(request); err != nil {
			t.Fatalf("%s rejected: %v", command, err)
		}
		got, _, ok := ownedVerb(request)
		if !ok || got != want {
			t.Fatalf("%s mapped to %q/%v, want %q/true", command, got, ok, want)
		}
	}
	request := validRequest("artifact.install")
	request.Artifact = &ArtifactRequest{Kind: "zapret_profile_manifest", Hash: request.ArtifactManifestHash, Operation: "install"}
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("device-scoped Zapret manifest artifact was rejected: %v", err)
	}
	if _, _, ok := ownedVerb(validRequest("nft.exec")); ok {
		t.Fatal("unknown owned command was accepted")
	}
}

func TestResponseFromPreservesSemanticBinding(t *testing.T) {
	request := validRequest("transaction.rollback")
	request.Transaction = &TransactionRequest{Operation: "rollback"}
	response := ResponseFrom(request, false, "ambiguous", "adapter state is unknown")
	if response.RequestID != request.RequestID || response.TransactionID != request.TransactionID || response.State != "rejected" || response.ErrorCode != "ambiguous" {
		t.Fatalf("semantic response lost binding: %+v", response)
	}
}

func TestCallRejectsSemanticHashMismatch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("unix helper transport is only exercised on Linux")
	}
	socket := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var request Request
		if json.NewDecoder(connection).Decode(&request) != nil {
			return
		}
		response := ResponseFrom(request, true, "", "")
		response.CandidateHash = "sha256:" + strings.Repeat("b", 64)
		_ = json.NewEncoder(connection).Encode(response)
	}()
	request := validRequest("transaction.rollback")
	request.Transaction = &TransactionRequest{Operation: "rollback"}
	_, err = Call(context.Background(), socket, request)
	if err == nil || !strings.Contains(err.Error(), "binding mismatch") {
		t.Fatalf("semantic hash mismatch was accepted: %v", err)
	}
}

func TestServeUnixBindsSocketAndPeerCredentials(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED is only available on Linux")
	}
	if os.Getuid() == 0 {
		t.Skip("test peer must be a non-root controller")
	}
	socket := filepath.Join(t.TempDir(), "helper.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ServeUnix(ctx, ServerOptions{SocketPath: socket, PeerUID: os.Getuid(), Executor: RejectingExecutor{}})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper socket was not created")
		}
		time.Sleep(5 * time.Millisecond)
	}
	info, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("helper socket mode=%o want 600", info.Mode().Perm())
	}
	connection, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest("transaction.rollback")
	request.Transaction = &TransactionRequest{Operation: "rollback"}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if response.ErrorCode != "helper_executor_not_configured" {
		t.Fatalf("unexpected helper response: %+v", response)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("helper server did not stop after context cancellation")
	}
}

func TestServeUnixDoesNotRemoveForeignSocketPathObject(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "helper.sock")
	const marker = "foreign-state"
	if err := os.WriteFile(socket, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ServeUnix(context.Background(), ServerOptions{
		SocketPath: socket,
		PeerUID:    1001,
		Executor:   RejectingExecutor{},
	})
	if err == nil || !strings.Contains(err.Error(), "non-socket") {
		t.Fatalf("foreign socket path was accepted: %v", err)
	}
	content, readErr := os.ReadFile(socket)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != marker {
		t.Fatalf("foreign socket path was modified: %q", content)
	}
}

func TestServeUnixDoesNotRemoveLiveSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	err = ServeUnix(context.Background(), ServerOptions{
		SocketPath: socket,
		PeerUID:    1001,
		Executor:   RejectingExecutor{},
	})
	if err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("live helper socket was not rejected: %v", err)
	}
	if _, err := net.Dial("unix", socket); err != nil {
		t.Fatalf("live helper socket was removed or stopped: %v", err)
	}
}
