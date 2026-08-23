// Package helper defines the narrow controller-to-root-helper protocol.
// Requests are typed, generation-bound and fail closed on unknown fields.
package helper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const ProtocolVersion = 1

var (
	ErrUnknownCommand = errors.New("helper command is not allowlisted")
	ErrInvalidRequest = errors.New("helper request is invalid")
	ErrPeerRejected   = errors.New("helper peer credentials rejected")
)

type Request struct {
	ProtocolVersion      int                 `json:"protocol_version"`
	RequestID            string              `json:"request_id"`
	Command              string              `json:"command"`
	Generation           string              `json:"generation"`
	RevisionID           string              `json:"revision_id"`
	TransactionID        string              `json:"transaction_id"`
	RollbackTokenHash    string              `json:"rollback_token_hash,omitempty"`
	CandidateHash        string              `json:"candidate_hash,omitempty"`
	ArtifactManifestHash string              `json:"artifact_manifest_hash,omitempty"`
	Transaction          *TransactionRequest `json:"transaction,omitempty"`
	NFT                  *NFTRequest         `json:"nft,omitempty"`
	IPPlan               *IPPlanRequest      `json:"ip_plan,omitempty"`
	Service              *ServiceRequest     `json:"service,omitempty"`
	Artifact             *ArtifactRequest    `json:"artifact,omitempty"`
}

type TransactionRequest struct {
	Operation string `json:"operation"`
}

type NFTRequest struct {
	Family       string `json:"family"`
	Table        string `json:"table"`
	Generation   string `json:"generation"`
	ArtifactHash string `json:"artifact_hash"`
}

type IPPlanRequest struct {
	Generation string `json:"generation"`
	PlanHash   string `json:"plan_hash"`
	Operation  string `json:"operation"`
}

type ServiceRequest struct {
	Name      string `json:"name"`
	Operation string `json:"operation"`
}

type ArtifactRequest struct {
	Kind      string `json:"kind"`
	Hash      string `json:"hash"`
	Operation string `json:"operation"`
}

type Response struct {
	ProtocolVersion      int               `json:"protocol_version"`
	RequestID            string            `json:"request_id"`
	Command              string            `json:"command"`
	Operation            string            `json:"operation,omitempty"`
	Accepted             bool              `json:"accepted"`
	Committed            bool              `json:"committed"`
	RollbackCapable      bool              `json:"rollback_capable"`
	State                string            `json:"state"`
	SemanticState        string            `json:"semantic_state,omitempty"`
	Generation           string            `json:"generation"`
	RevisionID           string            `json:"revision_id"`
	TransactionID        string            `json:"transaction_id"`
	CandidateHash        string            `json:"candidate_hash,omitempty"`
	ArtifactManifestHash string            `json:"artifact_manifest_hash,omitempty"`
	RollbackTokenHash    string            `json:"rollback_token_hash,omitempty"`
	ErrorCode            string            `json:"error_code,omitempty"`
	Error                string            `json:"error,omitempty"`
	Reason               string            `json:"reason,omitempty"`
	ManagementVerified   bool              `json:"management_verified,omitempty"`
	DataPlaneVerified    bool              `json:"data_plane_verified,omitempty"`
	Evidence             map[string]string `json:"evidence,omitempty"`
}

type Executor interface {
	Execute(context.Context, Request) Response
}

type RejectingExecutor struct{}

func (RejectingExecutor) Execute(_ context.Context, request Request) Response {
	return ResponseFrom(request, false, "helper_executor_not_configured", "privileged operation is disabled")
}

func ResponseFrom(request Request, accepted bool, code, message string) Response {
	return Response{
		ProtocolVersion:      request.ProtocolVersion,
		RequestID:            request.RequestID,
		Command:              request.Command,
		Accepted:             accepted,
		State:                map[bool]string{true: "accepted", false: "rejected"}[accepted],
		Generation:           request.Generation,
		RevisionID:           request.RevisionID,
		TransactionID:        request.TransactionID,
		CandidateHash:        request.CandidateHash,
		ArtifactManifestHash: request.ArtifactManifestHash,
		RollbackTokenHash:    request.RollbackTokenHash,
		ErrorCode:            code,
		Error:                message,
	}
}

func ValidateRequest(request Request) error {
	if request.ProtocolVersion != ProtocolVersion || strings.TrimSpace(request.RequestID) == "" || len(request.RequestID) > 96 {
		return ErrInvalidRequest
	}
	if !safeToken(request.RequestID) || !safeToken(request.Generation) || !safeToken(request.RevisionID) || !safeToken(request.TransactionID) {
		return ErrInvalidRequest
	}
	if request.Command == "" {
		return ErrUnknownCommand
	}
	switch request.Command {
	case "transaction.prepare", "transaction.validate_candidate", "transaction.snapshot_current", "transaction.apply_candidate", "transaction.verify_management", "transaction.verify_data_plane", "transaction.commit_prepared", "transaction.finalize_commit", "transaction.rollback":
		if request.Transaction == nil || request.Transaction.Operation != transactionOperation(request.Command) || !requestBound(request) {
			return ErrInvalidRequest
		}
	case "nft.replace_owned_table":
		if !requestBound(request) || request.NFT == nil || request.NFT.Family != "inet" || !safeObjectName(request.NFT.Table) || request.NFT.Generation != request.Generation || request.NFT.ArtifactHash != request.ArtifactManifestHash {
			return ErrInvalidRequest
		}
	case "ip_plan.apply", "ip_plan.rollback":
		if !requestBound(request) || request.IPPlan == nil || request.IPPlan.Generation != request.Generation || request.IPPlan.Operation != strings.TrimPrefix(request.Command, "ip_plan.") || !safeHash(request.IPPlan.PlanHash) || request.IPPlan.PlanHash != request.ArtifactManifestHash {
			return ErrInvalidRequest
		}
	case "service.start", "service.stop", "service.reload":
		if !requestBound(request) || request.Service == nil || !allowlistedService(request.Service.Name) || request.Service.Operation != strings.TrimPrefix(request.Command, "service.") {
			return ErrInvalidRequest
		}
	case "artifact.install", "artifact.remove":
		if !requestBound(request) || request.Artifact == nil || !allowlistedArtifact(request.Artifact.Kind) || !safeHash(request.Artifact.Hash) || request.Artifact.Hash != request.ArtifactManifestHash || request.Artifact.Operation != strings.TrimPrefix(request.Command, "artifact.") {
			return ErrInvalidRequest
		}
	default:
		return ErrUnknownCommand
	}
	return nil
}

func requestBound(request Request) bool {
	return safeHash(request.RollbackTokenHash) && safeHash(request.CandidateHash) && safeHash(request.ArtifactManifestHash)
}

func transactionOperation(command string) string {
	switch command {
	case "transaction.prepare":
		return "prepare"
	case "transaction.validate_candidate":
		return "validate-candidate"
	case "transaction.snapshot_current":
		return "snapshot-current"
	case "transaction.apply_candidate":
		return "apply-candidate"
	case "transaction.verify_management":
		return "verify-management"
	case "transaction.verify_data_plane":
		return "verify-data-plane"
	case "transaction.commit_prepared":
		return "commit-prepared"
	case "transaction.finalize_commit":
		return "finalize-commit"
	case "transaction.rollback":
		return "rollback"
	default:
		return ""
	}
}

func safeToken(value string) bool {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n\x00/\\ ") {
		return false
	}
	return true
}

func safeObjectName(value string) bool {
	if !safeToken(value) || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func safeHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func allowlistedService(name string) bool {
	switch name {
	case "router-policy", "router-policy-xray", "router-policy-zapret", "router-policy-boot-guard":
		return true
	default:
		return false
	}
}

func allowlistedArtifact(kind string) bool {
	switch kind {
	case "xray_config", "zapret_config", "nft_table", "dnsmasq_config", "ip_plan":
		return true
	default:
		return false
	}
}

type ServerOptions struct {
	SocketPath string
	Executor   Executor
	PeerUID    int
}

func ServeUnix(ctx context.Context, options ServerOptions) error {
	if options.SocketPath == "" {
		options.SocketPath = "/var/run/router-policy/helper.sock"
	}
	if !filepath.IsAbs(options.SocketPath) || filepath.Base(options.SocketPath) != "helper.sock" {
		return errors.New("helper socket path is not allowlisted")
	}
	if options.Executor == nil {
		options.Executor = RejectingExecutor{}
	}
	if err := os.Remove(options.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", options.SocketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(options.SocketPath, 0o600); err != nil {
		return err
	}
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-closed:
		}
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go serveConnection(ctx, connection, options.Executor, options.PeerUID)
	}
}

func serveConnection(ctx context.Context, connection net.Conn, executor Executor, expectedPeerUID int) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
	if uid, err := peerUID(connection); err != nil || ValidatePeerUID(uid, expectedPeerUID) != nil {
		_ = writeResponse(connection, Response{ProtocolVersion: ProtocolVersion, State: "rejected", ErrorCode: "peer_rejected", Error: "helper peer credentials rejected"})
		return
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 64<<10))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		_ = writeResponse(connection, Response{ProtocolVersion: ProtocolVersion, State: "rejected", ErrorCode: "invalid_json", Error: "invalid helper request"})
		return
	}
	if err := ValidateRequest(request); err != nil {
		_ = writeResponse(connection, ResponseFrom(request, false, errorCode(err), "helper request rejected"))
		return
	}
	response := executor.Execute(ctx, request)
	if response.ProtocolVersion == 0 {
		response.ProtocolVersion = ProtocolVersion
	}
	_ = writeResponse(connection, response)
}

func writeResponse(writer io.Writer, response Response) error {
	encoder := json.NewEncoder(writer)
	return encoder.Encode(response)
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrUnknownCommand):
		return "unknown_command"
	case errors.Is(err, ErrPeerRejected):
		return "peer_rejected"
	default:
		return "invalid_request"
	}
}

// ValidatePeerUID is kept separate so Linux builds can add SO_PEERCRED
// without changing the wire protocol. The current server is still fail-closed
// when no dedicated peer credential adapter is supplied by the platform.
func ValidatePeerUID(uid, expected int) error {
	// The helper is a root service, so accepting uid 0 would turn a malformed
	// or defaulted peer-uid setting into a privileged self-call.  Only an
	// explicitly configured non-root controller identity is valid.
	if uid <= 0 || expected <= 0 || uid != expected {
		return ErrPeerRejected
	}
	return nil
}
