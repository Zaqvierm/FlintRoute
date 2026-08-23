package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// AdapterExecutor is the deliberately boring privileged side of the helper
// boundary.  The request can select only one of the fixed verbs below; it can
// never provide an executable, a path, or a shell fragment.
type AdapterExecutor struct {
	AdapterPath string
	ConfigPath  string
	InitDir     string
}

func (e AdapterExecutor) Execute(ctx context.Context, request Request) Response {
	response := ResponseFrom(request, false, "", "")
	if err := ValidateRequest(request); err != nil {
		response.ErrorCode = errorCode(err)
		response.Error = "helper request rejected"
		return response
	}
	if err := e.validatePaths(); err != nil {
		response.ErrorCode = "helper_configuration_invalid"
		response.Error = err.Error()
		return response
	}
	if strings.HasPrefix(request.Command, "transaction.") {
		return e.executeTransaction(ctx, request)
	}
	if strings.HasPrefix(request.Command, "service.") {
		return e.executeService(ctx, request)
	}
	if strings.HasPrefix(request.Command, "nft.") || strings.HasPrefix(request.Command, "ip_plan.") || strings.HasPrefix(request.Command, "artifact.") {
		return e.executeOwned(ctx, request)
	}
	response.ErrorCode = "unknown_command"
	response.Error = "helper command is not allowlisted"
	return response
}

func (e AdapterExecutor) validatePaths() error {
	if !filepath.IsAbs(e.AdapterPath) || filepath.Base(e.AdapterPath) != "adapter.sh" {
		return errors.New("adapter path is not allowlisted")
	}
	if !filepath.IsAbs(e.ConfigPath) || filepath.Base(e.ConfigPath) != "default.json" {
		return errors.New("config path is not allowlisted")
	}
	if e.InitDir == "" {
		e.InitDir = "/etc/init.d"
	}
	if !filepath.IsAbs(e.InitDir) || filepath.Clean(e.InitDir) != e.InitDir {
		return errors.New("init directory is not allowlisted")
	}
	return nil
}

func transactionVerb(command string) (string, bool) {
	switch command {
	case "transaction.prepare":
		return "prepare", true
	case "transaction.validate_candidate":
		return "validate-candidate", true
	case "transaction.snapshot_current":
		return "snapshot-current", true
	case "transaction.apply_candidate":
		return "apply-candidate", true
	case "transaction.verify_management":
		return "verify-management", true
	case "transaction.verify_data_plane":
		return "verify-data-plane", true
	case "transaction.commit_prepared":
		return "commit-prepared", true
	case "transaction.finalize_commit":
		return "finalize-commit", true
	case "transaction.rollback":
		return "rollback", true
	case "transaction.reconcile":
		return "reconcile", true
	default:
		return "", false
	}
}

func (e AdapterExecutor) executeTransaction(ctx context.Context, request Request) Response {
	response := ResponseFrom(request, false, "", "")
	verb, ok := transactionVerb(request.Command)
	if !ok {
		response.ErrorCode = "unknown_command"
		response.Error = "transaction operation is not allowlisted"
		return response
	}
	args := []string{verb, e.ConfigPath, request.TransactionID, request.RevisionID, request.CandidateHash, request.ArtifactManifestHash}
	command := exec.CommandContext(ctx, e.AdapterPath, args...)
	raw, err := command.Output()
	if exitErr := new(exec.ExitError); errors.As(err, &exitErr) {
		raw = append(raw, exitErr.Stderr...)
	}
	if len(raw) > 64<<10 {
		raw = raw[:64<<10]
	}
	response.Evidence = parseEvidence(raw)
	response.Operation = response.Evidence["operation"]
	if response.Operation == "" {
		response.Operation = verb
	}
	response.SemanticState = response.Evidence["transaction_state"]
	response.Reason = response.Evidence["reason"]
	response.Committed = response.Evidence["committed"] == "true"
	response.RollbackCapable = response.Evidence["rollback_capable"] == "true"
	response.ManagementVerified = response.Evidence["management_ok"] == "true"
	response.DataPlaneVerified = response.Evidence["data_plane_ok"] == "true"
	if err != nil {
		response.ErrorCode = "adapter_exit_nonzero"
		response.Error = "owned adapter operation failed"
		return response
	}
	if request.Command == "transaction.rollback" && response.Evidence["rollback"] != "true" {
		response.ErrorCode = "rollback_not_semantically_confirmed"
		response.Error = "adapter exited successfully without proving rollback"
		return response
	}
	if request.Command == "transaction.commit_prepared" && (response.SemanticState != "adapter_activated" || response.Committed || !response.RollbackCapable) {
		response.ErrorCode = "commit_prepare_not_semantically_confirmed"
		response.Error = "adapter did not prove activation with rollback retained"
		return response
	}
	if request.Command == "transaction.finalize_commit" && (response.SemanticState != "committed" || !response.Committed || response.RollbackCapable) {
		response.ErrorCode = "commit_finalize_not_semantically_confirmed"
		response.Error = "adapter did not prove finalized commit"
		return response
	}
	if request.Command == "transaction.reconcile" {
		reconcileState := response.Evidence["reconcile"]
		if reconcileState == "skipped-no-last-good" {
			response.SemanticState = "skipped"
		} else if reconcileState != "ok" && reconcileState != "noop" {
			response.ErrorCode = "reconcile_not_semantically_confirmed"
			response.Error = "adapter did not prove a bounded reconcile result"
			return response
		} else {
			for key, expected := range map[string]string{
				"operation":                     "reconcile",
				"generation":                    request.Generation,
				"transaction_id":                request.TransactionID,
				"active_transaction":            request.TransactionID,
				"active_revision":               request.RevisionID,
				"active_candidate_hash":         request.CandidateHash,
				"active_artifact_manifest_hash": request.ArtifactManifestHash,
			} {
				if response.Evidence[key] != expected {
					response.ErrorCode = "reconcile_binding_mismatch"
					response.Error = "adapter reconcile evidence did not match the requested target"
					return response
				}
			}
			if response.SemanticState != "committed" {
				response.ErrorCode = "reconcile_state_not_committed"
				response.Error = "adapter reconcile did not prove committed state"
				return response
			}
		}
	}
	response.Accepted = true
	response.State = "accepted"
	return response
}

func ownedVerb(request Request) (verb string, extra string, ok bool) {
	switch request.Command {
	case "nft.replace_owned_table":
		return "replace-owned-nft", "", true
	case "ip_plan.apply":
		return "apply-ip-plan", "", true
	case "ip_plan.rollback":
		return "rollback-ip-plan", "", true
	case "artifact.install", "artifact.remove":
		return "artifact-" + request.Artifact.Operation, request.Artifact.Kind, true
	default:
		return "", "", false
	}
}

func (e AdapterExecutor) executeOwned(ctx context.Context, request Request) Response {
	response := ResponseFrom(request, false, "", "")
	verb, extra, ok := ownedVerb(request)
	if !ok {
		response.ErrorCode = "unknown_command"
		response.Error = "owned operation is not allowlisted"
		return response
	}
	args := []string{verb, e.ConfigPath, request.TransactionID, request.RevisionID, request.CandidateHash, request.ArtifactManifestHash}
	if extra != "" {
		args = append(args, extra)
	}
	command := exec.CommandContext(ctx, e.AdapterPath, args...)
	raw, err := command.Output()
	if exitErr := new(exec.ExitError); errors.As(err, &exitErr) {
		raw = append(raw, exitErr.Stderr...)
	}
	if len(raw) > 64<<10 {
		raw = raw[:64<<10]
	}
	response.Evidence = parseEvidence(raw)
	response.Operation = response.Evidence["operation"]
	if response.Operation == "" {
		response.Operation = request.Command
	}
	response.SemanticState = response.Evidence["transaction_state"]
	response.Reason = response.Evidence["reason"]
	response.Committed = response.Evidence["committed"] == "true"
	response.RollbackCapable = response.Evidence["rollback_capable"] == "true"
	if err != nil {
		response.ErrorCode = "adapter_exit_nonzero"
		response.Error = "owned adapter operation failed"
		return response
	}
	if response.Evidence["generation"] != "" && response.Evidence["generation"] != request.Generation {
		response.ErrorCode = "generation_binding_mismatch"
		response.Error = "adapter returned a different generation"
		return response
	}
	response.Accepted = true
	response.State = "accepted"
	return response
}

func (e AdapterExecutor) executeService(ctx context.Context, request Request) Response {
	response := ResponseFrom(request, false, "", "")
	initDir := e.InitDir
	if initDir == "" {
		initDir = "/etc/init.d"
	}
	path := filepath.Join(initDir, request.Service.Name)
	if filepath.Dir(path) != initDir || filepath.Base(path) != request.Service.Name {
		response.ErrorCode = "service_path_not_allowlisted"
		response.Error = "service path is not owned"
		return response
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		response.ErrorCode = "service_not_owned"
		response.Error = "allowlisted service script is unavailable"
		return response
	}
	command := exec.CommandContext(ctx, path, request.Service.Operation)
	if err := command.Run(); err != nil {
		response.ErrorCode = "service_operation_failed"
		response.Error = fmt.Sprintf("managed service operation failed: %s", request.Service.Operation)
		return response
	}
	response.Accepted = true
	response.State = "accepted"
	response.Operation = request.Service.Operation
	return response
}

func parseEvidence(raw []byte) map[string]string {
	evidence := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || key == "" || len(key) > 64 || strings.ContainsAny(key, " \t\r\n") {
			continue
		}
		evidence[key] = value
	}
	return evidence
}
