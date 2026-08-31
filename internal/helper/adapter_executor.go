package helper

import (
	"bytes"
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
	if request.Command == "recovery.clear_boot_guard_baseline" {
		return e.executeBaselineBootGuardClear(ctx, request)
	}
	if strings.HasPrefix(request.Command, "service.") {
		return e.executeService(ctx, request)
	}
	if strings.HasPrefix(request.Command, "nft.") || strings.HasPrefix(request.Command, "ip_plan.") || strings.HasPrefix(request.Command, "artifact.") {
		return e.executeOwned(ctx, request)
	}
	if strings.HasPrefix(request.Command, "global.") {
		return e.executeGlobal(ctx, request)
	}
	if strings.HasPrefix(request.Command, "probe.") {
		return e.executeProbe(ctx, request)
	}
	if strings.HasPrefix(request.Command, "route_assignment.") {
		if request.Command == "route_assignment.reconcile" {
			return e.executeRouteAssignmentReconcile(ctx, request)
		}
		return e.executeRouteAssignment(ctx, request)
	}
	response.ErrorCode = "unknown_command"
	response.Error = "helper command is not allowlisted"
	return response
}

func (e AdapterExecutor) executeProbe(ctx context.Context, request Request) Response {
	response := ResponseFrom(request, false, "", "")
	probeRequest := request.Probe
	if probeRequest == nil {
		response.ErrorCode = "invalid_probe_request"
		response.Error = "probe request is missing"
		return response
	}
	response.Operation = probeRequest.Operation
	response.SemanticState = "read_only"

	var output []byte
	var err error
	switch probeRequest.Operation {
	case "route_get":
		args := []string{"-j", "route", "get", probeRequest.Destination}
		if probeRequest.Mark != "" {
			args = append(args, "mark", probeRequest.Mark)
		}
		output, err = runFixedProbeCommand(ctx, "/sbin/ip", args...)
	case "rules":
		output, err = runFixedProbeCommand(ctx, "/sbin/ip", "-"+probeRequest.Family, "-j", "rule", "show")
	case "default_route":
		output, err = runFixedProbeCommand(ctx, "/sbin/ip", "-"+probeRequest.Family, "-j", "route", "show", "table", fmt.Sprint(probeRequest.Table), "default")
	case "nft_policy":
		output, err = runFixedProbeCommand(ctx, "/usr/sbin/nft", "-j", "list", "table", "inet", "router_policy")
	case "process":
		output, err = runFixedProbeCommand(ctx, "/bin/pidof", probeRequest.Process)
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
				output = []byte("false")
				err = nil
			}
		} else {
			output = []byte("true")
		}
	case "conntrack":
		for _, path := range []string{"/proc/net/nf_conntrack", "/proc/net/ip_conntrack"} {
			contents, readErr := os.ReadFile(path)
			if readErr != nil {
				err = readErr
				continue
			}
			if len(contents) > 8<<20 {
				err = fmt.Errorf("conntrack output exceeds limit")
				break
			}
			for _, line := range strings.Split(string(contents), "\n") {
				if !strings.Contains(line, "src="+probeRequest.LocalIP) || !strings.Contains(line, "dst="+probeRequest.ConnectedIP) {
					continue
				}
				for _, field := range strings.Fields(line) {
					if strings.HasPrefix(field, "mark=") {
						output = []byte(strings.TrimPrefix(field, "mark="))
						err = nil
						break
					}
				}
				if len(output) > 0 {
					break
				}
			}
			if len(output) > 0 {
				break
			}
		}
		if len(output) == 0 && err == nil {
			err = errors.New("conntrack_mark_not_found")
		}
	default:
		err = errors.New("probe operation is not allowlisted")
	}
	if err != nil {
		response.ErrorCode = "probe_command_failed"
		response.Error = "read-only probe command failed"
		return response
	}
	if len(output) > 8<<20 {
		response.ErrorCode = "probe_output_exceeded"
		response.Error = "read-only probe output exceeded limit"
		return response
	}
	response.Evidence = map[string]string{"payload": string(output)}
	response.Accepted = true
	response.State = "accepted"
	return response
}

func runFixedProbeCommand(ctx context.Context, path string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, path, args...)
	var output boundedProbeOutput
	var stderr boundedProbeOutput
	command.Stdout = &output
	command.Stderr = &stderr
	err := command.Run()
	if output.exceeded || stderr.exceeded {
		return nil, errors.New("probe output exceeded limit")
	}
	return output.Bytes(), err
}

type boundedProbeOutput struct {
	bytes.Buffer
	exceeded bool
}

func (b *boundedProbeOutput) Write(data []byte) (int, error) {
	const maxBytes = 8 << 20
	if b.Len()+len(data) > maxBytes {
		b.exceeded = true
		return len(data), nil
	}
	return b.Buffer.Write(data)
}

func (e AdapterExecutor) executeBaselineBootGuardClear(ctx context.Context, request Request) Response {
	response := ResponseFrom(request, false, "", "")
	command := exec.CommandContext(ctx, e.AdapterPath, "clear-boot-guard-baseline", e.ConfigPath, "baseline", request.RevisionID, request.CandidateHash)
	raw, err := command.Output()
	if exitErr := new(exec.ExitError); errors.As(err, &exitErr) {
		raw = append(raw, exitErr.Stderr...)
	}
	if len(raw) > 64<<10 {
		raw = raw[:64<<10]
	}
	response.Evidence = parseEvidence(raw)
	response.Operation = response.Evidence["operation"]
	response.SemanticState = response.Evidence["transaction_state"]
	response.Reason = response.Evidence["reason"]
	if err != nil {
		response.ErrorCode = "adapter_exit_nonzero"
		response.Error = "baseline boot guard clear failed"
		return response
	}
	for key, expected := range map[string]string{
		"operation":             "clear-boot-guard-baseline",
		"generation":            request.Generation,
		"transaction_id":        "baseline",
		"revision_id":           request.RevisionID,
		"candidate_hash":        request.CandidateHash,
		"active_revision":       request.RevisionID,
		"active_candidate_hash": request.CandidateHash,
	} {
		if response.Evidence[key] != expected {
			response.ErrorCode = "baseline_boot_guard_binding_mismatch"
			response.Error = "adapter baseline clear evidence did not match the request"
			return response
		}
	}
	if response.Evidence["boot_guard"] != "cleared" || response.SemanticState != "baseline_confirmed" {
		response.ErrorCode = "boot_guard_not_semantically_confirmed"
		response.Error = "adapter did not prove baseline-bound boot guard removal"
		return response
	}
	response.Accepted = true
	response.State = "accepted"
	return response
}

func (e AdapterExecutor) executeGlobal(ctx context.Context, request Request) Response {
	response := ResponseFrom(request, false, "", "")
	verb := globalOperation(request.Command)
	if verb == "" {
		response.ErrorCode = "unknown_command"
		response.Error = "global operation is not allowlisted"
		return response
	}
	command := exec.CommandContext(ctx, e.AdapterPath, verb, e.ConfigPath)
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
	response.Reason = response.Evidence["reason"]
	if err != nil {
		response.ErrorCode = "adapter_exit_nonzero"
		response.Error = "owned global operation failed"
		return response
	}
	if verb == "clear-boot-guard" && response.Evidence["boot_guard"] != "cleared" {
		response.ErrorCode = "boot_guard_not_semantically_confirmed"
		response.Error = "adapter did not prove boot guard removal"
		return response
	}
	response.Accepted = true
	response.State = "accepted"
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
	case "transaction.clear_boot_guard":
		return "clear-boot-guard-bound", true
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
	if request.Command != "transaction.reconcile" || response.Evidence["reconcile"] != "skipped-no-last-good" {
		if code, message := evidenceBindingError(request, response.Evidence, transactionOperation(request.Command)); code != "" {
			response.ErrorCode = code
			response.Error = message
			return response
		}
		if request.Command == "transaction.validate_candidate" && response.Evidence["candidate_valid"] != "true" {
			response.ErrorCode = "candidate_not_verified"
			response.Error = "adapter did not prove that the candidate is deployable"
			response.Reason = response.Evidence["reason"]
			return response
		}
	}
	if request.Command == "transaction.rollback" && response.Evidence["rollback"] != "true" {
		response.ErrorCode = "rollback_not_semantically_confirmed"
		response.Error = "adapter exited successfully without proving rollback"
		return response
	}
	if request.Command == "transaction.clear_boot_guard" {
		if response.Evidence["boot_guard"] != "cleared" || response.SemanticState != "committed" {
			response.ErrorCode = "boot_guard_not_semantically_confirmed"
			response.Error = "adapter did not prove generation-bound boot guard removal"
			return response
		}
		for key, expected := range map[string]string{
			"operation":                     "clear-boot-guard",
			"generation":                    request.Generation,
			"transaction_id":                request.TransactionID,
			"active_transaction":            request.TransactionID,
			"active_revision":               request.RevisionID,
			"active_candidate_hash":         request.CandidateHash,
			"active_artifact_manifest_hash": request.ArtifactManifestHash,
		} {
			if response.Evidence[key] != expected {
				response.ErrorCode = "boot_guard_binding_mismatch"
				response.Error = "adapter boot guard evidence did not match the committed transaction"
				return response
			}
		}
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
	case "route_assignment.apply", "route_assignment.rollback":
		return "route-assignment-" + request.RouteAssignment.Operation, "", true
	default:
		return "", "", false
	}
}

func (e AdapterExecutor) executeRouteAssignment(ctx context.Context, request Request) Response {
	response := ResponseFrom(request, false, "", "")
	if request.RouteAssignment == nil {
		response.ErrorCode = "route_assignment_request_missing"
		response.Error = "route assignment payload is required"
		return response
	}
	verb, _, ok := ownedVerb(request)
	if !ok {
		response.ErrorCode = "unknown_command"
		response.Error = "route assignment operation is not allowlisted"
		return response
	}
	r := request.RouteAssignment
	args := []string{verb, e.ConfigPath, request.TransactionID, request.RevisionID, request.CandidateHash, request.ArtifactManifestHash,
		r.Domain, r.RouteTag, r.RouteType, r.RouteSetID, r.AssignmentID, r.MappingHash, request.RequestID}
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
		response.Operation = "route_assignment." + r.Operation
	}
	response.SemanticState = response.Evidence["transaction_state"]
	response.Reason = response.Evidence["reason"]
	response.Committed = response.Evidence["committed"] == "true"
	response.RollbackCapable = response.Evidence["rollback_capable"] == "true"
	if err != nil {
		response.ErrorCode = "adapter_exit_nonzero"
		response.Error = "owned route assignment operation failed"
		return response
	}
	if code, message := evidenceBindingError(request, response.Evidence, response.Operation); code != "" {
		response.ErrorCode = code
		response.Error = message
		return response
	}
	for key, want := range map[string]string{
		"domain": r.Domain, "route_tag": r.RouteTag, "route_type": r.RouteType,
		"route_set_id": r.RouteSetID, "assignment_id": r.AssignmentID, "mapping_hash": r.MappingHash,
	} {
		if response.Evidence[key] != want {
			response.ErrorCode = "route_assignment_binding_mismatch"
			response.Error = "adapter route assignment evidence did not match the request"
			return response
		}
	}
	if r.Operation == "apply" && (response.Evidence["applied"] != "true" || response.Evidence["verified"] != "true") {
		response.ErrorCode = "route_assignment_not_semantically_confirmed"
		response.Error = "adapter did not prove route assignment apply and verification"
		return response
	}
	if r.Operation == "rollback" && (response.Evidence["rollback"] != "true" || response.Evidence["verified"] != "true") {
		response.ErrorCode = "route_assignment_rollback_not_semantically_confirmed"
		response.Error = "adapter did not prove route assignment rollback and verification"
		return response
	}
	response.RouteAssignment = &RouteAssignmentResponse{
		Domain: r.Domain, RouteTag: r.RouteTag, RouteType: r.RouteType,
		RouteSetID: r.RouteSetID, AssignmentID: r.AssignmentID, MappingHash: r.MappingHash,
		Applied: response.Evidence["applied"] == "true", Verified: response.Evidence["verified"] == "true",
	}
	response.Accepted = true
	response.State = "accepted"
	return response
}

func (e AdapterExecutor) executeRouteAssignmentReconcile(ctx context.Context, request Request) Response {
	response := ResponseFrom(request, false, "", "")
	command := exec.CommandContext(ctx, e.AdapterPath, "route-assignment-reconcile", e.ConfigPath, request.TransactionID, request.RevisionID, request.CandidateHash, request.ArtifactManifestHash, request.RequestID)
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
	if err != nil {
		response.ErrorCode = "adapter_exit_nonzero"
		response.Error = "owned route assignment reconcile failed"
		return response
	}
	if code, message := evidenceBindingError(request, response.Evidence, response.Operation); code != "" {
		response.ErrorCode = code
		response.Error = message
		return response
	}
	if response.Evidence["reconciled"] != "true" || response.Evidence["verified"] != "true" {
		response.ErrorCode = "route_assignment_reconcile_not_semantically_confirmed"
		response.Error = "adapter did not prove route assignment reconcile"
		return response
	}
	response.Accepted = true
	response.State = "accepted"
	return response
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
	if code, message := evidenceBindingError(request, response.Evidence, request.Command); code != "" {
		response.ErrorCode = code
		response.Error = message
		return response
	}
	response.Accepted = true
	response.State = "accepted"
	return response
}

// evidenceBindingError is the semantic second factor for adapter success.
// ResponseFrom binds the helper envelope, but the adapter's own stdout must
// independently prove that it executed this operation for the same resource
// generation. Missing fields are rejected just like mismatched fields; an
// exit code of zero is never enough.
func evidenceBindingError(request Request, evidence map[string]string, operation string) (string, string) {
	expected := map[string]string{
		"operation":              operation,
		"generation":             request.Generation,
		"transaction_id":         request.TransactionID,
		"revision_id":            request.RevisionID,
		"candidate_hash":         request.CandidateHash,
		"artifact_manifest_hash": request.ArtifactManifestHash,
	}
	if request.RollbackTokenHash != "" {
		expected["rollback_token_hash"] = request.RollbackTokenHash
	}
	for key, want := range expected {
		got, present := evidence[key]
		if !present || strings.TrimSpace(got) == "" {
			return "adapter_response_binding_missing", "adapter response omitted required " + key + " binding"
		}
		if got != want {
			return "adapter_response_binding_mismatch", "adapter response " + key + " binding did not match the request"
		}
	}
	return "", ""
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
	if strings.HasPrefix(request.Service.Name, "router-policy-zapret-") && filepath.Clean(initDir) == "/etc/init.d" {
		if !ownedDeviceZapretService(request.Service.Name) {
			response.ErrorCode = "service_not_owned"
			response.Error = "device-scoped Zapret service is not bound to the active profile manifest"
			return response
		}
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
	// An init script returning zero only proves that it accepted the request.
	// The helper must prove the resulting lifecycle state before reporting a
	// successful privileged operation. OpenWrt procd exposes the fixed
	// read-only "running" action for managed init scripts.
	running := exec.CommandContext(ctx, path, "running").Run() == nil
	switch request.Service.Operation {
	case "start", "reload":
		if !running {
			response.ErrorCode = "service_not_running"
			response.Error = "managed service did not prove running after operation"
			return response
		}
		response.SemanticState = "running"
	case "stop":
		if running {
			response.ErrorCode = "service_still_running"
			response.Error = "managed service did not prove stopped after operation"
			return response
		}
		response.SemanticState = "stopped"
	}
	response.Accepted = true
	response.State = "accepted"
	response.Operation = request.Service.Operation
	return response
}

func ownedDeviceZapretService(name string) bool {
	raw, err := os.ReadFile("/etc/router-policy/zapret/profiles.manifest")
	if err != nil || len(raw) > 64<<10 {
		return false
	}
	want := "|/etc/init.d/" + name + "|"
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, want) {
			return true
		}
	}
	return false
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
