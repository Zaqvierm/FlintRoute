package adapter

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/helper"
)

var (
	transactionIDPattern = regexp.MustCompile(`^tx_[a-f0-9]{16}$`)
	revisionIDPattern    = regexp.MustCompile(`^rev_[0-9]+_[a-f0-9]{12}$`)
	changeIDPattern      = regexp.MustCompile(`^chg_[a-f0-9]{16}$`)
	sha256Pattern        = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	evidenceKeyPattern   = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
)

type OpenWrt struct {
	helperPath   string
	configPath   string
	stateDir     string
	helperSocket string
}

func NewOpenWrt(cfg *config.Config, configPath string) (*OpenWrt, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	helper := filepath.Clean(cfg.OpenWrt.Adapter)
	if helper == "." || !filepath.IsAbs(helper) {
		return nil, fmt.Errorf("openwrt adapter helper must be an absolute path")
	}
	cleanConfig := filepath.Clean(configPath)
	if cleanConfig == "." || !filepath.IsAbs(cleanConfig) {
		return nil, fmt.Errorf("production config path must be absolute")
	}
	stateDir := filepath.Clean(cfg.Storage.StateDir)
	if stateDir == "." || !filepath.IsAbs(stateDir) {
		return nil, fmt.Errorf("production state_dir must be absolute")
	}
	return &OpenWrt{helperPath: helper, configPath: cleanConfig, stateDir: stateDir, helperSocket: os.Getenv("ROUTER_POLICY_HELPER_SOCKET")}, nil
}

func (a *OpenWrt) Diagnose(ctx context.Context) StepResult { return a.runGlobal(ctx, "diagnose") }
func (a *OpenWrt) ClearBootGuard(ctx context.Context) StepResult {
	return a.runGlobal(ctx, "clear-boot-guard")
}
func (a *OpenWrt) ClearBootGuardForTransaction(ctx context.Context, tx Transaction) StepResult {
	return a.runTransaction(ctx, "clear-boot-guard", tx)
}
func (a *OpenWrt) Reconcile(ctx context.Context, target RecoveryTarget) StepResult {
	start := time.Now().UTC()
	if err := validateRecoveryTarget(target); err != nil {
		return failedStep("reconcile", start, err)
	}
	if a.helperSocket != "" {
		return a.executeHelperRecovery(ctx, start, target)
	}
	return a.execute(ctx, "reconcile", start, a.configPath, target.TransactionID, target.RevisionID, target.CandidateHash, target.ArtifactManifestHash)
}
func (a *OpenWrt) Status(ctx context.Context) StepResult { return a.runGlobal(ctx, "status") }

func (a *OpenWrt) Prepare(ctx context.Context, tx Transaction) StepResult {
	return a.runTransaction(ctx, "prepare", tx)
}
func (a *OpenWrt) ValidateCandidate(ctx context.Context, tx Transaction) StepResult {
	return a.runTransaction(ctx, "validate-candidate", tx)
}
func (a *OpenWrt) SnapshotCurrent(ctx context.Context, tx Transaction) StepResult {
	return a.runTransaction(ctx, "snapshot-current", tx)
}
func (a *OpenWrt) ApplyCandidate(ctx context.Context, tx Transaction) StepResult {
	return a.runTransaction(ctx, "apply-candidate", tx)
}
func (a *OpenWrt) VerifyManagementPath(ctx context.Context, tx Transaction) StepResult {
	return a.runTransaction(ctx, "verify-management", tx)
}
func (a *OpenWrt) VerifyDataPlane(ctx context.Context, tx Transaction) StepResult {
	return a.runTransaction(ctx, "verify-data-plane", tx)
}
func (a *OpenWrt) Commit(ctx context.Context, tx Transaction) StepResult {
	return a.runTransaction(ctx, "commit", tx)
}
func (a *OpenWrt) CommitPrepared(ctx context.Context, tx Transaction) StepResult {
	return a.runTransaction(ctx, "commit-prepared", tx)
}
func (a *OpenWrt) FinalizeCommit(ctx context.Context, tx Transaction) StepResult {
	return a.runTransaction(ctx, "finalize-commit", tx)
}
func (a *OpenWrt) Rollback(ctx context.Context, tx Transaction) StepResult {
	return a.runTransaction(ctx, "rollback", tx)
}

func (a *OpenWrt) runGlobal(ctx context.Context, command string) StepResult {
	start := time.Now().UTC()
	if !allowedGlobalCommand(command) {
		return failedStep(command, start, fmt.Errorf("command is not allowlisted"))
	}
	if a.helperSocket != "" {
		return a.executeHelperGlobal(ctx, command, start)
	}
	return a.execute(ctx, command, start, a.configPath)
}

func (a *OpenWrt) executeHelperGlobal(ctx context.Context, command string, start time.Time) StepResult {
	requestID, err := secureRandomHex(8)
	if err != nil {
		return failedStep(command, start, err)
	}
	request := helper.Request{
		ProtocolVersion: helper.ProtocolVersion,
		RequestID:       "req_" + requestID,
		Command:         "global." + strings.ReplaceAll(command, "-", "_"),
		Generation:      "global",
		RevisionID:      "global",
		TransactionID:   "global",
		Global:          &helper.GlobalRequest{Operation: command},
	}
	return a.executeHelperRequest(ctx, command, start, request)
}

func (a *OpenWrt) runTransaction(ctx context.Context, command string, tx Transaction) StepResult {
	start := time.Now().UTC()
	if !allowedTransactionCommand(command) {
		return failedStep(command, start, fmt.Errorf("command is not allowlisted"))
	}
	if err := a.validateTransaction(tx); err != nil {
		return failedStep(command, start, err)
	}
	if command != "prepare" && command != "finalize-commit" {
		if _, err := ReadCapability(tx); err != nil {
			return failedStep(command, start, err)
		}
	}
	if a.helperSocket != "" {
		return a.executeHelperTransaction(ctx, command, start, tx)
	}
	return a.execute(ctx, command, start, a.configPath, tx.ID, tx.RevisionID, tx.CandidateHash, tx.ArtifactManifestHash)
}

func (a *OpenWrt) executeHelperTransaction(ctx context.Context, command string, start time.Time, tx Transaction) StepResult {
	requestID, err := secureRandomHex(8)
	if err != nil {
		return failedStep(command, start, err)
	}
	request := helper.Request{
		ProtocolVersion:      helper.ProtocolVersion,
		RequestID:            "req_" + requestID,
		Command:              "transaction." + strings.ReplaceAll(command, "-", "_"),
		Generation:           tx.RevisionID,
		RevisionID:           tx.RevisionID,
		TransactionID:        tx.ID,
		RollbackTokenHash:    tx.RollbackTokenHash,
		CandidateHash:        tx.CandidateHash,
		ArtifactManifestHash: tx.ArtifactManifestHash,
		Transaction:          &helper.TransactionRequest{Operation: command},
	}
	return a.executeHelperRequest(ctx, command, start, request)
}

func (a *OpenWrt) executeHelperRecovery(ctx context.Context, start time.Time, target RecoveryTarget) StepResult {
	requestID, err := secureRandomHex(8)
	if err != nil {
		return failedStep("reconcile", start, err)
	}
	request := helper.Request{
		ProtocolVersion:      helper.ProtocolVersion,
		RequestID:            "req_" + requestID,
		Command:              "transaction.reconcile",
		Generation:           target.RevisionID,
		RevisionID:           target.RevisionID,
		TransactionID:        target.TransactionID,
		CandidateHash:        target.CandidateHash,
		ArtifactManifestHash: target.ArtifactManifestHash,
		Transaction:          &helper.TransactionRequest{Operation: "reconcile"},
	}
	return a.executeHelperRequest(ctx, "reconcile", start, request)
}

func (a *OpenWrt) executeHelperRequest(ctx context.Context, command string, start time.Time, request helper.Request) StepResult {
	response, callErr := helper.Call(ctx, a.helperSocket, request)
	result := StepResult{ProtocolVersion: AdapterProtocolVersion, RequestID: request.RequestID, Operation: command, Step: stepName(command), StartedAt: start, FinishedAt: time.Now().UTC(), Evidence: map[string]any{}}
	for key, value := range response.Evidence {
		result.Evidence[key] = value
	}
	result.Evidence["committed"] = response.Committed
	result.Evidence["rollback_capable"] = response.RollbackCapable
	result.SemanticState = response.SemanticState
	result.Committed = response.Committed
	result.RollbackCapable = response.RollbackCapable
	result.ManagementVerified = response.ManagementVerified
	result.DataPlaneVerified = response.DataPlaneVerified
	result.OK = callErr == nil && response.Accepted
	if callErr != nil {
		result.Status = "ERROR"
		result.Reason = callErr.Error()
		if response.Reason != "" {
			result.Reason = response.Reason
		}
		return result
	}
	result.Status = "OK"
	return result
}

func (a *OpenWrt) validateTransaction(tx Transaction) error {
	if !transactionIDPattern.MatchString(tx.ID) || !revisionIDPattern.MatchString(tx.RevisionID) || !changeIDPattern.MatchString(tx.ChangeID) {
		return fmt.Errorf("transaction, revision or change id failed strict validation")
	}
	if !strings.HasPrefix(tx.RollbackTokenHash, "sha256:") || tx.RevisionID == "rev-manual" {
		return fmt.Errorf("rollback capability hash or revision failed strict validation")
	}
	txDir := filepath.Join(a.stateDir, "transactions", tx.RevisionID, tx.ID)
	expected := filepath.Join(txDir, "candidate.json")
	if filepath.Clean(tx.CandidatePath) != filepath.Clean(expected) {
		return fmt.Errorf("candidate path is not the deterministic transaction path")
	}
	if filepath.Clean(tx.ArtifactRoot) != filepath.Join(txDir, "generated") || filepath.Clean(tx.CapabilityPath) != filepath.Join(txDir, "rollback.cap") || filepath.Clean(tx.BindingPath) != filepath.Join(txDir, "binding.env") {
		return fmt.Errorf("artifact or capability path is not deterministic")
	}
	if tx.ArtifactManifestHash == "" {
		return fmt.Errorf("artifact manifest hash is required")
	}
	return nil
}

func validateRecoveryTarget(target RecoveryTarget) error {
	if !transactionIDPattern.MatchString(target.TransactionID) || !revisionIDPattern.MatchString(target.RevisionID) {
		return fmt.Errorf("recovery transaction or revision failed strict validation")
	}
	if !sha256Pattern.MatchString(target.CandidateHash) || !sha256Pattern.MatchString(target.ArtifactManifestHash) {
		return fmt.Errorf("recovery candidate or artifact hash failed strict validation")
	}
	return nil
}

func (a *OpenWrt) execute(ctx context.Context, command string, start time.Time, args ...string) StepResult {
	cmd := exec.CommandContext(ctx, a.helperPath, append([]string{command}, args...)...)
	raw, err := cmd.CombinedOutput()
	if len(raw) > 64*1024 {
		raw = raw[:64*1024]
	}
	evidence := parseEvidence(raw)
	res := okStatus(stepName(command), start, err)
	res.Operation = command
	res.ProtocolVersion = AdapterProtocolVersion
	res.Evidence = evidence
	res.Committed, _ = evidence["committed"].(bool)
	res.RollbackCapable, _ = evidence["rollback_capable"].(bool)
	if state, ok := evidence["transaction_state"].(string); ok {
		res.SemanticState = state
	}
	if err != nil {
		if reason, ok := evidence["reason"].(string); ok && reason != "" {
			res.Reason = reason
		}
		return res
	}
	if command == "verify-management" {
		res.ManagementVerified = evidence["management_ok"] == true
		if evidence["verification_status"] == "UNVERIFIED" {
			res.OK = false
			res.Status = "UNVERIFIED"
			res.Reason = "LAN management path is not verified"
		} else {
			res.OK = res.ManagementVerified
		}
		if !res.OK && res.Status != "UNVERIFIED" {
			res.Status = "ERROR"
			res.Reason = "management path was not verified"
		}
	}
	if command == "verify-data-plane" {
		res.DataPlaneVerified = evidence["data_plane_ok"] == true
		if evidence["verification_status"] == "UNVERIFIED" {
			res.OK = false
			res.Status = "UNVERIFIED"
			res.Reason = "complete data-plane evidence is not available"
			if reason, ok := evidence["reason"].(string); ok && reason != "" {
				res.Reason = reason
			}
		} else {
			res.OK = res.DataPlaneVerified
		}
		if !res.OK && res.Status != "UNVERIFIED" {
			res.Status = "ERROR"
			res.Reason = "data plane was not verified"
		}
	}
	if command == "validate-candidate" && evidence["candidate_valid"] != true {
		res.OK = false
		res.Status = "UNVERIFIED"
		res.Reason = "candidate is not deployable on the current device"
		if reason, ok := evidence["reason"].(string); ok && reason != "" {
			res.Reason = reason
		}
	}
	return res
}

func parseEvidence(raw []byte) map[string]any {
	out := map[string]any{}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok || !evidenceKeyPattern.MatchString(key) {
			continue
		}
		switch value {
		case "true":
			out[key] = true
		case "false":
			out[key] = false
		default:
			out[key] = value
		}
	}
	return out
}

func allowedGlobalCommand(command string) bool {
	return command == "diagnose" || command == "reconcile" || command == "status" || command == "clear-boot-guard"
}

func allowedTransactionCommand(command string) bool {
	switch command {
	case "prepare", "validate-candidate", "snapshot-current", "apply-candidate", "verify-management", "verify-data-plane", "commit", "commit-prepared", "finalize-commit", "rollback", "clear-boot-guard":
		return true
	default:
		return false
	}
}

func stepName(command string) string {
	if command == "verify-management" {
		return "verify_management_path"
	}
	return strings.ReplaceAll(command, "-", "_")
}

func failedStep(step string, start time.Time, err error) StepResult {
	return StepResult{Step: stepName(step), Status: "ERROR", Reason: err.Error(), StartedAt: start, FinishedAt: time.Now().UTC()}
}
