package adapter

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/secureid"
)

var secureRandomHex = secureid.Hex

type Interface interface {
	Diagnose(context.Context) StepResult
	Prepare(context.Context, Transaction) StepResult
	ValidateCandidate(context.Context, Transaction) StepResult
	SnapshotCurrent(context.Context, Transaction) StepResult
	ApplyCandidate(context.Context, Transaction) StepResult
	VerifyManagementPath(context.Context, Transaction) StepResult
	VerifyDataPlane(context.Context, Transaction) StepResult
	Commit(context.Context, Transaction) StepResult
	Rollback(context.Context, Transaction) StepResult
	Reconcile(context.Context, RecoveryTarget) StepResult
	Status(context.Context) StepResult
}

// PreparedCommitter is implemented by adapters that can activate a
// candidate while retaining rollback capability.  It is intentionally an
// optional interface so development/fake adapters can keep the older contract
// while the production OpenWrt adapter uses the split protocol.
type PreparedCommitter interface {
	CommitPrepared(context.Context, Transaction) StepResult
	FinalizeCommit(context.Context, Transaction) StepResult
}

type RecoveryTarget struct {
	TransactionID        string `json:"transaction_id"`
	RevisionID           string `json:"revision_id"`
	CandidateHash        string `json:"candidate_hash"`
	ArtifactManifestHash string `json:"artifact_manifest_hash"`
}

type Transaction struct {
	ID                     string    `json:"id"`
	RevisionID             string    `json:"revision_id"`
	ChangeID               string    `json:"change_id"`
	BaseVersion            int64     `json:"base_version"`
	CandidateVersion       int64     `json:"candidate_version"`
	CandidateHash          string    `json:"candidate_hash"`
	CandidatePath          string    `json:"candidate_path"`
	ArtifactRoot           string    `json:"artifact_root"`
	ArtifactManifestHash   string    `json:"artifact_manifest_hash"`
	ArtifactsReady         bool      `json:"artifacts_ready"`
	ArtifactBlockReason    string    `json:"artifact_block_reason,omitempty"`
	ArtifactsSimulation    bool      `json:"artifacts_simulation"`
	RollbackTokenHash      string    `json:"rollback_token_hash"`
	CapabilityPath         string    `json:"capability_path"`
	BindingPath            string    `json:"binding_path"`
	RollbackToken          string    `json:"-"`
	CreatedAt              time.Time `json:"created_at"`
	ExpiresAt              time.Time `json:"expires_at"`
	RollbackTimeoutSeconds int       `json:"rollback_timeout_seconds"`
	ManagementVerifiedAt   time.Time `json:"management_verified_at,omitempty"`
	DataPlaneVerifiedAt    time.Time `json:"data_plane_verified_at,omitempty"`
}

type StepResult struct {
	ProtocolVersion    int            `json:"protocol_version,omitempty"`
	RequestID          string         `json:"request_id,omitempty"`
	Operation          string         `json:"operation,omitempty"`
	Step               string         `json:"step"`
	Status             string         `json:"status"`
	OK                 bool           `json:"ok"`
	ManagementVerified bool           `json:"management_verified"`
	DataPlaneVerified  bool           `json:"data_plane_verified"`
	Reason             string         `json:"reason,omitempty"`
	Evidence           map[string]any `json:"evidence,omitempty"`
	SemanticState      string         `json:"semantic_state,omitempty"`
	Committed          bool           `json:"committed,omitempty"`
	RollbackCapable    bool           `json:"rollback_capable,omitempty"`
	Generation         string         `json:"generation,omitempty"`
	StartedAt          time.Time      `json:"started_at"`
	FinishedAt         time.Time      `json:"finished_at"`
}

const AdapterProtocolVersion = 1

// ValidateBinding checks the semantic identity returned by an adapter.  An
// exit code/OK bit alone is not enough: a helper may return a process success
// while reporting that the requested transaction was already committed or
// that rollback capability is gone.
func ValidateBinding(result StepResult, operation string, tx Transaction) error {
	if !result.OK || result.Status != "OK" {
		return fmt.Errorf("adapter %s failed: %s", operation, result.Reason)
	}
	if result.Operation != "" && result.Operation != operation {
		return fmt.Errorf("adapter operation mismatch: got %q want %q", result.Operation, operation)
	}
	if result.ProtocolVersion != 0 && result.ProtocolVersion != AdapterProtocolVersion {
		return fmt.Errorf("unsupported adapter protocol version %d", result.ProtocolVersion)
	}
	strict := result.ProtocolVersion != 0 || result.Operation != ""
	for key, expected := range map[string]string{
		"transaction_id":         tx.ID,
		"revision_id":            tx.RevisionID,
		"candidate_hash":         tx.CandidateHash,
		"artifact_manifest_hash": tx.ArtifactManifestHash,
	} {
		if value, present := result.Evidence[key]; present {
			actual, ok := value.(string)
			if !ok || actual != expected {
				return fmt.Errorf("adapter %s binding mismatch for %s", operation, key)
			}
		} else if strict {
			return fmt.Errorf("adapter %s omitted binding field %s", operation, key)
		}
	}
	return nil
}

func ValidatePreparedCommit(result StepResult, tx Transaction) error {
	if err := ValidateBinding(result, "commit-prepared", tx); err != nil {
		return err
	}
	if result.Committed || result.SemanticState == "committed" || result.SemanticState != "adapter_activated" {
		return fmt.Errorf("adapter committed before control-plane finalization")
	}
	if value, present := result.Evidence["rollback_capable"]; present {
		capable, ok := value.(bool)
		if !ok || !capable {
			return fmt.Errorf("adapter did not prove rollback capability after prepared commit")
		}
	} else if !result.RollbackCapable {
		return fmt.Errorf("adapter did not prove rollback capability after prepared commit")
	}
	return nil
}

func ValidateFinalizedCommit(result StepResult, tx Transaction) error {
	if err := ValidateBinding(result, "finalize-commit", tx); err != nil {
		return err
	}
	if !result.Committed || result.SemanticState != "committed" {
		return fmt.Errorf("adapter did not prove committed state")
	}
	return nil
}

func ValidateRollback(result StepResult, tx Transaction) error {
	if err := ValidateBinding(result, "rollback", tx); err != nil {
		return err
	}
	if value, present := result.Evidence["rollback"]; present {
		rolled, ok := value.(bool)
		if !ok || !rolled {
			return fmt.Errorf("adapter reported rollback=false")
		}
	}
	if result.SemanticState == "committed" || result.Committed {
		return fmt.Errorf("adapter is committed; rollback result is ambiguous")
	}
	if result.ProtocolVersion != 0 && result.SemanticState != "rolled_back" {
		return fmt.Errorf("adapter rollback state is not rolled_back")
	}
	return nil
}

type FileSnapshot struct {
	Path   string `json:"path"`
	State  string `json:"state"`
	SHA256 string `json:"sha256,omitempty"`
	Bytes  int64  `json:"bytes,omitempty"`
}

type Manifest struct {
	TransactionID string         `json:"transaction_id"`
	RevisionID    string         `json:"revision_id"`
	CreatedAt     time.Time      `json:"created_at"`
	Files         []FileSnapshot `json:"files"`
}

type Filesystem struct {
	cfg        *config.Config
	stateDir   string
	runtimeDir string
}

func NewFilesystem(cfg *config.Config) *Filesystem {
	stateDir := cfg.Storage.StateDir
	if stateDir == "" {
		stateDir = ".router-policy-state"
	}
	runtimeDir := cfg.Storage.RuntimeDir
	if runtimeDir == "" {
		runtimeDir = filepath.Join(stateDir, "runtime")
	}
	return &Filesystem{cfg: cfg, stateDir: stateDir, runtimeDir: runtimeDir}
}

func NewTransaction(cfg *config.Config, changeID, revisionID string, baseVersion, candidateVersion int64, canonicalCandidate []byte) (Transaction, error) {
	if len(canonicalCandidate) == 0 {
		return Transaction{}, fmt.Errorf("canonical candidate is required")
	}
	randomID, err := secureRandomHex(8)
	if err != nil {
		return Transaction{}, fmt.Errorf("generate transaction ID: %w", err)
	}
	id := "tx_" + randomID
	txDir := filepath.Join(cfg.Storage.StateDir, "transactions", revisionID, id)
	candidatePath := filepath.Join(txDir, "candidate.json")
	token, err := secureRandomHex(32)
	if err != nil {
		return Transaction{}, fmt.Errorf("generate rollback capability: %w", err)
	}
	now := time.Now().UTC()
	ttl := time.Duration(cfg.OpenWrt.RollbackTimeoutSeconds) * time.Second
	if ttl <= 0 {
		ttl = 120 * time.Second
	}
	return Transaction{
		ID:                     id,
		RevisionID:             revisionID,
		ChangeID:               changeID,
		BaseVersion:            baseVersion,
		CandidateVersion:       candidateVersion,
		CandidateHash:          "sha256:" + sha256Hex(canonicalCandidate),
		CandidatePath:          candidatePath,
		ArtifactRoot:           filepath.Join(txDir, "generated"),
		RollbackTokenHash:      "sha256:" + sha256Hex([]byte(token)),
		CapabilityPath:         filepath.Join(txDir, "rollback.cap"),
		BindingPath:            filepath.Join(txDir, "binding.env"),
		RollbackToken:          token,
		CreatedAt:              now,
		ExpiresAt:              now.Add(ttl),
		RollbackTimeoutSeconds: int(ttl / time.Second),
	}, nil
}

func PersistBinding(tx Transaction) error {
	if tx.ID == "" || tx.RevisionID == "" || tx.CandidateHash == "" || tx.ArtifactManifestHash == "" || tx.RollbackTokenHash == "" || tx.BindingPath == "" {
		return fmt.Errorf("complete transaction binding is required")
	}
	rollbackTimeoutSeconds := tx.RollbackTimeoutSeconds
	if rollbackTimeoutSeconds <= 0 && tx.ExpiresAt.After(tx.CreatedAt) {
		rollbackTimeoutSeconds = int(tx.ExpiresAt.Sub(tx.CreatedAt) / time.Second)
	}
	if rollbackTimeoutSeconds <= 0 {
		rollbackTimeoutSeconds = 120
	}
	if rollbackTimeoutSeconds > 3600 {
		return fmt.Errorf("rollback timeout must be between 1 and 3600 seconds")
	}
	content := fmt.Sprintf("transaction_id=%s\nrevision_id=%s\ncandidate_hash=%s\nartifact_manifest_hash=%s\nartifacts_ready=%t\nartifact_block_reason=%s\nartifacts_simulation=%t\nrollback_token_hash=%s\nrollback_timeout_seconds=%d\n", tx.ID, tx.RevisionID, tx.CandidateHash, tx.ArtifactManifestHash, tx.ArtifactsReady, tx.ArtifactBlockReason, tx.ArtifactsSimulation, tx.RollbackTokenHash, rollbackTimeoutSeconds)
	if err := os.MkdirAll(filepath.Dir(tx.BindingPath), 0o700); err != nil {
		return err
	}
	suffix, err := secureRandomHex(6)
	if err != nil {
		return fmt.Errorf("generate binding temporary name: %w", err)
	}
	tmp := tx.BindingPath + ".tmp." + suffix
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, tx.BindingPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func PersistCapability(tx Transaction) error {
	if tx.RollbackToken == "" || tx.CapabilityPath == "" || !VerifyRollbackToken(tx.RollbackTokenHash, tx.RollbackToken) {
		return fmt.Errorf("valid rollback capability is required")
	}
	if err := os.MkdirAll(filepath.Dir(tx.CapabilityPath), 0o700); err != nil {
		return err
	}
	suffix, err := secureRandomHex(6)
	if err != nil {
		return fmt.Errorf("generate capability temporary name: %w", err)
	}
	tmp := tx.CapabilityPath + ".tmp." + suffix
	if err := os.WriteFile(tmp, []byte(tx.RollbackToken+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, tx.CapabilityPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func ReadCapability(tx Transaction) (string, error) {
	info, err := os.Lstat(tx.CapabilityPath)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		return "", fmt.Errorf("rollback capability must be a regular mode-0600 file")
	}
	raw, err := os.ReadFile(tx.CapabilityPath)
	if err != nil {
		return "", err
	}
	token := strings.TrimRight(string(raw), "\r\n")
	if !VerifyRollbackToken(tx.RollbackTokenHash, token) {
		return "", fmt.Errorf("rollback capability hash mismatch")
	}
	return token, nil
}

func RetireCapability(tx Transaction) error {
	err := os.Remove(tx.CapabilityPath)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (a *Filesystem) Diagnose(context.Context) StepResult {
	start := time.Now().UTC()
	err := os.MkdirAll(a.stateDir, 0o700)
	status := okStatus("diagnose", start, err)
	status.Evidence = map[string]any{
		"adapter":      "filesystem-contract",
		"state_dir":    a.stateDir,
		"runtime_dir":  a.runtimeDir,
		"network_safe": true,
	}
	return status
}

func (a *Filesystem) Prepare(_ context.Context, tx Transaction) StepResult {
	start := time.Now().UTC()
	err := a.writeTransaction(tx, "prepared")
	res := okStatus("prepare", start, err)
	res.Evidence = map[string]any{"transaction": tx.ID, "revision": tx.RevisionID}
	return res
}

func (a *Filesystem) ValidateCandidate(_ context.Context, tx Transaction) StepResult {
	start := time.Now().UTC()
	err := a.requirePrepared(tx)
	if err == nil && (tx.ID == "" || tx.RevisionID == "" || tx.CandidateHash == "") {
		err = fmt.Errorf("transaction is incomplete")
	}
	if err == nil {
		err = a.writeStatus(tx, "candidate_validated")
	}
	res := okStatus("validate_candidate", start, err)
	res.Evidence = map[string]any{"candidate_hash": tx.CandidateHash}
	return res
}

func (a *Filesystem) SnapshotCurrent(_ context.Context, tx Transaction) StepResult {
	start := time.Now().UTC()
	manifest, err := a.snapshot(tx)
	if err == nil {
		err = writeJSONAtomic(filepath.Join(a.txDir(tx), "snapshot.manifest.json"), manifest, 0o600)
	}
	if err == nil {
		err = a.writeStatus(tx, "snapshotted")
	}
	res := okStatus("snapshot_current", start, err)
	if err == nil {
		res.Evidence = map[string]any{"files": len(manifest.Files)}
	}
	return res
}

func (a *Filesystem) ApplyCandidate(_ context.Context, tx Transaction) StepResult {
	start := time.Now().UTC()
	err := a.requirePrepared(tx)
	if err == nil {
		err = a.writeStatus(tx, "apply_requires_privileged_openwrt_adapter")
	}
	res := okStatus("apply_candidate", start, err)
	if err == nil {
		res.OK = false
		res.Status = "SKIPPED"
		res.Reason = "privileged_openwrt_adapter_not_executed_in_local_control_plane"
	}
	res.Evidence = map[string]any{"network_changed": false, "requires_device": true}
	return res
}

func (a *Filesystem) VerifyManagementPath(_ context.Context, tx Transaction) StepResult {
	start := time.Now().UTC()
	err := a.requirePrepared(tx)
	if err == nil {
		err = a.writeStatus(tx, "management_path_local_only")
	}
	res := okStatus("verify_management_path", start, err)
	if err == nil {
		res.OK = false
		res.Status = "UNVERIFIED"
		res.ManagementVerified = false
		res.Reason = "local_state_is_not_a_management_path_verification"
	}
	res.Evidence = map[string]any{"network_changed": false}
	return res
}

func (a *Filesystem) VerifyDataPlane(_ context.Context, tx Transaction) StepResult {
	start := time.Now().UTC()
	err := a.requirePrepared(tx)
	if err == nil {
		err = a.writeStatus(tx, "data_plane_unverified")
	}
	res := okStatus("verify_data_plane", start, err)
	if err == nil {
		res.OK = false
		res.Status = "UNVERIFIED"
		res.Reason = "needs_target_openwrt_probe_then_test_apply"
	}
	res.DataPlaneVerified = false
	res.Evidence = map[string]any{"network_changed": false, "requires_device": true}
	return res
}

func (a *Filesystem) Commit(ctx context.Context, tx Transaction) StepResult {
	prepared := a.CommitPrepared(ctx, tx)
	if !prepared.OK {
		return prepared
	}
	return a.FinalizeCommit(ctx, tx)
}

func (a *Filesystem) CommitPrepared(_ context.Context, tx Transaction) StepResult {
	start := time.Now().UTC()
	err := a.requirePrepared(tx)
	if err == nil {
		err = a.writeStatus(tx, "adapter_activated")
	}
	res := okStatus("commit_prepared", start, err)
	res.Operation = "commit-prepared"
	res.ProtocolVersion = AdapterProtocolVersion
	res.RollbackCapable = err == nil
	res.SemanticState = "adapter_activated"
	res.Evidence = map[string]any{"transaction_id": tx.ID, "revision_id": tx.RevisionID, "candidate_hash": tx.CandidateHash, "artifact_manifest_hash": tx.ArtifactManifestHash, "rollback_capable": err == nil}
	return res
}

func (a *Filesystem) FinalizeCommit(_ context.Context, tx Transaction) StepResult {
	start := time.Now().UTC()
	err := a.requirePrepared(tx)
	if err == nil {
		err = a.writeStatus(tx, "committed")
	}
	res := okStatus("finalize_commit", start, err)
	res.Operation = "finalize-commit"
	res.ProtocolVersion = AdapterProtocolVersion
	res.Committed = err == nil
	res.SemanticState = "committed"
	res.RollbackCapable = false
	res.Evidence = map[string]any{"transaction_id": tx.ID, "revision_id": tx.RevisionID, "candidate_hash": tx.CandidateHash, "artifact_manifest_hash": tx.ArtifactManifestHash, "committed": err == nil, "rollback_capable": false}
	return res
}

func (a *Filesystem) Rollback(_ context.Context, tx Transaction) StepResult {
	start := time.Now().UTC()
	err := a.requirePrepared(tx)
	if err == nil {
		err = a.writeStatus(tx, "rolled_back")
	}
	res := okStatus("rollback", start, err)
	res.Operation = "rollback"
	res.ProtocolVersion = AdapterProtocolVersion
	res.SemanticState = "rolled_back"
	res.RollbackCapable = false
	res.Evidence = map[string]any{"transaction_id": tx.ID, "revision_id": tx.RevisionID, "candidate_hash": tx.CandidateHash, "artifact_manifest_hash": tx.ArtifactManifestHash, "rollback": err == nil, "rollback_capable": false}
	return res
}

func (a *Filesystem) Reconcile(_ context.Context, target RecoveryTarget) StepResult {
	start := time.Now().UTC()
	err := os.MkdirAll(filepath.Join(a.stateDir, "transactions"), 0o700)
	res := okStatus("reconcile", start, err)
	res.Evidence = map[string]any{
		"network_changed":               false,
		"active_transaction":            target.TransactionID,
		"active_revision":               target.RevisionID,
		"active_candidate_hash":         target.CandidateHash,
		"active_artifact_manifest_hash": target.ArtifactManifestHash,
		"transaction_state":             "committed",
	}
	return res
}

func (a *Filesystem) Status(context.Context) StepResult {
	start := time.Now().UTC()
	res := okStatus("status", start, nil)
	res.Evidence = map[string]any{"adapter": "filesystem-contract", "state_dir": a.stateDir}
	return res
}

func (a *Filesystem) txDir(tx Transaction) string {
	return filepath.Join(a.stateDir, "transactions", tx.RevisionID, tx.ID)
}

func (a *Filesystem) writeTransaction(tx Transaction, status string) error {
	if tx.ID == "" || tx.RevisionID == "" {
		return fmt.Errorf("transaction id and revision are required")
	}
	if err := os.MkdirAll(a.txDir(tx), 0o700); err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(a.txDir(tx), "transaction.json"), tx, 0o600); err != nil {
		return err
	}
	return a.writeStatus(tx, status)
}

func (a *Filesystem) requirePrepared(tx Transaction) error {
	if tx.ID == "" || tx.RevisionID == "" {
		return fmt.Errorf("transaction id and revision are required")
	}
	_, err := os.Stat(filepath.Join(a.txDir(tx), "transaction.json"))
	return err
}

func (a *Filesystem) writeStatus(tx Transaction, status string) error {
	return writeJSONAtomic(filepath.Join(a.txDir(tx), "status.json"), map[string]any{
		"transaction_id": tx.ID,
		"revision_id":    tx.RevisionID,
		"status":         status,
		"updated_at":     time.Now().UTC(),
	}, 0o600)
}

func (a *Filesystem) snapshot(tx Transaction) (Manifest, error) {
	paths := []string{
		filepath.Join(a.stateDir, "router-policy.bbolt"),
		a.cfg.OpenWrt.FirewallInclude,
		a.cfg.OpenWrt.DNSMasqInclude,
		a.cfg.Xray.ActiveConfig,
	}
	manifest := Manifest{TransactionID: tx.ID, RevisionID: tx.RevisionID, CreatedAt: time.Now().UTC()}
	for _, path := range paths {
		if path == "" {
			continue
		}
		item := FileSnapshot{Path: path, State: "absent"}
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return manifest, readErr
			}
			item.State = "present"
			item.Bytes = int64(len(raw))
			item.SHA256 = "sha256:" + sha256Hex(raw)
		} else if err != nil && !os.IsNotExist(err) {
			return manifest, err
		}
		manifest.Files = append(manifest.Files, item)
	}
	return manifest, nil
}

func okStatus(step string, start time.Time, err error) StepResult {
	status := StepResult{Step: step, StartedAt: start, FinishedAt: time.Now().UTC()}
	if err != nil {
		status.Status = "ERROR"
		status.Reason = err.Error()
		return status
	}
	status.OK = true
	status.Status = "OK"
	return status
}

func writeJSONAtomic(path string, value any, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	suffix, err := secureRandomHex(6)
	if err != nil {
		return fmt.Errorf("generate JSON temporary name: %w", err)
	}
	tmp := path + ".tmp." + suffix
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func VerifyRollbackToken(expectedHash, token string) bool {
	actual := "sha256:" + sha256Hex([]byte(token))
	if len(actual) != len(expectedHash) {
		padded := make([]byte, len(actual))
		copy(padded, expectedHash)
		_ = subtle.ConstantTimeCompare([]byte(actual), padded)
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expectedHash)) == 1
}
