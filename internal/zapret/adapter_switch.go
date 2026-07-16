package zapret

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"router-policy/internal/adapter"
)

// AdapterSwitchApplier binds one adaptive decision to one fully generated
// transaction. The binding prevents a late or cross-bundle decision from
// applying artifacts prepared for another profile.
type AdapterSwitchApplier struct {
	mu       sync.Mutex
	adapter  adapter.Interface
	tx       adapter.Transaction
	decision SwitchDecision
	cleanup  error
}

func NewAdapterSwitchApplier(target adapter.Interface, tx adapter.Transaction, decision SwitchDecision) (*AdapterSwitchApplier, error) {
	if target == nil {
		return nil, errors.New("transaction adapter is required")
	}
	if err := validateBoundSwitch(decision); err != nil {
		return nil, err
	}
	if err := validateSwitchTransaction(tx); err != nil {
		return nil, err
	}
	return &AdapterSwitchApplier{adapter: target, tx: tx, decision: decision}, nil
}

func (a *AdapterSwitchApplier) Prepare(ctx context.Context, decision SwitchDecision) error {
	if err := a.validateDecision(decision); err != nil {
		return err
	}
	if err := adapter.PersistCapability(a.tx); err != nil {
		return fmt.Errorf("persist rollback capability: %w", err)
	}
	if err := adapter.PersistBinding(a.tx); err != nil {
		_ = adapter.RetireCapability(a.tx)
		return fmt.Errorf("persist transaction binding: %w", err)
	}
	if err := requireAdapterStep(a.adapter.Prepare(ctx, a.tx), "prepare"); err != nil {
		_ = adapter.RetireCapability(a.tx)
		return err
	}
	return nil
}

func (a *AdapterSwitchApplier) Validate(ctx context.Context, decision SwitchDecision) error {
	if err := a.validateDecision(decision); err != nil {
		return err
	}
	return requireAdapterStep(a.adapter.ValidateCandidate(ctx, a.tx), "validate")
}

func (a *AdapterSwitchApplier) Snapshot(ctx context.Context, decision SwitchDecision) error {
	if err := a.validateDecision(decision); err != nil {
		return err
	}
	return requireAdapterStep(a.adapter.SnapshotCurrent(ctx, a.tx), "snapshot")
}

func (a *AdapterSwitchApplier) Apply(ctx context.Context, decision SwitchDecision) error {
	if err := a.validateDecision(decision); err != nil {
		return err
	}
	return requireAdapterStep(a.adapter.ApplyCandidate(ctx, a.tx), "apply")
}

func (a *AdapterSwitchApplier) Verify(ctx context.Context, decision SwitchDecision) error {
	if err := a.validateDecision(decision); err != nil {
		return err
	}
	management := a.adapter.VerifyManagementPath(ctx, a.tx)
	if err := requireAdapterStep(management, "verify_management"); err != nil {
		return err
	}
	if !management.ManagementVerified {
		return errors.New("adapter did not prove the management path")
	}
	dataPlane := a.adapter.VerifyDataPlane(ctx, a.tx)
	if err := requireAdapterStep(dataPlane, "verify_data_plane"); err != nil {
		return err
	}
	if !dataPlane.DataPlaneVerified {
		return errors.New("adapter did not prove the data plane")
	}
	return nil
}

func (a *AdapterSwitchApplier) Commit(ctx context.Context, decision SwitchDecision) error {
	if err := a.validateDecision(decision); err != nil {
		return err
	}
	if err := requireAdapterStep(a.adapter.Commit(ctx, a.tx), "commit"); err != nil {
		return err
	}
	// A local cleanup failure must not turn an already committed transaction
	// into a rollback attempt. Keep it observable for the caller instead.
	a.recordCleanup(adapter.RetireCapability(a.tx))
	return nil
}

func (a *AdapterSwitchApplier) Rollback(ctx context.Context, decision SwitchDecision) error {
	if err := a.validateDecision(decision); err != nil {
		return err
	}
	if err := requireAdapterStep(a.adapter.Rollback(ctx, a.tx), "rollback"); err != nil {
		return err
	}
	a.recordCleanup(adapter.RetireCapability(a.tx))
	return nil
}

func (a *AdapterSwitchApplier) CleanupError() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cleanup
}

func (a *AdapterSwitchApplier) validateDecision(decision SwitchDecision) error {
	if a == nil {
		return errors.New("adaptive transaction is not initialized")
	}
	if decision.Action != a.decision.Action || decision.FromProfile != a.decision.FromProfile ||
		decision.ToProfile != a.decision.ToProfile || decisionKeyString(decision.Key) != decisionKeyString(a.decision.Key) {
		return errors.New("switch decision does not match the prepared transaction")
	}
	return nil
}

func (a *AdapterSwitchApplier) recordCleanup(err error) {
	if err == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanup = errors.Join(a.cleanup, err)
}

func validateBoundSwitch(decision SwitchDecision) error {
	if decision.Action != SwitchProfile || !profileIDPattern.MatchString(decision.FromProfile) ||
		!profileIDPattern.MatchString(decision.ToProfile) || decision.FromProfile == decision.ToProfile {
		return errors.New("complete profile switch decision is required")
	}
	key := decision.Key
	if !profileIDPattern.MatchString(key.BundleID) || (key.Transport != "tcp" && key.Transport != "udp") ||
		key.Port == 0 || (key.IPFamily != "ipv4" && key.IPFamily != "ipv6") || !digestPattern.MatchString(key.NetworkFingerprint) {
		return errors.New("complete adaptive decision key is required")
	}
	return nil
}

func validateSwitchTransaction(tx adapter.Transaction) error {
	if tx.ID == "" || tx.RevisionID == "" || tx.ChangeID == "" || !digestPattern.MatchString(tx.CandidateHash) ||
		!digestPattern.MatchString(tx.ArtifactManifestHash) || !tx.ArtifactsReady || tx.ArtifactsSimulation ||
		tx.RollbackToken == "" || !adapter.VerifyRollbackToken(tx.RollbackTokenHash, tx.RollbackToken) ||
		tx.CreatedAt.IsZero() || !tx.ExpiresAt.After(tx.CreatedAt) {
		return errors.New("complete deployment-ready transaction is required")
	}
	for _, path := range []string{tx.CandidatePath, tx.ArtifactRoot, tx.CapabilityPath, tx.BindingPath} {
		if !filepath.IsAbs(path) {
			return errors.New("adaptive transaction paths must be absolute")
		}
	}
	return nil
}

func requireAdapterStep(result adapter.StepResult, expected string) error {
	if !result.OK || result.Status != "OK" {
		reason := result.Reason
		if reason == "" {
			reason = "adapter rejected the transaction"
		}
		return fmt.Errorf("%s: %s", expected, reason)
	}
	return nil
}

var _ SwitchApplier = (*AdapterSwitchApplier)(nil)
