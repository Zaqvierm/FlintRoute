package api

import (
	"context"
	"sync"
	"time"

	"router-policy/internal/adapter"
)

type fakeAdapter struct {
	mu                         sync.Mutex
	calls                      []string
	fail                       map[string]bool
	status                     map[string]string
	activeRevision             string
	activeTransaction          string
	activeCandidateHash        string
	activeArtifactManifestHash string
	transactionState           string
	wrongApplyArtifactEvidence bool
	applyStarted               chan struct{}
	applyRelease               chan struct{}
	lastRecoveryTarget         adapter.RecoveryTarget
}

func newFakeAdapter() *fakeAdapter {
	return &fakeAdapter{fail: map[string]bool{}, status: map[string]string{}}
}

func (f *fakeAdapter) Diagnose(context.Context) adapter.StepResult {
	return f.result("diagnose", adapter.Transaction{})
}
func (f *fakeAdapter) Prepare(_ context.Context, tx adapter.Transaction) adapter.StepResult {
	return f.result("prepare", tx)
}
func (f *fakeAdapter) ValidateCandidate(_ context.Context, tx adapter.Transaction) adapter.StepResult {
	return f.result("validate_candidate", tx)
}
func (f *fakeAdapter) SnapshotCurrent(_ context.Context, tx adapter.Transaction) adapter.StepResult {
	return f.result("snapshot_current", tx)
}
func (f *fakeAdapter) ApplyCandidate(_ context.Context, tx adapter.Transaction) adapter.StepResult {
	if f.applyStarted != nil {
		select {
		case f.applyStarted <- struct{}{}:
		default:
		}
	}
	if f.applyRelease != nil {
		<-f.applyRelease
	}
	res := f.result("apply_candidate", tx)
	if res.OK {
		artifactHash := tx.ArtifactManifestHash
		if f.wrongApplyArtifactEvidence {
			artifactHash = "sha256:wrong-artifact-manifest"
		}
		res.Evidence = map[string]any{"transaction_id": tx.ID, "revision_id": tx.RevisionID, "candidate_hash": tx.CandidateHash, "artifact_manifest_hash": artifactHash}
		f.mu.Lock()
		f.activeRevision = tx.RevisionID
		f.activeTransaction = tx.ID
		f.activeCandidateHash = tx.CandidateHash
		f.activeArtifactManifestHash = tx.ArtifactManifestHash
		f.transactionState = "applied"
		f.mu.Unlock()
	}
	return res
}
func (f *fakeAdapter) VerifyManagementPath(_ context.Context, tx adapter.Transaction) adapter.StepResult {
	res := f.result("verify_management_path", tx)
	res.ManagementVerified = res.OK
	return res
}
func (f *fakeAdapter) VerifyDataPlane(_ context.Context, tx adapter.Transaction) adapter.StepResult {
	res := f.result("verify_data_plane", tx)
	res.DataPlaneVerified = res.OK
	return res
}
func (f *fakeAdapter) Commit(_ context.Context, tx adapter.Transaction) adapter.StepResult {
	res := f.result("commit", tx)
	if res.OK {
		f.mu.Lock()
		f.transactionState = "committed"
		f.mu.Unlock()
	}
	return res
}
func (f *fakeAdapter) Rollback(_ context.Context, tx adapter.Transaction) adapter.StepResult {
	res := f.result("rollback", tx)
	if res.OK {
		f.mu.Lock()
		f.transactionState = "rolled_back"
		f.activeRevision = ""
		f.activeTransaction = ""
		f.activeCandidateHash = ""
		f.activeArtifactManifestHash = ""
		f.mu.Unlock()
	}
	return res
}
func (f *fakeAdapter) Reconcile(_ context.Context, target adapter.RecoveryTarget) adapter.StepResult {
	res := f.result("reconcile", adapter.Transaction{})
	if res.OK {
		f.mu.Lock()
		f.lastRecoveryTarget = target
		f.activeRevision = target.RevisionID
		f.activeTransaction = target.TransactionID
		f.activeCandidateHash = target.CandidateHash
		f.activeArtifactManifestHash = target.ArtifactManifestHash
		f.transactionState = "committed"
		f.mu.Unlock()
	}
	return res
}
func (f *fakeAdapter) Status(context.Context) adapter.StepResult {
	res := f.result("status", adapter.Transaction{})
	f.mu.Lock()
	res.Evidence = map[string]any{
		"active_revision":               f.activeRevision,
		"active_transaction":            f.activeTransaction,
		"transaction_state":             f.transactionState,
		"active_candidate_hash":         f.activeCandidateHash,
		"active_artifact_manifest_hash": f.activeArtifactManifestHash,
	}
	f.mu.Unlock()
	return res
}

func (f *fakeAdapter) result(step string, _ adapter.Transaction) adapter.StepResult {
	now := time.Now().UTC()
	f.mu.Lock()
	f.calls = append(f.calls, step)
	fail := f.fail[step]
	status := f.status[step]
	f.mu.Unlock()
	if fail {
		return adapter.StepResult{Step: step, Status: "ERROR", Reason: "fake " + step + " failure", StartedAt: now, FinishedAt: time.Now().UTC()}
	}
	if status != "" && status != "OK" {
		return adapter.StepResult{Step: step, Status: status, Reason: "fake " + status, StartedAt: now, FinishedAt: time.Now().UTC()}
	}
	return adapter.StepResult{Step: step, Status: "OK", OK: true, StartedAt: now, FinishedAt: time.Now().UTC()}
}

func (f *fakeAdapter) callCount(step string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, call := range f.calls {
		if call == step {
			count++
		}
	}
	return count
}
