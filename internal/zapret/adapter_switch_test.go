package zapret

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"router-policy/internal/adapter"
	"router-policy/internal/config"
)

func TestAdapterSwitchApplierCommitsBoundTransaction(t *testing.T) {
	decision := adapterSwitchDecision()
	tx := adapterSwitchTransaction(t)
	target := &switchAdapterStub{}
	applier, err := NewAdapterSwitchApplier(target, tx, decision)
	if err != nil {
		t.Fatal(err)
	}
	controller, _ := NewSwitchController(DefaultSwitchingPolicy())
	if err := controller.SetActive(decision.Key, decision.FromProfile, decision.EvaluatedAt.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	executor, _ := NewSwitchExecutor(controller)
	result := executor.Execute(context.Background(), decision, applier, decision.EvaluatedAt)
	if result.Status != "COMMITTED" || result.RollbackTried {
		t.Fatalf("unexpected switch result: %+v", result)
	}
	want := []string{"prepare", "validate", "snapshot", "apply", "verify_management", "verify_data_plane", "commit"}
	if !reflect.DeepEqual(target.calls, want) {
		t.Fatalf("adapter call order = %v, want %v", target.calls, want)
	}
	if _, err := os.Stat(tx.CapabilityPath); !os.IsNotExist(err) {
		t.Fatalf("rollback capability was not retired: %v", err)
	}
	if applier.CleanupError() != nil {
		t.Fatalf("unexpected cleanup error: %v", applier.CleanupError())
	}
}

func TestAdapterSwitchApplierRejectsCrossBundleDecision(t *testing.T) {
	decision := adapterSwitchDecision()
	target := &switchAdapterStub{}
	applier, err := NewAdapterSwitchApplier(target, adapterSwitchTransaction(t), decision)
	if err != nil {
		t.Fatal(err)
	}
	tampered := decision
	tampered.Key.BundleID = "signal"
	if err := applier.Prepare(context.Background(), tampered); err == nil {
		t.Fatal("cross-bundle decision was accepted")
	}
	if len(target.calls) != 0 {
		t.Fatalf("adapter was called for rejected decision: %v", target.calls)
	}
}

func TestAdapterSwitchApplierRollsBackFailedDataPlaneProof(t *testing.T) {
	now := time.Date(2026, 7, 16, 15, 0, 0, 0, time.UTC)
	decision := adapterSwitchDecision()
	decision.EvaluatedAt = now
	target := &switchAdapterStub{unprovedDataPlane: true}
	tx := adapterSwitchTransaction(t)
	applier, err := NewAdapterSwitchApplier(target, tx, decision)
	if err != nil {
		t.Fatal(err)
	}
	controller, _ := NewSwitchController(DefaultSwitchingPolicy())
	if err := controller.SetActive(decision.Key, decision.FromProfile, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	executor, _ := NewSwitchExecutor(controller)
	result := executor.Execute(context.Background(), decision, applier, now)
	if result.Status != "FAILED" || result.FailedStep != "verify" || !result.RollbackTried || !result.RollbackOK {
		t.Fatalf("unexpected rollback result: %+v", result)
	}
	want := []string{"prepare", "validate", "snapshot", "apply", "verify_management", "verify_data_plane", "rollback"}
	if !reflect.DeepEqual(target.calls, want) {
		t.Fatalf("adapter call order = %v, want %v", target.calls, want)
	}
	state := controller.Snapshot(decision.Key, now)
	if !state.QuarantinedUntil[decision.ToProfile].After(now) {
		t.Fatalf("failed profile was not quarantined: %+v", state)
	}
}

func TestAdapterSwitchApplierRequiresDeploymentReadyArtifacts(t *testing.T) {
	tx := adapterSwitchTransaction(t)
	tx.ArtifactsSimulation = true
	if _, err := NewAdapterSwitchApplier(&switchAdapterStub{}, tx, adapterSwitchDecision()); err == nil {
		t.Fatal("simulation artifacts were accepted")
	}
	tx = adapterSwitchTransaction(t)
	tx.ArtifactManifestHash = ""
	if _, err := NewAdapterSwitchApplier(&switchAdapterStub{}, tx, adapterSwitchDecision()); err == nil {
		t.Fatal("unbound artifacts were accepted")
	}
}

func adapterSwitchTransaction(t *testing.T) adapter.Transaction {
	t.Helper()
	cfg := &config.Config{Storage: config.Storage{StateDir: t.TempDir()}, OpenWrt: config.OpenWrt{RollbackTimeoutSeconds: 120}}
	tx, err := adapter.NewTransaction(cfg, "chg_adaptive", "rev_adaptive", 4, 5, []byte(`{"version":5}`))
	if err != nil {
		t.Fatal(err)
	}
	tx.ArtifactManifestHash = Digest([]byte("adaptive manifest"))
	tx.ArtifactsReady = true
	return tx
}

func adapterSwitchDecision() SwitchDecision {
	return SwitchDecision{
		Key: DecisionKey{
			BundleID: "discord", Transport: "tcp", Port: 443, IPFamily: "ipv4",
			NetworkFingerprint: Digest([]byte("wan fingerprint")),
		},
		Action: SwitchProfile, FromProfile: "profile-a", ToProfile: "profile-b",
		Reason: "active_profile_degraded", EvaluatedAt: time.Date(2026, 7, 16, 14, 0, 0, 0, time.UTC),
	}
}

type switchAdapterStub struct {
	calls             []string
	fail              string
	unprovedDataPlane bool
}

func (s *switchAdapterStub) result(step string) adapter.StepResult {
	s.calls = append(s.calls, step)
	if s.fail == step {
		return adapter.StepResult{Step: step, Status: "FAILED", Reason: "injected failure"}
	}
	result := adapter.StepResult{Step: step, Status: "OK", OK: true}
	if step == "verify_management" {
		result.ManagementVerified = true
	}
	if step == "verify_data_plane" && !s.unprovedDataPlane {
		result.DataPlaneVerified = true
	}
	return result
}

func (s *switchAdapterStub) Diagnose(context.Context) adapter.StepResult {
	return s.result("diagnose")
}
func (s *switchAdapterStub) Prepare(context.Context, adapter.Transaction) adapter.StepResult {
	return s.result("prepare")
}
func (s *switchAdapterStub) ValidateCandidate(context.Context, adapter.Transaction) adapter.StepResult {
	return s.result("validate")
}
func (s *switchAdapterStub) SnapshotCurrent(context.Context, adapter.Transaction) adapter.StepResult {
	return s.result("snapshot")
}
func (s *switchAdapterStub) ApplyCandidate(context.Context, adapter.Transaction) adapter.StepResult {
	return s.result("apply")
}
func (s *switchAdapterStub) VerifyManagementPath(context.Context, adapter.Transaction) adapter.StepResult {
	return s.result("verify_management")
}
func (s *switchAdapterStub) VerifyDataPlane(context.Context, adapter.Transaction) adapter.StepResult {
	return s.result("verify_data_plane")
}
func (s *switchAdapterStub) Commit(context.Context, adapter.Transaction) adapter.StepResult {
	return s.result("commit")
}
func (s *switchAdapterStub) Rollback(context.Context, adapter.Transaction) adapter.StepResult {
	return s.result("rollback")
}
func (s *switchAdapterStub) Reconcile(context.Context, adapter.RecoveryTarget) adapter.StepResult {
	return adapter.StepResult{Step: "reconcile", Status: "OK", OK: true}
}
func (s *switchAdapterStub) Status(context.Context) adapter.StepResult {
	return adapter.StepResult{Step: "status", Status: "OK", OK: true}
}

var _ adapter.Interface = (*switchAdapterStub)(nil)
