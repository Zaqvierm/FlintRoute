package zapret

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSwitchControllerUsesHysteresisCooldownAndEmergencyBypass(t *testing.T) {
	controller := testSwitchController(t)
	key := switchKey()
	now := time.Date(2026, 7, 16, 17, 0, 0, 0, time.UTC)
	if err := controller.SetActive(key, "zapret-a", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	ranking := switchRanking(key)
	decision, err := controller.Evaluate(key, ranking, now)
	if err != nil || decision.Action != SwitchProfile || decision.ToProfile != "zapret-b" || decision.Reason != "challenger_lower_latency" {
		t.Fatalf("expected stable latency switch, got %+v err=%v", decision, err)
	}
	if err := controller.RecordApplied(decision, now); err != nil {
		t.Fatal(err)
	}
	reverse := []CandidateScore{ranking[1], ranking[0]}
	reverse[0].Key, reverse[1].Key = key, key
	reverse[0].ProfileID, reverse[1].ProfileID = "zapret-a", "zapret-b"
	reverse[0].MedianLatencyMS, reverse[1].MedianLatencyMS = 50, 100
	decision, err = controller.Evaluate(key, reverse, now.Add(time.Minute))
	if err != nil || decision.Action != SwitchHold || decision.Reason != "cooldown_active" {
		t.Fatalf("cooldown did not hold: %+v err=%v", decision, err)
	}
	reverse[1].RecentHardFailure = true
	reverse[1].SafetyGate = false
	decision, err = controller.Evaluate(key, reverse, now.Add(2*time.Minute))
	if err != nil || decision.Action != SwitchProfile || !decision.Emergency || decision.ToProfile != "zapret-a" {
		t.Fatalf("hard failure did not bypass cooldown: %+v err=%v", decision, err)
	}
}

func TestSwitchControllerRestoresCooldownAndQuarantine(t *testing.T) {
	controller := testSwitchController(t)
	key := switchKey()
	now := time.Date(2026, 7, 16, 17, 30, 0, 0, time.UTC)
	state := SwitchState{
		Key: key, ActiveProfileID: "zapret-a", LastSwitchAt: now.Add(-time.Minute),
		CooldownUntil: now.Add(time.Hour), QuarantinedUntil: map[string]time.Time{"zapret-b": now.Add(2 * time.Hour)},
	}
	if err := controller.Restore(state); err != nil {
		t.Fatal(err)
	}
	ranking := switchRanking(key)
	decision, err := controller.Evaluate(key, ranking, now)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != SwitchHold || decision.Reason != "cooldown_active" {
		t.Fatalf("restored cooldown was ignored: %+v", decision)
	}
	snapshot := controller.Snapshot(key, now)
	if !snapshot.QuarantinedUntil["zapret-b"].Equal(state.QuarantinedUntil["zapret-b"]) {
		t.Fatal("restored quarantine was lost")
	}
}

func TestManualPinFailsClosedAndUsesOnlyAllowedFallback(t *testing.T) {
	controller := testSwitchController(t)
	key := switchKey()
	now := time.Date(2026, 7, 16, 18, 0, 0, 0, time.UTC)
	if err := controller.SetActive(key, "zapret-a", now); err != nil {
		t.Fatal(err)
	}
	if err := controller.SetPin(key, ManualPin{ProfileID: "zapret-a", Mode: PinFailClosed}); err != nil {
		t.Fatal(err)
	}
	ranking := switchRanking(key)
	ranking[1].SafetyGate = false
	ranking[1].RecentHardFailure = true
	decision, err := controller.Evaluate(key, ranking, now.Add(time.Minute))
	if err != nil || decision.Action != SwitchDrop {
		t.Fatalf("fail-closed pin did not drop: %+v err=%v", decision, err)
	}
	if err := controller.SetPin(key, ManualPin{ProfileID: "zapret-a", Mode: PinSafeFallback, AllowedFallbacks: []string{"zapret-b"}}); err != nil {
		t.Fatal(err)
	}
	decision, err = controller.Evaluate(key, ranking, now.Add(2*time.Minute))
	if err != nil || decision.Action != SwitchProfile || decision.ToProfile != "zapret-b" {
		t.Fatalf("safe fallback pin chose wrong route: %+v err=%v", decision, err)
	}
}

func TestSwitchExecutorRollsBackAndQuarantinesBadCandidate(t *testing.T) {
	controller := testSwitchController(t)
	key := switchKey()
	now := time.Date(2026, 7, 16, 19, 0, 0, 0, time.UTC)
	if err := controller.SetActive(key, "zapret-a", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	decision := SwitchDecision{Key: key, Action: SwitchProfile, FromProfile: "zapret-a", ToProfile: "zapret-b", Reason: "test", EvaluatedAt: now}
	executor, _ := NewSwitchExecutor(controller)
	applier := &fakeSwitchApplier{failStep: "verify"}
	result := executor.Execute(context.Background(), decision, applier, now)
	if result.Status != "FAILED" || result.FailedStep != "verify" || !result.RollbackTried || !result.RollbackOK {
		t.Fatalf("unexpected rollback result: %+v", result)
	}
	state := controller.Snapshot(key, now)
	if state.ActiveProfileID != "zapret-a" || !state.QuarantinedUntil["zapret-b"].Equal(now.Add(6*time.Hour)) {
		t.Fatalf("rollback state was not preserved: %+v", state)
	}
	if got := applier.steps; len(got) != 6 || got[len(got)-1] != "rollback" {
		t.Fatalf("unexpected execution order: %v", got)
	}
}

func TestSwitchExecutorSerializesConcurrentTransactions(t *testing.T) {
	controller := testSwitchController(t)
	key := switchKey()
	now := time.Date(2026, 7, 16, 20, 0, 0, 0, time.UTC)
	_ = controller.SetActive(key, "zapret-a", now)
	executor, _ := NewSwitchExecutor(controller)
	decision := SwitchDecision{Key: key, Action: SwitchProfile, FromProfile: "zapret-a", ToProfile: "zapret-b", EvaluatedAt: now}
	applier := &fakeSwitchApplier{}
	var group sync.WaitGroup
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_ = executor.Execute(context.Background(), decision, applier, now)
		}()
	}
	group.Wait()
	state := controller.Snapshot(key, now)
	if state.ActiveProfileID != "zapret-b" {
		t.Fatalf("concurrent switch lost committed state: %+v", state)
	}
}

func TestProbeSchedulerPrioritizesConfirmationAndRecoversExpiredLease(t *testing.T) {
	policy := DefaultProbeSchedulePolicy()
	policy.ActiveInterval = time.Minute
	policy.BackupInterval = 2 * time.Minute
	policy.OtherInterval = 3 * time.Minute
	policy.ProbeDeadline = 5 * time.Second
	policy.JitterFraction = 0
	scheduler, err := NewProbeScheduler(policy)
	if err != nil {
		t.Fatal(err)
	}
	key := switchKey()
	ranking := switchRanking(key)
	now := time.Date(2026, 7, 16, 21, 0, 0, 0, time.UTC)
	if err := scheduler.RequestConfirmation(key, "zapret-b", now); err != nil {
		t.Fatal(err)
	}
	probe, ok, err := scheduler.Next(key, "zapret-a", ranking, now)
	if err != nil || !ok || probe.ProfileID != "zapret-b" || probe.Class != "confirmation" {
		t.Fatalf("confirmation was not prioritized: %+v ok=%v err=%v", probe, ok, err)
	}
	if _, ok, err := scheduler.Next(key, "zapret-a", ranking, now); err != nil || ok {
		t.Fatalf("concurrency budget was bypassed: ok=%v err=%v", ok, err)
	}
	probe, ok, err = scheduler.Next(key, "zapret-a", ranking, now.Add(6*time.Second))
	if err != nil || !ok || probe.Class != "confirmation" {
		t.Fatalf("expired lease did not recover: %+v ok=%v err=%v", probe, ok, err)
	}
}

func TestProbeSchedulerEnforcesDailyBudgetAndResetsAtUTCDate(t *testing.T) {
	policy := DefaultProbeSchedulePolicy()
	policy.ActiveInterval = time.Minute
	policy.BackupInterval = 2 * time.Minute
	policy.OtherInterval = 3 * time.Minute
	policy.MaxDailyProbes = 2
	policy.JitterFraction = 0
	scheduler, err := NewProbeScheduler(policy)
	if err != nil {
		t.Fatal(err)
	}
	key := switchKey()
	ranking := switchRanking(key)
	now := time.Date(2026, 7, 16, 22, 0, 0, 0, time.UTC)
	for index := 0; index < 2; index++ {
		probe, ok, err := scheduler.Next(key, "zapret-a", ranking, now.Add(time.Duration(index)*time.Minute))
		if err != nil || !ok {
			t.Fatalf("budgeted probe %d missing: ok=%v err=%v", index, ok, err)
		}
		if err := scheduler.Complete(probe.Token, probe.ScheduledAt.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok, err := scheduler.Next(key, "zapret-a", ranking, now.Add(3*time.Minute)); err != nil || ok {
		t.Fatalf("daily budget was bypassed: ok=%v err=%v", ok, err)
	}
	nextDay := now.Add(26 * time.Hour)
	if _, ok, err := scheduler.Next(key, "zapret-a", ranking, nextDay); err != nil || !ok {
		t.Fatalf("UTC budget did not reset: ok=%v err=%v", ok, err)
	}
}

func TestProbeSchedulerRestoresCompletedLeasesAndDailyBudget(t *testing.T) {
	policy := DefaultProbeSchedulePolicy()
	policy.JitterFraction = 0
	scheduler, err := NewProbeScheduler(policy)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	key := switchKey()
	ranking := switchRanking(key)
	probe, ok, err := scheduler.Next(key, ranking[0].ProfileID, ranking, now)
	if err != nil || !ok {
		t.Fatalf("initial lease failed: ok=%v err=%v", ok, err)
	}
	if err := scheduler.Complete(probe.Token, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := scheduler.Snapshot(now.Add(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewProbeScheduler(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Restore(snapshot, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	used, limit, inFlight := restored.Budget(now.Add(3 * time.Second))
	if used != 1 || limit != policy.MaxDailyProbes || inFlight != 0 {
		t.Fatalf("scheduler persistence mismatch: used=%d limit=%d in_flight=%d", used, limit, inFlight)
	}
	next, due, err := restored.Next(key, ranking[0].ProfileID, ranking, now.Add(time.Minute))
	if err != nil || !due || next.ProfileID == ranking[0].ProfileID {
		t.Fatalf("restored active lease interval was lost: probe=%+v due=%v err=%v", next, due, err)
	}
}

func TestProbeSchedulerCancelReleasesLeaseWithoutDelayingRetry(t *testing.T) {
	policy := DefaultProbeSchedulePolicy()
	policy.JitterFraction = 0
	scheduler, err := NewProbeScheduler(policy)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 16, 11, 0, 0, 0, time.UTC)
	key := switchKey()
	ranking := switchRanking(key)
	probe, ok, err := scheduler.Next(key, "zapret-a", ranking, now)
	if err != nil || !ok {
		t.Fatalf("initial lease failed: ok=%v err=%v", ok, err)
	}
	if err := scheduler.Cancel(probe.Token); err != nil {
		t.Fatal(err)
	}
	retry, ok, err := scheduler.Next(key, "zapret-a", ranking, now.Add(time.Second))
	if err != nil || !ok || retry.ProfileID != probe.ProfileID {
		t.Fatalf("cancelled lease was delayed: probe=%+v ok=%v err=%v", retry, ok, err)
	}
}

type fakeSwitchApplier struct {
	mu       sync.Mutex
	failStep string
	steps    []string
}

func (f *fakeSwitchApplier) step(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.steps = append(f.steps, name)
	if f.failStep == name {
		return errors.New(name + " failed")
	}
	return nil
}

func (f *fakeSwitchApplier) Prepare(context.Context, SwitchDecision) error { return f.step("prepare") }
func (f *fakeSwitchApplier) Validate(context.Context, SwitchDecision) error {
	return f.step("validate")
}
func (f *fakeSwitchApplier) Snapshot(context.Context, SwitchDecision) error {
	return f.step("snapshot")
}
func (f *fakeSwitchApplier) Apply(context.Context, SwitchDecision) error  { return f.step("apply") }
func (f *fakeSwitchApplier) Verify(context.Context, SwitchDecision) error { return f.step("verify") }
func (f *fakeSwitchApplier) Commit(context.Context, SwitchDecision) error { return f.step("commit") }
func (f *fakeSwitchApplier) Rollback(context.Context, SwitchDecision) error {
	return f.step("rollback")
}

func testSwitchController(t *testing.T) *SwitchController {
	t.Helper()
	controller, err := NewSwitchController(DefaultSwitchingPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func switchKey() DecisionKey {
	return DecisionKey{BundleID: "discord", Transport: "tcp", Port: 443, IPFamily: "ipv4", NetworkFingerprint: Digest([]byte("network"))}
}

func switchRanking(key DecisionKey) []CandidateScore {
	return []CandidateScore{
		{Key: key, ProfileID: "zapret-b", Attempts: 20, Successes: 20, SafetyGate: true, RequiredChecksPassed: true, WilsonLowerBound: 0.82, WilsonUpperBound: 1, SuccessRatio: 1, StableWindows: 4, MedianLatencyMS: 80, P95LatencyMS: 100, Eligible: true, ProductionReady: true},
		{Key: key, ProfileID: "zapret-a", Attempts: 20, Successes: 20, SafetyGate: true, RequiredChecksPassed: true, WilsonLowerBound: 0.82, WilsonUpperBound: 1, SuccessRatio: 1, StableWindows: 4, MedianLatencyMS: 120, P95LatencyMS: 140, Eligible: true, ProductionReady: true},
	}
}
