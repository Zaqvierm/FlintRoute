package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/health"
	"router-policy/internal/planner"
	"router-policy/internal/probe"
)

func fakeAdapterCallCount(fake *fakeAdapter) int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return len(fake.calls)
}

func TestRecoveryMutationFenceBlocksEveryUnsafeStatus(t *testing.T) {
	for _, status := range []string{"starting", "error", "recovery_required", ""} {
		t.Run("status_"+status, func(t *testing.T) {
			fake := newFakeAdapter()
			srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
			defer ts.Close()
			defer srv.Close()

			change := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
			if err := srv.setRecoveryStatus(recoveryStatus{Status: status, Reason: "test fence"}); err != nil {
				t.Fatalf("set recovery status: %v", err)
			}
			_, code := postAction(t, client, csrf, ts.URL, change.ID, "apply", `{}`)
			if code != http.StatusServiceUnavailable {
				t.Fatalf("apply status=%d want=%d", code, http.StatusServiceUnavailable)
			}
			if calls := fakeAdapterCallCount(fake); calls != 0 {
				t.Fatalf("unsafe recovery status allowed adapter calls=%d", calls)
			}
		})
	}
}

func TestRecoveryMutationFenceAllowsOnlyProvenStatuses(t *testing.T) {
	tests := []struct {
		name   string
		status recoveryStatus
	}{
		{name: "ok", status: recoveryStatus{Status: "ok"}},
		{name: "confirmed_baseline", status: recoveryStatus{Status: "not_required", RevisionID: "rev_baseline", CandidateHash: "sha256:baseline"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeAdapter()
			srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
			defer ts.Close()
			defer srv.Close()

			change := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
			if err := srv.setRecoveryStatus(test.status); err != nil {
				t.Fatalf("set recovery status: %v", err)
			}
			_, code := postAction(t, client, csrf, ts.URL, change.ID, "apply", `{}`)
			if code != http.StatusOK {
				t.Fatalf("apply status=%d want=%d", code, http.StatusOK)
			}
			if calls := fakeAdapterCallCount(fake); calls == 0 {
				t.Fatal("proven safe recovery status did not permit adapter work")
			}
		})
	}
}

func TestRecoveryStatusPersistenceFailureInstallsMemoryFence(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer ts.Close()
	defer srv.Close()

	srv.store.SetFaultHook(func(operation string) error {
		if operation == "save_json:meta" {
			return errors.New("injected recovery status write failure")
		}
		return nil
	})
	err := srv.setRecoveryStatus(recoveryStatus{Status: "ok"})
	srv.store.SetFaultHook(nil)
	if err == nil {
		t.Fatal("status persistence failure was hidden")
	}
	status := srv.currentRecoveryStatus()
	if status.Status != "recovery_required" || status.ReasonCode != "recovery_status_persist_failed" {
		t.Fatalf("persistence failure did not install visible fence: %+v", status)
	}
	if failure := srv.mutationFailure(); failure == nil || failure.Status != http.StatusServiceUnavailable {
		t.Fatalf("memory fence did not block mutation: %+v", failure)
	}
}

func TestRecoveryTransitionExcludesConcurrentMutation(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer ts.Close()
	defer srv.Close()

	release, failure := srv.acquireMutationLease()
	if failure != nil {
		t.Fatalf("acquire initial mutation lease: %+v", failure)
	}
	statusDone := make(chan error, 1)
	go func() {
		statusDone <- srv.setRecoveryStatus(recoveryStatus{Status: "starting", Reason: "transition"})
	}()
	select {
	case err := <-statusDone:
		t.Fatalf("recovery transition completed while mutation lease was held: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	mutationDone := make(chan *actionFailure, 1)
	go func() {
		_, blocked := srv.acquireMutationLease()
		mutationDone <- blocked
	}()
	release()
	if err := <-statusDone; err != nil {
		t.Fatalf("recovery transition failed: %v", err)
	}
	select {
	case blocked := <-mutationDone:
		if blocked == nil || blocked.Status != http.StatusServiceUnavailable {
			t.Fatalf("concurrent mutation was not fenced: %+v", blocked)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent mutation did not complete")
	}
}

func TestDiscoveryDraftCreationRespectsRecoveryFence(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer ts.Close()
	defer srv.Close()

	for _, status := range []string{"starting", "error"} {
		if err := srv.setRecoveryStatus(recoveryStatus{Status: status, Reason: "scheduler fence"}); err != nil {
			t.Fatalf("set status %q: %v", status, err)
		}
		_, err := srv.createDraftChange("blocked", "blocked", srv.configVersion, nil, "scheduler")
		if err == nil {
			t.Fatalf("status %q allowed background draft mutation", status)
		}
		if calls := fakeAdapterCallCount(fake); calls != 0 {
			t.Fatalf("status %q caused adapter calls=%d", status, calls)
		}
	}
}

func TestAutomaticDomainCommitRespectsRecoveryFence(t *testing.T) {
	for _, status := range []string{"starting", "error"} {
		t.Run(status, func(t *testing.T) {
			fake := newFakeAdapter()
			srv, ts, _, _, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
			defer ts.Close()
			defer srv.Close()

			if err := srv.setRecoveryStatus(recoveryStatus{Status: status, Reason: "scheduler fence"}); err != nil {
				t.Fatalf("set status: %v", err)
			}
			result := srv.commitAutomaticDomain(nil, planner.DomainCheck{
				Domain: "blocked.example", Category: "GEO_LOCKED", Confidence: 1,
				Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", PathVerified: true},
			})
			if result.Reason == "" {
				t.Fatalf("status %q returned an empty blocked reason: %+v", status, result)
			}
			if calls := fakeAdapterCallCount(fake); calls != 0 {
				t.Fatalf("status %q caused adapter calls=%d", status, calls)
			}
		})
	}
}

func TestHealthSchedulerSkipsProbesWhenRecoveryIsUnsafe(t *testing.T) {
	for _, status := range []string{"starting", "error"} {
		t.Run(status, func(t *testing.T) {
			srv := newTestServer(t)
			defer srv.Close()
			engine := &apiHealthEngine{}
			srv.probeEngineFactory = func(*config.Config) health.ProbeEngine { return engine }
			if err := srv.setRecoveryStatus(recoveryStatus{Status: status, Reason: "scheduler fence"}); err != nil {
				t.Fatal(err)
			}
			srv.runHealthCycle(context.Background())
			engine.mu.Lock()
			calls := engine.calls
			engine.mu.Unlock()
			if calls != 0 {
				t.Fatalf("unsafe recovery status %q allowed health probes=%d", status, calls)
			}
		})
	}
}
