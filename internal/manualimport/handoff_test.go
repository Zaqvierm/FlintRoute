package manualimport

import (
	"strings"
	"testing"
	"time"
)

const handoffHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func handoffPlanFixture() AdoptionPlan {
	return AdoptionPlan{
		SchemaVersion:   1,
		GeneratedAt:     fixedTime().Format(time.RFC3339Nano),
		CandidateSHA256: handoffHash,
		Resources: []AdoptionResource{
			{Kind: "process", Identifier: "manual-xray", ObservedOwner: "manual"},
			{Kind: "listener", Identifier: "127.0.0.1:12345", ObservedOwner: "manual-xray"},
		},
	}
}

func handoffManifestFixture() HandoffManifest {
	return HandoffManifest{
		SchemaVersion:        HandoffSchemaVersion,
		GeneratedAt:          fixedTime().Format(time.RFC3339Nano),
		CandidateSHA256:      handoffHash,
		Generation:           "generation-1",
		ManualOwnerQuiesced:  true,
		TransitionGuardReady: true,
		RollbackPrepared:     true,
		ManagementProof:      true,
		Resources: []HandoffResourceProof{
			{
				Kind:           "process",
				Identifier:     "manual-xray",
				CurrentOwner:   "manual",
				ClaimedOwner:   "flintroute",
				State:          "verified",
				Generation:     "generation-1",
				EvidenceSHA256: handoffHash,
				ConfigSHA256:   handoffHash,
				Executable:     "/usr/bin/xray",
				PID:            100,
				StartTimeTicks: 200,
				PGID:           100,
			},
			{
				Kind:           "listener",
				Identifier:     "127.0.0.1:12345",
				CurrentOwner:   "manual-xray",
				ClaimedOwner:   "flintroute",
				State:          "verified",
				Generation:     "generation-1",
				EvidenceSHA256: handoffHash,
				ProcessRef:     "manual-xray",
			},
		},
	}
}

func TestEvaluateHandoffReturnsReadyOnlyForExactVerifiedProof(t *testing.T) {
	decision, err := EvaluateHandoff(handoffPlanFixture(), handoffManifestFixture())
	if err != nil {
		t.Fatal(err)
	}
	if decision.State != handoffReady || !decision.EligibleForChangeSet {
		t.Fatalf("verified handoff was not eligible: %+v", decision)
	}
	if decision.ApplyAllowed {
		t.Fatal("handoff proof granted direct apply permission")
	}
	if decision.VerifiedResources != 2 || decision.RequiredResources != 2 || len(decision.Blockers) != 0 {
		t.Fatalf("unexpected ready decision: %+v", decision)
	}
}

func TestEvaluateHandoffAcceptsImporterPrefixedCandidateHash(t *testing.T) {
	plan := handoffPlanFixture()
	manifest := handoffManifestFixture()
	plan.CandidateSHA256 = "sha256:" + plan.CandidateSHA256
	if _, err := EvaluateHandoff(plan, manifest); err != nil {
		t.Fatalf("prefixed adoption-plan hash should compare semantically: %v", err)
	}
	manifest.CandidateSHA256 = "SHA256:" + manifest.CandidateSHA256
	if _, err := EvaluateHandoff(plan, manifest); err != nil {
		t.Fatalf("case-insensitive prefixed proof hash should compare semantically: %v", err)
	}
}

func TestEvaluateHandoffFailsClosedOnMissingOrChangedProof(t *testing.T) {
	plan := handoffPlanFixture()
	manifest := handoffManifestFixture()
	manifest.Resources = manifest.Resources[:1]
	decision, err := EvaluateHandoff(plan, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if decision.EligibleForChangeSet || decision.State != handoffBlocked || len(decision.Blockers) == 0 {
		t.Fatalf("missing listener proof was not fenced: %+v", decision)
	}

	manifest = handoffManifestFixture()
	manifest.Resources[0].CurrentOwner = "unexpected-owner"
	decision, err = EvaluateHandoff(plan, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if decision.EligibleForChangeSet || !strings.Contains(decision.Blockers[0].Reason, "owner changed") {
		t.Fatalf("changed owner was not fenced: %+v", decision)
	}
}

func TestEvaluateHandoffRequiresGuardRollbackAndManagementProof(t *testing.T) {
	manifest := handoffManifestFixture()
	manifest.TransitionGuardReady = false
	manifest.RollbackPrepared = false
	manifest.ManagementProof = false
	decision, err := EvaluateHandoff(handoffPlanFixture(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	if decision.EligibleForChangeSet || len(decision.Blockers) != 3 {
		t.Fatalf("missing safety gates were not all surfaced: %+v", decision)
	}
}

func TestEvaluateHandoffRequiresExplicitResolutionForPlanBlockers(t *testing.T) {
	plan := handoffPlanFixture()
	plan.Blockers = []Conflict{{Resource: "manual Xray topology handoff", Severity: "SEV-1"}}
	manifest := handoffManifestFixture()
	decision, err := EvaluateHandoff(plan, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if decision.EligibleForChangeSet || len(decision.Blockers) != 1 {
		t.Fatalf("unresolved plan blocker was not fenced: %+v", decision)
	}

	manifest.ResolvedBlockers = []string{"manual Xray topology handoff"}
	decision, err = EvaluateHandoff(plan, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.EligibleForChangeSet {
		t.Fatalf("explicitly resolved blocker still fenced: %+v", decision)
	}
}

func TestHandoffManifestRejectsWeakProcessIdentityAndUnknownKind(t *testing.T) {
	manifest := handoffManifestFixture()
	manifest.Resources[0].PID = 0
	if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), "PID/start-time/PGID") {
		t.Fatalf("weak process identity was accepted: %v", err)
	}

	manifest = handoffManifestFixture()
	manifest.Resources[0].Kind = "shell-command"
	if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported handoff resource kind") {
		t.Fatalf("unknown resource kind was accepted: %v", err)
	}
}
