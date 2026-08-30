package manualimport

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// HandoffSchemaVersion is the version of the proof envelope, not the
// candidate/config schema. Keeping it separate prevents a proof captured for
// one ownership contract from being silently reused after a schema change.
const HandoffSchemaVersion = 1

const (
	handoffBlocked = "blocked_on_ownership_handoff"
	handoffReady   = "ready_for_change_set"
)

var sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// normalizeSHA256 accepts both the historical xraybundle form
// "sha256:<hex>" and the bare digest used by handoff proofs. Keeping the
// comparison semantic avoids rejecting an otherwise identical plan solely
// because its producer chose a prefix.
func normalizeSHA256(value string) (string, bool) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.TrimPrefix(value, "sha256:"), "SHA256:")
	if !sha256Pattern.MatchString(value) {
		return "", false
	}
	return strings.ToLower(value), true
}

// HandoffManifest is a proof envelope produced during a reviewed maintenance
// window. It is input to EvaluateHandoff only; it is never an adapter command
// and cannot activate or stop anything by itself.
type HandoffManifest struct {
	SchemaVersion        int                    `json:"schema_version"`
	GeneratedAt          string                 `json:"generated_at"`
	CandidateSHA256      string                 `json:"candidate_sha256"`
	Generation           string                 `json:"generation"`
	ManualOwnerQuiesced  bool                   `json:"manual_owner_quiesced"`
	TransitionGuardReady bool                   `json:"transition_guard_ready"`
	RollbackPrepared     bool                   `json:"rollback_prepared"`
	ManagementProof      bool                   `json:"management_proof"`
	ResolvedBlockers     []string               `json:"resolved_blockers,omitempty"`
	Resources            []HandoffResourceProof `json:"resources"`
}

// HandoffResourceProof binds one imported resource to the exact resource
// observed in the redacted adoption plan. Sensitive values are represented by
// hashes or opaque IDs; no config, credential, URL or raw command is accepted.
type HandoffResourceProof struct {
	Kind           string `json:"kind"`
	Identifier     string `json:"identifier"`
	CurrentOwner   string `json:"current_owner"`
	ClaimedOwner   string `json:"claimed_owner"`
	State          string `json:"state"`
	Generation     string `json:"generation"`
	EvidenceSHA256 string `json:"evidence_sha256"`
	ConfigSHA256   string `json:"config_sha256,omitempty"`
	Executable     string `json:"executable,omitempty"`
	ProcessRef     string `json:"process_ref,omitempty"`
	PID            int    `json:"pid,omitempty"`
	StartTimeTicks uint64 `json:"start_time_ticks,omitempty"`
	PGID           int    `json:"pgid,omitempty"`
}

// HandoffDecision deliberately exposes eligibility for a reviewed ChangeSet,
// never direct apply permission. The caller must still run the transaction
// state machine and its transition guard.
type HandoffDecision struct {
	SchemaVersion        int        `json:"schema_version"`
	State                string     `json:"state"`
	EligibleForChangeSet bool       `json:"eligible_for_change_set"`
	ApplyAllowed         bool       `json:"apply_allowed"`
	VerifiedResources    int        `json:"verified_resources"`
	RequiredResources    int        `json:"required_resources"`
	Blockers             []Conflict `json:"blockers"`
}

func (m HandoffManifest) Validate() error {
	if m.SchemaVersion != HandoffSchemaVersion {
		return fmt.Errorf("unsupported handoff manifest schema %d", m.SchemaVersion)
	}
	if _, err := time.Parse(time.RFC3339Nano, m.GeneratedAt); err != nil {
		return fmt.Errorf("invalid handoff generated_at: %w", err)
	}
	if _, ok := normalizeSHA256(m.CandidateSHA256); !ok {
		return errors.New("handoff candidate_sha256 must be a 64-character hex digest")
	}
	if strings.TrimSpace(m.Generation) == "" || len(m.Generation) > 128 {
		return errors.New("handoff generation is required")
	}
	if len(m.Resources) == 0 {
		return errors.New("handoff resources are required")
	}
	seenBlockers := make(map[string]struct{}, len(m.ResolvedBlockers))
	for _, blocker := range m.ResolvedBlockers {
		blocker = strings.TrimSpace(blocker)
		if blocker == "" || len(blocker) > 128 {
			return errors.New("handoff resolved blocker is invalid")
		}
		if _, exists := seenBlockers[blocker]; exists {
			return fmt.Errorf("duplicate resolved blocker %q", blocker)
		}
		seenBlockers[blocker] = struct{}{}
	}
	seen := make(map[string]struct{}, len(m.Resources))
	for _, resource := range m.Resources {
		if strings.TrimSpace(resource.Kind) == "" || strings.TrimSpace(resource.Identifier) == "" {
			return errors.New("handoff resource kind and identifier are required")
		}
		key := resource.Kind + "\x00" + resource.Identifier
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate handoff resource %q", key)
		}
		seen[key] = struct{}{}
		if resource.ClaimedOwner != "flintroute" {
			return fmt.Errorf("resource %s/%s has invalid claimed owner", resource.Kind, resource.Identifier)
		}
		if resource.State != "verified" {
			return fmt.Errorf("resource %s/%s is not verified", resource.Kind, resource.Identifier)
		}
		if resource.Generation != m.Generation {
			return fmt.Errorf("resource %s/%s generation does not match manifest", resource.Kind, resource.Identifier)
		}
		if _, ok := normalizeSHA256(resource.EvidenceSHA256); !ok {
			return fmt.Errorf("resource %s/%s evidence_sha256 is invalid", resource.Kind, resource.Identifier)
		}
		switch resource.Kind {
		case "process":
			if resource.PID <= 0 || resource.StartTimeTicks == 0 || resource.PGID <= 0 {
				return fmt.Errorf("process %s lacks PID/start-time/PGID identity", resource.Identifier)
			}
			if strings.TrimSpace(resource.Executable) == "" {
				return fmt.Errorf("process %s lacks executable/config identity", resource.Identifier)
			}
			if _, ok := normalizeSHA256(resource.ConfigSHA256); !ok {
				return fmt.Errorf("process %s lacks executable/config identity", resource.Identifier)
			}
		case "listener":
			if strings.TrimSpace(resource.ProcessRef) == "" {
				return fmt.Errorf("listener %s lacks process reference", resource.Identifier)
			}
		case "nft", "nft-table", "nft-chain", "nft-set", "nft-rule", "nfqueue", "file", "lifecycle", "policy-inventory", "profile-model", "device-scope":
			// The evidence digest and generation bind non-process resources.
		default:
			return fmt.Errorf("unsupported handoff resource kind %q", resource.Kind)
		}
	}
	return nil
}

// EvaluateHandoff compares a proof envelope with the immutable redacted plan.
// It fails closed on missing, extra, stale or foreign resources. A successful
// result is only a prerequisite for creating a ChangeSet; ApplyAllowed remains
// false by design.
func EvaluateHandoff(plan AdoptionPlan, manifest HandoffManifest) (HandoffDecision, error) {
	decision := HandoffDecision{
		SchemaVersion:     HandoffSchemaVersion,
		State:             handoffBlocked,
		ApplyAllowed:      false,
		Blockers:          []Conflict{},
		RequiredResources: len(plan.Resources),
	}
	if plan.SchemaVersion != 1 {
		return decision, fmt.Errorf("unsupported adoption plan schema %d", plan.SchemaVersion)
	}
	planHash, planHashOK := normalizeSHA256(plan.CandidateSHA256)
	manifestHash, manifestHashOK := normalizeSHA256(manifest.CandidateSHA256)
	if !planHashOK || !manifestHashOK {
		return decision, errors.New("adoption plan has no candidate hash")
	}
	if err := manifest.Validate(); err != nil {
		return decision, err
	}
	if planHash != manifestHash {
		return decision, errors.New("handoff candidate hash does not match adoption plan")
	}

	proofByKey := make(map[string]HandoffResourceProof, len(manifest.Resources))
	for _, proof := range manifest.Resources {
		proofByKey[proof.Kind+"\x00"+proof.Identifier] = proof
	}
	planKeys := make(map[string]struct{}, len(plan.Resources))
	for _, resource := range plan.Resources {
		key := resource.Kind + "\x00" + resource.Identifier
		planKeys[key] = struct{}{}
		proof, ok := proofByKey[key]
		if !ok {
			decision.Blockers = append(decision.Blockers, Conflict{
				Resource: resource.Kind + "/" + resource.Identifier,
				Severity: "SEV-1",
				Reason:   "exact ownership proof is missing",
				Action:   "capture a fresh proof for this resource during the reviewed handoff",
			})
			continue
		}
		if proof.CurrentOwner != resource.ObservedOwner {
			decision.Blockers = append(decision.Blockers, Conflict{
				Resource: resource.Kind + "/" + resource.Identifier,
				Severity: "SEV-1",
				Reason:   "current owner changed since the adoption plan was captured",
				Action:   "refresh the inventory and refuse to claim a changed resource",
			})
			continue
		}
		decision.VerifiedResources++
	}
	for key, proof := range proofByKey {
		if _, ok := planKeys[key]; ok {
			continue
		}
		decision.Blockers = append(decision.Blockers, Conflict{
			Resource: proof.Kind + "/" + proof.Identifier,
			Severity: "SEV-1",
			Reason:   "proof contains a resource absent from the reviewed plan",
			Action:   "refresh the plan before accepting any additional resource",
		})
	}
	resolvedBlockers := make(map[string]struct{}, len(manifest.ResolvedBlockers))
	for _, blocker := range manifest.ResolvedBlockers {
		resolvedBlockers[strings.TrimSpace(blocker)] = struct{}{}
	}
	for _, blocker := range plan.Blockers {
		if _, ok := resolvedBlockers[blocker.Resource]; ok {
			continue
		}
		decision.Blockers = append(decision.Blockers, Conflict{
			Resource: blocker.Resource,
			Severity: blocker.Severity,
			Reason:   "adoption plan blocker has no reviewed resolution proof",
			Action:   "resolve this blocker explicitly in the same maintenance handoff",
		})
	}
	for blocker := range resolvedBlockers {
		found := false
		for _, planned := range plan.Blockers {
			if planned.Resource == blocker {
				found = true
				break
			}
		}
		if !found {
			decision.Blockers = append(decision.Blockers, Conflict{
				Resource: blocker,
				Severity: "SEV-1",
				Reason:   "proof resolves a blocker absent from the reviewed plan",
				Action:   "refresh the plan and capture proof against its exact blocker set",
			})
		}
	}
	if !manifest.ManualOwnerQuiesced {
		decision.Blockers = append(decision.Blockers, Conflict{Resource: "manual owner", Severity: "SEV-1", Reason: "manual lifecycle is still allowed to recreate the dataplane", Action: "quiesce the manual owner inside the same reviewed ChangeSet"})
	}
	if !manifest.TransitionGuardReady {
		decision.Blockers = append(decision.Blockers, Conflict{Resource: "transition guard", Severity: "SEV-1", Reason: "protected traffic is not fenced before the handoff", Action: "prepare a mark-scoped fail-closed guard and prove its generation"})
	}
	if !manifest.RollbackPrepared {
		decision.Blockers = append(decision.Blockers, Conflict{Resource: "rollback", Severity: "SEV-1", Reason: "manual dataplane rollback is not prepared", Action: "retain and verify the previous manual generation until post-apply probes pass"})
	}
	if !manifest.ManagementProof {
		decision.Blockers = append(decision.Blockers, Conflict{Resource: "management proof", Severity: "SEV-1", Reason: "management recovery path is not independently proven", Action: "obtain a fresh LAN/SSH management proof before any listener switch"})
	}
	if len(decision.Blockers) == 0 && decision.VerifiedResources == decision.RequiredResources {
		decision.State = handoffReady
		decision.EligibleForChangeSet = true
	}
	sort.SliceStable(decision.Blockers, func(i, j int) bool {
		left := decision.Blockers[i].Resource + "\x00" + decision.Blockers[i].Reason
		right := decision.Blockers[j].Resource + "\x00" + decision.Blockers[j].Reason
		return left < right
	})
	return decision, nil
}
