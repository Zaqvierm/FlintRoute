package manualimport

import (
	"fmt"
	"strings"
)

// AdoptionDraftSchemaVersion versions the review-only bridge between a
// manually captured ownership proof and the normal ChangeSet state machine.
// It is deliberately not an adapter request and cannot grant apply access.
const AdoptionDraftSchemaVersion = 1

// AdoptionDraft is the only artifact produced by the manual handoff review.
// It describes the exact, ordered operations a future ChangeSet must perform;
// all dataplane mutation remains owned by the regular transaction protocol.
type AdoptionDraft struct {
	SchemaVersion        int                 `json:"schema_version"`
	State                string              `json:"state"`
	CandidateSHA256      string              `json:"candidate_sha256"`
	Generation           string              `json:"generation"`
	EligibleForChangeSet bool                `json:"eligible_for_change_set"`
	ApplyAllowed         bool                `json:"apply_allowed"`
	VerifiedResources    int                 `json:"verified_resources"`
	RequiredResources    int                 `json:"required_resources"`
	Blockers             []Conflict          `json:"blockers"`
	Preconditions        []string            `json:"preconditions"`
	Operations           []AdoptionOperation `json:"operations"`
}

// AdoptionOperation is a typed, human-reviewable operation description. It
// intentionally contains resource references only; it never carries paths,
// shell fragments, credentials or provider JSON.
type AdoptionOperation struct {
	Sequence       int      `json:"sequence"`
	Action         string   `json:"action"`
	ResourceRefs   []string `json:"resource_refs,omitempty"`
	RequiresChange bool     `json:"requires_change_set"`
	Destructive    bool     `json:"destructive"`
}

// BuildAdoptionDraft evaluates the exact plan/proof pair and emits a
// review-only sequence. A ready draft is eligible to be turned into a normal
// ChangeSet by a future controller implementation, but ApplyAllowed is always
// false here: no caller may bypass validate/apply/confirm/rollback.
func BuildAdoptionDraft(plan AdoptionPlan, manifest HandoffManifest) (AdoptionDraft, error) {
	decision, err := EvaluateHandoff(plan, manifest)
	if err != nil {
		return AdoptionDraft{}, err
	}
	candidate, ok := normalizeSHA256(manifest.CandidateSHA256)
	if !ok {
		return AdoptionDraft{}, fmt.Errorf("handoff candidate hash is invalid")
	}
	draft := AdoptionDraft{
		SchemaVersion:        AdoptionDraftSchemaVersion,
		State:                decision.State,
		CandidateSHA256:      "sha256:" + candidate,
		Generation:           manifest.Generation,
		EligibleForChangeSet: decision.EligibleForChangeSet,
		ApplyAllowed:         false,
		VerifiedResources:    decision.VerifiedResources,
		RequiredResources:    decision.RequiredResources,
		Blockers:             append([]Conflict(nil), decision.Blockers...),
		Preconditions: []string{
			"fresh backup and independently proven management recovery path",
			"candidate, ownership proof and generation remain hash-bound",
			"manual owner is quiesced only inside the reviewed ChangeSet",
			"transition guard is installed before any listener or routing switch",
			"manual dataplane rollback remains available until post-apply probes pass",
		},
		Operations: []AdoptionOperation{},
	}
	if !decision.EligibleForChangeSet {
		return draft, nil
	}
	allResources := adoptionResourceRefs(plan.Resources)
	manualResources := adoptionResourceRefsByOwner(plan.Resources, "manual")
	// The sequence is intentionally fixed and descriptive. The future executor
	// must map each action to typed adapter/helper operations and persist every
	// boundary through the normal transaction journal.
	draft.Operations = []AdoptionOperation{
		{Sequence: 1, Action: "verify_handoff", ResourceRefs: allResources, RequiresChange: true},
		{Sequence: 2, Action: "prepare_transition_guard", RequiresChange: true},
		{Sequence: 3, Action: "quiesce_manual_owner", ResourceRefs: manualResources, RequiresChange: true, Destructive: true},
		{Sequence: 4, Action: "activate_candidate", RequiresChange: true, Destructive: true},
		{Sequence: 5, Action: "verify_management_path", RequiresChange: true},
		{Sequence: 6, Action: "verify_dataplane", RequiresChange: true},
		{Sequence: 7, Action: "persist_active_revision", RequiresChange: true},
		{Sequence: 8, Action: "finalize_ownership", ResourceRefs: manualResources, RequiresChange: true, Destructive: true},
	}
	return draft, nil
}

// Validate enforces the non-escalation contract when a draft is read back by
// another local tool or future UI: it must never become an apply instruction.
func (d AdoptionDraft) Validate() error {
	if d.SchemaVersion != AdoptionDraftSchemaVersion {
		return fmt.Errorf("unsupported adoption draft schema %d", d.SchemaVersion)
	}
	if _, ok := normalizeSHA256(d.CandidateSHA256); !ok {
		return fmt.Errorf("adoption draft candidate hash is invalid")
	}
	if strings.TrimSpace(d.Generation) == "" || len(d.Generation) > 128 {
		return fmt.Errorf("adoption draft generation is required")
	}
	if d.ApplyAllowed {
		return fmt.Errorf("adoption draft cannot grant apply permission")
	}
	if d.RequiredResources < 0 || d.VerifiedResources < 0 || d.VerifiedResources > d.RequiredResources {
		return fmt.Errorf("adoption draft resource counts are invalid")
	}
	if len(d.Preconditions) == 0 {
		return fmt.Errorf("adoption draft preconditions are required")
	}
	last := 0
	// ResourceRefs are validated as opaque kind/identifier references by the
	// producer below; the draft format intentionally does not duplicate the
	// plan (and therefore cannot carry paths or credentials).
	for _, operation := range d.Operations {
		if operation.Sequence != last+1 || strings.TrimSpace(operation.Action) == "" {
			return fmt.Errorf("adoption draft operation sequence is invalid")
		}
		if !operation.RequiresChange {
			return fmt.Errorf("adoption draft operation %d is missing ChangeSet binding", operation.Sequence)
		}
		for _, ref := range operation.ResourceRefs {
			ref = strings.TrimSpace(ref)
			if ref == "" || len(ref) > 256 {
				return fmt.Errorf("adoption draft operation %d has invalid resource reference", operation.Sequence)
			}
		}
		last = operation.Sequence
	}
	if d.EligibleForChangeSet && len(d.Operations) == 0 {
		return fmt.Errorf("eligible adoption draft has no operations")
	}
	if !d.EligibleForChangeSet && len(d.Operations) != 0 {
		return fmt.Errorf("blocked adoption draft contains executable operations")
	}
	return nil
}

func adoptionResourceRefs(resources []AdoptionResource) []string {
	refs := make([]string, 0, len(resources))
	for _, resource := range resources {
		refs = append(refs, strings.TrimSpace(resource.Kind)+"/"+strings.TrimSpace(resource.Identifier))
	}
	return refs
}

func adoptionResourceRefsByOwner(resources []AdoptionResource, owner string) []string {
	refs := make([]string, 0, len(resources))
	for _, resource := range resources {
		if strings.TrimSpace(resource.ObservedOwner) == owner {
			refs = append(refs, strings.TrimSpace(resource.Kind)+"/"+strings.TrimSpace(resource.Identifier))
		}
	}
	return refs
}
