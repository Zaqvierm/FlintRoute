package manualimport

import (
	"errors"
	"sort"
	"strconv"
	"strings"
)

// AdoptionPlan is a review-only description of how a manually maintained
// dataplane could be handed to FlintRoute. It deliberately has no apply
// method: a report is evidence, not proof of ownership.
type AdoptionPlan struct {
	SchemaVersion   int                `json:"schema_version"`
	GeneratedAt     string             `json:"generated_at"`
	MigrationState  string             `json:"migration_state"`
	ApplyAllowed    bool               `json:"apply_allowed"`
	CandidateSHA256 string             `json:"candidate_sha256,omitempty"`
	Resources       []AdoptionResource `json:"resources"`
	Blockers        []Conflict         `json:"blockers"`
	Steps           []string           `json:"steps"`
}

type AdoptionResource struct {
	Kind           string   `json:"kind"`
	Identifier     string   `json:"identifier"`
	ObservedOwner  string   `json:"observed_owner"`
	OwnershipState string   `json:"ownership_state"`
	Evidence       []string `json:"evidence,omitempty"`
	RequiredAction string   `json:"required_action"`
}

const (
	ownershipForeign   = "foreign"
	ownershipUnproven  = "unproven"
	ownershipCollision = "collision"
)

// BuildAdoptionPlan converts the redacted inspection report into a bounded,
// deterministic review plan. It never treats a readable file, live listener,
// queue number or process name as ownership proof.
func BuildAdoptionPlan(report Report) (AdoptionPlan, error) {
	if report.SecretsPrinted {
		return AdoptionPlan{}, errors.New("refusing adoption plan from a report that contains secrets")
	}

	plan := AdoptionPlan{
		SchemaVersion:  1,
		GeneratedAt:    report.GeneratedAt,
		MigrationState: "blocked_on_ownership_handoff",
		ApplyAllowed:   false,
		Blockers:       append([]Conflict(nil), report.Conflicts...),
		Resources:      []AdoptionResource{},
		Steps: []string{
			"freeze the manual owner only during a reviewed maintenance window",
			"capture a versioned backup and prove the management recovery path",
			"prove exact PID/start-time, listener, nft-table, NFQUEUE, DNS and lifecycle ownership",
			"build and validate a ChangeSet without changing the manual dataplane",
			"install a mark-scoped transition guard before any listener or routing switch",
			"run OpenAI, Telegram, Zapret and Direct post-apply probes",
			"retain the manual dataplane as rollback until every probe and persistence check passes",
		},
	}
	switch {
	case report.Xray.FullBundleReady:
		plan.CandidateSHA256 = report.Xray.FullBundleSHA256
	case report.Xray.BundleReady:
		plan.CandidateSHA256 = report.Xray.BundleSHA256
	}
	if report.Xray.FullBundleReady {
		plan.Blockers = append(plan.Blockers, Conflict{
			Resource: "manual Xray topology handoff",
			Severity: "SEV-1",
			Reason:   "the full loopback topology was validated into a review-only candidate, but listener, DNS, nft and service ownership are not transaction-bound",
			Action:   "bind the candidate to an owned ChangeSet and prove the complete dataplane handoff before activation",
		})
	} else if report.Xray.Transparent > 0 || report.Xray.DNSInbounds > 0 {
		plan.Blockers = append(plan.Blockers, Conflict{
			Resource: "manual Xray candidate scope",
			Severity: "SEV-1",
			Reason:   "the staged candidate contains only loopback SOCKS/VLESS routes and cannot replace the manual transparent or DNS inbounds",
			Action:   "model and validate TPROXY/DNS inbounds and their dataplane ownership before any Xray handoff",
		})
	}

	plan.Resources = append(plan.Resources, AdoptionResource{
		Kind:           "process",
		Identifier:     "manual-xray",
		ObservedOwner:  "manual",
		OwnershipState: ownershipUnproven,
		Evidence:       []string{"manual Xray config was parsed; PID, start time and procd ownership were not proven"},
		RequiredAction: "prove PID/start-time, exact config hash and lifecycle owner before claiming the process",
	})
	endpoints := append([]string(nil), report.Xray.ListenerEndpoints...)
	if len(endpoints) == 0 {
		ports := append([]int(nil), report.Xray.ListenerPorts...)
		sort.Ints(ports)
		for _, port := range ports {
			endpoints = append(endpoints, "127.0.0.1:"+strconv.Itoa(port))
		}
	}
	sort.Strings(endpoints)
	for _, endpoint := range endpoints {
		plan.Resources = append(plan.Resources, AdoptionResource{
			Kind:           "listener",
			Identifier:     endpoint,
			ObservedOwner:  "manual-xray",
			OwnershipState: ownershipCollision,
			Evidence:       []string{"listener is already occupied by the manual dataplane"},
			RequiredAction: "do not bind or stop it until the owning PID and rollback handoff are proven",
		})
	}

	for _, zapret := range report.Zapret {
		queue := strconv.Itoa(zapret.Queue)
		state := ownershipForeign
		if !zapret.QueueSafe {
			state = ownershipCollision
		}
		plan.Resources = append(plan.Resources,
			AdoptionResource{
				Kind:          "profile-model",
				Identifier:    "queue:" + queue,
				ObservedOwner: "manual-nfqws",
				OwnershipState: func() string {
					if zapret.TypedModelReady {
						return ownershipCollision
					}
					return ownershipUnproven
				}(),
				Evidence: append([]string{"typed strategy: " + zapret.TypedStrategy}, zapret.ModelBlockers...),
				RequiredAction: func() string {
					if zapret.TypedModelReady {
						return "keep the profile foreign until the exact nft/process handoff is proven"
					}
					return "define a structured profile and asset manifest before migration"
				}(),
			},
			AdoptionResource{
				Kind:           "nfqueue",
				Identifier:     "queue:" + queue,
				ObservedOwner:  "manual-nfqws",
				OwnershipState: state,
				Evidence:       []string{"queue number was observed in manual nfqws arguments; kernel consumer ownership is unproven"},
				RequiredAction: "prove the exact NFQUEUE consumer, nft rule set and cleanup boundary; never claim system queues 0/1",
			},
			AdoptionResource{
				Kind:           "process",
				Identifier:     "manual-nfqws-q" + queue,
				ObservedOwner:  "manual",
				OwnershipState: ownershipUnproven,
				Evidence:       []string{"nfqws command line was parsed; PID, process group and lifecycle owner were not proven"},
				RequiredAction: "prove PID/start-time/PGID and register cleanup only after an explicit ownership claim",
			},
		)
		if zapret.DeviceScoped {
			evidence := []string{"nft evidence contains a host-scoped source rule for this queue; source identity is intentionally redacted"}
			if scope := zapret.DeviceScope; scope != nil {
				evidence = append(evidence,
					"scope fingerprint: "+scope.ScopeFingerprint,
					"tcp queue ports: "+strings.Join(scope.TCPPorts, ","),
					"udp drop ports: "+strings.Join(scope.UDPDropPorts, ","),
					"source rule count: "+strconv.Itoa(scope.SourceRuleCount),
				)
				if scope.ScopeConflict {
					evidence = append(evidence, "scope conflict: multiple host scopes were observed for one queue")
				}
			}
			plan.Resources = append(plan.Resources, AdoptionResource{
				Kind:           "device-scope",
				Identifier:     "queue:" + queue,
				ObservedOwner:  "manual-nft",
				OwnershipState: ownershipCollision,
				Evidence:       evidence,
				RequiredAction: "model and prove the exact device binding, queue lifecycle and rollback before importing this profile",
			})
		}
	}

	for _, file := range report.Files {
		switch file.Role {
		case "manual-dnsmasq":
			plan.Resources = append(plan.Resources, AdoptionResource{
				Kind:           "file",
				Identifier:     "manual-dnsmasq-include",
				ObservedOwner:  "manual",
				OwnershipState: ownershipForeign,
				Evidence:       []string{"manual dnsmasq include hash: " + file.SHA256},
				RequiredAction: "include the exact file and dnsmasq runtime state in the reviewed transaction manifest",
			})
		case "manual-nft":
			plan.Resources = append(plan.Resources, AdoptionResource{
				Kind:           "nft",
				Identifier:     "manual-nft-snapshot",
				ObservedOwner:  "manual",
				OwnershipState: ownershipForeign,
				Evidence:       []string{"manual nft evidence hash: " + file.SHA256},
				RequiredAction: "enumerate exact owned tables/chains/sets; do not flush or replace foreign tables",
			})
		}
	}
	if len(report.Policies) > 0 {
		counts := map[string]int{}
		for _, policy := range report.Policies {
			counts[policy.Kind]++
		}
		plan.Resources = append(plan.Resources, AdoptionResource{
			Kind:           "policy-inventory",
			Identifier:     "manual-policy-rules",
			ObservedOwner:  "manual",
			OwnershipState: ownershipForeign,
			Evidence: []string{
				"redacted domain-policy rules: " + strconv.Itoa(len(report.Policies)),
				"rule kinds: " + formatPolicyCounts(counts),
			},
			RequiredAction: "review domain-to-route and DNS ownership before creating a managed ChangeSet",
		})
	}

	// A process can be recreated by cron/procd even when its current PID is
	// known. The lifecycle owner must therefore be handled as a separate
	// resource, not inferred from the executable name.
	plan.Resources = append(plan.Resources, AdoptionResource{
		Kind:           "lifecycle",
		Identifier:     "manual-cron-procd",
		ObservedOwner:  "manual",
		OwnershipState: ownershipForeign,
		Evidence:       []string{"manual lifecycle recreation path is not included in the importer manifest"},
		RequiredAction: "enumerate cron and procd entries, then disable or hand off only exact-owned entries during maintenance",
	})

	// Keep output stable for UI diffs and evidence hashing. The plan is never
	// applyable while any resource is foreign, unproven or colliding.
	sort.SliceStable(plan.Resources, func(i, j int) bool {
		left := strings.Join([]string{plan.Resources[i].Kind, plan.Resources[i].Identifier}, "\x00")
		right := strings.Join([]string{plan.Resources[j].Kind, plan.Resources[j].Identifier}, "\x00")
		return left < right
	})
	return plan, nil
}

func formatPolicyCounts(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strconv.Itoa(counts[key]))
	}
	return strings.Join(parts, ",")
}
