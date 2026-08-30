# Route selection and service evidence

This document defines the decision contract implemented by the planner. It is
deliberately separate from the operational workflow kept outside the public
repository.

## Eligibility is not priority

`eligibleRouteTypesForService` describes the eligible route types and the order in which a
bounded planner may collect evidence. It is not a winner rule. A normal domain
is selected only after every applicable candidate has a terminal result (or a
bounded timeout), hard safety filters have run, and the remaining candidates
have been scored. Explicit user overrides are the only exception: they are a
forced route decision and retain DROP as the failure fallback.

The planner never treats an HTTP success, DNS answer, process start, simulated
result, or array position as proof of a usable route. A selectable network
route requires `Simulation=false`, `Status=OK`, `PathVerified=true`,
`ServiceOK=true`, no regional denial, and a revision-bound candidate identity.
DROP is a separate terminal safety outcome. The exported
`planner.SelectionEvidence` gate is reused by API projections and route-only
assignment, so automatic mutation cannot accept weaker evidence than planner
selection.
The API's cached-decision projection uses the same typed `SelectionEvidence`
gate as the planner, so contradictory authentication, WAF/rate-limit, or
regional evidence cannot be rendered as a verified route.

## Comparable measurements

`route_latency_ms` is the request/path measurement reported by the probe.
`end_to_end_latency_ms` is the comparable service-path metric used for route
selection; it covers the required checks for that candidate. Verification job
duration is orchestration time (queue, setup, retries, cleanup) and is never a
latency score. If no honest network measurement exists, latency is unavailable
and the candidate ranks after measured paths.

The planner does not fall back to `route_latency_ms` when calculating a
selection score. Request-only measurements can still be displayed as evidence,
but they cannot make a candidate win a comparison against a route with a
comparable end-to-end measurement.

The API and Decision Flow expose these values separately, together with the
policy score and the evidence for each candidate.

## Hard filters and differential classification

Hard filters run before scoring:

* policy allowed/forbidden paths;
* complete path and service evidence;
* regional denial exclusion;
* required non-RU egress must be known and non-RU;
* candidate identity must match the active revision.
Health-control quorum applies the same principle: simulation results and
results carrying regional-denial, authentication, or WAF/rate-limit flags are
never promoted to healthy merely because legacy status fields contain `OK`.
The same gate is required for manual service preflight, classified-route
revalidation, failed-route recovery, and fresh configured-service readback;
these paths must not turn contradictory or simulated evidence into a route,
health recovery, or policy suggestion. A transport-verified but not-yet-bound
manual candidate is the sole explicit exception and must carry the dedicated
`route_not_bound_to_verification_plan` reason plus its own bounded checks.

`GEO_LOCKED` is confirmed only when the Direct baseline reports a regional
denial and at least one alternate non-DROP route passes the same service
contract. A Direct denial without an alternate is `SUSPECTED_GEO_LOCKED`.
Generic 401/403/429 results are typed as authentication or WAF/rate-limit
evidence and do not establish GEO by themselves. TSPU and GEO classification
state is independent from route-decision confidence and has an explicit TTL.

Known services should describe a service contract with required landing,
backend/auth, content and regional checks. A configured classification seed is
only a hint (`SEEDED_*`) until live evidence confirms or contradicts it.

## Selection stability

The default strategy is balanced; `fastest`, `privacy_first`, and
`fail_closed` are validated configuration values. The score combines the
end-to-end metric with health evidence. The relative penalties are configured
under `policy.route_selection_weights`: `end_to_end_latency` (default `1`),
`availability` (default `0.25`), `error_rate` (default `0.1`), and
`privacy` (default `0.25` for Direct under `privacy_first`). These are
multiplicative penalties after hard filtering; they never make an unverified
route eligible. Zero values in a legacy config use these defaults, while
negative, NaN, and infinite values are rejected. Metrics not present in the
typed probe/health evidence are not invented or substituted. Hysteresis
defaults to 15 percent: a healthy current route is retained when a new
candidate is only marginally better, and a new route must accumulate more than
one successful observation before replacing it. Health cooldown/backoff
remains authoritative for routes marked unhealthy.

## Cache and first-connection policy

Unknown-domain decisions are cached by normalized eTLD+1, active revision,
TSPU state, and a hash of the eligible route inventory. Inventory or revision
changes invalidate the cached decision; ordinary repeated DNS queries do not
rerun the flowchart. The initial unknown policy is explicit (`balanced`,
`privacy_first`, or `fail_closed`; `direct`, `vless`, and `drop` are accepted
compatibility aliases). The planner enforces the constraint in its candidate
set: balanced may include the unmarked system-default baseline, privacy-first
excludes Direct, and fail-closed exposes only DROP. This is still a
decision-layer constraint; a production dataplane consumer must enforce the
same mode before the first packet. The policy describes the first connection
while the passive observer classifies the domain.

Terminal `NO_SAFE_ROUTE` outcomes are cached under the same revision,
inventory, and TTL binding. The cache entry must contain non-empty, terminal
evidence for every candidate that the current bounded plan could probe, plus
the planner's exhaustion reason. The only omitted candidates are those the
planner can prove it intentionally skipped: speculative Zapret for an
ordinary unknown domain without TSPU evidence, or Direct/Zapret after a
direct regional denial. Duplicate, foreign, truncated, in-progress,
malformed, incomplete, or mismatched entries are rejected and re-probed; they
never suppress verification or manufacture a terminal decision.

The durable discovery-suggestion store applies the same boundary: only a
verified candidate, explicit fail-closed DROP, or fully evidenced terminal
exhaustion can be persisted. A provisional or empty `DomainCheck` remains a
RAM-only live view and is rejected by the durable write path.

Raw observations are retained only in the bounded in-memory ring (one hour).
Durable suggestions are keyed by normalized eTLD+1, capped at 256 entries, and
expire after seven days. Reads hide expired entries; the six-hour storage
maintenance pass removes them from bbolt without turning each DNS observation
into a persistent write.

## Route-only assignment

Automatic discovery may assign a domain only to an already enabled, verified
route. It does not install components, change Xray/Zapret topology, alter
marks/tables, or rebuild the base dataplane. The assignment is persisted under
the active revision and followed by a fresh exact-route service/path proof;
failure removes the tentative mapping and leaves the suggestion with its
reason. Full dataplane changes remain explicit ChangeSet operations.
