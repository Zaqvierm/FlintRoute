# Discovery and Smart DNS route contract

This document defines the user-facing discovery contract on the integration
branch. It is deliberately separate from the transaction remediation design:
the transaction engine remains the only mechanism allowed to change the full
dataplane.

## DNS observation and bounded storage

The dnsmasq reader is a line-aware tail reader. A cursor advances only after a
complete newline-terminated record has been parsed. Reads are bounded, so a
large historical file is drained over multiple polls and a malformed line
cannot grow memory without limit. Append, truncation, rename and inode
rotation are treated as normal lifecycle events. The reader never truncates a
file owned by dnsmasq.
After a truncate or inode rotation the new tail is consumed once; the watcher
does not rewind a second time and replay the replacement records on every poll.

Raw observations are a short-lived in-memory ring (maximum 1,000 records and a
one-hour TTL). They are telemetry, not durable policy. The reader reports
cursor, lag, emitted and dropped counts; `receiving` means records were
actually emitted, not merely that the file mtime changed.

Verified suggestions are a different entity. They are persisted in bbolt,
deduplicated by eTLD+1 during the discovery window, capped at 256 entries and
expired after seven days. A suggestion records classification evidence,
candidate results, the selected route, client/last-seen data and separate
classification, decision, probe and policy states. An ordinary DNS repeat does
not run a new check and does not write a raw observation to bbolt.
While verification is in progress, the provisional item exists only in the
bounded in-memory view; it is not persisted until the planner reaches a
terminal verified candidate or honest exhaustion result.
Persistence failures are observable and fail closed: a discovery check does
not proceed to automatic route assignment when its verified suggestion cannot
be written durably. An Ignore action restores the previous in-memory state if
its write fails. If a route assignment has already committed, a later failure
to persist auxiliary suggestion metadata is reported as a warning without
pretending that the assignment itself rolled back.
The durable discovery control-state write is also returned to its callers;
loss of applied/rollback counters is therefore observable rather than a
silent success.

## Discovery modes

* `observe_only` records observations and Decision Flow evidence only. It does
  not call the domain checker, start active probes, create suggestions or call
  the adapter.
* `suggest` performs one bounded classification/verification plan for a new
  subject and stores a verified suggestion. The user can Apply, Change route or
  Ignore it.
* `auto_apply_verified` is intentionally narrower than a normal ChangeSet. It
  may assign a domain only when a route-only runtime consumer is registered,
  the route already exists, is enabled and healthy, the selected result is
  `PathVerified`, service verification succeeded, classification confidence is
  at least 0.8 and the rate/circuit-breaker/transaction fences allow it.

The controller fails closed when that runtime consumer is absent. It does not
persist a selected decision or report `applied=true` merely because bbolt
accepted a record. A consumer must return a semantic, revision-bound receipt
(`Applied`, `Verified`, request ID, route identity and mapping hash) before the
decision is persisted; any later failure calls its idempotent rollback.

Auto-apply never installs components, changes Xray/Zapret configuration,
changes marks, tables, IP rules, DNS topology or service lifecycle. The
route-only consumer mutates only the exact owned dnsmasq overlay and its
revision-bound assignment manifest. A missing helper/runtime still exposes
`route_assignment_runtime_unavailable` rather than claiming success.

The production bridge is `cmd/router-policy/route_assignment_runtime.go` and
uses the typed `router-policy-helper` Unix-socket protocol. The privileged
adapter accepts only `route-assignment-apply`, `route-assignment-rollback` and
`route-assignment-reconcile`. The runtime validates the committed config hash,
active transaction binding, enabled route inventory and deterministic object
IDs before writing `router-policy-route-assignments.conf`; dnsmasq is restarted
and its `running` action is required as the post-write readiness proof. A full
active-revision change invalidates the old assignment manifest by replacing it
with an empty manifest bound to the new revision, but refuses cleanup if the
include lacks the FlintRoute ownership marker. No foreign dnsmasq file is
overwritten.

The suggestion Apply action uses the same route-only path. It is one bounded
backend operation for the user; it does not expose validate/apply/confirm
internals. It is rejected unless the stored candidate is still PathVerified
and the requested route matches the evidence. Recovery fences and the single
mutation lease apply to this action as to every other mutation.

If the post-apply proof fails, the owned mapping is rolled back before the
next already-verified, policy-allowed candidate is attempted. This retry is
bounded by the finite candidate evidence set and is reserved for
candidate-specific proof failure; helper, semantic-receipt, persistence, or
rollback errors stop the operation and never fan out into an apply storm.

## Smart DNS is a route candidate

Each configured Smart DNS endpoint is an independent route candidate. It is
not a global resolver health flag. For a domain, verification must query the
selected endpoint, validate the response, connect to a returned safe address
while preserving the original Host and TLS SNI, and complete the configured
HTTP/TLS/content/region checks. Only that candidate then receives
`PathVerified=true` and may be selected.

The planner enumerates eligible candidates by category; this list is not a
winner order. Every terminal candidate is scored from comparable evidence and
the selector chooses the best hard-filtered result, subject to hysteresis and
cooldown:

* GEO locked: Smart DNS, VLESS and Drop;
* TSPU restricted: Zapret, Smart DNS, VLESS and Drop;
* unknown/direct-preferred: Direct, Zapret, Smart DNS, VLESS and Drop;
* direct-only: Direct and Drop.

Transport reachability alone is never enough to call Smart DNS usable. A
resolver can be reachable while its returned address or content path is
invalid; the API reports those stages separately.

The endpoint preflight accepts only an explicit set of successful HTTP or
redirect responses (2xx and the supported 3xx codes). `401 Unauthorized`,
`403 Forbidden`, `404 Not Found`, `405 Method Not Allowed`, `429 Too Many
Requests`, regional-denial markers and WAF responses are never converted into
Smart DNS application proof merely because TCP/TLS completed. They remain a
typed failure/ambiguous result and cannot authorize a production route.

The Smart DNS screen keeps the safety transaction behind one product action:
“Add and verify endpoint”. A new endpoint is validated and represented as a
candidate/draft; existing production endpoints show their blast radius before
replacement. The UI does not ask a home user to operate internal transaction
states.

## Decision evidence and terminal states

Classification confidence, route-decision confidence and path evidence are
independent fields. `NO_SAFE_ROUTE` is terminal only when every allowed
candidate has a terminal result (or an honest bounded timeout) and policy
constraints reject all of them. Before that, the API exposes `VERIFYING` or
`WAITING_FOR_VERIFICATION`.

Route latency is measured only inside the network-path measurement boundary.
Queue wait, setup, retries and cleanup are represented by
`verification_duration_ms` instead. A missing latency measurement is reported
as unavailable; orchestration duration is never used as a fake latency score.

## Mutation and evidence boundary

No background discovery task runs a full dataplane apply. Local tests and CI
namespace tests are separate evidence levels from hardware validation. A
future hardware run must record the exact commit, firmware, command and raw
evidence before any claim of a working path is made.

Reactive VLESS failure detection follows the same boundary: it may verify the
selected route and one known-good standby, then emits a reviewable fallback.
It does not launch a full ChangeSet from a scheduler event. Configured-service
route-only assignment is now available only through the bounded, typed runtime
above and remains subject to the recovery mutation fence.
