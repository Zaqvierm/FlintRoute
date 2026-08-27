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

## Discovery modes

* `observe_only` records observations and Decision Flow evidence only. It does
  not call the domain checker, start active probes, create suggestions or call
  the adapter.
* `suggest` performs one bounded classification/verification plan for a new
  subject and stores a verified suggestion. The user can Apply, Change route or
  Ignore it.
* `auto_apply_verified` is intentionally narrower than a normal ChangeSet. It
  may persist a revision-bound domain-to-route assignment only when the route
  already exists, is enabled and healthy, the selected result is
  `PathVerified`, service verification succeeded, classification confidence is
  at least 0.8 and the rate/circuit-breaker/transaction fences allow it.

Auto-apply never installs components, changes Xray/Zapret configuration,
changes marks, tables, IP rules, DNS topology or service lifecycle. A mapping
assignment is persisted against the current active revision and is therefore
safe to discard or expire independently of a full dataplane ChangeSet. Any
ambiguous result remains a suggestion.

The suggestion Apply action uses the same route-only path. It is one bounded
backend operation for the user; it does not expose validate/apply/confirm
internals. It is rejected unless the stored candidate is still PathVerified
and the requested route matches the evidence. Recovery fences and the single
mutation lease apply to this action as to every other mutation.

## Smart DNS is a route candidate

Each configured Smart DNS endpoint is an independent route candidate. It is
not a global resolver health flag. For a domain, verification must query the
selected endpoint, validate the response, connect to a returned safe address
while preserving the original Host and TLS SNI, and complete the configured
HTTP/TLS/content/region checks. Only that candidate then receives
`PathVerified=true` and may be selected.

The planner orders candidates by category:

* GEO locked: Smart DNS, then VLESS, then Drop;
* TSPU restricted: Zapret, then Smart DNS, then VLESS, then Drop;
* unknown/direct-preferred: Direct, then Zapret, Smart DNS, VLESS, Drop;
* direct-only: Direct, then Drop.

Transport reachability alone is never enough to call Smart DNS usable. A
resolver can be reachable while its returned address or content path is
invalid; the API reports those stages separately.

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
It does not launch a full ChangeSet from a scheduler event; configured-service
route-only assignment remains a separate follow-up capability.
