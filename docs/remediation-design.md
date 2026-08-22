# Remediation design: transaction and privilege boundaries

Base review SHA: `d45a779dfa9dc024b426cef358d3df4d32478897`

This document defines the local remediation contract. It is deliberately
independent of Flint 2 hardware evidence; no hardware action is part of this
branch.

## Safety invariants

1. A protected mark is never allowed to use Direct while the active revision,
   adapter generation, or recovery journal is ambiguous.
2. The durable control-plane revision, adapter metadata, and observed dataplane
   generation must agree before a transaction is finalized.
3. A candidate is not an active configuration. It is content-addressed state
   owned by one transaction and may be discarded after recovery proves it is
   not active.
4. An ambiguous operation is `RECOVERY_REQUIRED`, not `rolled_back` and not a
   successful exit code.
5. Resources without a verified FlintRoute owner are foreign and are never
   stopped, deleted, or overwritten automatically.
6. Observation, health, watchdog, and adaptive calibration have no implicit
   authority to rebuild the production dataplane.

## Transaction state machine

The durable journal and adapter use the following ordered states:

```text
intent_persisted
  -> candidate_prepared
  -> adapter_prepared (rollback retained)
  -> adapter_activated (rollback retained)
  -> control_plane_committed
  -> adapter_finalized
  -> committed
```

Failure before adapter activation may become `rolled_back` after an idempotent
owned cleanup. Failure after activation is first classified from a semantic
adapter status. If adapter and bbolt cannot be reconciled, the transaction is
`RECOVERY_REQUIRED`; new mutation is fenced and protected marks remain in the
fail-closed guard. `rollback=false` with process exit code zero is not a
successful rollback.

The status binding includes operation, transaction ID, rollback token hash,
revision, candidate hash, artifact manifest hash, generation, and observed
adapter state. Finalization deletes rollback capability only after the durable
active revision and adapter state have been compared.

## Configuration layout

`bootstrap.json` is immutable launch metadata. It does not contain a pending
candidate and is never replaced by apply. Candidate artifacts live under a
transaction/revision content-addressed directory. The durable journal selects
the committed artifact on restart. Missing or inconsistent journal state
enters rescue/fence mode; startup does not guess from `default.json`.

## Privilege boundary

The target boundary is an unprivileged controller and a small root helper on a
0600 Unix socket. The controller owns API, state, parsing and unprivileged
probes. The helper owns only fixed, typed, owner-bound adapter operations. It
does not fetch URLs, parse subscriptions, expose HTTP, or execute arbitrary
shell fragments. The current branch introduces the boundary incrementally so
that every operation remains testable and no second untracked supervisor is
created.

The packaged `router-policy-helper` is fail-closed: it requires an explicit
non-root peer UID in `helper.env`, binds a fixed Unix socket with mode `0600`,
and accepts only protocol-versioned, request-ID and generation/revision/
token-bound operations. Its allowlist covers transaction verbs, the owned nft
table, managed IP plan, managed procd services, and fixed artifact kinds. It
has no HTTP client, remote fetch, subscription parser, provider JSON parser, or
arbitrary command/path input. The existing root controller enables the helper
only when its socket is explicitly configured, so this branch does not claim
that the whole controller is already non-root. The opt-in boundary is packaged
and tested; the remaining controller migration is a separate follow-up.

## Background authority

`observe_only` performs observation/classification only. Route-only automatic
assignment may be enabled only for an already-created, verified route and a
bounded domain mapping update. Any artifact, service, nft topology, mark, IP
rule, listener, or DNS topology change remains an explicit ChangeSet.
Adaptive Zapret calibration is suggestion/isolated-test work until a separate
NFQUEUE and network namespace proves resource isolation.

The ordinary discovery path returns after recording an observation: it does not
call the domain checker, acquire a probe slot, invoke the adapter, or create a
change. Automatic assignment is fenced until a route-only existing-route
mapping operation with TTL, rate limit, rollback, and evidence is available.

Subscription, GeoIP, and TSPU fetches share HTTPS-only SSRF protection,
resolved-address pinning, redirect revalidation, private/metadata/link-local
address rejection, response and decompressed-size limits, and bounded
timeouts. Provider Xray input is converted through a strict typed model; raw
provider JSON is never copied into an active configuration.

## Evidence policy

Local tests are not hardware proof. Every evidence record names the exact
commit, environment, command, raw-log path, digest, scope and PASS/FAIL/SKIP
state. Evidence from an older commit is `STALE FOR CURRENT SHA`.

## Remediation order

Transaction protocol, bootstrap separation, boot guard, nft transition and
hotplug fencing are the first gate. Rescue, watchdog, privilege, SSRF, typed
Xray generation and ownership follow. Auto-routing, adaptive calibration,
DNS watcher, polling/auth/storage budgets then receive their own regression
tests. Hardware validation is explicitly out of scope for this branch.

The local resource budget is intentionally small: the global probe semaphore is
four workers, the discovery queue capacity is 32, route probe targets are
capped at four per candidate, and probe/observation rings are bounded. These
are logical limits covered by local tests, not claims about router CPU, socket,
or NAND behavior.
