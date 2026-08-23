# Remediation evidence

This file records evidence for the transaction/privilege remediation branch.
Evidence is bound to an exact commit; a result from another commit is stale.

## Scope

- Base review SHA: `d45a779dfa9dc024b426cef358d3df4d32478897`
- Branch: `remediation/transaction-and-privilege-boundaries`
- Code verification SHA: `82845295b76a0fe1938289de013d46716edfc0df` (recovery
  fence, route-verification semantics, bounded Zapret modes, truthful UI/browser
  coverage, screen-specific request budget, refresh cancellation, backend-gated
  onboarding, stateful Fast Start completion, robust Zapret process ownership,
  and non-terminal Decision Flow states). Earlier Go/safety evidence remains
  explicitly attributed to its original SHA.
- Verification scope: the exact code SHA recorded here; older evidence is not
  inherited by this follow-up.
- Hardware scope: **not run**. Flint 2 was not contacted, installed, rebooted,
  or modified by this remediation.
- Evidence levels are independent: local unit/mock, Linux namespace/CI, and
  hardware. A lower level never upgrades to a higher level.
- Historical hardware records, including `docs/flint2-hardware-report.md` and
  `H:\\LAN\\Versions\\FlintRoute 0.2.0-alpha.1\\hardware\\summary.txt`, are
  `STALE FOR CURRENT SHA` until a new hardware run is captured.

## Acceptance matrix

| Area | Command or test | Result | Evidence scope |
|---|---|---|---|
| transaction semantic responses | `go test ./internal/adapter ./internal/helper ./internal/api` | PASS | local |
| transaction fault boundaries | API fault-injection tests in `internal/api/transaction_test.go` | PASS | local |
| recovery mutation allowlist | `go test ./internal/api -run 'TestRecovery|TestAutomaticDomainCommit|TestHealthScheduler'` | PASS | local |
| recovery status persistence failure | `TestRecoveryStatusPersistenceFailureInstallsMemoryFence` | PASS | local |
| concurrent recovery/apply fence | `TestRecoveryTransitionExcludesConcurrentMutation` | PASS | local |
| frontend recovery mutation fence | `npm run test`, `npm run browser:test` (`recovery=starting`) | PASS (37 unit tests; 11 browser tests) | local Chromium |
| immutable bootstrap | `tests/openwrt-adapter-integration.sh` | PASS | local/mock |
| installer parent modes | `tests/installer-lifecycle.sh` | PASS | local/mock |
| legacy shell atomic write | `tests/shell-library.sh` | PASS (mode check is Linux-only; Windows reports `NOT RUN LOCALLY`) | local/mock |
| artifact directory fsync failure | `tests/content-aware-install.sh` | PASS — failed exact and fallback sync is surfaced as `fsync_failed` | local/mock |
| boot guard | `tests/boot-guard-policy.sh`, `tests/boot-guard-service.sh` | PASS | local/mock |
| privileged helper boundary | `tests/helper-service.sh`, `go test ./internal/helper` | PASS | local/mock |
| nft transition | `tests/nft-transition-namespace.sh` | PASS — [run 32575449189](https://github.com/Zaqvierm/FlintRoute/actions/runs/32575449189), exact code SHA `3173e32c6e040794bdf73078e013908aabc18c38` | Linux namespace |
| hotplug boundedness | `tests/hotplug-bounded.sh` | PASS | local/mock |
| Zapret cleanup | `tests/zapret-calibration-runtime.sh` | PASS — [run 32575449237](https://github.com/Zaqvierm/FlintRoute/actions/runs/32575449237), exact code SHA `3173e32c6e040794bdf73078e013908aabc18c38` | Linux process/procfs |
| SSRF and decompression limits | `go test ./internal/remotefetch ./internal/vpnsub ./internal/tspu ./internal/geoip` | PASS | local |
| Xray typed input | `go test ./internal/vpnsub` | PASS | local |
| resource budget | `go test ./internal/api ./internal/probe` | PASS | local |
| `NO_SAFE_ROUTE` terminal state | planner cancellation/exhaustion and API probe-state tests | PASS | local |
| classification vs route confidence | `TestClassificationConfidenceIsIndependentFromRouteConfidence` | PASS | local |
| route latency vs verification duration | probe/API separation tests | PASS | local |
| unknown route latency scoring | `TestSelectBestDoesNotTreatUnknownLatencyAsZero` | PASS | local |
| frontend build | `npm run build` | PASS | local |
| frontend tests | `npm test` | PASS (37 tests) | local |
| browser smoke/responsive | `npm run browser:test` | PASS (11 tests; 10 viewport matrix); [CI run 32575449236](https://github.com/Zaqvierm/FlintRoute/actions/runs/32575449236) | local Chromium + Linux CI |
| ShellCheck | `.tools/shellcheck-v0.11.0/shellcheck.exe -x <tracked shell files>` | PASS | local |
| race/vet | `go test -race ./...`, `go vet ./...` | PASS | local |

The full local runner at the recorded code SHA completed in 322.5 seconds with
`all_tests_ok=true`. Its Linux-only namespace/process-group steps were
honestly reported as `NOT RUN LOCALLY`; the independent GitHub runs above are
the Linux evidence. The earlier `e04778e` nft run failed because the fixture's
background traffic generator died before the counter assertion. Follow-up
`abf26b6` keeps the namespace-side generator alive and the rerun passed. That
failure remains part of the evidence trail rather than being erased.

The previous Zapret CI runs for `2a61405`, `29680f1` and `d598278` exposed
three real harness errors: trusting `setsid`'s launcher PID, using `$11`/`$13`
instead of braced positional parameters, and a release-file race. The current
`163b17c` test publishes the child PID from inside the new session, stops it
before ownership validation, resumes it only after the PGID check, and then
performs owned cleanup. Those failures remain recorded here; they are not
being hidden behind a retry.

The final lint-only follow-up `3173e32` makes the shell-library regression
portable on Windows; its mode assertion remains explicitly Linux-only.

The UI refresh budget is explicit: a Services-screen refresh requests only the
always-on overview/system/health snapshots plus services and revisions. The
browser regression asserts that unrelated collections are not requested, and a
second regression asserts that a delayed services response is aborted when
navigation changes.

The Zapret calibration UI now has two explicit modes. `quick` is the bounded
default and runs four built-in curated profiles through the pinned nfqws
binary. Each attempt must prove the owned NFQUEUE counter, target and process
group, and cleanup; a curl result without path evidence is an infrastructure
failure. `exhaustive` is an explicit maintenance action capped at six hours
and passes `SCANLEVEL=force`. The current repository has no authoritative
fixed 21-strategy asset, so the UI does not invent that number. Neither mode
silently activates a production profile; the result is a reviewed candidate/draft.

## Prior follow-up evidence

The prior follow-up code SHA was `4345207ec79e5290a3a6de78a01b8ce84ad702e2`.
The artifact directory fsync regression now fails closed when both the exact
directory sync and the explicit global sync fallback fail; the runtime write
log records `fsync_failed` and `atomic_install` returns an error. The local
full runner passed at this SHA in about 300.5 seconds with
`all_tests_ok=true`; Linux-only namespace/process-group checks remain
`NOT RUN LOCALLY` on Windows.

The Linux CI evidence for that SHA is:

- nft transition safety: [run 32576221526](https://github.com/Zaqvierm/FlintRoute/actions/runs/32576221526)
- Zapret process-group safety: [run 32576221472](https://github.com/Zaqvierm/FlintRoute/actions/runs/32576221472)
- UI browser/responsive: [run 32576221408](https://github.com/Zaqvierm/FlintRoute/actions/runs/32576221408)

The earlier matrix rows retain their original SHAs as historical evidence;
the entries above are the authoritative follow-up results for the current
that prior head; the latest local follow-up is recorded below.

## Latest local follow-up

At `084898c8898c99203017964de1d5e377b670df0d`, onboarding readiness is
fail-closed: only explicit route/DNS proof states pass; simulation,
unverified, missing-upstream, and unknown statuses do not. The UI consumes the
backend `router_ready` boolean when present and has a tested explicit-status
fallback, so an object cannot become `[object Object]` or readiness by
coercion. Incomplete Fast Start is now resumable from backend state: stale
localStorage screen/opened flags cannot suppress the wizard, and invalid or
old URLs are redirected only after backend onboarding/revision state is read.
The browser regression explicitly seeds the stale `flintroute-first-run-opened`
flag and still observes the backend-required wizard. Persisted onboarding step
statuses now use an explicit accepted/skipped allowlist in both backend and UI;
corrupt values cannot unlock completion. Fast Start component, VLESS, Smart
DNS, TGWS and Zapret reads are AbortController-bound and stale results are
discarded after navigation. Existing service data cannot mark the services step
complete while its persisted status is pending. The stateful browser fixture
now completes Direct-only → automatic services → backend completion → Overview,
and caught/fixed a callback that previously discarded `completed=true`. The
full local runner at this exact SHA passed in 365.3 seconds with
`all_tests_ok=true`; full `go test -race ./...`, the focused frontend gate and
browser gate also passed. Linux-only namespace/process-group checks remain
`NOT RUN LOCALLY` on Windows.

The prior code-SHA CI runs for this frontend/test state were:

- nft transition safety: [run 32578063407](https://github.com/Zaqvierm/FlintRoute/actions/runs/32578063407)
- Zapret process-group safety: [run 32578063499](https://github.com/Zaqvierm/FlintRoute/actions/runs/32578063499)
- UI browser/responsive: [run 32578063388](https://github.com/Zaqvierm/FlintRoute/actions/runs/32578063388)

The latest confirmation runs were triggered by docs-only head `097bb2f`; no
code changed after `91193d7`:

- nft transition safety: [run 32578987502](https://github.com/Zaqvierm/FlintRoute/actions/runs/32578987502)
- Zapret process-group safety: [run 32578987408](https://github.com/Zaqvierm/FlintRoute/actions/runs/32578987408)
- UI browser/responsive: [run 32578987494](https://github.com/Zaqvierm/FlintRoute/actions/runs/32578987494)

The current docs head is `2194119c0814813c4b5316112bfc46d69ca6fd7b`.
It contains documentation-only evidence updates after the code SHA above;
the code remains unchanged from `084898c8898c99203017964de1d5e377b670df0d`.
The latest required CI runs for that head passed:

- nft transition safety: [run 32579761689](https://github.com/Zaqvierm/FlintRoute/actions/runs/32579761689)
- Zapret process-group safety: [run 32579761688](https://github.com/Zaqvierm/FlintRoute/actions/runs/32579761688)
- UI browser/responsive: [run 32579761695](https://github.com/Zaqvierm/FlintRoute/actions/runs/32579761695)

### Current code follow-up

At production code `82845295b76a0fe1938289de013d46716edfc0df`, Decision Flow no longer labels
every `path_verified=false` event as a terminal failure. `VERIFYING` and
`in_progress` remain `Проверяется…`, observe-only remains passive, and
`NO_SAFE_ROUTE` is shown as terminal only when the planner reports exhausted
candidates. The same semantics are used in service details. This follow-up
added two frontend regressions; the focused gate passed with 37 unit tests and
11 browser tests. The current browser-fixture head is
`6bf28b890a25c7cf68033b37d3896e22efbe8d29`; it adds two browser assertions and
does not change production code. `gofmt` was clean, `go test -race ./...` passed in 136.3
seconds, `go vet ./...` passed, and the full local runner passed in 322.5
seconds. The production bundle is 185.15 kB JS (58.04 kB gzip) and 26.52 kB
CSS (6.28 kB gzip). Linux-only namespace/process-group checks remain
`NOT RUN LOCALLY` on Windows.

The required Linux/CI checks for the exact code head passed:

- nft transition safety: [run 32580143066](https://github.com/Zaqvierm/FlintRoute/actions/runs/32580143066)
- Zapret process-group safety: [run 32580143067](https://github.com/Zaqvierm/FlintRoute/actions/runs/32580143067)
- UI browser/responsive: [run 32580143064](https://github.com/Zaqvierm/FlintRoute/actions/runs/32580143064)

The following docs-only head `c6bfb273255b98538f0e97239b146cf856c35602`
also reran all three workflows successfully; it did not change the code
covered by the exact SHA above:

- nft transition safety: [run 32580583726](https://github.com/Zaqvierm/FlintRoute/actions/runs/32580583726)
- Zapret process-group safety: [run 32580583820](https://github.com/Zaqvierm/FlintRoute/actions/runs/32580583820)
- UI browser/responsive: [run 32580583755](https://github.com/Zaqvierm/FlintRoute/actions/runs/32580583755)

The follow-up UI change at code head `44865acfcfae316ff1220270fd08f1ba3a4597cf` makes a `requires_device`
ChangeSet actionable without weakening the safety fence. The operation center
now explains that router verification did not finish, states that the network
was not changed, and offers a direct `Open diagnostics` action. Unknown block
reasons use the same safe human explanation instead of exposing only an
internal lifecycle enum. A browser regression covers the message and the
navigation target (12 browser tests total); this is presentation only and does
not grant mutation.

The same code head `44865acfcfae316ff1220270fd08f1ba3a4597cf` passed the full
local runner in 320.1 seconds (`all_tests_ok=true`). The focused frontend gate
passed typecheck, 37 unit tests, 12 browser tests and production build; the
bundle is 185.46 kB JS (58.10 kB gzip) and 26.52 kB CSS (6.28 kB gzip).
Linux CI also passed for this exact code head:

- nft transition safety: [run 32581217696](https://github.com/Zaqvierm/FlintRoute/actions/runs/32581217696)
- Zapret process-group safety: [run 32581217782](https://github.com/Zaqvierm/FlintRoute/actions/runs/32581217782)
- UI browser/responsive: [run 32581217757](https://github.com/Zaqvierm/FlintRoute/actions/runs/32581217757)

The current documentation head is `9f304923721b68775d4b34694543bbad86780261`;
it records evidence only and does not alter the production behavior above.

The adversarial follow-up at code head
`b36b8a56d2a471aa0fcceccd5e38d8d6da9fab1b` removed the last dormant
background-calibration path that could have called `applyChangeSet` merely to
test a Zapret candidate. The scheduler now has no candidate-apply function to
call. The old automatic domain commit path was also reduced to an explicit
`automatic_route_assignment_unavailable` result; verified DNS decisions remain
suggestions until a bounded route-only assignment backend exists. The direct
regression proves a verified discovery result causes zero adapter calls and no
persisted service, even with a safe recovery baseline. Targeted API tests,
race tests and `go vet` passed; hardware remains unverified.

At code/docs head `c803c06a8152a51232deee7cf33705ec06d86915`, the local gate was
rerun after this hardening. `gofmt` was clean, full `tests/run-all.ps1` passed
with `all_tests_ok=true` in 742.8 seconds, full `go test -race ./...` passed in
84.8 seconds, and `go vet ./...` passed. The OpenWrt adapter integration fixture
passed with `openwrt_adapter_integration_ok=true` (377.7 seconds). The runner
explicitly reported Linux-only Zapret process-group and nft namespace checks as
`NOT RUN LOCALLY` on Windows; those are covered by the required CI workflows,
not by a mock PASS. CI for this exact head passed:

- nft transition safety: [run 32581995540](https://github.com/Zaqvierm/FlintRoute/actions/runs/32581995540)
- Zapret process-group safety: [run 32581995601](https://github.com/Zaqvierm/FlintRoute/actions/runs/32581995601)
- UI browser/responsive: [run 32581995554](https://github.com/Zaqvierm/FlintRoute/actions/runs/32581995554)

The code remains local-only with respect to hardware: no SSH, install, apply,
reboot, or Flint 2 validation was performed for this head.

### NO_SAFE_ROUTE and verification metric follow-up

At the current follow-up code head, planner results with empty or in-progress
candidate status (`VERIFYING`, `PROBING`, `WAITING_FOR_VERIFICATION`,
`IN_PROGRESS`) remain `verification_state=in_progress`; they are not evidence of
candidate exhaustion and cannot produce terminal `NO_SAFE_ROUTE`. Regression
coverage is `TestInProgressOrMalformedProbeCannotBecomeTerminalNoSafeRoute`.

Decision-cache records now persist the full planner verification job duration in
`verification_duration_ms`, while per-candidate path verification duration
remains inside each `RouteResult`. Discovery events include
`verification_cached=true` for cache hits. The API emits zero when no planner
measurement exists instead of converting cache lookup time into verification
duration. Coverage includes the planner cache round-trip and
`TestCachedVerificationDurationUsesStoredEvidence`.

These changes are local source/test evidence only until the next full gate and
CI run; no hardware evidence is inferred.

For code/docs commit `d3ccfbc` (`d3ccfbcd608b63356368ba850f39b0a115b00ec5`),
the follow-up local gate is:

- `go test ./...` — PASS;
- `go test -race ./...` — PASS;
- `go vet ./...` — PASS;
- `gofmt` and `git diff --check` — PASS.

The exact-SHA Linux workflows also passed: [nft transition safety run
32585760475](https://github.com/Zaqvierm/FlintRoute/actions/runs/32585760475),
[Zapret process-group safety run
32585760472](https://github.com/Zaqvierm/FlintRoute/actions/runs/32585760472),
and [UI browser/responsive run
32585760504](https://github.com/Zaqvierm/FlintRoute/actions/runs/32585760504).
These are unit/CI evidence levels only; hardware remains untouched.

## Known limitation

The packaged helper boundary is tested, but the production `router-policy`
controller still runs as root on this branch. Privilege split is therefore
`PARTIAL`; no document may call it complete until the controller is actually
non-root and has no direct privileged execution path.

## Required hardware gate (not executed here)

Before any deployment, capture a read-only backup and baseline for model,
firmware, kernel, services, ubus, routes, rules, nft tables, DNS, processes,
FDs, sockets, CPU, free storage, and memory. Verify `/`, `/etc`, `/usr`,
`/usr/bin`, `/usr/lib`, `/etc/init.d`, and `/etc/hotplug.d` modes before
installation and again after installation, before reboot. Only then proceed to
controlled deployment, with a tested recovery path and explicit user approval.

No hardware PASS may be entered in this matrix without raw logs, hashes, the
device environment, and the exact installed commit SHA.
> **Evidence correction (2026-08-23):** the historical local/CI evidence for
> `SCANLEVEL=quick` proves only bounded upstream invocation and cleanup. It
> does not prove a curated strategy count or NFQUEUE path binding. The current
> runner has a separate per-attempt evidence contract; exhaustive remains the
> only mode that invokes the upstream blockcheck.

At code head `cbd60607390955fb254bfa280c366bbed526b075`, production wires the
curated runner through `ExecCalibrationRunner.QuickScript` to
`scripts/quick-zapret-check.sh`. The same head retains the defensive per-route
GeoIP fan-out limit: configuration accepts at most two supported providers and
the probe rejects an unvalidated larger set before making any remote request.
Together with the four-probe-URL and four-address-target limits, this is a
finite route-check budget. The real nft/NFQUEUE/process-group proof still
requires Linux CI or hardware; Windows unit tests do not inherit that evidence.

The current local gate for this exact head is green: `go test ./...`,
`go test -race ./...`, `go vet ./...`, ShellCheck, frontend
typecheck/tests/build, browser tests, and `tests/run-all.ps1` all passed
(`tests/run-all.ps1` took 407.4 seconds). The runner continues to report the
Linux-only nft namespace and Zapret process-group/Quick runtime checks as
`NOT RUN LOCALLY` on Windows. Exact-SHA CI also passed:

- nft transition safety: [run 32592026594](https://github.com/Zaqvierm/FlintRoute/actions/runs/32592026594)
- Zapret process-group and Quick contract: [run 32592026507](https://github.com/Zaqvierm/FlintRoute/actions/runs/32592026507)
- UI browser/responsive: [run 32592026497](https://github.com/Zaqvierm/FlintRoute/actions/runs/32592026497)

This remains unit/CI evidence only. No SSH, install, apply, reboot, or other
hardware action was performed for this head.

### NO_SAFE_ROUTE and latency semantics hardening (fead514)

The planner now treats `NO_SAFE_ROUTE` as terminal exhaustion only when every
candidate returned a known terminal probe status. Empty, in-progress, and
unknown/malformed statuses remain `verification_state=in_progress`; malformed
evidence can no longer manufacture a terminal `NO_SAFE_ROUTE`. The regression
matrix covers in-progress, malformed, and known terminal candidate results.

Route selection now uses only an explicitly available `RouteLatencyMS`.
The legacy `LatencyMS` fallback was removed because older persisted evidence
could contain the complete verification-job duration in that field. Unknown
route latency is ranked after an honest measurement, never as zero. A planner
regression proves that a legacy duration cannot beat a measured path.

Discovery events expose independent `classification_confidence` and
`decision_confidence` fields. Observe-only events are explicitly marked as
passive and have decision confidence zero; the UI shows both values in Details
and fails closed when contradictory evidence says a decision is both verified
and terminally exhausted. The decision card continues to keep route latency,
full verification duration, and orchestration duration separate.

Local evidence for `fead514`:

- `go test ./...` — PASS;
- `go test -race ./...` — PASS;
- `go vet ./...` — PASS;
- frontend unit tests (39) — PASS;
- frontend typecheck — PASS;
- hardware cases A/B/C — NOT RUN LOCALLY (current task forbids router access);
- no SSH, install, apply, reboot, or Flint 2 validation was performed.

The same source-plus-bundle tree was rechecked by the full runner before this
evidence update: `tests/run-all.ps1` — PASS (`all_tests_ok=true`, 405.2s).
That runner honestly reported Linux-only shell mode, Zapret process-group,
Quick runner, and nft namespace checks as `NOT RUN LOCALLY` on Windows; the
corresponding exact-SHA CI jobs are the evidence for those Linux paths.

This is source/unit/CI evidence, not hardware proof. The previous CI runs listed
above apply to their exact SHAs and do not inherit to `fead514` until this SHA's
workflow results are recorded.

The embedded web bundle was rebuilt from the same source in `60848ab`
(`60848abe6e5b9797a4ad8a92400131a4dac0d92d`). Exact-SHA CI for that final
source-plus-bundle head passed:

- nft transition safety: [run 32593006604](https://github.com/Zaqvierm/FlintRoute/actions/runs/32593006604);
- Zapret process-group safety: [run 32593006566](https://github.com/Zaqvierm/FlintRoute/actions/runs/32593006566);
- UI browser/responsive: [run 32593006602](https://github.com/Zaqvierm/FlintRoute/actions/runs/32593006602).

These remain local/CI evidence levels only. Hardware cases A/B/C are still
`NOT RUN LOCALLY` by policy, and no router action was performed.

### Classification confidence survives cache and API round trips (e06363c)

The domain-decision cache now persists classification evidence separately from
route-decision confidence: `classification_confidence`,
`classification_source`, and `classification_evidence` are independent fields.
Cache hits preserve those fields; legacy records without them use only the
derived classification metadata and never reinterpret route confidence as a
classification score. `/api/v1/services` exposes both
`decision_confidence` and `classification_confidence`, and the Services drawer
renders the latter as classification confidence. Unknown/legacy values remain
explicitly unavailable instead of being invented.

Regression coverage includes a cache round-trip with non-zero classification
evidence, a zero-confidence legacy round-trip, API field separation, and the
frontend decision-card parser. On commit `e06363c` the focused and full local
checks passed: `go test ./...`, `go test -race ./...`, `go vet ./...`, 40
frontend unit tests, typecheck, production build, and 16 browser tests.
The generated embedded bundle is rebuilt from this source and is recorded in
the follow-up build commit. This is still local/CI evidence only; no hardware
validation is inferred.

The follow-up state-classification correction is `a68fee3`: Discovery now
marks classification as known from explicit classification evidence (including
evidence with a zero numeric confidence) rather than borrowing route-decision
confidence. The exact bundle head `387e0c2` passed GitHub Actions: nft run
[32594514976](https://github.com/Zaqvierm/FlintRoute/actions/runs/32594514976),
Zapret run
[32594514968](https://github.com/Zaqvierm/FlintRoute/actions/runs/32594514968),
and UI run
[32594514972](https://github.com/Zaqvierm/FlintRoute/actions/runs/32594514972).

The follow-up `938406a` closes the remaining presentation fail-open: a bare
`NO_SAFE_ROUTE` status with missing or corrupt verification state is rendered
as `verifying`; only `verification_state=terminal_no_safe_route` is terminal.
Regression tests cover missing and corrupt terminal evidence. This prevents a
partially populated legacy/API object from masquerading as exhausted probing.

The UI grouping fix in `2295194` keeps automatic observation confidence and
classification evidence when a configured policy has the same service id.
Policy ownership still wins for configured fields, but telemetry is no longer
silently replaced by the configured row. The grouping regression covers a
configured plus automatic Discord fixture with independent 0.42/1.0 values.

Discovery suggestions received the same typed split: the compatibility
`confidence` alias remains route-decision confidence, while explicit
`decision_confidence` and classification evidence fields cross the API
boundary. Suggestion tests prove the two values survive independently.

Cache validation now rejects out-of-range classification confidence just like
route-decision confidence; a malformed persisted record cannot inflate the UI
score after restart. The domaincache regression covers the `>1` case.

### Decision stream evidence hardening (3b02a85)

The UI now applies the same fail-closed evidence rule as the planner at the
presentation boundary. `NO_SAFE_ROUTE` is shown as terminal only when
`verification_state=terminal_no_safe_route` is present. A bare status or a
malformed `probe_state=no_safe_route` remains visibly in verification and
cannot claim that candidate exhaustion was proven.

Administrative lifecycle events are excluded from the user decision stream
even when their payload happens to contain `domain` or `route` fields. They
remain available in the separate administrative journal.

The decision-card parser no longer treats legacy `probe_latency_ms` as route
latency. Only an explicit measured `route_latency_ms`, with a valid
availability bit when supplied, is presented as path latency. The card now
labels route latency and total verification time separately, and the details
drawer uses the typed route-latency field.

Regression coverage on `3b02a85`: 43 frontend unit tests, typecheck and
production build passed. The generated embedded bundle is included in the
same commit (188.88 kB JS raw, 59.06 kB gzip; 26.52 kB CSS raw, 6.28 kB
gzip). This is local source/unit evidence only; Linux-only CI and hardware
validation are not inherited by this SHA until their exact runs are recorded.
