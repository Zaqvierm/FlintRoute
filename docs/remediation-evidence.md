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
default and passes the pinned upstream `SCANLEVEL=quick`; `exhaustive` is an
explicit maintenance action capped at six hours and passes `SCANLEVEL=force`.
The current repository has no authoritative fixed 21-strategy asset, so the
UI does not invent that number. Neither mode silently activates a production
profile; the result is a reviewed candidate/draft.

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

The follow-up UI change at the next code head makes a `requires_device`
ChangeSet actionable without weakening the safety fence. The operation center
now explains that router verification did not finish, states that the network
was not changed, and offers a direct `Open diagnostics` action. Unknown block
reasons use the same safe human explanation instead of exposing only an
internal lifecycle enum. A browser regression covers the message and the
navigation target; this is presentation only and does not grant mutation.

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
