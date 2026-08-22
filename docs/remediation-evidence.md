# Remediation evidence

This file records evidence for the transaction/privilege remediation branch.
Evidence is bound to an exact commit; a result from another commit is stale.

## Scope

- Base review SHA: `d45a779dfa9dc024b426cef358d3df4d32478897`
- Branch: `remediation/transaction-and-privilege-boundaries`
- Code verification SHA: `50fdf63eb79302a10d22c91ad275f5b921630da1` (recovery
  fence, route-verification semantics, bounded Zapret modes, truthful UI/browser
  coverage, screen-specific request budget, refresh cancellation, and robust
  Zapret process ownership). This document may be advanced by docs-only
  commits; the code evidence remains bound to this SHA.
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
| frontend recovery mutation fence | `npm run test`, `npm run browser:test` (`recovery=starting`) | PASS (32 unit tests; 8 browser tests) | local Chromium |
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
| frontend tests | `npm test` | PASS (32 tests) | local |
| browser smoke/responsive | `npm run browser:test` | PASS (8 tests; 10 viewport matrix); [CI run 32575449236](https://github.com/Zaqvierm/FlintRoute/actions/runs/32575449236) | local Chromium + Linux CI |
| ShellCheck | `.tools/shellcheck-v0.11.0/shellcheck.exe -x <tracked shell files>` | PASS | local |
| race/vet | `go test -race ./...`, `go vet ./...` | PASS | local |

The full local runner at the recorded code SHA completed in 328 seconds with
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

At `50fdf63eb79302a10d22c91ad275f5b921630da1`, onboarding readiness is
fail-closed: only explicit route/DNS proof states pass; simulation,
unverified, missing-upstream, and unknown statuses do not. The UI consumes the
backend `router_ready` boolean when present and has a tested explicit-status
fallback, so an object cannot become `[object Object]` or readiness by
coercion. The full local runner passed in 318.2 seconds with
`all_tests_ok=true`; Linux-only namespace/process-group checks remain
`NOT RUN LOCALLY` on Windows.

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
