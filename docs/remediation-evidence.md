# Remediation evidence

This file records evidence for the transaction/privilege remediation branch.
Evidence is bound to an exact commit; a result from another commit is stale.

## Scope

- Base review SHA: `d45a779dfa9dc024b426cef358d3df4d32478897`
- Branch: `remediation/transaction-and-privilege-boundaries`
- Code verification SHA: `d7dffaf` (recovery fence plus route-verification semantics follow-up).
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
| immutable bootstrap | `tests/openwrt-adapter-integration.sh` | PASS | local/mock |
| installer parent modes | `tests/installer-lifecycle.sh` | PASS | local/mock |
| boot guard | `tests/boot-guard-policy.sh`, `tests/boot-guard-service.sh` | PASS | local/mock |
| privileged helper boundary | `tests/helper-service.sh`, `go test ./internal/helper` | PASS | local/mock |
| nft transition | `tests/nft-transition-namespace.sh` | PASS, GitHub Actions run [32559811433](https://github.com/Zaqvierm/FlintRoute/actions/runs/32559811433) | Linux namespace |
| hotplug boundedness | `tests/hotplug-bounded.sh` | PASS | local/mock |
| Zapret cleanup | `tests/zapret-calibration-runtime.sh` | PASS, GitHub Actions run [32559811439](https://github.com/Zaqvierm/FlintRoute/actions/runs/32559811439) | Linux process/procfs |
| SSRF and decompression limits | `go test ./internal/remotefetch ./internal/vpnsub ./internal/tspu ./internal/geoip` | PASS | local |
| Xray typed input | `go test ./internal/vpnsub` | PASS | local |
| resource budget | `go test ./internal/api ./internal/probe` | PASS | local |
| `NO_SAFE_ROUTE` terminal state | planner cancellation/exhaustion and API probe-state tests | PASS | local |
| classification vs route confidence | `TestClassificationConfidenceIsIndependentFromRouteConfidence` | PASS | local |
| route latency vs verification duration | probe/API separation tests | PASS | local |
| unknown route latency scoring | `TestSelectBestDoesNotTreatUnknownLatencyAsZero` | PASS | local |
| frontend build | `npm run build` | PASS | local |
| frontend tests | `npm.cmd test -- --run` | PASS (16 tests) | local |
| race/vet | `go test -race ./...`, `go vet ./...` | PASS | local |

The full local runner at the recorded SHA completed in 326.6 seconds with
`all_tests_ok=true`. Its Linux-only namespace/process-group steps were
honestly reported as `NOT RUN LOCALLY`; the independent GitHub runs above are
the Linux evidence. The earlier `e04778e` nft run failed because the fixture's
background traffic generator died before the counter assertion. Follow-up
`abf26b6` keeps the namespace-side generator alive and the rerun passed. That
failure remains part of the evidence trail rather than being erased.

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
