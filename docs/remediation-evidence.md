# Remediation evidence

This file records evidence for the transaction/privilege remediation branch.
Evidence is bound to an exact commit; a result from another commit is stale.

## Scope

- Base review SHA: `d45a779dfa9dc024b426cef358d3df4d32478897`
- Branch: `remediation/transaction-and-privilege-boundaries`
- Code verification SHA: `d7f0562152d5e349d361609638e3a74944617934` (full local gate completed after this code
  commit; the follow-up commit that records this line is documentation-only).
- Verification scope: code at `d7f0562`; a later documentation-only HEAD does
  not upgrade or alter this code evidence.
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
| immutable bootstrap | `tests/openwrt-adapter-integration.sh` | PASS | local/mock |
| installer parent modes | `tests/installer-lifecycle.sh` | PASS | local/mock |
| boot guard | `tests/boot-guard-policy.sh`, `tests/boot-guard-service.sh` | PASS | local/mock |
| privileged helper boundary | `tests/helper-service.sh`, `go test ./internal/helper` | PASS | local/mock |
| nft transition | `tests/nft-transition-namespace.sh` | NOT RUN LOCALLY on Windows; CI Linux job required | Linux namespace |
| hotplug boundedness | `tests/hotplug-bounded.sh` | PASS | local/mock |
| Zapret cleanup | `tests/zapret-calibration-runtime.sh` | NOT RUN LOCALLY on Windows; CI Linux job required | Linux namespace |
| SSRF and decompression limits | `go test ./internal/remotefetch ./internal/vpnsub ./internal/tspu ./internal/geoip` | PASS | local |
| Xray typed input | `go test ./internal/vpnsub` | PASS | local |
| resource budget | `go test ./internal/api ./internal/probe` | PASS | local |
| frontend build | `npm run build` | PASS | local |
| frontend tests | `npm.cmd test -- --run` | PASS (15 tests) | local |
| race/vet | `go test -race ./...`, `go vet ./...` | PASS | local |

The full local runner (`tests/run-all.ps1`) completed with
`all_tests_ok=true`. Its Linux-only steps reported `NOT RUN LOCALLY` rather
than claiming a namespace or process-group PASS.

## Required hardware gate (not executed here)

Before any deployment, capture a read-only backup and baseline for model,
firmware, kernel, services, ubus, routes, rules, nft tables, DNS, processes,
FDs, sockets, CPU, free storage, and memory. Verify `/`, `/etc`, `/usr`,
`/usr/bin`, `/usr/lib`, `/etc/init.d`, and `/etc/hotplug.d` modes before
installation and again after installation, before reboot. Only then proceed to
controlled deployment, with a tested recovery path and explicit user approval.

No hardware PASS may be entered in this matrix without raw logs, hashes, the
device environment, and the exact installed commit SHA.
