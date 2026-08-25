# Adversarial remediation checkpoint — 2026-08-25

This document records the safety contract for the ten findings reviewed against
`bb0ed42f036b9d4bbb51ff2426a2bf40c6c9c54e`.  It is an engineering design and
evidence record, not hardware proof.

## State and safety boundaries

An OpenWrt apply has two independent safety boundaries:

1. A **forwarding fence** is armed before the first file, service, route, or
   nft change.  It is an owned `inet router_policy_boot_guard` table with a
   `forward` hook at priority `-300` whose default policy is `drop`.  This deliberately stops
   transit traffic while a generation is incomplete; it does not block the
   loopback management listener.
2. The fence is removed only after the control plane has durably recorded the
   committed revision and the adapter has proven the exact generation.  A
   failed verification, failed final persistence, crash, or ambiguous helper
   response leaves the fence in place.  Recovery may remove it only after an
   exact committed generation has been reconciled.

The fence is therefore a fail-closed transition mechanism, not a health
indicator. A local test or a successful HTTP response is not evidence that a
full dataplane generation is correct. The installer accepts health only when
the response says `status=ok`, recovery is explicitly `ok` (or the proven
`not_required:baseline_confirmed` state), `active_revision` is present, and
the candidate hash is a valid `sha256:` digest. Committed generations must
also expose a valid artifact-manifest hash; the baseline is the only allowed
exception because it has no deployed artifact.

The durable transaction protocol remains:

```text
intent persisted
  -> candidate prepared (rollback retained)
  -> adapter activated (rollback retained)
  -> control-plane committed (bbolt revision/hash durable)
  -> adapter finalized (rollback capability retired)
  -> fence cleared after the final binding is durable
```

Any mismatch or false-success response is `RECOVERY_REQUIRED`; new mutations
are fenced until recovery compares the bbolt record, adapter metadata and
owned dataplane.  We do not claim that a crash/reboot matrix or real hardware
has proved the absence of split-brain.

## Finding disposition at the audited SHA

| # | Finding | Status | Evidence | Remediation boundary |
|---|---|---|---|---|
| 1 | Boot guard allowed unmarked forwarding | CONFIRMED / SEV-1 | `openwrt/adapter.sh:229-278`; generated nft `rp_forward_guard` | Fail-closed owned transition/boot fence; exact-generation clear |
| 2 | Installer accepted `recovery_required` | CONFIRMED / SEV-1 | `install.sh:wait_control_health`; `/api/v1/health` | Strict recovery state plus revision/candidate/artifact hash binding |
| 3 | Full apply was only partially atomic | CONFIRMED / SEV-1/2 | `openwrt/adapter.sh:1127-1185` | Fence before mutation; no claim of whole-system atomicity |
| 4 | DNS observer was outside install targets | CONFIRMED / SEV-2 | `install.sh:31,912-920`; `openwrt/ensure-dns-observer.sh` | Snapshot exact observer target and runtime metadata |
| 5 | Secret permissions were broader than manifest | CONFIRMED / SEV-2 | `install.sh:894-900` | Only owned secret files may be normalized and restored |
| 6 | Prefix switch was not power-loss durable | CONFIRMED / SEV-2 | `install.sh:850-878` | Durable switch marker and last-good retention |
| 7 | No disk-space preflight | CONFIRMED / SEV-2 | `install.sh:68-79,966` | Size estimate before snapshot/staging mutation |
| 8 | Root helper was opt-in while controller stayed root | PARTIAL / SEV-2 | `openwrt/init.d/router-policy`; `cmd/router-policy/main.go` | Keep helper optional but force loopback-only while root |
| 9 | Exact-SHA full CI gate was missing | CONFIRMED / SEV-2 | `.github/workflows` and `tests/run-all.*` | Reproducible full-gate workflow |
| 10 | Clean-clone runner depended on local artifacts | CONFIRMED / SEV-2 | `tests/run-all.sh:5-41`; `tests/run-all.ps1` | Build artifacts/toolchain explicitly before tests |

## What this does not prove

The Linux namespace workflows and local fixtures prove only the properties
they execute.  They do not inherit hardware status.  Flint 2 is untouched in
this remediation cycle; hardware work, if approved later, starts with
read-only diagnostics and a saved recovery point.
