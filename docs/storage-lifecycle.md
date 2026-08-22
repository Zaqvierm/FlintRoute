# Storage and lifecycle

This document describes the storage contract implemented by FlintRoute. It is
not hardware evidence: this remediation branch has not been installed on a
router.

## Ownership and supervisors

`procd` is the production process supervisor. FlintRoute does not use a second
unbounded supervisor. A resource may be stopped, removed, or replaced only if
the lifecycle manifest proves its owner, generation, and identity. A PID or a
process name alone is never sufficient; process start time, executable, run or
transaction ID, and expected configuration are checked as well.

Production and test resources are separate. Test resources use an explicit
`test-run:<id>` owner and project namespace. Cleanup is dry-run by default and
does not touch production resources or ambiguous/foreign objects.

## Storage classes

### Immutable installed data

Installed binaries, init scripts, schemas, and factory defaults are immutable
inputs. The installer uses content-aware replacement and never archives
synthetic staging parents as restore targets.

### Durable committed and recovery state

- committed control state in bbolt;
- the active revision and content-addressed active artifact manifest;
- one verified `last-good` recovery copy;
- one active transaction journal when a transaction is in progress;
- authentication material and secret references.

`bootstrap.json` contains only immutable launch metadata and paths. It is never
replaced by a candidate. On restart, the journal selects the committed
artifact. Missing, corrupt, or mismatched state enters rescue/fenced mode; the
controller does not guess from a candidate or a legacy `default.json`.

### Bounded operational history

Terminal changes, durable security/configuration audit events, recovery records,
and occasional adaptive checkpoints have bounded retention. Identical encoded
values are compared before a bbolt write. Heartbeats, `checked_at`, and
`last_seen` do not create persistent writes by themselves.

### Runtime state

Locks, rollback timers, current probe results, discovery observations, bounded
SSE buffers, scheduler deadlines, temporary generated files, and test-run
working state live under `/tmp/router-policy` (tmpfs where available). Probe
details and operational events use bounded in-memory rings unless the user
explicitly exports a diagnostic bundle.

### Exported diagnostics

Support bundles and hardware reports are explicit exports. They must be
redacted and bound to the exact source commit and environment before being
shared.

## Write-path budget

The budget measures logical operations, not physical NAND writes:

| Path | Persistent policy |
|---|---|
| `meta`, `revisions`, `transactions` | write only on config/security/recovery transitions or bounded maintenance |
| `changes` | one entry per real change, bounded terminal retention |
| route health | state transition or infrequent checkpoint; no heartbeat writes |
| probe results and discovery | bounded RAM/tmpfs ring by default |
| events | durable security/config audit only; operational events are transient |
| generated artifacts | compare bytes/hash first; identical content is a no-op |
| snapshots and backups | one verified last-good plus bounded upgrade/installer fallback |

The storage diagnostics endpoint exposes logical write transactions, bytes,
file create/replace/delete counts, fsync counts, snapshot/backup counts, and
the last write reason. It does not claim to measure physical flash wear.

Artifact replacement treats the parent-directory sync as part of the write
contract. OpenWrt targets use an exact directory `sync -f` when available and
record a clearly labelled global-sync fallback otherwise; if both fail,
`atomic_install` returns an error and records `fsync_failed` instead of
reporting a durable install.

## Recovery artifact policy

If bbolt cannot be opened or an interrupted compaction cannot be recovered, the
controller enters rescue mode. It preserves the damaged database as a bounded,
mode-0600 forensic artifact (at most three artifacts, each capped at 64 MiB),
without replacing or deleting the original. Rescue mode is loopback-only,
read-only, and disables discovery, calibration, and mutation until an
administrator explicitly validates and restores a compatible backup.

## Installer and uninstall safety

Installer snapshots contain only manifest-listed existing files. Parent
directories such as `/`, `/etc`, `/usr`, and `/usr/bin` are never snapshot
members and therefore cannot inherit staging `umask` metadata during rollback.
Rollback restores the recorded uid/gid/mode of owned files only. Critical
system-directory mode invariants are checked before an operation and after a
simulated failure.

Uninstall removes only the FlintRoute-owned nft tables, exact init services,
and allowlisted files. It does not run a global `fw4 reload`, wildcard-delete
system paths, or delete a foreign nft table.

## Hardware status

No hardware validation is claimed for this branch. Any evidence from an older
commit is `STALE FOR CURRENT SHA`. Before a future deployment, capture a
read-only baseline and verify `/`, `/etc`, `/usr`, `/usr/bin`, `/usr/lib`,
`/etc/init.d`, and `/etc/hotplug.d` modes before and after installation, before
any reboot. See `docs/remediation-evidence.md` and
`docs/flint2-hardware-validation.md` for the separate hardware gate.
