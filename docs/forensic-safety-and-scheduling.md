# Forensic safety review and probe scheduling

This document records the three failure chains found during the Flint 2
review. The hardware observations are treated as evidence; claims about a
second `ubusd` are deliberately not attributed to FlintRoute without a
reproduction.

## A. Installer rollback and system permissions

**Fact.** `install.sh` sets `umask 077`. The old implementation of
`snapshot_installation` copied allowlisted paths into a synthetic staging tree
and archived `.`. `restore_installation` then extracted that archive with
`tar -C / -xf`. The archive therefore contained synthetic `etc`, `usr`, and
other parent entries with restrictive staging metadata. On the live router
those entries changed `/`, `/etc`, `/usr`, `/usr/bin`, `/usr/lib` and service
directories to `0700`; ujail then returned `EACCES` while starting hostapd.

**Code path.** `install.sh:408` (`snapshot_installation`) and
`install.sh:472` (`restore_installation`). The old dangerous operation was
`tar -C / -xf "$archive"`.

**Reproduction.** `tests/installer-lifecycle.sh` now builds a mock OpenWrt
tree with all critical parents at `0755`, creates a snapshot under `umask
077`, simulates a failed install, restores it, and checks the content plus
the mode of every parent. The test would fail if archive metadata were
replayed onto the mock root.

**Fix.** The snapshot manifest now records mode/uid/gid for each allowlisted
object. Archive copies preserve nested metadata. Restore extracts only into a
private rollback directory, removes and reinstalls only allowlisted targets,
and reapplies the recorded metadata to the target itself. It never extracts
into `/`, never archives the staging root as a restore target, and rejects
critical system directories in manifests.
Legacy two-column manifests are accepted only by deriving metadata from the
private extracted target; they are still never extracted into `/`.

`preflight_install` checks critical system directory modes and, when present,
compares them with `/rom`. A mismatch blocks the operation with a diagnosis;
it is not repaired automatically.

## B. Zapret timeout and orphan `nfqws`

**Fact.** The previous runner killed the calibration shell process group, but
the upstream blockcheck could daemonize `nfqws` into a new session. A timeout
therefore left an `nfqws` child with `PPid=1` and could leave NFQUEUE state.

**Code path.** `internal/zapret/calibration_runner_linux.go:49` bounds the
runner process group. `scripts/calibrate-zapret.sh:236` is the cleanup trap;
the blockcheck session starts at `scripts/calibrate-zapret.sh:327`.

**Fix.** Calibration starts blockcheck in its own session where `setsid` is
available, records the process identity, and always executes cleanup on
success, error, timeout, and signal. Cleanup terminates the owned process
group, then sweeps only new `nfqws` processes whose PID/start-time/executable
or command line matches the calibration binary. PID reuse is rejected. It
also checks for the calibration NFQUEUE/table namespace before restarting a
previously managed Zapret service, and compares `ip route`/`ip rule` snapshots
before and after the run. No global `pkill`, `killall`, or nft flush is used.

`tests/zapret-calibration-runtime.sh` covers success, failure, timeout, and a
blockcheck that starts a copied `nfqws` daemon before returning `124`; the
daemon must not survive cleanup. It also fails a calibration that leaves a
temporary route behind.

## C. Background probing and socket pressure

**Fact.** `startOperationalSchedulers` used an immediate full VLESS health
cycle and then repeated it on a short global interval. `startDNSDiscovery`
called `discoverDomain` directly for every observation. In `discoverDomain`,
the old `observe_only` check happened *after* `domainChecker`, so a passive
mode still performed DNS/TLS/HTTP/SOCKS probes. `fetchTextViaRoute` created a
fresh `http.Transport` without closing idle connections, unlike
`runHTTPAttempt`.

**Fix.** `observe_only` now emits a bounded observation event and returns
before `domainChecker`; repeated DNS observations are deduplicated without a
route probe. DNS events enter a queue of at most 32 items and one worker.
The legacy `router-policy daemon` loop that rechecked three hard-coded services
every five minutes was removed; it was not referenced by procd and was not a
safe production scheduler. All route-health jobs and discovery jobs share a
process-wide probe semaphore with a hard maximum of four active jobs. The inventory health cycle is delayed
after boot and scheduled daily with jitter (21–27 hours for the default 24h
period), rather than acting as a five-minute load test. `fetchTextViaRoute`
closes idle connections on every request.

Regression coverage includes observe-only zero-probe assertions,
baseline/discovery behavior, shared probe-budget enforcement, and the
installer/Zapret runtime tests above. `TestDiscoveryStormIsBoundedAndDrainsToBaseline`
fills the queue with 1,000 synthetic observations and asserts that only the
configured 32 entries are accepted and that the queue returns to zero after
drain. Health tests run eight routes with a process-wide four-slot semaphore
and assert that active route jobs never exceed four. The deterministic tests
also cover the smaller configured limits used by development fixtures.

Idle CPU, FD/socket stability, and thread/goroutine growth are not honestly
provable from a Windows unit-test run. They are explicit hardware-gate
measurements in `docs/hardware-read-only-gate.md`; no hardware PASS is claimed
until the one-minute idle samples and before/after FD/socket counts are saved.

### One logical check and fan-out

`planner.CheckDomain` iterates the finite candidate list once and stops at the
first verified result. A single `probeRoute` iterates only the configured
probe URLs, then performs at most one external-egress check. DNS answers,
HTTP redirects, and SOCKS dials are bounded by the probe context and route
implementation; they do not enqueue new discovery observations. Unknown-domain
discovery holds one global probe-budget token while this sequential candidate
chain runs. Therefore one logical discovery job cannot multiply into an
unbounded number of concurrent route jobs, and the global ceiling remains four.

## Scheduling contract

| Event | Work | Max route probes | Timeout / next attempt |
|---|---|---:|---|
| Cold start | recovery and control-plane readiness | 0 immediately; one delayed inventory cycle | 30–90s startup jitter |
| First unknown domain | observe/cache only; decision job only in suggest/auto modes | 0 in observe-only; 1 job otherwise | 10–15s, eTLD+1 dedupe |
| Repeated DNS query | update observation counters | 0 | no probe |
| Selected VLESS failure | selected route, then one fallback candidate | 2 sequential | 3–5s, circuit breaker |
| Failed-route recovery | one probe for one cooled-down route | 1 | 5m → 15m → 1h → 6h |
| Subscription refresh | fetch/parse; candidate verification is bounded by the shared budget | 4 global jobs | 2m timeout, no overlap |
| Known expiry | subscription refresh only | 0 if unchanged | one refresh window |
| TSPU/GEO revalidation | targeted Direct check for the named domain | 1 | weekly scheduler or manual request; no VLESS fan-out |
| Manual path check | selected path for the named service | 1 | 10s |

The hard process-wide maximum is four concurrent route-check jobs. A discovery
job holds one budget slot while it checks its candidate chain sequentially, so
it cannot multiply concurrency by the number of routes. The unknown-domain
queue is bounded at 32. Backpressure drops only redundant observations and
emits `discovery_queue_full`; it does not start unbounded work.

## Filesystem and process-operation audit

The audit covered `chmod`, `chown`, `umask`, `mkdir`/`MkdirAll`, recursive
copy, `tar`, `rm -rf`, `os.Chmod`, `os.Chown`, `os.MkdirAll`,
`exec.Command`, timeout wrappers, and snapshot/rollback call sites.

- Installer rollback is now allowlist- and manifest-bound; no archive is
  extracted onto `/`.
- Install and uninstall backup roots are validated, path components may not be
  symlinks, and export archives contain only allowlisted descendants rather
  than a synthetic staging root.
- Runtime/component directories use private `0700` roots; installed public
  binaries/scripts are explicitly set to `0755`.
- Process termination in calibration validates PID, start time and executable
  before signalling.
- Lifecycle cleanup remains namespace-specific; no global process or nft
  cleanup was introduced.
- Other archives found by the audit are backup/export producers, not restore
  paths onto system parents. They remain subject to their existing registry
  and allowlist checks.

## Runtime boundary

Expiry-aware subscription refresh is wired to subscription metadata: a known
expiry schedules one refresh window before expiry, while sources without an
expiry use a jittered daily refresh. It is not part of the route-health cycle.

Reactive failover now has an explicit `ReportSelectedRouteFailure` ingress and
a single worker. Three consecutive transport failures are required before a
five-second confirmation probe; at most one known-good standby is then probed
and the route change goes through the normal transaction/rollback path. Duplicate
reports are coalesced for 10 seconds and a failed route is held for five minutes.
The current dataplane adapters do not yet emit this ingress automatically, so
callers must wire their real request-path error to that method; the scheduler
does not infer user failures from periodic inventory checks.

An unhealthy route is recovered independently: at most one cooled-down route is
probed per minute, with a 5-minute first retry and bounded 15-minute, 45-minute,
135-minute and 6-hour caps. A successful probe clears the retry state but does
not silently steal traffic back from the currently selected route.

TSPU/GEO revalidation is separate from health: `RevalidateClassifiedDomain`
performs one Direct probe and emits a suggestion if Direct recovers. The
background scheduler runs no more than one such job per hour and spaces each
service by seven days. It never silently removes an existing bypass policy.
