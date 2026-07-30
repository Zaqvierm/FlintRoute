# 72-hour soak test

The soak starts only after the route matrix, crash/reboot recovery, physical
power-loss recovery and multi-client preflight are green. It is an evidence run,
not three days of leaving the router on and hoping for the best.

## Preflight

Record a redacted baseline before the timer starts:

- Git SHA, package SHA-256, firmware version and boot ID;
- active revision and recovery status;
- managed procd instances with PID/start time/executable/config identity;
- nftables objects, policy rules/tables and listeners owned by FlintRoute;
- persistent/runtime storage sizes, backup/snapshot counts and write counters;
- route-health state and one bound proof for each active route type;
- CPU, RSS, conntrack, NFQUEUE counters, temperature and WAN fingerprint;
- external SSH, router UI and FlintRoute Web availability.

Verify an off-router backup and a management path independent of routed client
traffic. The router must have no unfinished transaction, stale test-run,
ambiguous owned resource or expired watchdog inhibit. A missing rollback timer,
unknown baseline or unavailable monitor blocks the start.

## Workload

Run for at least 72 continuous hours with normal mixed traffic and at least three
clients when available. Add bounded DNS, Direct, Zapret, VLESS and Drop checks
with jitter; do not synchronize every probe on the same minute.

During the run include:

1. one controlled managed-service restart;
2. one controlled reboot;
3. one bounded degradation of Zapret and VLESS with recovery;
4. a WAN fingerprint change when it can be done without touching unrelated
   router services;
5. periodic UI GET/SSE activity to prove that observation remains write-free.

Do not perform another physical power cut inside the soak unless it is planned
as a separate fault case with an independent recovery path.

## Evidence cadence

Capture health and resource counters every minute in tmpfs. Persist a redacted
checkpoint no more often than every 15 minutes and on state transitions. Export
the bundle off-router at least daily so a device failure cannot erase the whole
run.

Each checkpoint contains timestamps, boot ID, active revision, route state,
provider identity, nft/NFQUEUE counters, CPU/RSS/temperature, storage sizes and
logical write counters. It must not contain subscription URLs, UUIDs, keys,
tokens, cookies or private endpoints.

## Stop conditions

Stop and mark the run failed on:

- unsafe Direct fallback or route evidence bound to the wrong revision;
- unknown/contradictory transaction or recovery state;
- loss of management beyond the documented boot window;
- production process not owned by its expected procd instance;
- NFQUEUE drops, OOM, thermal throttling or persistent restart loop;
- unbounded RAM, cache, snapshot, backup or persistent-write growth;
- unexplained adaptive profile oscillation.

## PASS

PASS requires 72 completed hours, no stop condition, no leaked/stale resources,
bounded storage/write counters and the same internally consistent committed
state after the final audit. Any pause in monitoring is documented; a gap that
prevents proving route or resource state invalidates the affected interval.
