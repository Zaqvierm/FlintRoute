# Device-scoped Zapret handoff design

This document defines the boundary required before a manually maintained
device-specific Zapret profile can become FlintRoute-owned. It is a design and
acceptance contract, not permission to change a router.

## Current evidence

The Flint 2 production snapshot contains two different semantics in
`inet app_zapret`:

- q205 is a LAN-wide queue used by the general Flowseal profile;
- q208 is selected by a host-scoped source rule, with UDP/443 dropped and
  TCP/443 sent to q208 for the TV path.

The manual importer reports q208 as a redacted `device_scope` with an opaque
per-report scope ID, TCP queue ports and UDP drop ports. It deliberately keeps
the resource in `collision` and never emits an apply operation.

The typed renderer in `internal/zapretprofile` validates this shape and emits
deterministic nft rules, nfqws configs and fixed procd service scripts. The
artifact generator binds those files and a line-oriented ownership manifest to
the transaction. The OpenWrt adapter snapshots, installs, starts, verifies,
rolls back and reconciles each profile independently while replacing only the
single owned FlintRoute nft table. The helper accepts only the fixed
`router-policy-zapret-<id>` service family and, on production paths, checks the
active profile manifest before allowing a service operation.

The config schema carries `zapret.device_profiles` as a typed field so an
imported profile cannot be silently discarded by JSON decoding. `Config.Validate`
requires an enabled managed Zapret route, rejects queue collisions with the
base profile, and validates every selector/path/strategy before activation.
The normal renderer keeps q205 and q208 as separate queues and service owners;
it never collapses q208 into the generic q205 profile.

## Required managed model

A managed device profile must bind all of the following to one generation:

1. stable profile ID and a typed device selector (MAC or a DHCP/neighbor
   identity resolved to an address at apply time);
2. exact NFQUEUE number, with queues 0/1 forbidden and no duplicate queue;
3. immutable nfqws binary/config hash and a dedicated procd service instance;
4. typed nft source, protocol, port, verdict and conntrack scope;
5. owner, transaction ID, generation, PID/start-time/PGID and cleanup policy;
6. a rollback artifact that restores both the previous nft generation and the
   previous process/service state.

Raw shell fragments, arbitrary command lines and an IP copied from a stale
snapshot are not acceptable as the profile identity. A selector that cannot
be resolved unambiguously is a hard preflight failure.

## Runtime boundary

The managed model provides:

- one owned config, service script and lifecycle record per profile;
- a helper allowlist for the exact profile service name family and paths;
- a single owned nft table (or versioned generation switch) containing both
  q205 and q208 rules;
- transition guard before stopping any existing managed owner;
- service readiness proof before the nft generation switch;
- cleanup that can stop only manifest-bound services and never a foreign q205,
  q208 or system queue consumer.

## Handoff sequence

1. Capture backup, firmware/kernel, active revision and read-only ownership
   evidence.
2. Resolve the device selector and prove it still maps to the intended LAN
   device; otherwise stop.
3. Stage q205/q208 artifacts and dedicated service definitions offline.
4. Validate all hashes, queue collisions, nft syntax, service ownership and
   rollback manifest without touching the live table.
5. Arm the mark-scoped transition guard and prove management reachability.
6. Start and health-check the new profile services while the manual owner is
   still available; no traffic switch occurs yet.
7. Atomically switch the owned nft generation, then run real TCP/UDP probes for
   general LAN and the selected device.
8. Commit ownership only after OpenAI, Telegram, Discord/YouTube, TV and Direct
   probes plus persistence checks pass. Any ambiguous result fences and rolls
   back; it never claims success from a process start or listening queue.

The production lifecycle is now implemented in the candidate generator,
adapter and helper, but q208 remains foreign/manual on the current Flint 2
until a reviewed hardware ChangeSet proves the selector, process ownership,
post-apply traffic and rollback. Local artifact/adapter tests are not hardware
evidence.

## Acceptance tests

- q205 and q208 render as separate services with distinct queues and exact
  ownership records;
- host selector mismatch blocks apply before any helper call;
- foreign q208 process/table survives a failed prepare;
- invalid nft generation preserves the old generation and both services;
- process-group cleanup removes only the recorded profile and leaves queues 0/1
  and unrelated nfqws intact;
- crash/restart at every handoff boundary yields the previous committed
  generation or a protected fenced state;
- a simulated TV path proves UDP/443 drop plus TCP/443 q208, while general LAN
  traffic still uses q205.
