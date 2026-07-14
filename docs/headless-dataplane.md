# Headless Dataplane

P3.1 owns the transparent Xray and Zapret processes instead of treating an
installed binary as proof that a route works. Both processes use project procd
services and participate in the same snapshot/apply/verify/rollback transaction
as nftables, dnsmasq and policy routing.

## Xray

The managed mode is explicit:

- binary: `/usr/bin/xray`;
- service: `/etc/init.d/router-policy-xray`;
- active config: `/etc/router-policy/xray/active.json`;
- command: `xray run -config /etc/router-policy/xray/active.json`.

`candidate_only` still generates and validates the config but blocks transparent
activation. `managed` permits deployment only when the IP plan also contains the
TPROXY route/rule operations derived from live, non-simulated diagnostics.

## Zapret

The repository does not vendor nfqws. Installation must provide a compatible
Linux arm64 binary at `/usr/bin/nfqws`. The first hardware syntax gate used the
official Zapret v72.12 arm64 build; its release archive and binary are not part
of the project or a transaction bundle.

The generated candidate contains only a fixed reviewed preset:

- service: `/etc/init.d/router-policy-zapret`;
- active config: `/etc/router-policy/zapret/nfqws.conf`;
- NFQUEUE number: `200`;
- strategy identifier: `tls-fake-ttl3-v1`;
- TCP 80: `fake,fakedsplit`;
- TCP 443: `fake` with `ttl=3` and first-original-packet TTL rewrite (`orig-ttl=1`, `s1..d1`);
- UDP 443: DROP, forcing a later TCP attempt through nfqws.

Arbitrary nfqws arguments are deliberately not accepted through user config.
The adapter copies the candidate config into the transaction directory, appends
`--dry-run`, and runs the exact configured binary before any active file or rule
is changed. The nft queue rule has no `bypass`: if nfqws dies, matching traffic
fails closed instead of silently escaping direct.

## Transaction order

For an enabled managed route the adapter performs:

1. validate generated artifacts and binary dry-runs;
2. snapshot active configs and exact project-service running state;
3. atomically install active configs;
4. start or restart the required project services;
5. apply IP routes/rules, then nftables and dnsmasq;
6. run transaction-bound verification;
7. commit, or restore the old firewall/config first, then prior service state
   and snapshotted routes/rules.

Starting the processes before the queue/TPROXY rules avoids activating a rule
whose consumer is absent. Restoration reverses the data plane before returning
the services to their snapshotted state.

The installer places both init scripts but does not boot-enable them yet. A
validated transaction can start them for the active revision; durable enablement
and recovery after reboot belong to P6 and must not be faked by blindly starting
an inactive route at boot.

## Proven boundary

Locally, unit, race and mocked OpenWrt integration tests cover generation,
ordering, failure and rollback. On the real Flint 2, the generated nfqws config
passed the official arm64 binary's `--dry-run`, and the generated table passed
`nft -c`. That check used temporary files only. Persistent install, procd
lifecycle, traffic counters, route proof, management survival and rollback on
the router remain mandatory P13 hardware gates.
