# Manual dataplane migration

FlintRoute can inspect a manually maintained Xray/Zapret dataplane and build a
redacted migration report plus an immutable Xray candidate. The importer is an
inventory and staging boundary, not an adoption shortcut.

## Safety contract

`router-policy manual-import` is read-only for all source files and never calls
the adapter, procd, nft, dnsmasq, `xray`, or `nfqws`. The only write is an
explicit local candidate path passed with `--out-bundle`; it is created as a
0600 content-addressed-compatible artifact. Reports set `secrets_printed` to
false and do not contain UUIDs, subscription URLs, or raw provider JSON.

The command rejects malformed or unsafe VLESS endpoints, loopback/private
server addresses, duplicate SOCKS/VLESS topology, missing SOCKS routing rules,
symlink inputs, and reserved NFQUEUE 0/1. It keeps manual resources marked as
`foreign/manual` until ownership is proven.

Add `--plan` to print a deterministic, review-only ownership handoff plan next
to the report:

```text
router-policy manual-import --xray ... --q205 ... --q208 ... --plan
```

The plan is deliberately `apply_allowed: false`. It lists occupied Xray
listeners, manual nfqws processes and queues, DNS/nft evidence, and the
manual cron/procd lifecycle as `foreign`, `unproven`, or `collision`. A
candidate hash in that plan identifies what would be reviewed; it does not
grant permission to stop a process, bind a listener, alter nftables, reload
dnsmasq, or change routing.

Example (local staging only):

```text
router-policy manual-import \
  --xray C:\private\manual\xray.json \
  --q205 C:\private\manual\q205.args \
  --q208 C:\private\manual\q208.args \
  --dnsmasq C:\private\manual\dnsmasq.conf \
  --nft C:\private\manual\base.nft \
  --out-bundle C:\private\candidates\manual-vless.json
```

## Why the candidate is not activated automatically

The manual owner may already hold the same TPROXY, DNS and SOCKS listeners as
the managed Xray service. Its nft tables, dnsmasq include, cron/procd hooks and
NFQUEUE consumers are not FlintRoute-owned. Starting the managed service or
replacing its table before a handoff would create two owners and can drop
OpenAI/Telegram traffic or recreate an apparently removed process.

The current importer therefore reports these blocking conflicts:

- one owner must be proven for every Xray listener and process;
- manual nft tables must stay foreign and must not be flushed or replaced;
- DNS includes and runtime state need an install/recovery manifest;
- manual cron/procd lifecycle must be disabled only in the same reviewed
  ChangeSet as the replacement;
- q205 and q208 need separate, device-aware managed profiles; collapsing them
  into one generic Zapret profile is not a valid migration.

## Required adoption sequence

1. Preserve a router backup and a private redacted inventory.
2. Detect processes, listeners, nft tables/chains/sets, routes, marks and
   NFQUEUE consumers; classify each as owned, foreign or conflict.
3. Stage the Xray candidate and run offline schema/hash/Xray validation.
4. Review the generated adoption plan and prove exact PID/start-time,
   listener, nft-table, NFQUEUE, DNS and lifecycle ownership.
5. Add a typed ChangeSet that proves the manual owner can be stopped and that
   the rollback can restore it without touching system queues 0/1 or foreign
   tables.
6. Prepare a transition guard and management proof before changing any
   listener, route, nft table, DNS include or service.
7. Switch one generation atomically, verify the actual OpenAI/Telegram path and
   Zapret device profiles, and retain the manual rollback until all probes pass.
8. Only after post-apply evidence is complete may ownership be committed.

Until those steps exist, the correct state is `blocked_on_ownership_handoff`.
An Xray config file or a listening port alone is not proof of a safe migration.
