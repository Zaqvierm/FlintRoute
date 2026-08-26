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

The full-topology review candidate additionally rejects non-loopback inbounds,
unsupported inbound/outbound protocols, unsafe DNS inbounds, missing routing
references, and a TPROXY topology without an explicit blackhole fail-closed
rule. This validation is deliberately a staging gate; it does not claim that
the managed renderer can yet replace the live manual service.

Add `--plan` to print a deterministic, review-only ownership handoff plan next
to the report:

```text
router-policy manual-import --xray ... --q205 ... --q208 ... --plan
```

Use `--out-plan` when another local tool or the UI needs a persisted,
redacted plan. The file is written atomically with mode `0600`; it contains
only ownership states, hashes, bounded evidence and next actions, never the
manual configuration or credentials:

```text
router-policy manual-import --xray ... --plan \
  --out-plan /tmp/router-policy/manual-adoption-plan.json
```

Writing this plan does not grant apply permission. A plan remains
`apply_allowed: false` until a separately reviewed handoff proves every
listener, process, nft/NFQUEUE object, DNS include and recreation lifecycle.

Pass each manual recreation path with the repeatable `--lifecycle` flag. The
files are bounded, hashed evidence only; they are never executed by the
importer and their absolute paths are not copied into the redacted plan:

```text
router-policy manual-import --xray ... \
  --lifecycle /etc/crontabs/root \
  --lifecycle /etc/init.d/chatgpt-proxy \
  --lifecycle /etc/init.d/nfqws-flowseal205
```

If no lifecycle evidence is supplied, the plan keeps an explicit
`manual-cron-procd` missing-evidence resource. A readable Xray/Zapret config is
not enough to claim that the old owner cannot recreate a process.

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

Для текущего ручного Xray можно дополнительно получить отдельный полный
кандидат для ревью:

```text
router-policy manual-import \
  --xray C:\private\manual\xray.json \
  --out-full-bundle C:\private\candidates\manual-full-topology.json
```

`--out-full-bundle` сохраняет только проверенную top-level схему и loopback
топологию TPROXY/DNS/SOCKS/VLESS. Это не разрешение на запуск: кандидат всё
ещё review-only, а секреты находятся только в локальном файле с режимом 0600.
Он нужен, чтобы следующим шагом связать полный Xray topology с owned nft,
dnsmasq, сервисом и rollback в одном ChangeSet. Пока такой binding не доказан,
ручной процесс остаётся production owner и не останавливается.

For the current manual Xray, an additional full-topology review candidate can
be generated with `--out-full-bundle`. It stores the validated loopback
TPROXY/DNS/SOCKS/VLESS topology in a local 0600 artifact. This is review-only,
not launch permission: ownership of listeners, nft, dnsmasq, services and
rollback must still be bound in one ChangeSet before the manual owner is
stopped.

## Why the candidate is not activated automatically

The manual owner may already hold the same TPROXY, DNS and SOCKS listeners as
the managed Xray service. Its nft tables, dnsmasq include, cron/procd hooks and
NFQUEUE consumers are not FlintRoute-owned. Starting the managed service or
replacing its table before a handoff would create two owners and can drop
OpenAI/Telegram traffic or recreate an apparently removed process.

The current importer therefore reports these blocking conflicts:

- one owner must be proven for every Xray listener and process;
- the staged Xray artifact is SOCKS/VLESS-only; if the manual config also has
  TPROXY or DNS inbounds, it is not a replacement candidate until those
  inbounds and their routing/DNS ownership are modeled;
- manual nft tables must stay foreign and must not be flushed or replaced;
- DNS includes and runtime state need an install/recovery manifest;
- manual cron/procd lifecycle must be disabled only in the same reviewed
  ChangeSet as the replacement;
- q205 and q208 need separate, device-aware managed profiles; collapsing them
  into one generic Zapret profile is not a valid migration.

Every generated candidate reports `bundle_scope=loopback_socks_vless_only`.
That field is an explicit scope contract, not a health signal: `bundle_ready`
means only that the bounded candidate artifact was written and hashed.

The importer also inspects the supplied nft evidence for host-scoped source
rules on queue verdicts. A full-length host address (for example, a `/32`)
marks that queue as `device_scoped` and records only an opaque per-report
scope ID plus typed TCP/UDP port facts; the source identity itself is never
copied or hashed into the redacted report. The review plan adds a separate
`device-scope` collision resource and keeps that queue foreign until the
device selector, NFQUEUE/process lifecycle, and rollback boundary are all
typed and proven. A subnet rule such as `192.168.0.0/24` is not treated as a
device binding.

On the current Flint 2 read-only snapshot, q205 is a LAN-wide queue while
q208 has a host-scoped rule for the TV path. The importer therefore reports
q208 as `device_scoped`/`SEV-1` and refuses to collapse it into the generic
q205 profile. This is evidence for a migration gate, not permission to alter
the live table.

The importer now has a second, deliberately narrow readiness signal for
Zapret. A profile is `typed_model_ready` only when its complete argument
vector exactly matches an audited FlintRoute profile vocabulary. The current
TV vector is recognized as `tv-fake-multidisorder-v1`; it is still reported as
foreign/collision until the exact nft rule, process group, device selector and
rollback handoff are proven. The LAN-wide q205 vector remains untyped because
it contains multiple stages plus hostlist/ipset and payload assets. Reading
its argument file is therefore not evidence that FlintRoute can reproduce or
clean it safely. Unknown, split, or asset-backed vectors stay fenced and must
receive a dedicated structured profile/manifest before adoption.

Command-line evidence exported from `/proc/<pid>/cmdline` may be wrapped by a
text-aware copier and acquire a UTF-8 BOM before the first NUL-delimited
argument. The importer strips only that leading BOM before matching `argv[0]`;
all other argument bytes remain exact evidence. This keeps the audited q208
profile recognizable without weakening its ownership, device-scope, or
rollback gates.

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

## Typed ownership proof gate

The importer can now validate a separate, redacted handoff proof without
touching the router. The proof must bind every resource in the adoption plan
to the same candidate hash and generation. Process proofs include PID,
start-time ticks, PGID, executable and config digest; listeners reference the
proved process; non-process resources carry an evidence digest. The envelope
also records that the manual lifecycle is quiesced, a mark-scoped transition
guard is prepared, rollback is retained, and the management path is proved.

Run the check only on local evidence files:

```text
router-policy manual-handoff-check \
  --plan /private/manual-adoption-plan.json \
  --proof /private/manual-handoff-proof.json
```

The command is read-only and strict: unknown JSON fields, missing resources,
changed owners, stale generations, weak process identity and extra resources
are rejected. A successful result is `ready_for_change_set`; it never sets
`apply_allowed` and cannot replace the transaction/adapter state machine. The
manual dataplane remains the rollback owner until a separately reviewed
ChangeSet proves the complete handoff.

To materialize the review sequence without granting execution permission, use
the typed draft command:

```text
router-policy manual-handoff-draft \
  --plan /private/manual-adoption-plan.json \
  --proof /private/manual-handoff-proof.json \
  --out /private/manual-adoption-draft.json
```

The draft is either blocked with its exact blockers or marked
`eligible_for_change_set`. In both cases `apply_allowed` is always `false`.
A ready draft contains the fixed sequence (verify handoff, guard, quiesce the
manual owner, activate, verify management and dataplane, persist the active
revision, finalize ownership) as typed review steps. It is not an adapter
request, does not execute commands, and cannot stop the live manual service.

Before producing a handoff proof, capture a live, redacted observation of the
exact plan resources. This is read-only: it inspects `/proc` identity and
hashes explicitly supplied evidence/config files, but never copies command
lines, secrets or file paths into the output and never starts or stops a
resource:

```text
router-policy manual-handoff-observe \
  --plan /private/manual-adoption-plan.json \
  --pid process/manual-xray=10775 \
  --config process/manual-xray=/etc/chatgpt-proxy/xray.json \
  --evidence nft/table-flintroute-lite=/private/evidence/flintroute-lite.txt \
  --out /private/manual-live-observation.json
```

The `kind/identifier=value` references must name resources already present in
the plan. Process observations include PID, start-time ticks, PGID,
executable and a redacted identity digest; evidence observations include only
a bounded SHA-256. Missing or unreadable targets are explicit `missing` or
`error` states, never implicit proof. A live observation is evidence for the
reviewer, not an ownership claim and not permission to apply a ChangeSet.

## Flint 2 handoff boundary (current)

The current manual Flint 2 dataplane has a larger Xray topology than the
read-only candidate builder: twelve loopback SOCKS inbounds, two transparent
inbounds, and one DNS inbound. The candidate builder intentionally emits only
the SOCKS/VLESS subset because the managed artifact renderer needs typed
transparent-proxy, DNS-proxy, mark, route-table, and outbound-bundle state. It
must not be treated as a drop-in replacement for the manual service.

The safe implementation order is therefore:

1. Import and validate the full Xray topology into a typed, hash-bound bundle,
   including transparent/DNS inbounds and exact outbound/rule references.
2. Bind that bundle to the existing TPROXY mark/table and prove the generated
   config preserves the manual listener and DNS contracts without starting a
   second Xray.
3. Add the manual DNS include and runtime readiness to the same ownership and
   rollback manifest; do not restart dnsmasq as a side effect of inspection.
4. Model the shared nft objects at exact rule/generation granularity. A table
   name or queue number is not ownership proof; foreign rules remain untouched.
5. Adopt q208 only after its device selector, process group, and rollback are
   typed. Adopt q205 last, after its multi-stage assets have a bounded manifest
   with hashes and cleanup ownership.

Each phase needs its own candidate, backup, post-apply OpenAI/Telegram probe,
and recovery evidence. Until phase 1 is complete, `apply_allowed` remains
false even when individual SOCKS servers or a Zapret vector are readable.
