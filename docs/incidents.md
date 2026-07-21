# Hardware incidents and validation defects

This log records failures that affected hardware validation or could have made a
release claim unreliable. It contains no credentials, private endpoints or raw
device dumps.

## 2026-07-18 — lifecycle sandbox controlled real services

### What was tested

The OpenWrt install, upgrade, rollback and uninstall lifecycle was exercised
under `ROUTER_POLICY_SYSTEM_ROOT`. The intent was to keep every write and
service action inside an isolated filesystem tree.

### What happened

Filesystem paths were isolated, but copied init scripts still invoked the real
`/etc/rc.common`. The test therefore stopped global procd services while policy
state was still active. Internet access disappeared first. The router then
stopped advertising Wi-Fi, stopped assigning DHCP leases on LAN and became
unreachable through LAN, SSH and the web UI. Recovery required reflashing the
factory image through U-Boot.

The loss of management access prevented collection of final on-device logs.
The confirmed defect is the escape from the lifecycle sandbox and control of
global services. There is not enough evidence to claim that the test itself
damaged the bootloader or flash contents.

### Fix and verification

Commit `ffa4215` blocks every service-manager action while a system-root
override is active. Sentinel init scripts cover install, upgrade, compatible
downgrade, rollback and uninstall. The replacement lifecycle procedure is
staged: files, providers, controller and dataplane activation have separate
management gates. A factory reinstall, transactional activation and controlled
reboot subsequently passed on Flint 2.

## 2026-07-19 06:47–06:50 +07 — recursion gate used the wrong transport field

### What was tested

The P13 ARM64 harness checked the active Xray configuration, early nftables
bypass rules and a live VLESS request. The release gate must prove that traffic
to a proxy endpoint cannot be captured again by policy routing.

### What happened

The first run failed even though the VLESS route returned `OK`, had bound path
evidence and used a loopback SOCKS inbound. The validation code additionally
required `ProxyFlowProcessed`. That field belongs to the `tg_ws_proxy` proof
contract, not the VLESS contract. Because the gate returned before its second
nft read, the result also displayed a default zero for the final counter; the
counter had not actually been reset.

### Fix and verification

Commit `23ccc0c` binds the proof to the selected non-simulated VLESS route, its
Xray outbound tag and loopback SOCKS path. `ProxyFlowProcessed` is deliberately
false in the regression test. The repeated Flint 2 run passed: 13 non-blackhole
Xray outbounds carried the bypass mark, both early nft rules were present, the
VLESS path was bound to the selected outbound, and the output bypass counter
increased from 731 to 841 packets.

## 2026-07-19 07:05 +07 — timer runner used the file schema version

### What was tested

The first Smart DNS rollback-timer run attempted to create a ChangeSet against
the active Flint 2 configuration.

### What happened

The request returned HTTP 409 before a ChangeSet was created. The runner used
the JSON file's schema `version` as `base_version`. The control plane tracks a
separate monotonic config version; the active value was 3 while the file schema
version was 2. The first runner revision also reported only HTTP 409, without
the failed API stage, which made the failure needlessly vague. No candidate was
applied and the dataplane was unchanged.

### Fix and verification

The runner now reads `config_version` from `/api/v1/revisions`, includes the API
method, path and error code in failures, and rolls back or deletes an unfinished
ChangeSet during error cleanup. The hardware test is repeated from a clean
control-plane state after this correction.

The second attempt reached candidate validation and failed before apply because
the resolver probe accepts a bare IP while an enabled Smart DNS route requires
an explicit `IP:port` endpoint. The runner now normalizes IPv4 and IPv6 resolver
input to port 53 for the route candidate and reports persisted validation codes.
The failed draft was deleted automatically; active config and dataplane were not
changed.

The third attempt was also rejected before apply. It tried to shorten
`openwrt.rollback_timeout_seconds` through a ChangeSet, but that field is
intentionally immutable through the public control API. The active device value
is already bounded at 180 seconds. The runner now treats that value as a
precondition and tests the real configured timer instead of weakening the API
allowlist for test convenience.

## 2026-07-19 07:12 +07 — rollback lost equivalent default routes

### What was tested

The first Smart DNS candidate that reached the OpenWrt adapter was applied
through the normal transaction path. Automatic data-plane verification did not
reach the confirmation window, so the API invoked rollback.

### What happened

Config files, services and the committed binding returned, but rollback left
every IPv6 policy table and the IPv4 Xray table empty. Direct, Zapret and VLESS
probes became `UNVERIFIED`. The router stayed reachable. Restarting only the
project controller invoked the committed `Reconcile` path and restored all
three IPv4 rules, all three IPv6 rules, tables 100/101/102 and the three route
proofs.

The snapshot obtained from `ip -j` represented a default route as `default`.
The generated plan represented the same route as `0.0.0.0/0` or `::/0`.
Rollback compared those strings literally, treated the pre-existing route as a
different key and deleted the candidate route without restoring its equivalent
predecessor.

### Fix and verification

Default destinations are now canonicalized by address family before snapshot,
rollback and verification keys are compared. The regression test covers an
IPv4 local default route and an IPv6 unreachable default route using the two
different spellings. The fix must pass the full local suite and a repeated
Flint 2 rollback test before this incident is considered closed.

The first runner revision deleted a terminal `requires_device` record during
cleanup, which also removed the easiest API-level explanation of the failed
verification. Cleanup now deletes only drafts that never applied. Terminal
failure and rollback records are retained, and an unexpected apply result
prints its state plus the last adapter step, status and reason.

## 2026-07-19 07:32–07:43 +07 — Smart DNS path was both allowed and forbidden

### What was tested

The corrected rollback candidate was applied on Flint 2 to enter the real
confirmation window and exercise the configured 180-second rollback timer.

### What happened

The adapter applied the candidate, but automatic data-plane collection stopped
at `requires_device` and rolled it back. The retained error was
`no compatible probe service for route smart-dns-primary`. The candidate had
added `smart_dns` to the ChatGPT service's `allowed_paths` without removing the
same route type from `forbidden_paths`. The route selector correctly gave the
forbidden list priority, but configuration validation had accepted the
contradiction. The rollback completed, and policy rules, tables 100/101/102 and
the committed config were restored.

### Fix and verification

The hardware runner now removes `smart_dns` from the service's forbidden paths
in the same ChangeSet that enables it. Configuration validation rejects a path
that appears in both lists and also rejects duplicate forbidden paths. Unit
tests cover both cases. The full timer test must still pass on Flint 2 before
this incident is closed.

The next hardware run passed service selection, then stopped with
`route_smart-dns-primary_lacks_ipv4_proof`. The verification plan had assigned
each configured route a new IP-rule priority even when several routes shared
one mark and one table. The IP plan correctly deduplicated those routes into a
single kernel rule, so the Smart DNS proof looked for a rule that was never
supposed to exist. The same mismatch would also affect the second and later
VLESS outbounds. Proof generation now reuses the installed rule priority for a
shared mark/table pair. A regression test checks every non-drop proof against
the generated IPv4 rule set. Hardware confirmation is still required.

On the following run, the candidate reached `awaiting_confirmation` and passed
its bound Smart DNS proof. After about one minute, one loopback API poll failed
with `Recv failure: Connection reset by peer`. SSH, the controller PID, the
watchdog and `/api/v1/health` remained available; no controller restart was
recorded. The runner treated that single transport error as fatal and its
cleanup requested an early rollback, so the 180-second timer was not actually
tested. Polling now tolerates up to four consecutive transient failures, counts
them in the evidence, and still fails closed on the fifth. The cause of the
single reset is not proven and is not being mislabeled as a controller crash.

The repeated run stayed in `awaiting_confirmation` for the configured 180
seconds and then expired safely. It restored the exact committed config and
runtime binding digests; Direct, Zapret and VLESS bound probes all passed after
rollback. A separate confirmed ChangeSet then activated both production Smart
DNS routes. Both Smart DNS path proofs and the three existing route proofs
passed after commit. This closes the timer and Smart DNS activation parts of
the incident; the isolated loopback reset remains unexplained but did not recur.

## 2026-07-19 08:08–08:13 +07 — backup metadata existed without a backup file

### What was tested

The state-corruption preflight checked whether Flint 2 had a restorable bbolt
backup before any destructive fault injection.

### What happened

The active database existed and was healthy, but the state backup directory had
no backup file. Maintenance can retain a recent `last_backup_at` value inside
the database after the corresponding file has disappeared. While that timestamp
is inside the configured interval, the old code skipped backup creation and
only ran pruning. A state-corruption test would therefore have had no local
recovery source.

### Fix and verification

Maintenance now verifies that at least one regular, non-symlink bbolt backup
exists and passes a full bbolt consistency check before trusting the timestamp.
If not, it creates a new backup immediately. Unit and race tests cover the
missing-file case. The fixed binary created a backup on Flint 2 and the router
verified it before fault injection.

## 2026-07-19 08:21–08:27 +07 — state rescue runner assumed `nohup`

### What was tested

The active bbolt database was deliberately damaged after a verified byte-for-byte
backup had been created. The test keeps the committed dataplane and managed Xray
and Zapret processes running, then requires autonomous state restoration before
checking Direct, Zapret, VLESS and Smart DNS again.

### What happened

The first run stopped after taking the backup because factory OpenWrt does not
ship `nohup`. The PowerShell emergency restore returned the verified database and
started the controller; routing tables 100/101/102 and managed providers stayed
present. The watchdog needed an explicit start after this failed setup run. A
second run proved that the autonomous rescue itself worked, but its local wrapper
was terminated before it could collect the final evidence bundle.

### Fix and verification

The rescue process now uses a redirected background shell without depending on
`nohup`. A complete repeated run detected the corrupted database, preserved the
committed dataplane, restored a backup with the expected SHA-256 digest, and
returned controller health plus watchdog supervision. Bound Direct, Zapret,
VLESS and Smart DNS probes all passed after recovery. Evidence is stored outside
the repository under the private Flint 2 hardware results.

## 2026-07-19 08:45–09:05 +07 — protocol matrix initially reused HTTPS evidence

### What was tested

The published 50-cell matrix was rerun with protocol-specific packets for DNS
over UDP/TCP, TCP/80, TCP/443 and UDP/443 instead of treating the protocol field
as descriptive metadata.

### What happened

The previous harness executed the same HTTPS route probe for every active cell.
The first strict run produced 8 PASS and 17 FAIL. Follow-up runs exposed four
test-contract errors: inherited route marks were not applied, VLESS traffic was
sent to its policy table instead of its SOCKS ingress, DROP expected a connected
IPv4 address even though its proof is dual-stack enforcement, and the TCP probe
stopped after the first resolved address. Zapret DNS also had no matching output
counter because LAN DNS is intercepted before Zapret classification; those two
Cartesian cells are not applicable by design.

### Fix and verification

Active cells now require a packet for their declared protocol plus bound route
evidence. Direct, Smart DNS, Zapret and DROP use their configured marks and exact
nft route counters. VLESS uses its route-bound SOCKS TCP/UDP ingress. TCP probes
try every resolved IPv4 target. A final Flint 2 run completed 23 applicable
cells with 23 PASS, 0 FAIL and 0 NOT_TESTED. The other 27 cells are explicit:
25 require unavailable WAN6 and two are pre-route Zapret DNS combinations. The
same run repeated the production Smart DNS and proxy-recursion release gates.
