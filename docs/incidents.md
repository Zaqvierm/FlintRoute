# Hardware incidents and validation defects

This log records failures that affected hardware validation or could have made a
release claim unreliable. It contains no credentials, private endpoints or raw
device dumps.

## 2026-08-17 — startup recovery exceeded the installer health window

### What happened

During an upgrade the new controller entered committed-dataplane recovery before
opening its HTTP listener. The installer allowed only 20 health attempts, timed
out while recovery was still running and started file rollback before the new
process had reached a stable service state. Management later became unavailable
and the router required factory recovery through U-Boot.

The blocking startup path and the too-short health window are confirmed defects.
The loss of router-local Wi-Fi, DHCP and management is not attributed to either
defect as a proven root cause because volatile OpenWrt evidence was unavailable
after access was lost.

### Fix and verification boundary

Production startup now opens the HTTP control plane first and runs committed
recovery in a tracked, bounded background task. Health reports `starting` until
reconcile finishes, and policy schedulers start only after recovery succeeds.
The installer health window is 120 seconds and still requires `status=ok`, the
expected active revision and a non-error recovery result before disarming
rollback.

Unit and full local gates cover a deliberately blocked reconcile while the
health endpoint remains responsive. A clean install on factory OpenWrt created
one baseline revision and started the controller successfully. The original
in-place upgrade with a committed dataplane has not yet been repeated on
hardware, so unattended upgrade remains unconfirmed.

## 2026-08-17 — clean baseline had no DNS observation source

### What happened

The clean-install baseline correctly avoided a dataplane apply, but DNS query
logging was bundled only with generated dataplane artifacts. Discovery started
in `observe_only` and watched its runtime file, while dnsmasq had no matching
`log-facility`; no observation file existed and new domains could not enter the
decision pipeline.

### Fix and verification boundary

The control-plane service now installs an observation-only dnsmasq include when
no committed include exists. It enables query logging to tmpfs but contains no
domain server rules, marks, nftables state, routes or flow-offloading changes.
The helper rejects symlink targets, validates the include before installation,
restarts dnsmasq only when the bootstrap file is first created and never
overwrites an existing managed include. Local shell and full integration gates
cover creation, idempotence and preservation of managed content. Hardware proof
requires a LAN-client query to appear in Discovery after the updated package is
installed.

## 2026-08-01 — upgrade rewrote a committed legacy route in memory

### What was tested

An in-place control-plane upgrade was run against a verified committed revision.
No new ChangeSet or dataplane candidate was requested. A checked off-router
backup and an installation rollback snapshot existed before the upgrade.

### What happened

The new controller started but `/api/v1/health` reported `degraded` with
`active_config_mismatch`. The installer treated the successful HTTP request as
healthy, disarmed its rollback and returned success. A later manual file restore
could not verify procd services because ubus stopped accepting clients. After a
reboot the device did not return Wi-Fi, DHCP or management access, so factory
recovery through U-Boot was required.

Offline inspection of the pre-upgrade bbolt database proved the first failure.
The stored active config and revision candidate had the same SHA-256 digest and
contained the legacy `tg_ws_proxy` route name. The upgraded validator silently
rewrote that value to `external_socks` after the persisted digest had already
been checked. Startup recovery then re-serialized the changed in-memory value,
compared it with the immutable committed digest and rejected its own revision.

The later ubus/procd failure is recorded separately as an unresolved symptom.
The volatile evidence needed to identify its kernel or service-manager trigger
was unavailable after management access was lost. The boot guard's previous
unconditional forwarding drop explains an Internet outage during recovery, but
does not explain loss of Wi-Fi, DHCP or router-local SSH and is not presented as
the root cause of those symptoms.

### Fix and verification

Legacy route names are now accepted as compatibility aliases without mutating
the serialized committed config. Migration to `external_socks` requires a new
explicit ChangeSet. A restart regression commits a legacy-shaped config and
verifies that its digest, revision and reconcile result remain unchanged.

Installer health validation now requires `status=ok`, non-error recovery, a
non-empty active revision and, during upgrade, the same revision observed by
preflight. The controller and watchdog are stopped under a maintenance lease
before the state database is copied. Automatic rollback refuses to replace any
file while a managed controller process may still be running, and restores the
verified pre-upgrade database before restarting the previous controller.

The boot guard no longer drops every forwarded packet. It blocks only traffic
carrying configured FlintRoute marks, leaving unclassified OpenWrt forwarding
and the management plane outside that temporary guard. Unit, race, installer,
shell integration, frontend, package and secret-scan gates pass locally. The
hardware upgrade/reboot claim must be renewed with evidence from the fixed
revision before unattended upgrade is considered verified again.

The fixed revision was subsequently installed on a freshly recovered Flint 2.
Installation created one safe baseline revision without Xray, Zapret, nftables
or policy-routing resources. The system default route, DNS, SSH and the router
administration page remained available. A controlled reboot preserved the same
active revision and restored the controller, watchdog and source-restricted Web
listener. This renews the clean-install and baseline-reboot result for the fixed
revision. It does not renew an in-place upgrade from the legacy committed state;
that exact hardware scenario remains blocked until it can be replayed without
restoring old production state onto the recovered router.

## 2026-07-27 — external listener rollback was not armed

### What was tested

The Web API listener was moved from loopback to an explicitly enabled wildcard
bind, protected by a source-restricted firewall rule. A verified off-router
backup and external SSH/web monitoring were available before the change.

### What happened

The helper attempted to arm its bounded rollback with `nohup`. Factory OpenWrt
does not ship that command, so the rollback process never started. The listener
and firewall change itself succeeded, SSH remained available and the following
physical power-loss test recovered the same committed revision, but the planned
rollback guarantee was absent during the apply window.

### Fix and release impact

The public service keeps loopback as its default and requires an explicit
`allow_firewalled_bind=1` opt-in for non-loopback addresses. The supported
recovery procedure starts a redirected background shell available in BusyBox
and verifies its PID before applying a network change; missing rollback
capability is a failed preflight, not a warning. The successful listener result
is retained, but the failed helper invocation is not counted as rollback proof.

## 2026-07-27 — factory adapter dependency and recovery lost management

### What was tested

A clean Flint 2 baseline had no active revision, provider process or FlintRoute
nft/IP resource. The next test attempted to restore the previously verified
production configuration and activate Xray, Zapret and the committed dataplane
through the normal ChangeSet transaction. A verified off-router recovery
archive and an independent 30-minute rollback process were prepared first.

### What happened

Candidate validation completed, but adapter `prepare` returned exit code 127.
Automatic rollback returned the same code. The adapter still used external GNU
`stat` to verify its rollback capability and file modes; factory OpenWrt does
not provide that binary. The failure happened before `apply-candidate`, and the
captured baseline confirmed that FlintRoute nftables, policy rules and provider
services had not been activated.

The independent recovery script then restored the captured project files and
service state. It also removed the temporarily installed Xray package, reloaded
the global firewall and restarted dnsmasq. The script completed, but new SSH,
web and ICMP checks to the WAN-side management address stopped succeeding.
After a physical power cycle the router did not return Wi-Fi, DHCP or management
access and appeared to restart repeatedly. Recovery therefore required another
factory reflash through U-Boot.

The failed adapter dependency is proven. The recovery procedure also exceeded a
safe project-owned rollback boundary: it performed package and global firewall
operations without a separately proven management path. The exact persistent
cause of the later restart loop is not proven because kernel, procd and overlay
evidence became unavailable with the device. The pre-test archive contains the
same factory firewall and DHCP hashes as the earlier recovery baseline, no
`last-good` snapshot and no unfinished transaction, so those files alone do not
explain the restart loop.

### Fix and release impact

The adapter now obtains regular-file mode and owner data with factory BusyBox
`ls`/`awk`; an integration fixture makes any external `stat` invocation fail
with code 127.

After the factory reflash, a fresh read-only baseline and off-router recovery
archive were captured before retrying the same transaction path. The corrected
adapter completed prepare, validate, apply, route verification and commit on
factory OpenWrt. Managed Xray and nfqws then passed restart and SIGKILL recovery,
the controller passed restart, and 11 Direct, Zapret, VLESS and Drop route
proofs completed while external SSH and web management remained available.
At that point the idle write observation and rollback/downgrade/uninstall gates
remained separate P14 checks; the later P14 lifecycle tail closed them.

## 2026-07-27 — uninstall DNS readiness race

### What was tested

The lifecycle tail expired a real rollback timer, restored the committed
revision, performed a compatible downgrade and returned to the current package.
It then removed FlintRoute while an external monitor checked SSH and web
management.

### What happened

Project processes, nftables, policy routing and runtime files were removed, and
the persistent flow-offloading baseline was restored. The first post-uninstall
DNS check failed because it ran immediately after `dnsmasq restart`. DNS became
available seconds later; SSH and web management remained continuously
available.

### Fix and verification

Uninstall now waits up to 30 seconds for both the dnsmasq PID and a successful
loopback lookup. A local lifecycle test forces two failed lookups before
readiness. The repeated Flint 2 uninstall returned only after DNS was usable,
kept the backup registry within 2 operations / 128 MiB, and was followed by a
successful reinstall and committed-dataplane reconcile.

## 2026-07-22 — failed P14 upgrade left procd/ubus unavailable

### What was tested

An in-place P14 package upgrade was attempted over the previously verified
FlintRoute installation. No candidate configuration or new dataplane revision
was applied. A verified external recovery archive and a bounded file-rollback
timer were prepared before the upgrade.

### What happened

The first package revision called a maintenance command that the installed
older binary did not support. The installer entered its automatic file and
service rollback path and printed `install_rollback=restored`.

Before the second attempt changed any files, its diagnostic step already
reported that `ubus` was unavailable. The installer treated that failure as
non-fatal and continued. Subsequent procd service operations failed, while the
rollback path suppressed service restoration errors and again printed a
successful restoration message. A file-only recovery snapshot was restored and
the device was rebooted, but it did not return to the network. Recovery required
reflashing the factory image through U-Boot.

The pre-upgrade baseline showed about 5.3 GiB free on the overlay, so storage
exhaustion is ruled out. The confirmed defects are the missing procd/ubus
preflight gate, a rollback result that did not reflect service restoration
failures, unsafe restoration order around the legacy watchdog, and a boot-guard
stop action that did not remove its forwarding guard. The final on-device cause
of the ubus failure cannot be proven because management access and volatile logs
were lost.

### Release impact

Hardware install, upgrade, rollback, reboot recovery and P14 lifecycle claims
are blocked. No further production-device mutation is allowed until the local
fault tests cover an unavailable ubus socket, partial service restoration,
legacy watchdog startup, boot-guard cleanup and repeated rollback.

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
required `ProxyFlowProcessed`. That field belongs to the `external_socks` proof
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

## 2026-07-19 09:35–10:30 +07 — scoped Zapret profiles lost pre-SNI setup

### What was tested

The adaptive acceptance run enabled a bundle-scoped nfqws profile, switched to
a challenger, exercised cooldown and pin behavior, and required every ChangeSet
to pass the normal data-plane proof before commit.

### What happened

The first candidate reached nfqws but the Discord proof stalled until the
180-second transaction timer rolled it back. An isolated run reproduced the
failure in 248 seconds. nfqws debug output showed that the initial packets used
its empty fallback profile; only after TLS SNI was decoded did the
`discord.com` hostlist select the intended profile. The static strategy depends
on `orig-*` connection setup before SNI exists, so copying that strategy into a
host-scoped profile changed its behavior even though the hostlist match itself
was correct.

### Fix and verification

Adaptive rendering now derives a common pre-hostname bootstrap from the selected
profiles, rejects conflicting bootstrap options across bundles, and appends one
unscoped hard-filter fallback after the scoped profiles. The scoped Flint 2
probe completed in nine seconds, compared with the previous timeout. A complete
acceptance run then passed active-profile degradation, transactional challenger
switching, safe-fallback pinning, cooldown, corrupted-challenger quarantine,
reselection blocking, static baseline restoration and Direct/Zapret/VLESS route
proofs. Automatic production scheduling and live ranking remain a separate
P13.2 requirement and are not claimed by this result.

## 2026-08-09 — upgrade stopped on a second procd delete

An upgrade from an already running installation stopped after copying the new
control-plane files. The installer had intentionally stopped `router-policy`,
then called the new init script with `restart`. On the tested OpenWrt build that
issued a second `ubus service delete` for an already absent service and returned
`Not found`. The controller was healthy after procd respawn, but the installer
reported failure, left maintenance active and did not restart the watchdog.

The recovery path ended maintenance and started the watchdog only after local
health, active revision, recovery state, ubus and SSH were rechecked. No route,
nftables or DNS candidate was applied, and the committed revision did not
change.

The installer now starts services that it deliberately stopped instead of
restarting them. Rollback also skips `stop` for an already inactive control
service and accepts a boot-guard stop error only when the owned nft table is
already absent. A repeated hardware run also exposed that procd can report an
instance as running briefly after a successful `stop`; the installer now waits
up to a bounded 15 seconds for the instance to disappear instead of treating the
first status sample as final. Installer lifecycle tests cover delayed stop and
assert controller health before the watchdog is started.

## 2026-08-09 — dnsmasq failed during a control-plane settings change

A hardware run that changed Discovery settings entered the full ChangeSet path.
The candidate dnsmasq configuration enabled query observations at
`/tmp/router-policy/dns-observations.log`, but that runtime path was not present
when dnsmasq restarted. OpenWrt logged `cannot open log ... No such file or
directory`; the adapter reported `dnsmasq_not_ready` and the transaction rolled
back.

Two defects were involved:

- Discovery mode and rate limits were incorrectly treated as data-plane config,
  so a control-plane setting restarted firewall and DNS;
- the adapter did not prepare and validate the observation log immediately
  before every dnsmasq restart.

Discovery settings now persist through a dedicated control-plane state update
without a ChangeSet. The adapter creates only the allowlisted regular runtime
log, rejects symlink or out-of-runtime targets, and runs the same preparation
for apply, rollback and recovery. The OpenWrt adapter integration test removes
the assumption that the observation file already exists. Hardware confirmation
belongs to the next installation run; this entry does not claim it in advance.

## 2026-08-17 — DNS observer restarted DHCP/DNS late during boot

A controlled reboot returned SSH and the FlintRoute HTTP listener, but that
check did not prove that LAN clients had Wi-Fi, DHCP and working forwarding.
The initial report that the router was unreachable was later withdrawn. The
read-only post-boot inventory showed both access points enabled, LAN and WAN up,
the system default route intact and dnsmasq running.

The boot log still confirmed an unsafe sequence. `/etc/rc.d/S95router-policy`
created the observation include after Wi-Fi was already enabled, sent SIGTERM
to dnsmasq and restarted it. Because the include lives in a tmpfs confdir, this
happened on every reboot and created a needless DHCP/DNS outage window. No
dataplane transaction or route change was involved.

DNS observation bootstrap now has its own one-shot init service at S18, before
the normal dnsmasq startup. The control-plane service no longer invokes it.
Normal boot never restarts dnsmasq; only an explicit first live activation may
request one bounded restart, followed by a DNS readiness check. Bootstrap and
installer lifecycle tests cover the no-restart boot path. Hardware verification
of this new ordering is still pending and must include a real LAN client, not
only SSH or the control-plane health endpoint.
