# Flint 2 hardware validation — 2026-08-30

This is the current hardware evidence index for the remediation branch. It
supersedes older prose that described Flint 2 as untouched; older evidence is
historical and must be treated as stale when its SHA differs.

## Binding

- Repository branch: `integration/discovery-smartdns-local-dod`
- Software HEAD: `29e276c43855e95be8ccf575a35caaa95f344422`
- Device: GL.iNet GL-MT6000, OpenWrt 24.10.4, kernel 6.6.110, aarch64
- Installed package SHA-256:
  `773a78ce21ff3ab36ae63a2026ad1284416a7e87cf2cfacd147473bfca573612`
- Redacted raw evidence (outside git):
  `H:\LAN\Internal\Context\hardware-evidence\20260830-stage11-final\`

## PASS evidence

- Critical OpenWrt parent directories remained `0755` through installation,
  rollback attempts, service restarts and cold reboot.
- Controller runs as `daemon`; root helper is reached only through its fixed
  Unix socket, which is `0600` and owned by the declared peer UID.
- bbolt, adapter metadata and dataplane stayed on one committed revision,
  candidate hash and artifact manifest binding.
- Boot guard logged `armed` before controller startup and disappeared only
  after generation-bound reconcile; unclassified forwarding was fenced while
  the guard was active.
- Exactly one project-owned queue-200 nfqws survived controller/helper crash
  canaries and reboot; no Xray process was created.
- dnsmasq interception counters grew, observer logging received live queries,
  and the log was readable by the daemon controller.
- Post-reboot controller health was HTTP 200 with `status=ok` and
  `recovery_status=ok`; idle FD/thread/CPU samples stayed bounded.

## Explicit limitations

The committed inventory contains no Xray service/config. Therefore VLESS,
Happ/crypt4, HWID and VLESS-egress end-to-end hardware claims remain
`OPEN-HW`/`BLOCKED ON INVENTORY`; no false PASS is claimed. Linux namespace and
procfs tests are CI PASS but are `NOT RUN LOCALLY` on Windows. Adding Xray or a
subscription requires a fresh backup, reviewed ChangeSet and a separate
hardware gate.
