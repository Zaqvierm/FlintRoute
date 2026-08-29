# Changelog

## 0.2.0-alpha.4 — 2026-08-29

Development alpha snapshot for the `integration/discovery-smartdns-local-dod`
branch. This entry records software changes only; it does not claim Flint 2
installation, reboot, or dataplane validation.

- Hardened privileged-helper lifecycle ordering during install, restart, and
  rollback.
- Added a typed, read-only empty-IP-state proof before unbound uninstall can
  report a verified-empty dataplane.
- Rebound safety evidence and status documentation to the current code tree.
- Kept Linux namespace and hardware evidence explicitly separate from local
  Windows results and CI.

The exact source SHA and CI run IDs for each checkpoint are recorded in
`docs/remediation-evidence.md` and the external per-item ledger.
