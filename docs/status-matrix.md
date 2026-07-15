# Status Matrix

> Матрица разделяет реализацию, локальную проверку и аппаратное подтверждение.

## Фазы

Процент показывает готовность по критериям конкретной фазы. Это не оценка всего
проекта и не обещание релизной готовности.

| Фаза | Готовность | Коротко |
|---|---:|---|
| P0 | 100% | Transaction state machine, bbolt и adapter |
| P0.5 | 100% | Candidate-bound артефакты и shell adapter |
| P1 | 100% | Route proof, Smart DNS, VPN/Xray, VLESS health и GeoIP |
| P2 | 75% | TSPU cache, eTLD+1 и domain profiling |
| P3 | 100% | Headless Direct/Zapret/Drop/VLESS dataplane доказан на Flint 2 |
| P4 | 0% | Telegram notifications и tg-ws-proxy |
| P5 | 85% | Production OpenWrt provider и API |
| P6 | 100% | Persistent state и post-reboot recovery доказаны на Flint 2 |
| P7 | 60% | Auth и security audit |
| P8 | 15% | Встроенная Web UI |
| P9 | 40% | Loopback и доступ к панели из LAN |
| P10 | 30% | Сборка, установщик и упаковка |
| P11 | 85% | Автоматические тесты |
| P12 | 10% | Адаптивный выбор стратегии Zapret |
| P13 | 35% | Полная аппаратная матрица и fault injection |

| Area | Implemented | Tested locally | Needs Flint 2 |
|---|---:|---:|---:|
| Full canonical candidate + real diff/hash | yes | integration | no |
| Candidate -> nft/dnsmasq/Xray/nfqws/IP artifacts + manifest v6 binding | yes | unit + shell integration | no |
| IP route then IP rule fixed-argument plan | yes | unit + shell integration + Flint Direct/Zapret/VLESS/Drop proof | no for active route set |
| Missing/simulated network diagnostics fail closed | yes | unit + API + shell integration + Flint diagnostics | no |
| Adapter dependency injection | yes | unit/integration | no |
| Fake production apply/verify/commit | yes | integration + race | no |
| Filesystem adapter fail-closed (SKIPPED/UNVERIFIED/requires_device) | yes | unit/integration | no |
| Confirm calls adapter Commit | yes | integration | no |
| Rollback and automatic rollback call adapter | yes | integration | no |
| Expiry timer and restart recovery (in-flight ChangeSet) | yes | integration + race | no |
| **Post-reboot recovery: committed dataplane via `Reconcile`** | yes | unit + integration + physical Flint 2 reboot | no |
| Idempotent Go/shell rollback and stale timer protection | yes | API + shell integration + race | reboot/crash matrix |
| Concurrent apply/action locking with lock cleanup | yes | integration + race | no |
| bbolt schema/retention/backup pruning/active compaction recovery | yes | unit | no |
| SSE stream epoch and long-lived response | yes | unit/API | no |
| Production OpenWrt fixed-command exec adapter | yes | unit + mocked shell integration + Flint apply/rollback/commit | remaining route types |
| Unified helper lock with stale-owner proof | yes | shell integration + ShellCheck + Flint transactions | reboot/crash matrix |
| Snapshot hash and absent-marker enforcement | yes | shell integration + Flint rollback | reboot/crash matrix |
| config/nft/dnsmasq/Xray/Zapret/active-revision rollback restore | yes | shell integration + Flint rollback with live Xray hash preservation | real Xray activation/rollback |
| Managed Xray TPROXY procd lifecycle | yes | unit + shell integration + persistent Flint VLESS proof | broader exit/protocol matrix |
| Managed Zapret/nfqws lifecycle, fixed preset, NFQUEUE fail-closed | yes | unit + shell integration + Flint nfqws dry-run/nft syntax + Zapret `discord.com` committed | full matrix |
| Flow offloading preserve/disable transaction | yes | unit + shell integration + Flint UCI 1/1 -> 0/0 | no |
| VPN-подписка: extract/dedup/classify/retag/bundle | yes | unit + live subscription (12 supported) | per-exit persistent proof |
| VLESS health cycle (quorum, EWMA, roles) | yes | unit + race + live | persistent selected route |
| Proxy endpoint recursion guard | no | no | required before persistent VLESS activation |
| TSPU cache v2 (multi-source, ETag, drop-ratio, wildcard, SHA-256) | yes | unit + httptest | live source quality |
| GeoIP MMDB + two-source consensus | yes | unit + live | no |
| Domain decision cache (bounded LRU, revision-bound, TTL) | yes | unit | no |
| Installer atomic backup validation | yes | shell integration | yes |
| Full local suite | yes | `run-all.ps1` | no |
| Full Go race suite | yes | `go test -race ./...` | no |

## Remaining hardware gates

- Direct, Zapret, fail-closed Drop and VLESS/Xray are committed and proved on
  Flint 2. A fresh bound evidence run after physical reboot also passed strict
  verification; DNS, IPv6 and geo kill-switch report flags are true.
- Post-reboot recovery is proved with state under `/etc/router-policy/state`,
  no `/var/lib/router-policy` compatibility alias, and automatic restoration of
  controller, Xray, nfqws, nftables and IPv4/IPv6 policy rules.
- Reboot/crash matrix, timer firing under lost management, multi-client and
  production install/upgrade/downgrade still need hardware runs.
- Smart DNS still needs a real production resolver. The broader route ×
  protocol × address-family matrix remains part of P13.
