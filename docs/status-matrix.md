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
| P3 | 85% | nft/dnsmasq/Xray/Zapret/IP plan и проверка Zapret на железе |
| P4 | 0% | Telegram notifications и tg-ws-proxy |
| P5 | 85% | Production OpenWrt provider и API |
| P6 | 55% | Post-reboot recovery и boot guard |
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
| IP route then IP rule fixed-argument plan | yes | unit + shell integration + Flint Direct proof | no for Direct; other routes remain |
| Missing/simulated network diagnostics fail closed | yes | unit + API + shell integration + Flint diagnostics | no |
| Adapter dependency injection | yes | unit/integration | no |
| Fake production apply/verify/commit | yes | integration + race | no |
| Filesystem adapter fail-closed (SKIPPED/UNVERIFIED/requires_device) | yes | unit/integration | no |
| Confirm calls adapter Commit | yes | integration | no |
| Rollback and automatic rollback call adapter | yes | integration | no |
| Expiry timer and restart recovery (in-flight ChangeSet) | yes | integration + race | no |
| **Post-reboot recovery: committed dataplane via `Reconcile`** | yes | unit + integration | **физ reboot = P13** |
| Idempotent Go/shell rollback and stale timer protection | yes | API + shell integration + race | reboot/crash matrix |
| Concurrent apply/action locking with lock cleanup | yes | integration + race | no |
| bbolt schema/retention/backup pruning/active compaction recovery | yes | unit | no |
| SSE stream epoch and long-lived response | yes | unit/API | no |
| Production OpenWrt fixed-command exec adapter | yes | unit + mocked shell integration + Flint apply/rollback/commit | remaining route types |
| Unified helper lock with stale-owner proof | yes | shell integration + ShellCheck + Flint transactions | reboot/crash matrix |
| Snapshot hash and absent-marker enforcement | yes | shell integration + Flint rollback | reboot/crash matrix |
| config/nft/dnsmasq/Xray/Zapret/active-revision rollback restore | yes | shell integration + Flint rollback with live Xray hash preservation | real Xray activation/rollback |
| Managed Xray TPROXY procd lifecycle | yes | unit + shell integration | persistent activation and route proof |
| Managed Zapret/nfqws lifecycle, fixed preset, NFQUEUE fail-closed | yes | unit + shell integration + Flint nfqws dry-run/nft syntax + Zapret `discord.com` committed | full matrix |
| Flow offloading preserve/disable transaction | yes | unit + shell integration | Flint UCI layout |
| VPN-подписка: extract/dedup/classify/retag/bundle | yes | unit + live subscription (12 supported) | per-exit persistent proof |
| VLESS health cycle (quorum, EWMA, roles) | yes | unit + race + live | persistent selected route |
| Proxy endpoint recursion guard | no | no | required before persistent VLESS activation |
| TSPU cache v2 (multi-source, ETag, drop-ratio, wildcard, SHA-256) | yes | unit + httptest | live source quality |
| GeoIP MMDB + two-source consensus | yes | unit + live | no |
| Domain decision cache (bounded LRU, revision-bound, TTL) | yes | unit | no |
| Installer atomic backup validation | yes | shell integration | yes |
| Full local suite | yes | `run-all.ps1` | no |
| Full Go race suite | yes | `go test -race ./...` | no |

## Current hard blockers

- Minimal Direct + fail-closed Drop proven on Flint 2 (committed): real nft
  counter movement, mark/rule/table/conntrack evidence, DNS/IPv6 leak checks.
- Zapret `discord.com` proven and committed: NFQUEUE counter, HTTP 200,
  `path_verified=true`. Smart DNS and VLESS/Xray persistent activation are NOT
  yet applied/proved on Flint. Live Xray was hash-preserved during Direct/Drop
  and Zapret transactions.
- Post-reboot recovery (`Reconcile`) implemented and locally tested; physical
  reboot on Flint 2 is a P13 gate.
- Reboot/crash matrix, timer firing under lost management, multi-client and
  production install/upgrade/downgrade still need hardware runs.
- Transparent routing and final leak-prevention across every route type remain
  part of P3/P13 hardware matrix.
- VLESS endpoint addresses must bypass transparent classification to prevent a
  tunnel from being routed into itself. This guard is not yet implemented.
