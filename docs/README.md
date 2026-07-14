# docs/ — карта документации

> Соответствие коду на commit `4634515` (ветка `main`). Статус — по факту кода и
> железных доказательств, не по пожеланиям. Бренд конкретного VPN-провайдера
> убран; FlintRoute не привязан к одному поставщику подписки.

## Статус документов

| Документ | Статус | Назначение |
|---|---|---|
| `README.md` (корень) | **переписан** | обзор проекта, статус фаз под P6/P3, 4 уровня |
| `architecture.md` | **переписан** | плоскости, компоненты, 4 уровня, слои по графу |
| `algorithm-flow.md` | **переписан** | единый `probe_route`, 4 уровня, flowchart |
| `api.md` | **переписан** | endpoints, recovery, 4 уровня |
| `adapter-transaction.md` | **переписан** | `adapter.Interface`, `RecoveryTarget`, P6 recovery, 4 уровня |
| `probe-route.md` | **переписан** | `probe.RouteResult`, 4 уровня, route descriptor, drop |
| `tspu-cache.md` | **переписан** | `tspu.Cache` v2, multi-source, ETag/drop-ratio, wildcard, SHA-256 |
| `vpn-subscription.md` | **новый** (вместо `vpnsub-xray.md`) | VPN-провайдер, подписка/ключ, список VPN-серверов, Xray pipeline, 4 уровня |
| `testing.md` | **переписан** | P0/P0.5/P3/P6/API тесты по факту |
| `implementation-plan.md` | **переписан с 0** | что реализовано (P1/P3/P6), 4 уровня, что не сделано (P12/P13) |
| `domain-flow.md` | **переписан** | поток домена, 4 уровня, привязка к трафику, IPv6/QUIC |
| `failure-model.md` | **переписан** | health cycle, recovery, 4 уровня при отказе, повреждённая подписка |
| `status-matrix.md` | **переписан** | matrix + P6 recovery строка + hard blockers |
| `tspu-sources.md` | **переписан** | источники, `config.TSPUSource`, update pipeline, форматы |
| `web-ui.md` | **переписан** | Aegis Console, экраны, API-контракт, безопасность |
| `flint2-hardware-report.md` | **новый** | обезличенный отчёт: commit, прошивка, P1/P3/P6 результаты |
| `flint2-hardware-validation.md` | план (P13) | дизайн full hardware matrix; не отчёт |
| `flint2-diagnostics.md` | актуален | Phase 0 read-only diagnostics |
| `headless-dataplane.md` | актуален | managed Xray TPROXY + Zapret/nfqws lifecycle (P3.1) |
| `adaptive-zapret-strategy.md` | дизайн (P12) | bounded catalog, ranking, hysteresis; код не начат |

## Приоритет чтения

1. `implementation-plan.md` — текущий статус и что не сделано.
2. `algorithm-flow.md` + `probe-route.md` — алгоритм и 4 уровня.
3. `adapter-transaction.md` — транзакция и recovery.
4. `flint2-hardware-report.md` — что реально доказано на железе.
5. `api.md` — контрольная плоскость.
6. `vpn-subscription.md` — VPN-провайдер и Xray.

## Правило правды

Если документ расходится с кодом — прав код. Железные факты — в
`flint2-hardware-report.md`, не в предположениях.