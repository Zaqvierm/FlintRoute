# Документация FlintRoute

FlintRoute не привязан к конкретному поставщику VPN-подписки. Документация
разделяет реализованные контракты, аппаратные доказательства и ещё не закрытые
критерии приёмки.

## Карта документов

| Документ | Назначение |
|---|---|
| `architecture.md` | плоскости, компоненты, границы и ключевые инварианты |
| `algorithm-flow.md` | алгоритм выбора, проверки и применения маршрута |
| `domain-flow.md` | путь DNS-имени до nftables и policy routing |
| `failure-model.md` | отказоустойчивость, fail-closed правила и recovery |
| `adapter-transaction.md` | транзакционный контракт OpenWrt adapter |
| `probe-route.md` | единый probe contract и route proof |
| `api.md` | локальный management API и ChangeSet lifecycle |
| `vpn-subscription.md` | безопасная обработка подписки и Xray bundle |
| `headless-dataplane.md` | managed Xray TPROXY и Zapret/nfqws lifecycle |
| `tspu-cache.md` | формат и lifecycle локального TSPU cache |
| `tspu-sources.md` | источники, валидация и применение списков |
| `adaptive-zapret-strategy.md` | bounded catalog, ranking, hysteresis и quarantine |
| `flint2-diagnostics.md` | read-only диагностика GL-MT6000 |
| `flint2-hardware-report.md` | обезличенные аппаратные результаты и ограничения |
| `flint2-hardware-validation.md` | полная аппаратная матрица приёмки |
| `incidents.md` | аппаратные инциденты и дефекты validation gates |
| `testing.md` | автоматизированные проверки и непокрытые hardware gates |
| `installation.md` | сборка пакета, установка, обновление и удаление на OpenWrt |
| `status-matrix.md` | подтверждённое состояние подсистем |
| `implementation-plan.md` | оставшиеся этапы реализации и критерии завершения |
| `web-ui.md` | web console и её API/security contract |

## Приоритет чтения

1. `architecture.md` — границы системы и основные инварианты.
2. `algorithm-flow.md` + `probe-route.md` — алгоритм и четыре уровня proof.
3. `adapter-transaction.md` — транзакция, rollback и recovery.
4. `flint2-hardware-report.md` — подтверждённое состояние на железе.
5. `api.md` — контрольная плоскость.
6. `vpn-subscription.md` — VPN-провайдер и Xray.

## Правило правды

Если описание расходится с реализацией, поведение определяют код и тесты.
Аппаратные утверждения считаются подтверждёнными только при наличии записи в
`flint2-hardware-report.md` и соответствующего критерия проверки.
