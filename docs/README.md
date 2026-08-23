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
| `component-manager.md` | установка, update/rollback внешних компонентов и калибровка |
| `headless-dataplane.md` | managed Xray TPROXY и Zapret/nfqws lifecycle |
| `tspu-cache.md` | формат и lifecycle локального TSPU cache |
| `storage-lifecycle.md` | ownership manifests, stale cleanup, retention и write budget |
| `network-platform-audit.md` | сетевой hardcode, runtime discovery и карта зависимостей GL.iNet/OpenWrt |
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
| `documentation-status.md` | сверка каждого документа с кодом, SHA и уровнем evidence |

## Приоритет чтения

1. `architecture.md` — границы системы и основные инварианты.
2. `algorithm-flow.md` + `probe-route.md` — алгоритм и четыре уровня proof.
3. `adapter-transaction.md` — транзакция, rollback и recovery.
4. `storage-lifecycle.md` — владение ресурсами и ресурс записи.
5. `documentation-status.md` — сначала проверить актуальность и уровень evidence.
6. `flint2-hardware-report.md` — только историческое аппаратное состояние; для
   текущего SHA читать с пометкой `STALE`.
7. `api.md` — контрольная плоскость.
8. `vpn-subscription.md` — VPN-провайдер и Xray.

## Правило правды

Если описание расходится с реализацией, поведение определяют код и тесты.
Аппаратные утверждения считаются подтверждёнными только при наличии записи в
`flint2-hardware-report.md` и соответствующего критерия проверки.
