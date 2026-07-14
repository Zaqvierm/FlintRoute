# Модель отказов

> Соответствует `internal/health/service.go`, `internal/probe/health.go`,
> `internal/adapter`, `internal/api/recovery.go` на commit `4634515`.

## Базовые правила

- Одна ошибка не переключает маршрут (hysteresis).
- `fail_after_consecutive_errors` (default 3) — путь признаётся неисправным.
- `recover_after_consecutive_successes` (default 5) — путь восстанавливается.
- `route_hold_seconds` — удержание от дёрганья.
- Любое применение — через транзакцию с rollback.
- Параллельные запуски — per-ChangeSet action locks + global transaction lock.
- `path_verified=false` → маршрут не production, даже при HTTP 200.

## Health cycle (`health.Service.RunCycle`)

- bounded parallelism (`policy.parallel_server_checks`, ≤16);
- control quorum: ≥2 control-сервисов, majority OK;
- consensus по `adapter_revision`/`candidate_hash`/`manifest_hash`/`country`/`ip_hash`
  — расхождение → `health_evidence_consensus_mismatch`;
- `probe.HealthTracker`: EWMA latency, failure/recovery hysteresis, quarantine;
- `AssignVLESSRoles`: `selected`/`standby`/`quarantine`;
- bbolt persistence + API `/api/v1/route-health`.

`safeHealthResult`: route tag/type match, `OK` + `path_verified` + `service_ok` +
`egress_consensus` + non-empty bindings + country ≠ RU/UNKNOWN.

## Если путь умер

| Категория | Цепочка | Запрещено |
|---|---|---|
| `GEO_LOCKED` | smart_dns → VLESS (non-RU) → DROP | direct, Zapret, RU egress |
| `TELEGRAM` | tg_ws_proxy → VLESS → DROP | ненадёжный прямой выход |
| `TSPU_RESTRICTED` | zapret → smart_dns → VLESS → DROP | небезопасный direct |
| `DIRECT_ONLY` | только direct; при отказе — ошибка, не VLESS | зарубежный proxy |
| `DIRECT_PREFERRED` | direct → zapret → smart_dns → VLESS | глобальный VLESS |
| `BLOCKED` | DROP | любой обход |

## Четыре уровня при отказе

Отказ определяется per-уровнем, не одной суммой:

1. **DNS** — resolver timeout, poisoned answer, empty → `dns_failed`.
2. **Классификация** — regional block, TSPU marker → `REGION_BLOCK`/`SUSPECTED_TSPU`.
3. **Фактический egress** — RU exit для `GEO_LOCKED` → `RU_EXIT`; unknown country → `FAIL`.
4. **Доказательство маршрута** — missing mark/rule/table/outbound → `UNVERIFIED`.

Hard failure (утечка, MITM, неверный outbound, мёртвый процесс) немедленно
исключает профиль. Обычная деградация — streak-based.

## Повреждённая VPN-подписка

Не применять, если: HTTP ≠ 200, ответ > `policy.max_subscription_bytes`, битый
JSON, нет `.outbounds`, нет VLESS, нет обязательных полей, `xray run -test`
падает, supported = 0. Действие: оставить last-good bundle, записать событие,
уведомление в очередь. См. `vpn-subscription.md`.

## Повреждённый TSPU-список

Не применять, если: список пустой, слишком мал/велик, мусорный синтаксис, число
записей резко просело (`drop_ratio > max_drop_ratio`), источник вернул
HTML/капчу/non-200. `retainPrevious` сохраняет прошлый кеш. Ручные правила выше
внешних списков. См. `tspu-cache.md`.

## Recovery (P6)

При старте `recoverCommittedDataplane` восстанавливает committed dataplane через
`adapter.Reconcile`. In-flight ChangeSet — через `recoverTransactions`. Любое
расхождение bindings → `failedRecovery` с `reason_code`, management остаётся
доступен в degraded state. Crash mid-transaction → rollback или безопасный DROP.

## Уведомления

Событие: id, тип, сервис, first/last seen, count, last status, recovery flag.
`dedupe_seconds` — нельзя слать одинаковую тревогу каждые 5 минут. Очередь +
dedup; отправка через рабочий VLESS или резервный канал.