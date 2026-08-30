# Модель отказов

> Основные реализации: `internal/health/service.go`,
> `internal/probe/health.go`, `internal/adapter`, `internal/api/recovery.go`.

## Базовые правила

- Одна ошибка не переключает маршрут (hysteresis).
- `fail_after_consecutive_errors` (default 3) — путь признаётся неисправным.
- `recover_after_consecutive_successes` (default 5) — путь восстанавливается.
- `route_hold_seconds` — удержание от дёрганья.
- Любое применение — через транзакцию с rollback.
- Параллельные запуски — per-ChangeSet action locks + global transaction lock.
- `path_verified=false` → маршрут не production, даже при HTTP 200.

## Цикл здоровья (`health.Service.RunCycle`)

- ограниченный параллелизм (`policy.parallel_server_checks`, ≤16);
- control quorum: ≥2 control-сервисов, majority OK;
- consensus по `adapter_revision`/`candidate_hash`/`manifest_hash`/`country`/`ip_hash`
  — расхождение → `health_evidence_consensus_mismatch`;
- `probe.HealthTracker`: задержка EWMA, гистерезис отказа/восстановления, карантин;
- `AssignVLESSRoles`: `selected`/`standby`/`quarantine`;
- bbolt стойкость + API `/api/v1/route-health`.

`safeHealthResult`: соответствие тега/типа маршрута, `OK` + `path_verified` + `service_ok` +
`egress_consensus` + непустые привязки + страна ≠ RU/НЕИЗВЕСТНО.

## Если путь умер

| Категория | Допустимые кандидаты | Запрещено |
|---|---|---|
| `GEO_LOCKED` | все Smart DNS, VLESS (non-RU), DROP | Direct, Zapret, RU/unknown egress |
| `TELEGRAM` | все external SOCKS, VLESS, DROP | каждый внешний SOCKS должен пройти preflight и PathVerified |
| `TSPU_RESTRICTED` | все Zapret, Smart DNS, VLESS, DROP | небезопасный Direct |
| `DIRECT_ONLY` | Direct; при отказе — явный DROP | зарубежный proxy |
| `DIRECT_PREFERRED` | Direct, Zapret, Smart DNS, VLESS, DROP | выбор по порядку списка; hard filter обязателен |
| `BLOCKED` | DROP | любой обход |

Порядок в столбце «Допустимые кандидаты» не является приоритетом победителя.
Все кандидаты с terminal evidence проходят hard filter (`PathVerified`,
`ServiceOK`, policy/egress), затем сравниваются по сопоставимому
end-to-end latency и health evidence. Hysteresis/cooldown предотвращают
переключение из-за незначительной разницы.

## Четыре уровня при отказе

Отказ определяется per-уровнем, не одной суммой:

1. **DNS** — тайм-аут резолвера, отравленный ответ, пустой → `dns_failed`.
2. **Классификация** — regional block, TSPU marker → `REGION_BLOCK`/`SUSPECTED_TSPU`.
3. **Фактический egress** — RU exit для `GEO_LOCKED` → `RU_EXIT`; unknown country → `FAIL`.
4. **Доказательство маршрута** — missing mark/rule/table/outbound → `UNVERIFIED`.

Hard failure (утечка, MITM, неверный outbound, мёртвый процесс) немедленно
исключает профиль. Обычная деградация — streak-based.

## Повреждённая VPN-подписка

Не применять, если: HTTP ≠ 200, ответ > `policy.max_subscription_bytes`, битый
JSON, нет `.outbounds`, нет VLESS, нет обязательных полей, `xray run -test`
падает, supported = 0. Действие: оставить last-good bundle и записать событие.
См. `vpn-subscription.md`.

## Повреждённый TSPU-список

Не применять, если: список пустой, слишком мал/велик, мусорный синтаксис, число
записей резко просело (`drop_ratio > max_drop_ratio`), источник вернул
HTML/капчу/non-200. `retainPrevious` сохраняет прошлый кеш. Ручные правила выше
внешних списков. См. `tspu-cache.md`.

## Восстановление (P6)

При старте `recoverCommittedDataplane` восстанавливает committed dataplane через
`adapter.Reconcile`. In-flight ChangeSet — через `recoverTransactions`. Любое
расхождение bindings → `failedRecovery` с `reason_code`, management остаётся
доступен в degraded state. Crash mid-transaction → rollback или безопасный DROP.

## Уведомления

Telegram sender использует bounded queue, retry, rate limit и allowlist событий.
Ошибки доставки переводят подсистему в `degraded`/`failed`, но не считаются отказом
core routing. `external_socks` не является managed process: FlintRoute проверяет
внешний loopback endpoint и откатывает только собственный routing ChangeSet.
