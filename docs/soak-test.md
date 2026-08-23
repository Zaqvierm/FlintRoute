# 72-часовой soak-test

> **Статус на `effa938`:** это план будущего evidence-run. 72-часовой прогон
> на Flint 2 для текущего SHA не выполнялся.

Soak начинается только после зелёных route matrix, crash/reboot recovery,
physical power-loss recovery и multi-client preflight. Это evidence-run, а не
три дня «оставить роутер и надеяться».

## Предварительная проверка

До таймера записать redacted baseline:

- Git SHA, package SHA-256, firmware и boot ID;
- active revision и recovery status;
- managed procd instances с PID/start time/executable/config identity;
- принадлежащие FlintRoute nft objects, policy rules/tables и listeners;
- размеры persistent/runtime storage, backup/snapshot counts и write counters;
- route-health и один bound proof для каждого активного route type;
- CPU, RSS, conntrack, NFQUEUE counters, temperature и WAN fingerprint;
- доступность внешнего SSH, router UI и FlintRoute Web.

Проверить off-router backup и независимый management path. Не должно быть
unfinished transaction, stale test-run, ambiguous owned resource или истёкшего
watchdog inhibit. Неизвестный baseline или недоступный monitor блокирует старт.

## Нагрузка

Работать не менее 72 часов с обычным mixed traffic и минимум тремя clients,
если они доступны. Добавить bounded DNS, Direct, Zapret, VLESS и Drop checks с
jitter; не синхронизировать probes в одну минуту.

В run включить:

1. один контролируемый restart managed service;
2. один контролируемый reboot;
3. bounded degradation Zapret и VLESS с recovery;
4. WAN fingerprint change, если это не затрагивает чужие services;
5. периодическую UI GET/SSE активность для доказательства write-free observation.

Physical power cut внутри soak не выполнять, если это не отдельный fault-case с
независимым recovery path.

## Периодичность evidence

Health/resource counters писать каждую минуту в tmpfs. Redacted checkpoint — не
чаще 15 минут и при state transition. Bundle ежедневно выгружать за роутер.
Checkpoint содержит timestamp, boot ID, active revision, route state, provider
identity, nft/NFQUEUE counters, CPU/RSS/temperature, storage и logical write
counters. Subscription URL, UUID, keys, tokens, cookies и private endpoints
туда не попадают.

## Условия остановки

Остановить run и отметить FAIL при unsafe Direct fallback, неправильной revision,
unknown/contradictory transaction или recovery state, потере management,
процессе не от ожидаемого procd, NFQUEUE drops, OOM, thermal throttling,
persistent restart loop, неограниченном росте RAM/cache/snapshot/backup/write или
необъяснимой oscillation adaptive profile.

## Условия PASS

PASS требует 72 завершённых часов, отсутствия stop condition и leaked/stale
resources, bounded storage/write counters и того же internally consistent
committed state после финального аудита. Любой пробел мониторинга документируется;
если он мешает доказать route/resource state, соответствующий интервал invalid.
