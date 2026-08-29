# Дизайн remediation: границы транзакций и привилегий

Базовый SHA аудита: `d45a779dfa9dc024b426cef358d3df4d32478897`.

Документ фиксирует локальный контракт remediation. Он намеренно не зависит от
доказательств на Flint 2: в этой ветке роутер не трогается.

## Инварианты безопасности

1. Защищённый mark никогда не получает Direct, пока активная revision,
   generation адаптера или журнал recovery неоднозначны.
2. Перед финализацией транзакции durable revision control plane, метаданные
   адаптера и наблюдаемая generation dataplane должны совпадать.
3. Candidate не является активной конфигурацией. Это content-addressed-состояние
   одной транзакции; его можно удалить только после доказательства, что оно не
   используется как active.
4. Неоднозначная операция получает `RECOVERY_REQUIRED`, а не `rolled_back` и не
   считается успешной по одному коду выхода процесса.
5. Ресурс без подтверждённого владельца FlintRoute считается чужим. Его нельзя
   автоматически останавливать, удалять или перезаписывать.
6. Observation, health, watchdog и adaptive calibration не имеют скрытого права
   перестраивать production dataplane.
7. Installer и rollback используют канонические allowlist-идентификаторы без
   компонентов `.` и `..`. Пути с `..`, двойными разделителями и завершающим
   разделителем отклоняются до любого рекурсивного удаления/копирования/restore.

Атомарность nft не равна атомарности всего dataplane: owned nft table
заменяется одним `nft` batch, но конфиги, listeners, IP plan и dnsmasq
обновляются отдельными шагами. На время этой последовательности включён
fail-closed transition guard; при любой ошибке операция отклоняется/откатывается,
а не объявляется атомарной.

## Машина состояний транзакции

Durable journal и adapter проходят состояния в таком порядке:

```text
intent_persisted
  -> candidate_prepared
  -> adapter_prepared (rollback сохранён)
  -> adapter_activated (rollback сохранён)
  -> control_plane_committed
  -> adapter_finalized
  -> committed
```

Сбой до активации адаптера может перейти в `rolled_back` после идемпотентного
удаления только принадлежащих FlintRoute ресурсов. Сбой после активации сначала
сверяется с семантическим статусом адаптера. Если adapter и bbolt нельзя
согласовать, транзакция получает `RECOVERY_REQUIRED`, новые mutation блокируются,
а защищённые marks остаются под fail-closed guard. `rollback=false` при exit code
`0` не является успешным rollback.

В binding статуса входят operation, transaction ID, hash rollback token, revision,
hash candidate, hash manifest артефактов, generation и фактическое состояние
adapter. Rollback capability удаляется только после сравнения durable active
revision с состоянием adapter.

## Размещение конфигурации

`bootstrap.json` — неизменяемые параметры запуска. В нём нет pending candidate,
и apply никогда его не заменяет. Candidate-артефакты лежат в
content-addressed-каталоге транзакции/revision. При рестарте durable journal
выбирает только committed artifact. Отсутствующий или противоречивый journal
включает rescue/fence; запуск не угадывает active-конфигурацию из `default.json`.

## Граница привилегий

Целевая схема — непривилегированный controller и небольшой root helper на Unix
socket `0600`. Controller обслуживает API, state, parsing и непривилегированные
probes. Helper выполняет только фиксированные typed-операции, привязанные к
владельцу. Он не скачивает URL, не разбирает подписки, не публикует HTTP и не
исполняет произвольные shell-фрагменты. Граница вводится постепенно, чтобы все
операции оставались тестируемыми и не появился второй неучтённый supervisor.

Упакованный `router-policy-helper` работает fail-closed: требует явный non-root
peer UID в `helper.env`, слушает фиксированный Unix socket с mode `0600` и
принимает только операции с версией протокола, request ID и binding по
generation/revision/token. Allowlist покрывает transaction verbs, принадлежащую
таблицу nft, управляемый IP-план, managed procd services и фиксированные виды
артефактов. У helper нет HTTP-клиента, remote fetch, parser подписок/provider
JSON или произвольного command/path input.

Production entrypoint требует non-root peer и настроенный helper socket:
`validateProductionPrivilege` отвергает root и запуск без socket, а OpenWrt
procd init задаёт `daemon:daemon`; installer включает и запускает
`router-policy-helper` до controller и блокирует восстановление controller без
его running-состояния. При настроенном socket recovery reconciliation
идёт через typed `transaction.reconcile`, а не через прямую shell mutation.
Read-only `status` и `diagnose` остаются вне этой mutation boundary. Runtime
проверка UID/peer credentials и hardware proof ещё не выполнены, поэтому
acceptance остаётся `PARTIAL`, хотя production startup contract уже fail-closed.

### Ранний boot fence и committed classifier

После cold boot conntrack пуст, поэтому один только match по `meta mark` не
защищает новый поток. `router-policy-boot-guard` сначала ставит отдельную
owned-таблицу с `forward policy drop`. Если в
`state/last-good/active-transaction.env` доказаны `transaction_state=committed`,
candidate hash, artifact manifest hash и ownership `router_policy`, guard в том
же атомарном `nft` batch загружает этот committed classifier. В guard разрешаются
только не-DROP marks, полученные typed-командой
`internal-print-managed-marks`; нулевые и foreign marks остаются под DROP.

При отсутствующем/повреждённом binding, недоступном parser/helper или конфликте
чужой `router_policy` classifier не загружается: безопасный fallback — полный
transit DROP до reconcile. Это fail-closed degraded mode, а не обещание
доступности WAN. Guard не ставит hook на loopback management plane и снимается
только generation-bound операцией после полного reconcile.

Lifecycle socket также проверяет ownership: regular file, symlink или живой
listener в `helper.sock` считается чужим и не удаляется. Перед bind можно убрать
только stale Unix socket, который не принимает соединения. Тест helper сохраняет
чужой marker-файл побайтно.

## Полномочия фоновых задач

`observe_only` выполняет только observation/classification. Route-only automatic
assignment допустим лишь для уже созданного verified route и ограниченного
обновления domain mapping. Любое изменение артефактов, services, nft topology,
marks, IP rules, listener или DNS topology остаётся явным ChangeSet.

Adaptive Zapret calibration остаётся suggestion/изолированным тестом, пока
отдельные NFQUEUE и network namespace не докажут изоляцию ресурсов.

Обычный discovery после записи observation сразу возвращает результат: он не
вызывает domain checker, не занимает probe slot, не вызывает adapter и не создаёт
change. Automatic assignment отключён до появления безопасной операции mapping
для существующего route с TTL, rate limit, rollback и evidence.

Fetch подписок, GeoIP и TSPU используют единую SSRF-защиту: только HTTPS,
закрепление проверенного адреса, повторную проверку redirect, запрет private,
metadata и link-local адресов, ограничения размера ответа/распакованных данных и
bounded timeout. Ввод провайдера Xray проходит strict typed model; raw provider
JSON никогда не копируется в active config.

## Правила доказательств

Локальный тест не является hardware proof. В каждой записи evidence указываются
точные commit, окружение, команда, путь к raw log, digest, scope и состояние
PASS/FAIL/SKIP. Evidence старого commit помечается `STALE FOR CURRENT SHA`.

## Fence mutation при recovery

Dataplane mutation разрешена только при семантически подтверждённом статусе `ok`
или `not_required`, который содержит подтверждённые baseline revision и hash
candidate. `starting`, `error`, `recovery_required`, пустое и неизвестное значения
всегда fail-closed и возвращают HTTP 503.

`not_required` принимается только если recovery-path установил
`baseline_confirmed`; произвольная пара revision/hash не может сама создать
безопасный baseline. На всю mutation-операцию удерживается server-level
read/write lease, поэтому переход recovery не может состязаться с apply у входа
и у adapter boundary.

Discovery, health, refresh подписок, reactive recovery и adaptive scheduler перед
активной работой проверяют тот же fence. Read-only health/status остаются доступны.

Сохранение recovery status не является best effort: при ошибке durable write
памятный статус немедленно меняется на `recovery_required`, а событие публикуется
как `recovery_status_persist_failed`. Это видимый безопасный fence, а не ложный
durable success.

Это ограниченная гарантия, а не заявление о математической невозможности
split-brain. Подтверждённые ambiguous states fenced как `RECOVERY_REQUIRED`, а
silent rollback/committed divergence отклоняются semantic-response и
fault-injection тестами. Полная reboot/fault matrix и hardware evidence нужны
до заявления об абсолютном отсутствии split-brain.

## Текущий статус privilege boundary

`router-policy-helper` — упакованный typed helper с фиксированным путём и Unix
socket; его контракт протестирован. Production-controller запускается через
procd как `daemon`, а root и запуск без helper отвергаются. Разделение
привилегий всё ещё **PARTIAL** до Linux runtime/peer-credential и hardware
evidence. Основной transaction/route dataplane использует helper path; прямой
shell adapter оставлен только legacy/development режимом. Для component API
отдельно действует fail-closed ограждение: пока helper-backed component
executor не подключён, production controller может читать inventory/status, но
не имеет права выполнять install/update/restart/rollback/uninstall через
прямой `OpenWrtDriver`. LAN exposure по умолчанию запрещён.

## Порядок remediation

Сначала закрываются transaction protocol, разделение bootstrap, boot guard, nft
transition и hotplug fence. Затем rescue, watchdog, privilege, SSRF, typed Xray
generation и ownership. После этого отдельными regression-тестами проверяются
auto-routing, adaptive calibration, DNS watcher, polling/auth/storage budgets.
Hardware validation из этой ветки исключена.

Resource budget намеренно мал: глобальный probe semaphore — 4 worker, discovery
queue — 32 элемента, targets route probe — не более 4 на candidate, rings
probe/observation ограничены. Это логические лимиты локальных тестов, а не
утверждение о CPU, socket или NAND роутера.

## Семантика проверки решения

`NO_SAFE_ROUTE` — terminal result полного исчерпания. Planner начинает проверку с
`verification_state=in_progress` и `status=VERIFYING`; перейти в
`terminal_no_safe_route` можно только после bounded result каждого разрешённого
policy candidate (либо доказанного policy skip), если ни один не дал полного
path proof.

Внешняя отмена или timeout до этого момента оставляет `VERIFYING` и не сохраняется
как failed route decision. API отправляет событие `VERIFYING` до активного
discovery, а terminal exhaustion выдаёт отдельно.

Classification confidence не смешивается с route confidence. API раскрывает
`classification_confidence`, `classification_source` и `classification_evidence`;
`confidence` остаётся бинарной уверенностью полностью verified выбранного route.
Поэтому TSPU match со слабой уверенностью источника может быть классифицирован,
пока verification ещё идёт.

`latency_ms` — измеренная latency запроса/path для совместимости со старыми
клиентами. Поле заполняется только при `route_latency_available=true` и никогда
не содержит orchestration duration. Явное эквивалентное поле —
`route_latency_ms`. `verification_duration_ms` включает DNS, подготовку,
retries, проверку доказательств и cleanup. Если тип route не умеет честно
измерить path, latency показывается как unavailable, а не как замаскированная
длительность job.

Decision cache отдельно сохраняет полную verification duration planner и
`VerificationDurationMS` каждого candidate. Cache hit помечается
`verification_cached=true`, использует сохранённое evidence (или legacy duration)
и не подставляет wall-clock поиска в кэше. Ответ RouteProber с пустым или
in-progress status также non-terminal и не может стать `NO_SAFE_ROUTE` без
bounded terminal result.
