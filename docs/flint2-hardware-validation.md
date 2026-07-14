# P13: Full Flint 2 Hardware Validation

## Цель

P13 закрывает разницу между «локальные тесты зелёные» и «FlintRoute можно
оставить на реальном GL.iNet Flint 2 без дежурства с отвёрткой».

P13 не добавляет новую маршрутизационную логику. Он доказывает на физическом
GL-MT6000, что уже реализованные Direct, DROP, Zapret, Smart DNS, VLESS/Xray и
адаптивный выбор P12 работают вместе, переживают отказ и не затрагивают чужой
трафик.

## Входной gate

P13 начинается только когда:

- P12 завершил bounded catalog, service bundles, ranking, hysteresis и rollback;
- `tests/run-all.ps1` возвращает `all_tests_ok=true`;
- ARM64 binary и все OpenWrt artifacts собраны из конкретного commit;
- версии OpenWrt, Flint firmware, Zapret provider, Xray и config schema записаны;
- существует внешний recovery backup с проверенным SHA-256;
- аварийный watchdog откатывает незавершённую транзакцию без CLI-сессии;
- management, DNS и контрольный внешний endpoint имеют baseline evidence.

Если любой пункт отсутствует, запуск называется rehearsal, а не P13 pass.

## Принцип доказательства

Каждый тест должен связать четыре факта:

```text
intent -> generated artifact -> live kernel/process state -> observed traffic
```

«Сайт открылся» недостаточно. Для PASS нужны route mark, nft counter,
IP rule/table либо Xray outbound/NFQUEUE evidence, DNS provenance, отсутствие
IPv4/IPv6 leak и положительный service-level probe.

Контрольный bundle запускается рядом с целевым. Если тест YouTube изменил путь
GitHub или другого сервиса, тест провален даже при рабочем видео.

## Аппаратная матрица

### Маршруты

| Route type | Положительный тест | Обязательное доказательство | Failure test |
|---|---|---|---|
| Direct | разрешённый сервис идёт через WAN | direct mark/rule/table, WAN egress, content | WAN/DNS failure не переезжает в запрещённый proxy |
| DROP | IPv4, IPv6, TCP и UDP блокируются | drop counter растёт, transport не проходит | отсутствие правила считается FAIL |
| Zapret | TSPU service проходит через выбранный profile | profile ID, NFQUEUE counter, nfqws process, content | kill nfqws, bad profile, queue failure -> rollback/fallback |
| Smart DNS | bundle получает нужный ответ и работает | выбранный resolver, DNS answer provenance, path | resolver timeout/poisoned answer -> backup/DROP |
| VLESS/Xray | только bundle выходит через конкретный outbound | TPROXY mark/rule/table, outbound tag, external country/IP | dead server/process -> другой доказанный outbound/DROP |

### Протоколы и адресные семейства

Для каждого применимого route type проверяются:

- TCP/80;
- TCP/443 с TLS и content marker;
- UDP/443/QUIC: рабочий профиль либо доказанный DROP с TCP fallback;
- IPv4;
- IPv6;
- DNS UDP/53 и TCP/53;
- контролируемое поведение DoH/DoT согласно policy;
- established conntrack flow и новое соединение после switch.

`not applicable` допустим только с записанной причиной. Молча пропустить IPv6
потому, что тестовый скрипт его не увидел, нельзя.

### Service isolation

Минимальный набор одновременно активных bundles:

1. Direct control, например GitHub;
2. TSPU_RESTRICTED через Zapret;
3. GEO_LOCKED через конкретный non-RU VLESS или Smart DNS + доказанный egress;
4. BLOCKED через DROP;
5. неизвестный домен по default policy.

Для каждого переключения проверяется, что четыре остальных маршрута не
изменились. Отдельно тестируются связанные CDN-домены, shared IP collision,
TTL expiry, A/AAAA divergence и добавление нового IP через DNS cache.

## P12 adaptive scenarios

P13 обязан доказать адаптивную часть, а не только статический happy path:

1. два service bundles одновременно закреплены за разными Zapret/VLESS
   profiles;
2. активный Zapret profile искусственно деградирует;
3. bounded re-probe проверяет только разрешённый каталог и соблюдает budgets;
4. backup выигрывает по reliability, а не только по latency;
5. switch проходит snapshot -> apply -> verify -> commit;
6. старый профиль помещается в quarantine и не вызывает oscillation;
7. bad challenger вызывает полный rollback;
8. cooldown блокирует бессмысленный обратный switch;
9. manual pin и обе политики отказа проверены;
10. смена WAN/network fingerprint инвалидирует старый active decision и запускает
    ограниченную перекалибровку.

## Отказы и восстановление

Обязательные fault injections:

- `nfqws` завершён до и после активации NFQUEUE;
- Xray завершён, config повреждён, outbound недоступен;
- dnsmasq restart завис или resolver перестал отвечать;
- nft apply отклонён;
- IP rule/route применены частично;
- flow offload включён вопреки manifest;
- процесс FlintRoute убит в каждой transaction phase;
- питание/перезагрузка между snapshot, apply, verify и commit;
- bbolt active revision повреждена или не совпадает с manifest;
- management probe пропал;
- WAN исчез и вернулся с другим network fingerprint;
- закончилось место либо достигнут лимит RAM/CPU.

После каждого отказа проверяются не только файлы. Live nft table, routes, rules,
process states, dnsmasq, Xray, nfqws, active revision и service traffic должны
соответствовать одной целой ревизии. Полусобранный data-plane — FAIL.

## Reboot/crash matrix

| Состояние перед reboot/crash | Ожидаемое восстановление |
|---|---|
| committed healthy revision | та же ревизия и те же bindings |
| prepared/candidate_validated | кандидат не активируется |
| snapshotted/applying | rollback на последний committed либо безопасный DROP |
| applied, not verified | commit запрещён, rollback обязателен |
| rollback in progress | идемпотентное завершение rollback |
| manifest/hash mismatch | fail closed и явная диагностика |

Каждая строка выполняется минимум дважды: controlled reboot и hard process
termination. Power loss допускается только при наличии внешнего recovery path.

## Multi-client

Минимум три клиента одновременно:

- проводной LAN;
- основной Wi-Fi;
- guest Wi-Fi или отдельный VLAN.

Проверяются параллельные DNS requests, одинаковый service bundle с разных
клиентов, разные bundles, долгий download/stream, reconnect, смена IP клиента и
изоляция guest policy. Решение маршрута не должно зависеть от того, кто первым
прогрел nft set, если policy не задаёт client-specific override.

## Производительность и ресурсные пределы

Baseline снимается без управляемого обхода, затем для каждого route type и
смешанной нагрузки:

- throughput down/up;
- median/p95 latency и jitter;
- packet loss/retransmits;
- CPU total и по процессам;
- RAM/RSS, slab/conntrack usage;
- NFQUEUE backlog/drop;
- размер hostlists/nft sets/domain cache;
- DNS QPS и cache hit ratio;
- температура и throttling;
- время apply, verify и rollback.

Числа фиксируются как evidence. Финальные пороги утверждаются после baseline,
но любой packet drop в NFQUEUE, OOM, thermal throttling или потеря management —
немедленный FAIL независимо от среднего throughput.

## Длительный прогон

После fault matrix запускается soak не короче 72 часов:

- обычный смешанный домашний трафик;
- периодические active/backup probes с jitter;
- минимум одна контролируемая деградация Zapret и VLESS;
- смена public IP или имитация нового network fingerprint;
- один scheduled reboot;
- постоянный сбор resource и route evidence.

PASS требует ноль unsafe Direct leaks, ноль неизвестных transaction states,
ноль необъяснимых switches и отсутствие устойчивого роста RAM/cache.

## Install, upgrade, downgrade

На чистом Flint 2 проверяются:

1. diagnose;
2. dry-run;
3. install без активации маршрутов;
4. первая активация;
5. upgrade с предыдущей schema/revision;
6. rollback upgrade;
7. downgrade при совместимой schema;
8. uninstall с восстановлением исходного состояния.

Installer не имеет права перетирать чужой Xray/Zapret/firewall config. Все
изменения принадлежат project namespace и входят в backup/manifest.

## Evidence bundle

Каждый hardware run сохраняет:

```text
hardware-evidence/<run-id>/
  metadata.json
  baseline.json
  config.redacted.json
  manifest.json
  transaction-events.jsonl
  probes.jsonl
  nft.txt
  ip-rules.txt
  ip-routes.txt
  process-state.txt
  resource-samples.jsonl
  failure-injections.jsonl
  checksums.sha256
  summary.md
```

Secrets, subscription URLs и private keys в evidence запрещены. `run-id`
связывается с Git commit, build digest, firmware и upstream versions.

## PASS/FAIL

P13 считается завершённым только если:

- вся применимая матрица имеет evidence-backed PASS;
- нет unsafe Direct fallback для TSPU_RESTRICTED/GEO_LOCKED;
- service isolation доказана negative controls;
- rollback и crash recovery идемпотентны;
- reboot поднимает только последнюю committed revision;
- 72-hour soak прошёл без leak, oscillation, OOM и transaction corruption;
- install/upgrade/downgrade/uninstall воспроизводимы;
- документация содержит реальные версии, пороги и известные ограничения.

Процент в README — ориентир, не доказательство. До выполнения этих условий
FlintRoute остаётся Alpha, даже если UI выглядит охуенно.

## Подэтапы

| Этап | Содержание | Результат |
|---|---|---|
| P13.0 | harness, metadata, evidence bundle | воспроизводимый run |
| P13.1 | route/protocol/AF matrix | базовая функциональная матрица |
| P13.2 | adaptive/service isolation | доказательство P12 на железе |
| P13.3 | fault/reboot/crash | fail-closed recovery |
| P13.4 | multi-client/performance | пределы Flint 2 |
| P13.5 | install/upgrade/downgrade | жизненный цикл релиза |
| P13.6 | 72-hour soak и финальный audit | решение о выходе из Alpha |
