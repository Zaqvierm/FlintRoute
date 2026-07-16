# P12: Adaptive Zapret Strategy Orchestration

## Решение

FlintRoute не форкает, не копирует и не переписывает `bol-van/zapret`.
Zapret остаётся внешним upstream-компонентом, а FlintRoute управляет только
проверенным каталогом профилей, адресными правилами, измерениями и
транзакционным переключением.

Целевая цепочка строго адресная:

```text
domain -> service bundle -> policy -> route candidates
       -> конкретный route profile -> только набор этого сервиса
       -> nft set/mark -> Zapret | Smart DNS | VLESS | Direct | DROP
```

Успех YouTube через VLESS не даёт права завернуть весь роутер в VLESS. Он
разрешает привязать только bundle `youtube` к конкретному VLESS outbound.
Трафик других сервисов и неизвестных доменов остаётся на своих маршрутах.

## Проверенные возможности upstream

Документация Zapret подтверждает нужные строительные блоки:

- `blockcheck.sh` проверяет DNS и перебирает ограниченный набор техник для
  конкретных доменов, но сам upstream предупреждает: результат зависит от
  клиента, TLS fingerprint, адреса, маршрута и конкретного DPI;
- `nfqws --dry-run` проверяет параметры и завершает работу без активации;
- `nfqws` и `tpws` поддерживают несколько профилей через `--new`, с фильтрами
  по IP family, TCP/UDP, портам, L7, hostlist и ipset;
- hostlist автоматически учитывает поддомены и перечитывается после атомарного
  обновления файла или `HUP`;
- autohostlist обнаруживает признаки блокировки и добавляет хосты, но не
  сравнивает стратегии и не выбирает лучшую;
- для autohostlist в `nfqws` нужен также входящий трафик, а объём обработки надо
  ограничивать conntrack/connbytes;
- nftables позволяет поставить NFQUEUE после NAT, однако flow offload и порядок
  hooks обязаны проверяться на реальном OpenWrt.

Источники: [основной manual](https://github.com/bol-van/zapret/blob/master/docs/readme.md),
[quick start и blockcheck](https://github.com/bol-van/zapret/blob/master/docs/quick_start.md),
[blockcheck.sh](https://github.com/bol-van/zapret/blob/master/blockcheck.sh),
[MIT license](https://github.com/bol-van/zapret/blob/master/docs/LICENSE.txt).

Важный факт на 2026-07-14: upstream `bol-van/zapret` объявлен EOL и указывает
на [zapret2](https://github.com/bol-van/zapret2) как на актуальное продолжение.
Текущий FlintRoute уже проверен с `nfqws` v72.12, поэтому P12 вводит интерфейс
`ZapretProvider`: первый adapter обслуживает совместимый `nfqws` v1, а формат
каталога не должен блокировать отдельный adapter для `nfqws2`. Нельзя молча
переехать на `master` другого движка: сначала отдельная совместимость и
аппаратная проверка.

## Что добавляет FlintRoute

Upstream умеет применять профили. FlintRoute добавляет то, чего upstream не
обещает:

1. модель сервисов и связанных доменов;
2. ограниченный, версионированный каталог кандидатов;
3. измерение результата одинаковым `probe_route`;
4. рейтинг отдельно для сервиса, протокола, IP family и сетевого профиля;
5. периодическую проверку активного и резервных профилей;
6. hysteresis, cooldown и ручной pin;
7. транзакционное переключение с rollback;
8. безопасный переход на Smart DNS, VLESS или DROP, если Zapret не помогает.

`blockcheck.sh` используется как инструмент калибровки и ограниченного
повторного поиска, а не как вечный демон и не как источник аргументов, которые
сразу летят в production.

## Service bundle

Один сервис — это не один apex-domain. Bundle описывает весь минимально
необходимый набор:

```yaml
id: youtube
category: TSPU_RESTRICTED
domains:
  required:
    - youtube.com
    - googlevideo.com
    - ytimg.com
    - youtubei.googleapis.com
  optional:
    - youtu.be
    - youtube-nocookie.com
protocols:
  - tcp/443
  - udp/443
checks:
  - tls
  - http
  - content
failure_route: vless-frankfurt-3
```

Списки должны быть ревьюируемыми и версионированными. Автоматическое
обнаружение может предложить новый домен в quarantine, но не имеет права сразу
расширить production bundle. Иначе один общий CDN-IP легко потянет за собой
чужой трафик.

### Привязка домена к трафику

FlintRoute перехватывает DNS, сохраняет `domain -> IP` вместе с TTL,
provenance и service bundle, затем атомарно обновляет nft sets. Марка назначается
только пакетам к IP из конкретного bundle и только по разрешённым протоколам.

Ограничения:

- TTL нельзя искусственно растягивать бесконечно;
- A и AAAA ведутся независимо;
- IP, общий для bundles с несовместимыми маршрутами, нельзя слепо закреплять за
  одним из них;
- DoH/DoT/QUIC, обходящие контролируемый DNS, должны блокироваться политикой или
  обрабатываться отдельным доказанным путём;
- существующий conntrack flow не переносится между маршрутами посреди сессии;
  новое решение применяется к новым соединениям.

При конфликте shared IP система сохраняет прежний безопасный маршрут,
использует более точное L7/SNI сопоставление там, где оно доказано, либо
переводит сервис в VLESS/DROP. Угадывание запрещено.

## Route profile

Единица выбора — не строка аргументов, а неизменяемый профиль:

```yaml
id: zapret-v1-tls-fake-ttl3
provider: nfqws-v1
provider_version: "72.12"
route_type: zapret
ip_families: [ipv4]
transports: [tcp]
ports: [443]
strategy_file: catalog/zapret-v1-tls-fake-ttl3.conf
queue: 200
safety: reviewed
digest: sha256:...
```

Ключ решения:

```text
service_id × transport × ip_family × network_fingerprint
```

`network_fingerprint` включает минимум WAN interface, provider/ASN при наличии,
public IP prefix, DNS mode, IPv4/IPv6 reachability и upstream engine version.
Смена WAN, провайдера, адресного семейства или версии Zapret инвалидирует
доверие к старому результату, но оставляет его как историю.

Zapret, Smart DNS и каждый VLESS outbound — разные route profiles. VLESS
`frankfurt-3` и VLESS `warsaw-1` не считаются одним маршрутом только потому, что
оба используют Xray.

## Каталог кандидатов и валидация

Произвольные `nfqws`/`nfqws2` аргументы из UI, API, Telegram или autohostlist
запрещены. Кандидат попадает в каталог только после ревью:

1. профиль имеет стабильный ID, provider/version constraints и digest;
2. аргументы разобраны allowlist-валидатором, запрещённые пути и shell syntax
   отклонены;
3. профиль ограничен IP family, transport, ports и service hostlist;
4. временная копия config содержит `--dry-run`, после чего запускается как
   единственный аргумент `nfqws @candidate`; у `@config` остальные аргументы
   игнорируются, поэтому приписывать `--dry-run` после имени файла нельзя;
5. сгенерированный nft проходит `nft -c`;
6. dnsmasq/Xray/IP plan проходят существующие проверки;
7. negative probes доказывают, что посторонний bundle не попал в профиль;
8. профиль имеет бюджет CPU/RAM/queue и максимальное время эксперимента.

Вывод `blockcheck.sh` — только предложение кандидата. Он нормализуется,
сравнивается с allowlist и проходит все восемь шагов. Неизвестная комбинация
никуда автоматически не применяется.

## Пробы

Каждый кандидат проверяется одной моделью `probe_route`, расширенной полями
`service_bundle`, `profile_id`, `transport`, `ip_family` и
`network_fingerprint`.

Обязательные уровни:

1. DNS: корректный ответ, отсутствие известной подмены, A/AAAA отдельно;
2. transport: TCP connect или UDP/QUIC handshake;
3. TLS: валидная цепочка, ожидаемый SNI/hostname, отсутствие MITM;
4. HTTP: допустимый status и отсутствие block-page redirect;
5. content: сервисный marker, а не просто `200 OK`;
6. path evidence: нужные nft counters/mark/queue/outbound действительно
   использованы;
7. leak checks: запрещённый WAN path не использован;
8. latency: median и p95 успешных попыток;
9. reliability: success ratio и нижняя граница Wilson interval;
10. stability: число последовательных успешных окон и возраст результата.

Проверка только apex-domain или только `curl` недостаточна. Для bundle берётся
малый набор дешёвых обязательных probes и ротационный набор дополнительных,
чтобы не устроить DDoS самому себе и не сжечь Flint 2.

## Рейтинг: сначала надёжность, потом задержка

Профили сравниваются лексикографически, а не одной мутной суммой, где быстрый,
но дырявый маршрут внезапно побеждает стабильный:

```text
score = (
  safety_gate,
  required_checks_passed,
  wilson_success_lower_bound,
  success_ratio,
  stable_windows,
  -failure_streak,
  -median_latency_ms,
  -p95_latency_ms,
  -route_cost
)
```

`safety_gate=false` исключает кандидата независимо от задержки. Для первичного
выбора нужно минимум 5 попыток и 2 успешных окна; production-ready профиль
должен набрать минимум 10 попыток, success ratio не ниже 95% и не иметь hard
failure в последних двух окнах. Эти стартовые числа конфигурируются только в
bounded policy и уточняются аппаратными измерениями P12/P13.

Если разница по надёжности статистически незначима, выигрывает меньшая median,
затем p95. Среднее арифметическое не используется: один зависший probe делает
его бесполезным.

Рейтинг хранится отдельно для каждого ключа решения. Успешный TCP/IPv4 профиль
для Discord не получает очки для UDP/IPv6 YouTube.

## Периодическая проверка и bounded re-probe

Scheduler работает с jitter и жёсткими лимитами:

- активный профиль: лёгкий probe каждые 5 минут;
- подтверждение деградации: до 3 попыток в течение 2 минут;
- лучший backup: каждые 30 минут;
- остальные допустимые backups: ротация не чаще раза в 6 часов;
- полный ограниченный discovery: только после подтверждённой деградации,
  смены network fingerprint, upstream version или ручного запроса;
- одновременно проверяется не более одного тяжёлого кандидата на Flint 2;
- каждый цикл имеет deadline, packet/connection budget и общий daily budget.

Это стартовые defaults, не священные цифры. P13 должен подобрать их на железе.
Случайный бесконечный перебор стратегий запрещён.

## Hysteresis, cooldown и pin

Переключение не происходит от одного неудачного запроса:

- hard failure (утечка, MITM, неверный outbound, мёртвый процесс) немедленно
  исключает профиль;
- обычная деградация требует 3 последовательных failures или провала двух окон;
- challenger должен быть надёжнее текущего либо при равной надёжности иметь
  median минимум на 20% лучше в трёх окнах;
- после переключения действует cooldown 30 минут;
- профиль, вызвавший rollback, помещается в quarantine минимум на 6 часов;
- аварийный hard failure может нарушить cooldown ради безопасного fallback.

Manual pin фиксирует `service × protocol × AF` на profile ID, но health-check не
отключается. У pin есть явная политика:

- `fail_closed`: при отказе только DROP;
- `safe_fallback`: разрешён только заранее перечисленный backup;
- `hold_last`: допустим лишь пока safety gate остаётся зелёным.

Pin никогда не превращает TSPU/GEO traffic в непроверенный Direct.

## Транзакционное переключение

P12 использует существующий контур FlintRoute, а не создаёт второй:

```text
plan
  -> validate candidate
  -> snapshot active artifacts, routes, rules, sets and process state
  -> stage candidate hostlists/configs
  -> start consumer before NFQUEUE/TPROXY rules
  -> atomically apply nft/DNS/IP plan
  -> verify service bundle and negative control bundle
  -> commit revision
  -> on any failure rollback snapshot and verify rollback
```

Commit разрешён только если одновременно доказаны:

- целевой bundle работает через выбранный profile;
- path evidence совпадает с profile;
- IPv4/IPv6 и DNS leak policy соблюдены;
- management path жив;
- контрольный чужой bundle не изменил маршрут;
- process/queue/counters соответствуют manifest.

Crash recovery использует persisted transaction state. Если после reboot нельзя
доказать committed revision, активируется последняя доказанная ревизия или
безопасный DROP, но не новая догадка.

## Fallback policy

| Категория | Zapret не найден/сломался | Запрещено |
|---|---|---|
| `TSPU_RESTRICTED` | доказанный VLESS, иначе DROP | небезопасный Direct |
| `GEO_LOCKED` | доказанный non-RU VLESS или Smart DNS, иначе DROP | Direct и Zapret как обход геоблока |
| `DIRECT_PREFERRED` | Smart DNS/VLESS по policy, иначе сохранить Direct только если safety gate разрешает | глобальный VLESS |
| `BLOCKED` | DROP | любой обход |

Smart DNS может решать географию ответа, но сам по себе не доказывает egress.
Если сервис требует non-RU egress, обязательны external IP/country и path
evidence.

## Upstream integration и лицензия

Рекомендуемая схема:

- FlintRoute не включает исходники, бинарники или release archive Zapret;
- оператор устанавливает совместимый upstream package отдельно, либо installer
  скачивает конкретный release по явной команде;
- версия и SHA-256 pin обязательны;
- FlintRoute проверяет binary path, version, digest и provider compatibility;
- attribution и ссылка на upstream показываются в документации и UI;
- если бинарник когда-либо распространяется вместе с FlintRoute, рядом должен
  поставляться полный MIT notice upstream;
- upstream installer не получает владение nft/dnsmasq/procd lifecycle
  FlintRoute: один data-plane должен иметь одного хозяина транзакции.

MIT разрешает использование и распространение при сохранении copyright и
license notice. Это не повод копировать репозиторий внутрь FlintRoute без
необходимости.

## Риски

- DPI и рабочие техники меняются со временем;
- один провайдер может иметь несколько DPI paths с разной длиной и поведением;
- стратегия для `curl` может не работать для браузера/QUIC;
- shared CDN IP создаёт ложные совпадения между сервисами;
- DoH/DoT и IPv6 могут обойти DNS/nftset привязку;
- flow offload может обойти NFQUEUE;
- autohostlist может поймать ложный RST/redirect;
- probe endpoints могут rate-limit или менять content marker;
- слишком много profiles/hostlists съедят RAM Flint 2;
- upstream upgrade может изменить syntax и семантику стратегии;
- переключение живого conntrack flow может дать ложный negative;
- агрессивный re-probe сам создаёт нагрузку и нестабильность.

Каждый риск закрывается evidence, budget, version pin, negative control и
rollback. Где доказательства нет — статус `unknown`, а не зелёная галочка.

## Этапы P12

| Этап | Результат | Gate |
|---|---|---|
| P12.0 | этот контракт и upstream compatibility decision | review документа |
| P12.1 | `ZapretProvider`, version/digest checks, bounded catalog | unit + real config-embedded `--dry-run` |
| P12.2 | service bundles, DNS provenance, конфликт shared IP | unit + negative routing tests |
| P12.3 | probes, rolling windows, Wilson/latency ranking | deterministic simulation tests |
| P12.4 | scheduler, hysteresis, cooldown, pin, quarantine | race/crash/rollback tests |
| P12.5 | narrow Flint 2 proof для двух bundles и двух profiles | path/leak/negative-control evidence |

P12.1 проверен на Flint 2 с `nfqws` v72.12. Provider отклоняет неизвестные
опции, незакреплённые версии и несовпадающие SHA-256, создаёт временный config
с правами `0600` и передаёт его как единственный аргумент `nfqws @candidate`.
Проверка с `--dry-run` прошла, хеш активного config до и после запуска совпал.

P12.2 добавляет неизменяемые service bundles с ограничениями по доменам,
протоколам, IP family и разрешённым профилям. DNS provenance привязывается к
revision и candidate hash, хранит CNAME chain и ограничивает TTL 24 часами.
Истёкшие, приватные и принадлежащие другому bundle ответы не маршрутизируются.
Shared IP с несколькими владельцами получает статус `AMBIGUOUS` и исключается
из routable-наборов для всех затронутых bundles до исчезновения конфликта.

P12.3 хранит ограниченные окна наблюдений отдельно для каждого ключа решения.
Успех засчитывается только вместе с safety gate, обязательными проверками и
доказанным путём. Ранжирование использует Wilson interval, success ratio,
последовательные стабильные окна, failure streak, median/p95 и стоимость
маршрута. Старые наблюдения истекают, число samples ограничено, а профиль одной
сети, address family или bundle не получает доверие в другом ключе.

P12.4 добавляет bounded scheduler и state machine переключения. Активный,
резервный и остальные профили имеют разные интервалы; подтверждение деградации
ограничено тремя попытками и двухминутным окном. Probe lease истекает, дневной
бюджет ограничен, одновременно запускается не более заданного числа тяжёлых
проверок. Hysteresis учитывает hard failure, failed windows, статистически
значимое улучшение и latency threshold. Cooldown можно нарушить только при
аварии, rollback помещает плохой профиль в quarantine, а manual pin явно
выбирает `fail_closed`, `safe_fallback` или безопасный `hold_last`.

P12 заканчивается не красивым JSON, а доказательством на Flint 2: два сервиса
одновременно используют разные выходы, контрольный трафик не затронут,
деградация вызывает bounded switch, а плохой кандидат полностью откатывается.

После этого P13 закрывает полную аппаратную матрицу: все route types,
TCP/UDP, IPv4/IPv6, reboot/crash, несколько клиентов, длительная стабильность,
ресурсные пределы и upgrade/downgrade.
