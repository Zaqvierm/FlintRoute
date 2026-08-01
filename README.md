# FlintRoute

**Выборочная маршрутизация для OpenWrt. Текущий заводской профиль и аппаратные
доказательства относятся к GL.iNet Flint 2 / GL-MT6000.**

Роутер сам выбирает маршрут для каждого домена: `direct`, `Zapret`, `smart_dns`,
`VLESS/Xray` или `DROP`. Клиенты используют OpenWrt-устройство как обычный шлюз
и DNS. Код не запрещает другие OpenWrt-устройства по модели, но совместимость с
ними пока не подтверждена.

## Принцип

Один движок проверки для всех маршрутов:

```
probe_route(domain, service, route)
```

Перед выбором маршрута FlintRoute проверяет не только доступность сайта, но и
то, каким путём реально ушёл трафик. Результат состоит из четырёх частей:

1. **DNS resolution** — resolver, протокол, resolved IP, safe/unsafe ответ.
2. **Классификация** — HTTP status, content markers, regional block, TSPU.
3. **Фактический egress** — внешний IP (SHA-256 hash), страна, consensus.
4. **Доказательство маршрута** — nft mark/rule/table, conntrack, interface,
   Xray outbound tag, process running.

`http_ok=true` без `path_verified=true` → `UNVERIFIED`, маршрут не выбирается.

## Архитектура

- **Go CLI / ядро** `router-policy` — конфиг, пробы, планировщик, state machine, API
- **Preact/Vite UI** — встроен в Go-бинарник, без внешних зависимостей на роутере
- **bbolt** — ChangeSets, ревизии, транзакции, committed health transitions и recovery status; подробные пробы остаются в bounded RAM ring
- **OpenWrt adapter** — транзакционный apply: snapshot → apply → verify → commit/rollback; post-reboot `Reconcile`
- **Artifact generator** — nft, dnsmasq, Xray, nfqws, IPv4/IPv6 route/rule из одного конфига (manifest v6)
- **Auth** — Argon2id, setup token, CSRF, rate limit
- **VPN-подписка/Xray** — нормализация подписки VPN-провайдера, VLESS health-checks с EWMA и кворумом
- **TSPU cache** — multi-source, eTLD+1/wildcard matching, ETag/drop-ratio, SHA-256
- **GeoIP** — MaxMind MMDB, двухсорсный consensus
- **Dynamic discovery** — перехваченные DNS-запросы попадают в bounded runtime
  log; домены классифицируются по route evidence, а не по встроенному списку.
  Чистая установка начинает в `observe_only`: наблюдает, но не меняет правила

## Статус

FlintRoute пока находится в Alpha. Текущая сборка подходит для разработки и
контролируемых испытаний на совместимом OpenWrt, но ещё не для установки «и
забыл». Локальные утверждения ниже проверяются текущим test suite. Утверждения о
железе взяты из сохранённого evidence для GL-MT6000 и в этом цикле не
перепроверялись на роутере.

### Работает и проверено

- локальная сборка, тесты, race-проверка, ShellCheck, UI build и выпуск
  ARM64-бинарника;
- транзакции конфигурации с commit/rollback и fail-closed поведением;
- Direct, Zapret, Drop и VLESS/Xray на GL-MT6000 с bound route evidence;
- два production Smart DNS resolver ранее прошли UDP/53, TCP/53 и bound path
  evidence; заводской конфиг намеренно оставляет resolver slots пустыми;
- полная применимая матрица `route × protocol × address family`: 23 аппаратных
  PASS, без FAIL и непроверенных клеток;
- восстановление committed dataplane после физической перезагрузки: controller,
  Xray, nfqws, nftables и policy rules;
- production Xray и Zapret работают как отдельные procd-сервисы FlintRoute;
  состояние штатного сервиса `xray` показывается отдельно;
- production adaptive Zapret calibration, profile switch, cooldown, pin и
  quarantine проверены на Flint 2;
- persistent state в `/etc/router-policy/state` без зависимости от volatile `/var`;
- clean install, upgrade, restart, `SIGKILL`, watchdog maintenance lease и
  controlled reboot control plane повторно пройдены на factory OpenWrt;
- production Xray/Zapret и committed dataplane повторно прошли restart,
  `SIGKILL`, controller restart и 11 bound route proofs без потери SSH/web;
- 1000 read-only API GET и 35 минут idle на Flint 2 дали нулевой прирост
  persistent transactions, bytes и file replacements;
- rollback timer, compatible downgrade, restore, fixed uninstall и финальный
  reinstall/reconcile пройдены с внешним SSH/web monitor; cleanup вернул
  исходный flow-offload baseline и оставил bounded backup registry;
- физическое отключение питания пройдено: после загрузки восстановились та же
  committed revision, managed Xray/Zapret, nftables, policy routing и Web API;
- панель доступна из отдельной upstream-сети через явный non-loopback bind и
  source-restricted firewall rule; по умолчанию listener остаётся loopback-only;
- неизменный TSPU cache не переписывает два больших поколения: на Flint 2
  проверены 86 781 entry и отдельный freshness checkpoint размером меньше 2 KiB;
- локальные API, авторизация, журнал изменений и встроенная консоль.

### Реализовано, но требует проверки на железе

- автоматическое обнаружение доменов без заводского каталога сервисов;
- режимы discovery `observe_only`, `suggest`, `auto_apply_verified` и `locked`;
- ручные opt-in правила и редактируемый порядок fallback для найденных доменов;
- настройка Smart DNS с UDP/TCP DNS и HTTP/TLS preflight и пяти VPN-подписок
  через Web UI;
- явные managed activation flows для Xray и Zapret без ручного JSON: локальные
  API/UI tests зелёные, повторный аппаратный apply/rollback ещё нужен;
- импорт top-3 `blockcheck`-кандидатов, привязанных к фактически проверенному
  домену и fingerprint сети;
- расширенная IPv6-матрица на реальных LAN-клиентах;
- работа под нагрузкой с несколькими клиентами;

### Известные ограничения чистой установки

- готовый архив собирается только для Linux arm64; другие архитектуры требуют
  отдельной сборки;
- Xray и совместимый `nfqws` не входят в пакет и должны быть установлены
  отдельно до включения соответствующих маршрутов; Zapret setup принимает
  только immutable HTTPS source, закреплённые version и SHA-256;
- заводской конфиг не содержит VPN-подписку и production Smart DNS resolver,
  поэтому VLESS и Smart DNS после одной установки не становятся рабочими сами;
- штатный профиль `config/default.json` нацелен на GL-MT6000. Для другого
  OpenWrt-устройства нужны проверенный platform config и отдельное аппаратное
  доказательство;
- локальный installer fixture доказывает порядок операций и rollback, но не
  заменяет clean-install pass на конкретном устройстве;
- Telegram notifications реализованы как отдельная необязательная подсистема с
  проверкой bot/chat, bounded retry и фильтрами событий. `external_socks` честно
  оформлен как внешняя loopback-зависимость; FlintRoute не управляет её процессом.

Baseline revision не захватывает обычный трафик. Пока домен не получил явное
правило, он остаётся `unclassified` и идёт через системный default route
OpenWrt. `FlintRoute-managed Direct` появляется только для домена с применённым
Direct-правилом; это не то же самое, что системный маршрут по умолчанию.

### Запланировано

- длительный soak-test;
- аппаратная проверка Telegram delivery и пользовательского external SOCKS endpoint;

Точные фазы, проценты и критерии приёмки находятся в
[`docs/status-matrix.md`](docs/status-matrix.md). Аппаратные результаты — в
[`docs/flint2-hardware-report.md`](docs/flint2-hardware-report.md).

## Сборка

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-go.ps1
```

Артефакты:

```
dist/router-policy.exe              # Windows
dist/router-policy-linux-arm64      # Flint 2 / OpenWrt
```

## Тесты

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\run-all.ps1
```

Проверяет: `go test`, `go vet`, ShellCheck (если бинарник доступен), frontend
typecheck/build, ARM64 build и adapter integration. `go test -race ./...`
запускается отдельно.

## Установка

```sh
# Диагностика (read-only)
sh install.sh --diagnose

# Сухой запуск
sh install.sh --dry-run

# Установка и запуск control plane
sh install.sh --install --enable-services

# При ошибке установки предыдущая версия восстанавливается автоматически

# Удаление
sh uninstall.sh --uninstall
```

Полный порядок сборки пакета, обновления и удаления: [`docs/installation.md`](docs/installation.md).

## CLI

```sh
router-policy status
router-policy run --listen 127.0.0.1:8787
router-policy validate-config
router-policy routes
router-policy services
router-policy candidates observed.example automatic

# When the control plane already owns the state database, collect live
# transaction-bound evidence without trying to persist probe history:
router-policy check-domain observed.example
# Нормализовать VPN-подписку перед генерацией Xray-конфига:
router-policy subscription-normalize subscription.json
router-policy tspu-update --out tspu-cache.json
router-policy security audit
router-policy lifecycle status --json
router-policy cleanup stale --dry-run --json
router-policy storage migrate --dry-run
```

## Документация

Карта документов со статусом — [`docs/README.md`](docs/README.md). Основные:

- `docs/implementation-plan.md` — текущий статус и что не сделано
- `docs/algorithm-flow.md` — алгоритм выбора маршрута, 4 уровня
- `docs/probe-route.md` — единый `probe_route`
- `docs/adapter-transaction.md` — транзакция адаптера и recovery
- `docs/api.md` — API, auth, SSE, ChangeSet
- `docs/vpn-subscription.md` — VPN-провайдер, подписка, Xray генерация
- `docs/headless-dataplane.md` — managed Xray TPROXY и Zapret/nfqws lifecycle
- `docs/tspu-cache.md` — TSPU cache v2
- `docs/storage-lifecycle.md` — ownership, cleanup, retention и write budget
- `docs/flint2-hardware-report.md` — обезличенный отчёт по железу
- `docs/incidents.md` — аппаратные инциденты и найденные ошибки проверок
- `docs/status-matrix.md` — матрица готовности

## Платформа

- OpenWrt с `procd`, `ubus`, firewall4/nftables и policy routing;
- текущий готовый пакет: Linux arm64;
- текущий заводской профиль и аппаратное evidence: GL.iNet Flint 2 / GL-MT6000,
  OpenWrt 24.10.4;
- dnsmasq-full с nftset
- Xray для VLESS
- внешний `nfqws` arm64 для маршрута Zapret (бинарник не вендорится)

## Лицензия

Apache License 2.0. См. [LICENSE](LICENSE) и [NOTICE](NOTICE).

Copyright 2026 Zaqvierm
