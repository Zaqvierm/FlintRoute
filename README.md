# FlintRoute

**Выборочная маршрутизация для GL.iNet Flint 2 / GL-MT6000 на OpenWrt.**

Роутер сам выбирает маршрут для каждого домена: `direct`, `Zapret`, `smart_dns`, `VLESS/Xray` или `DROP`. Клиенты ничего не настраивают — получают Flint 2 как обычный шлюз и DNS.

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
- **bbolt** — ChangeSets, ревизии, транзакции, пробы, события, recovery status
- **OpenWrt adapter** — транзакционный apply: snapshot → apply → verify → commit/rollback; post-reboot `Reconcile`
- **Artifact generator** — nft, dnsmasq, Xray, nfqws, IPv4/IPv6 route/rule из одного конфига (manifest v6)
- **Auth** — Argon2id, setup token, CSRF, rate limit
- **VPN-подписка/Xray** — нормализация подписки VPN-провайдера, VLESS health-checks с EWMA и кворумом
- **TSPU cache** — multi-source, eTLD+1/wildcard matching, ETag/drop-ratio, SHA-256
- **GeoIP** — MaxMind MMDB, двухсорсный consensus

## Статус

FlintRoute пока находится в Alpha. Текущая сборка подходит для разработки и
контролируемых испытаний на Flint 2, но ещё не для установки «и забыл».

### Работает и проверено

- локальная сборка, тесты, race-проверка и выпуск ARM64-бинарника;
- транзакции конфигурации с commit/rollback и fail-closed поведением;
- Direct, Zapret, Drop и VLESS/Xray на GL-MT6000 с bound route evidence;
- два production Smart DNS resolver через UDP/53 и TCP/53, оба маршрута
  транзакционно активированы и проверены bound path evidence;
- восстановление committed dataplane после физической перезагрузки: controller,
  Xray, nfqws, nftables и policy rules;
- чистая установка на factory OpenWrt 24.10.4, первая транзакционная активация
  и повторное восстановление dataplane после reboot;
- persistent state в `/etc/router-policy/state` без зависимости от volatile `/var`;
- локальные API, авторизация, журнал изменений и встроенная консоль.

### Реализовано, но требует проверки на железе

- расширенная IPv6-матрица на реальных LAN-клиентах;
- downgrade и uninstall на отдельном чистом OpenWrt;
- работа под нагрузкой с несколькими клиентами.

### Запланировано

- аппаратное доказательство автоматической деградации и смены Zapret-профиля;
- полная protocol/AF-матрица и hard-crash fault injection;
- длительный soak-test;
- безопасный доступ к панели из LAN.

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

Проверяет: `go test`, `go vet`, `go test -race`, ShellCheck, frontend typecheck/build, ARM64 build, adapter integration.

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
router-policy candidates chatgpt.com openai
router-policy probe-route --route direct github.com github

# When the control plane already owns the state database, collect live
# transaction-bound evidence without trying to persist probe history:
router-policy probe-route --no-persist --route direct github.com github
router-policy check-domain github.com github
# Нормализовать VPN-подписку перед генерацией Xray-конфига:
router-policy subscription-normalize subscription.json
router-policy tspu-update --out tspu-cache.json
router-policy security audit
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
- `docs/flint2-hardware-report.md` — обезличенный отчёт по железу
- `docs/incidents.md` — аппаратные инциденты и найденные ошибки проверок
- `docs/status-matrix.md` — матрица готовности

## Платформа

- GL.iNet Flint 2 / GL-MT6000
- OpenWrt 24.10.4 с firewall4/nftables
- Linux arm64
- dnsmasq-full с nftset
- Xray для VLESS
- внешний `nfqws` arm64 для маршрута Zapret (бинарник не вендорится)

## Лицензия

Apache License 2.0. См. [LICENSE](LICENSE) и [NOTICE](NOTICE).

Copyright 2026 Zaqvierm
