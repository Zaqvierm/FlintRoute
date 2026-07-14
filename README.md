# FlintRoute

**Выборочная маршрутизация для GL.iNet Flint 2 / GL-MT6000 на OpenWrt.**

Роутер сам выбирает маршрут для каждого домена: `direct`, `Zapret`, `smart_dns`, `VLESS/Xray` или `DROP`. Клиенты ничего не настраивают — получают Flint 2 как обычный шлюз и DNS.

## Принцип

Один движок проверки для всех маршрутов:

```
probe_route(domain, service, route)
```

Планировщик выбирает маршрут по доказательствам, а не по догадкам. Проверка
делится на четыре независимых уровня:

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

Alpha. Локально всё собирается и проходит тесты. На Flint 2 доказаны и
committed: P1 (Direct + fail-closed Drop, `github.com`) и P3 (Zapret
`discord.com` с NFQUEUE proof). Post-reboot recovery реализован и локально
тестирован; физический reboot — часть P13. Полная матрица Smart DNS/VLESS
activation, reboot/crash, multi-client и 72h soak не закрыта. См.
[docs/flint2-hardware-report.md](docs/flint2-hardware-report.md).

| Фаза | Описание | Готовность |
|------|----------|-----------|
| P0 | Transaction state machine, bbolt, adapter | 100% |
| P0.5 | Candidate-bound артефакты, shell adapter | 100% |
| P1 | Route proof engine, Smart DNS, VPN/Xray, VLESS health, GeoIP | 100% |
| P2 | TSPU cache v2, eTLD+1, domain profiling | 75% |
| P3 | nft/dnsmasq/Xray/Zapret/IP-plan, managed procd lifecycle, flow-offload, DNS proxy; Zapret hardware proof | 85% |
| P4 | Telegram notifications, tg-ws-proxy | 0% |
| P5 | Production OpenWrt provider, API | 85% |
| P6 | Post-reboot recovery (`Reconcile`), boot guard | 55% (код+тесты; физ reboot = P13) |
| P7 | Auth, security audit | 60% |
| P8 | Web UI (Aegis Console) | 15% |
| P9 | Network access (loopback, LAN HTTPS) | 40% |
| P10 | Build, installer, packaging | 30% |
| P11 | Test suites | 85% |
| P12 | Adaptive Zapret strategy orchestration ([design](docs/adaptive-zapret-strategy.md)) | 10% |
| P13 | Full Flint 2 hardware validation ([matrix](docs/flint2-hardware-validation.md)) | 35% |

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

# Установка файлов
sh install.sh --install

# Включить сервисы
sh install.sh --install --enable-services

# Откат
sh install.sh --rollback

# Удаление
sh uninstall.sh --uninstall
```

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
# Сгенерировать Xray-конфиг из подписки VPN-провайдера (историческое имя vpnsub-normalize):
router-policy vpnsub-normalize subscription.json
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