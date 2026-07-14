# Архитектура

> Соответствует коду на commit `4634515`.

## Проверенные факты

- GL-MT6000 / Flint 2: Filogic 830, 4×Cortex-A53 2.0 GHz, 1 GB RAM, 8 GB eMMC.
- OpenWrt 24.10.4, firewall4/nftables (queue + tproxy support подтверждены),
  kernel 6.6.110.
- `dnsmasq-full` с nftset — путь для доменных политик.
- Xray: `xray run -test -c file.json` для проверки конфига; VLESS + REALITY/Vision.
- Zapret/nfqws — внешний Anti-DPI (pinned provider, не вендорится).
- Direct + fail-closed Drop и Zapret (`discord.com`) доказаны и committed на
  Flint 2 (см. `flint2-hardware-report.md`).

Источники совместимости: openwrt.org (gl-mt6000, firewall4, dnsmasq), xtls.github.io,
github.com/remittor/zapret-openwrt.

## Главная схема

```text
LAN client
  -> DNS request (53/tcp/udp перехват)
  -> Flint 2 dnsmasq/full resolver
  -> policy classifier (service/category/override/TSPU)
  -> nft sets для IPv4/IPv6
  -> nftables mark + collision guard
  -> policy route (IP rule -> table)
  -> WAN | Zapret/nfqws | smart DNS path | Xray VLESS | DROP
```

## Плоскости системы

### Presentation plane

Только web UI (Aegis Console): Preact/Vite static bundle, отдаётся из
`router-policy serve`, не содержит секретов, не вызывает shell/OpenWrt напрямую.
Все изменения — через `/api/v1/changes`.

### Control plane

Go-ядро (`internal/*`):
- `probe.ProbeRoute` — единая проверка маршрута (4 уровня);
- `health.Service.RunCycle` — VLESS quorum, EWMA, hysteresis, roles;
- planner / candidate builder / route selector;
- auth/session/CSRF, SSE events;
- ChangeSet validation/apply/confirm/rollback state machine;
- `artifact.Generate` — nft/dnsmasq/Xray/nfqws/IP plan/verification plan;
- `api.recoverCommittedDataplane` — post-reboot recovery через `adapter.Reconcile`;
- security audit.

Control plane принимает решения, но не молча ломает data plane. Опасный apply
идёт через backup, staged apply, confirm window, rollback.

### Data plane

OpenWrt-слой (`adapter.OpenWrt` + `openwrt/adapter.sh`):
- dnsmasq-full, nftables/firewall4, policy routing;
- Xray (TPROXY + SOCKS per outbound), Zapret/nfqws (NFQUEUE fail-closed);
- procd watchdog, boot guard.

Data plane недоверен к автоматическому включению, пока не снята диагностика
конкретного Flint 2. `--activate` gated через confirmed diagnostics.

## Компоненты

### DNS gateway

- DHCP/DNS для LAN; перехват 53/tcp и 53/udp;
- нормализация доменов (IDN, eTLD+1), отделение локальных зон;
- пополнение nft sets; DoT блокировка (853), DoH — по спискам;
- не задерживает запросы длинными проверками (решение выбирается заранее).

### Policy / availability database

bbolt: `changes`, `candidates`, `revisions`, `transactions`, `probes`, `events`,
`meta`. Матрица `domain/service × route × state × latency × reason × checked_at`.
Состояния: `OK`, `DEGRADED`, `FAIL`, `FORBIDDEN`, `UNKNOWN`, `STALE`,
`UNVERIFIED`, `NOT_CONFIGURED`. Domain decision cache: bounded LRU, revision-bound,
TTL. Retention по bounded probe count и time-based политикам.

### Route selector

Выбирает путь заранее, не во время DNS-запроса. `path_verified` обязателен.
Hysteresis: failure/recovery streaks, route hold, cooldown, quarantine. Для
`GEO_LOCKED` российский egress запрещён; нет безопасного пути → DROP.

### Unified probe engine

`probe.ProbeRoute(domain, service, route)` — один интерфейс для всех route types.
`direct`, `zapret`, `smart_dns`, `tg_ws_proxy`, `vless`, `drop` отличаются только
`config.Route`. Отдельные `check_*()` запрещены архитектурно.

### Xray и VPN-провайдер

Xray используется напрямую. VPN-провайдер — внешний сервис доступа к
VPN-серверам по подписке (ключу): отдаёт Xray-конфиг или массив VLESS outbounds.
Подписка может прийти в трёх формах (object / array of configs / array of
outbounds) — см. `vpn-subscription.md`. FlintRoute нормализует, дедуплицирует,
классифицирует и генерирует локальный Xray-конфиг (SOCKS per outbound).
Секреты (UUID, адреса, REALITY-ключи, URL подписки) вне bbolt/API/UI/SSE.

### Zapret/nfqws

Anti-DPI, не VPN. Managed lifecycle: fixed reviewed strategy
(`tls-fake-ttl3-v1`), NFQUEUE fail-closed (no `bypass`), `--dry-run` before
apply. Произвольные nfqws-аргументы запрещены. Бинарник не вендорится.

## Четыре уровня (архитектурный контракт)

1. **DNS resolution** — `resolveForRoute`: system / smart_dns / socks_remote.
2. **Классификация** — `probeOne`→`runHTTPAttempt`: HTTP/content/regional/TSPU.
3. **Фактический egress** — `probeExternalIP`: hash + country consensus.
4. **Доказательство маршрута** — `evidence.ValidateRouteProof`: per-type bound
   proof (mark/rule/table/outbound/SOCKS/Drop enforcement).

Уровни независимы. `path_verified=false` → маршрут не production-ready.

## Слои (по графу кода)

`api` (entry) → `probe`/`auth`/`platform`/`adapter` (core) → `state` (core,
high fan-in). Boundaries: api→state, probe→domaincache, api→probe, api→auth,
api→platform, api→adapter, domaincache→state, subscription→state, subscription→probe,
domaincache→tspu.