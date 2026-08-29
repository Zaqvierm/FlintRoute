# Архитектура

> **Статус на `e97f8dd`:** software-описание актуально. Раздел «Проверенные
> аппаратные факты» ниже — исторический и имеет `STALE FOR CURRENT SHA`: в этом
> цикле Flint 2 не подключался.

> Основные реализации находятся в `internal/*`, `cmd/router-policy` и
> `openwrt/*`.

## Платформенная граница

Исполняемый код ориентирован на OpenWrt primitives (`procd`, `ubus`,
firewall4/nftables, dnsmasq и policy routing), а не на проверку конкретной модели
роутера. Новая установка использует `platform.target=openwrt`; legacy-значение
`glinet-flint2` принимается без переписывания existing revisions. Оба production
target применяют одинаковые инварианты persistent/runtime storage.

Имена `lan`, `wan` и `br-lan` не являются контрактом. Logical interfaces
читаются через UBUS dump, WAN связывается с main default route, а management
proof требует фактический socket path и reachable neighbor. Полная карта
ограничений находится в `network-platform-audit.md`.

`config/default.json` больше не кодирует модель устройства. Готовый Linux arm64
package и всё текущее аппаратное evidence относятся к GL-MT6000. Совместимость
с другим OpenWrt-железом не заявляется без отдельной диагностики и проверки.

## Исторические аппаратные факты (`STALE FOR CURRENT SHA`)

- GL-MT6000 / Flint 2: Filogic 830, 4×Cortex-A53 2,0 ГГц, 1 ГБ ОЗУ, 8 ГБ eMMC.
- OpenWrt 24.10.4, firewall4/nftables (queue + tproxy support подтверждены),
ядро 6.6.110.
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
  -> OpenWrt dnsmasq/full resolver
  -> policy classifier (service/category/override/TSPU)
  -> nft sets для IPv4/IPv6
  -> nftables mark + collision guard
  -> policy route (IP rule -> table)
  -> WAN | Zapret/nfqws | smart DNS path | Xray VLESS | DROP
```

## Плоскости системы

### Плоскость презентации

Встроенный Web UI: Preact/Vite static bundle, отдаётся из
`router-policy serve`, не содержит секретов, не вызывает shell/OpenWrt напрямую.
Все изменения — через `/api/v1/changes`.

### Концентратор плоскости управления

Go-ядро (`internal/*`):
- `probe.ProbeRoute` — единая проверка маршрута (4 уровня);
- `health.Service.RunCycle` — VLESS кворум, EWMA, гистерезис, роли;
- планировщик /конструктор кандидатов/селектор маршрутов;
- события auth/session/CSRF, SSE;
- Машина состояния проверки/применения/подтверждения/отката ChangeSet;
- `artifact.Generate` — nft/dnsmasq/Xray/nfqws/IP план/план верификации;
- `api.recoverCommittedDataplane` — post-reboot recovery через `adapter.Reconcile`;
- аудит безопасности

Control plane принимает решения, но не молча ломает data plane. Опасный apply
идёт через backup, staged apply, confirm window, rollback.

### Плоскость данных

OpenWrt-слой (`adapter.OpenWrt` + `openwrt/adapter.sh`):
- dnsmasq-full, nftables/firewall4, маршрутизация политик;
- Xray (TPROXY + SOCKS на исходящий), Zapret/nfqws (NFQUEUE закрыт при отказе);
- Сторожевой таймер procd, ограждение багажника.

Data plane недоверен к автоматическому включению, пока не снята диагностика
целевого OpenWrt-устройства. `--activate` gated через confirmed diagnostics.

## Компоненты

### Шлюз DNS

- DHCP/DNS для LAN; перехват 53/tcp и 53/udp;
- нормализация доменов (IDN, eTLD+1), отделение локальных зон;
- пополнение nft sets; DoT блокировка (853), DoH — по спискам;
- не задерживает запросы длинными проверками (решение выбирается заранее).

### База данных политики / доступности

bbolt: `changes`, `candidates`, `revisions`, `transactions`, `probes`, `events`,
`meta`. Матрица `domain/service × route × state × latency × reason × checked_at`.
Состояния: `OK`, `DEGRADED`, `FAIL`, `FORBIDDEN`, `UNKNOWN`, `STALE`,
`UNVERIFIED`, `NOT_CONFIGURED`. Кэш решений домена: ограниченный LRU, ограниченный ревизией,
TTL. Retention по bounded probe count и time-based политикам.

### Выбор маршрута

Выбирает путь заранее, не во время DNS-запроса. `path_verified` обязателен.
Hysteresis: failure/recovery streaks, route hold, cooldown, quarantine. Для
`GEO_LOCKED` российский egress запрещён; нет безопасного пути → DROP.

Обычный default route принадлежит OpenWrt, а не FlintRoute. Baseline revision
нужна control plane как безопасная committed точка, но не добавляет catch-all
mark или переход в managed route chain. Только домены из service/override sets
получают `FlintRoute-managed Direct`, Zapret, Smart DNS, VLESS или Drop.
Остальной трафик остаётся `unclassified` и использует system default route.

Drop — единый fail-closed сценарий: dnsmasq возвращает локальный NXDOMAIN без
upstream forwarding, A/AAAA nft sets попадают в drop route chain, mark
устанавливается до drop, а forward guard режет и meta mark, и conntrack mark.

Smart DNS — conditional DNS, не туннель и не VPN. Его resolver можно включить
только после публичного IP/bogon guard, UDP и TCP DNS-запросов, проверки
полученных адресов и HTTP/TLS-запроса к выбранному домену с подключением к
ответу resolver. Proof живёт десять минут и повторно проверяется перед apply.

Discovery отделяет наблюдение от изменения конфигурации: `observe_only` только
пишет решение в bounded runtime/event stream, `suggest` сохраняет предложение.
`auto_apply_verified` — доступный, но узкий route-only контракт: при наличии
зарегистрированного production consumer он меняет только exact-owned dnsmasq
overlay для уже включённого маршрута, с revision-bound receipt и post-apply
proof. При отсутствии consumer режим остаётся fenced и возвращает
`route_assignment_runtime_unavailable`; полный ChangeSet из DNS-события не
создаётся. `locked` не запускает probe.
Предложения ограничены 256 доменами и не пишутся в persistent DB. Заводской
режим — `observe_only`.

### Унифицированный датчик двигателя

`probe.ProbeRoute(domain, service, route)` — один интерфейс для всех route types.
Рабочие маршруты `direct`, `zapret`, `smart_dns`, `vless`, `drop` отличаются
`config.Route`. `external_socks` использует проверенный внешний loopback SOCKS5;
FlintRoute не устанавливает и не управляет этим transport. Активация маршрута
проходит через общий ChangeSet и unified PathVerified contract. Отдельные
route-specific apply-механизмы запрещены архитектурно.

### Xray и VPN-провайдер

Xray используется напрямую. VPN-провайдер — внешний сервис доступа к
VPN-серверам по подписке (ключу): отдаёт Xray-конфиг или массив VLESS outbounds.
Подписка может прийти в трёх формах (object / array of configs / array of
outbounds) — см. `vpn-subscription.md`. Ручной `vless://` URI хранится отдельно
и входит в тот же candidate bundle. FlintRoute нормализует, дедуплицирует,
классифицирует и генерирует локальный Xray-конфиг (SOCKS per outbound).
UUID, исходный URI, REALITY credentials и URL подписки не возвращаются через
API/UI/SSE; безопасная инвентаризация может показывать hostname и порт сервера.

### Zapret/nfqws

Anti-DPI, не VPN. Managed lifecycle: fixed reviewed strategy
(`tls-fake-ttl3-v1`), NFQUEUE закрыт при отказе (без `bypass`), `--dry-run` ДО
apply. Произвольные nfqws-аргументы запрещены. Бинарник не вендорится.

## Четыре уровня (архитектурный контракт)

1. **Разрешение DNS** — `resolveForRoute`: system / smart_dns / socks_remote.
2. **Классификация** — `probeOne`→`runHTTPAttempt`: HTTP/content/regional/TSPU.
3. **Фактический egress** — `probeExternalIP`: hash + country consensus.
4. **Доказательство маршрута** — `evidence.ValidateRouteProof`: per-type bound
доказательство (mark/rule/table/outbound/SOCKS/Drop enforcement).

Уровни независимы. `path_verified=false` → маршрут не production-ready.

## Слои (по графу кода)

`api` (вход) → `probe`/`auth`/`platform`/`adapter` (сердечник) → `state` (сердечник,
high fan-in). Границы: api→state, probe→domaincache, api→probe, api→auth,
api→платформа, api→адаптер,→ состояние кэша домена,→ состояние подписки,→ зонд подписки,
domaincache→tspu.
