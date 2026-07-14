# VPN-провайдер и Xray

> Соответствует `internal/vpnsub/vpnsub.go` на commit `4634515`.
> Бренд конкретного провайдера из документации убран намеренно. FlintRoute не
> привязан к одному поставщику: он принимает любую совместимую Xray/VLESS
> подписку.

## Кто такой VPN-провайдер в этой системе

VPN-провайдер — внешний **сервис, предоставляющий по подписке (ключу) доступ к
списку VPN-серверов**. Доступ оформлен как HTTPS-подписка: URL, который отдаёт
Xray-конфиг или массив VLESS outbound-объектов. Серверы находятся в разных
юрисдикциях; каждый outbound описывает VLESS + REALITY/TLS/Vision.

FlintRoute **не владеет** серверами и не продаёт доступ. Он:
- читает подписку (URL хранится в секрете, `xray.subscription_secret_file`,
  mode 0600, вне репо/логов/UI/SSE);
- нормализует, дедуплицирует и классифицирует outbounds;
- генерирует локальный Xray-конфиг (SOCKS-порт per outbound);
- health-check'ит каждый exit через единый `probe.ProbeRoute`;
- связывает выбранный outbound с data-plane через транзакцию адаптера.

Ключ/подписка — секрет. UUID, адреса серверов, REALITY-ключи, URL подписки
никогда не попадают в bbolt/API/UI/SSE/логи.

## Pipeline

Подписка → extract → deduplicate → classify → retag → SOCKS inbound per
outbound → routing rule → content-addressed bundle.

## Accept-форма (`extractOutboundsWithShape`)

Подписка принимается в трёх top-level формах:

- **object** — один Xray config с `.outbounds`;
- **array of configs** — массив полных config-объектов, у каждого `.outbounds`;
- **array of outbounds** — массив одиночных outbound-объектов.

`Summary.TopLevelType` = `object`/`array`, `ConfigCount` — число top-level
конфигов. `extractRawOutbounds` сохраняет raw JSON каждого outbound.

## Classify (`validateVLESSOutbound`)

VLESS outbound получает `SUPPORTED` только если:

- `tag` матчит `safeTagPattern`;
- `settings.vnext`: 1..8 серверов, порт 1..65535, safe address (без
  `\x00\r\n\t /\\`, ≤253);
- `users`: 1..16, `id` = UUID, `encryption` пусто или `none`, `flow` пусто или
  `xtls-rprx-vision`;
- `streamSettings.security`: `tls` или `reality`;
- `streamSettings.network`: `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`.

Иначе `UNSUPPORTED` с reason (`invalid_tag`/`invalid_port`/`invalid_user_id`/
`unsupported_flow`/`unsupported_stream_security`/`unsupported_stream_network`).
`maxVLESSServers` глобально ограничивает число серверов → `server_limit_exceeded`.

## Deduplicate + retag (`prepareRawOutbounds`)

- **Identity** = SHA-256 от canonical JSON outbound **без поля `tag`**.
  Повторяющиеся identity → `DeduplicatedVLESS++`, отбрасываются (один и тот же
  сервер под разными тегами).
- Истинные коллизии tag (разные серверы, одинаковый tag) → `collisionSafeTag`:
  новый tag = `prefix + "-" + identity[:8..32]`. `SourceTag` сохраняет исходный.
- `Summary.DuplicateTags`, `DeduplicatedVLESSCount` — метрики нормализации.

## Generate (`GenerateXrayConfigFile`)

На каждый supported outbound:

- локальный SOCKS inbound `127.0.0.1:<basePort+idx>` (`socks-<tag>`,
  `auth=noauth`, `udp=true`, sniffing http/tls);
- исходный outbound JSON сохраняется как есть в `outbounds`;
- routing rule `inboundTag=[socks-<tag>]` → `outboundTag=<tag>`.

`domainStrategy=AsIs`, `log.loglevel=warning`. Файл пишется atomic mode 0600.

`XrayGenerationSummary` (safe, без секретов): `Inbounds`, `Outbounds`,
`RoutingRules`, `SOCKS5[]`, `Output`, `SHA256` (конфига, с финальным `\n`),
`SecretsPrinted=false`, `SubscriptionSHA256`, `Servers[]` (`Tag`, `SourceTag`,
`Status`, `Reason`, `SOCKS5`).

```powershell
.\dist\router-policy.exe vpnsub-xray --out .\xray.generated.json tests\sample-subscription-array.json
```

> CLI-имя `vpnsub-xray` — историческое имя реализации обработчика подписки
> (`internal/vpnsub`). Семантически это «сгенерировать Xray-конфиг из подписки
> VPN-провайдера».

## Routes (`GenerateRoutesFile`)

Генерирует `[]GeneratedRoute` для вставки в `config.routes`:

```json
{
  "type": "vless",
  "tag": "vpn-frankfurt-3",
  "priority": 100,
  "socks5": "127.0.0.1:12003",
  "dns_mode": "socks_remote",
  "external_ip_probe": true
}
```

`basePort` + idx → loopback SOCKS. `validatePortRange` проверяет 1024..65535 и
непересечение. Tag в конфиге — на ваше усмотрение, по умолчанию сохраняется из
подписки (или ретег при коллизии).

## Content-addressed bundle

Сгенерированный Xray-конфиг — content-addressed bundle под state-dir. Кандидат
хранит только `xray.outbound_bundle_sha256` + safe route metadata; UUID/адреса/
URL остаются вне bbolt/API/UI/SSE. `config.Validate` требует
`OutboundBundleSHA256` (regex `sha256:[0-9a-f]{64}`) при наличии enabled vless
routes. Artifact generator мержит bundle в транзакционный `xray.json`; mismatch
bundle hash/tag/SOCKS → validate fail.

## Live proof (история, обезличено)

На реальной подписке VPN-провайдера: 31 VLESS запись → 12 unique supported, 19
exact duplicates. Локальная сборка Xray 26.3.27 принимает 12-server bundle +
TPROXY inbounds. Health cycle: 10/12 exit non-RU OK, 1 UNVERIFIED (GeoIP
endpoints unreachable), 1 RU rejected, 1 selected (≈656 ms). Bundle hash
неизменен при пере-проверке.

## Четыре уровня в контексте VPN-подписки

1. **DNS resolution** — VLESS probe использует `dns_mode=socks_remote`:
   `queryDNSTCPViaSOCKS` (A+AAAA через loopback SOCKS, публичный resolver).
2. **Классификация** — `validateVLESSOutbound` решает supported/unsupported;
   `probeOne` проверяет HTTP/content/regional/TSPU.
3. **Фактический egress** — `probeExternalIP` через тот же SOCKS →
   `ExternalIPHash`/`ExternalCountry`/consensus. RU → `RU_EXIT`.
4. **Доказательство маршрута** — SOCKS inbound bound routing rule → VLESS
   outbound tag; `evidence.ValidateRouteProof` требует `SOCKS5Loopback=true` +
   bound `XrayOutboundTag == route.Tag`.

## Честное ограничение

Локальная генерация + `xray run -test` + health cycle доказаны. Persistent
activation на Flint 2 (install `/etc/router-policy/xray/active.json`, procd
lifecycle, per-exit external IP proof, route production-ready) — часть
data-plane фазы P3/P13. Смена провайдера = новая подписка + пересборка bundle;
маршруты остаются, если outbound tag/SHA-256 совпадают или конфиг обновлён.