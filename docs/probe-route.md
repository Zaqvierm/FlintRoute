# Единый probe_route

`probe.ProbeRoute(ctx, cfg, domain, serviceName, svc, route)` — единственная
функция, проверяющая любой маршрут. Источник: `internal/probe/probe.go`.

## Анти-паттерн

Отдельные `check_direct()`, `check_zapret()`, `check_vless()` запрещены
архитектурно. Route type отличается только `config.Route` дескриптором, а не
кодовой веткой проверки.

## Четыре независимых уровня

`probe.RouteResult` делит проверку на четыре уровня. Уровни независимы: успех
на одном не компенсирует провал на другом.

### 1. DNS resolution

`resolveForRoute` выбирает resolver по route type:

- `socks_remote` → `queryDNSTCPViaSOCKS` (DNS over SOCKS5, A+AAAA, loopback proxy);
- `smart_dns` → `queryDNS` (UDP с TCP-fallback на truncation, публичный resolver,
  `ConnectToResolvedIP` обязателен, unsafe-ответ отклоняется);
- иначе — `net.DefaultResolver` (`system`).

Каждый `CheckResult` несёт `DNSResolver`, `DNSProtocol`, `ResolvedIPs`.
`validateDNSResponse` проверяет transaction ID, rcode, question match, CNAME
loop/limit (≤8), размер ответа (≤16 KiB), лимит адресов (≤32), unrelated answer.

### 2. Классификация

`probeOne` → `runHTTPAttempt`: transport connect, TLS/SNI, HTTP status
(`ExpectedCodeMatched`), redirects, content markers (`ContentOK`),
`RegionalBlock`, `SuspectedTSPU`. Результат аггрегируется по всем `ProbeURLs`
сервиса: `required` probes должны быть OK, `optional` дают `DEGRADED`.

Статусы: `OK`, `DEGRADED`, `FAIL`, `REGION_BLOCK`, `SUSPECTED_TSPU`, `RU_EXIT`,
`NOT_CONFIGURED`.

### 3. Фактический egress

`probeExternalIP` (через тот же route) → `ExternalIPHash` (SHA-256 от IP),
`ExternalCountry`, `ExternalCountrySources`, `EgressConsensus`. Egress probe
включён для `vless`, `ExternalIPProbe=true`, и для direct/zapret/tg_ws_proxy вне
test-платформы. Для `RequireNonRUEgress` страна `RU` → `RU_EXIT`, пустая/`UNKNOWN`
→ `FAIL`.

### 4. Доказательство маршрута

`beginPathProof` / `finishWithPathProof` заполняют `PathVerified`, `AdapterRevision`,
`CandidateHash`, `ArtifactManifestHash`, `NFTMark`, `ConntrackMark`,
`IPRulePriority`, `RouteTable`, `Interface`, `SocketMark`, `XrayOutboundTag`,
`EvidenceSource`, `PathEvidence` (`evidence.RouteResult`). Полная проверка биндинга
— в `evidence.ValidateRouteProof` (см. `adapter-transaction.md`).

`PathVerified=false` → маршрут `UNVERIFIED`, production не выбирается.

## Route descriptor (`config.Route`)

```json
{
  "type": "vless",
  "tag": "vpn-frankfurt-3",
  "priority": 100,
  "socks5": "127.0.0.1:12003",
  "dns_mode": "socks_remote",
  "external_ip_probe": true,
  "requires_adapter": true,
  "adapter_mode": "managed",
  "mark": "0x100"
}
```

- `direct`/`drop` — без proxy fields.
- `smart_dns` — `dns_server` (публичный), `connect_to_resolved_ip=true`.
- `vless`/`tg_ws_proxy` — loopback `socks5`, `dns_mode=socks_remote`,
  `dns_server = xray.probe_dns_resolver` (порт 53, публичный).
- `zapret` — managed activation, fixed strategy.
- `disabled=true` или `status=NOT_CONFIGURED` → `NOT_CONFIGURED`, probe не идёт.

## Drop route

`type=drop` не делает HTTP probe. `exerciseDropProbe` проверяет enforcement
через path proof (`DropIPv4Enforced`, `DropIPv6Enforced`, `DropDNSEnforced`).
`ApplicationStatus=DROP`, результат проходит тот же `finishWithPathProof`.

## Ограничение проверки Zapret

Zapret как Anti-DPI — не отдельный curl proxy. `probe_route` подтверждает Zapret
только когда на роутере временно применён route namespace/mark, либо есть
локальный проверочный path через nfqws-обработку. До железного proof Zapret
остаётся dry-run моделью. Проверка direct-маршрута не считается доказательством
работы Zapret.
