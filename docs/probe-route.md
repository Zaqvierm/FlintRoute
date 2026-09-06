# Единый probe_route

> **Статус текущего remediation working tree:** software-контракт и локальные
> проверки актуальны; hardware evidence для установленного bundle привязана к
> отдельному evidence-файлу и не наследуется автоматически будущими SHA.

`probe.ProbeRoute(ctx, cfg, domain, serviceName, svc, route)` — единственная
функция, проверяющая любой маршрут. Источник: `internal/probe/probe.go`.

## Helper-backed marks и baseline

На OpenWrt controller работает non-root. Для `direct`, `zapret` и `smart_dns`
root helper на короткое время создаёт exact-owned `output` guard для UID
controller и ставит route mark через nft. Controller не пытается вызвать
`SO_MARK` сам: это требует `CAP_NET_ADMIN` и раньше превращало успешный
`example.com` в `connected_socket_observation_missing`. Фактический mark
подтверждается conntrack и owned-rule counter; временный нулевой conntrack
tuple не принимается как proof.

Synthetic `system-default` — отдельный unmarked baseline. К нему нельзя
применять managed mark guard: его proof должен показывать обычный kernel
default route. Smart DNS endpoints могут делить mark с Direct, поэтому их
проверка дополнительно связывается с конкретным `DNSResolver`, а не требует
счётчика только одного дублирующего комментария nft.

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
включён для `vless`, `ExternalIPProbe=true`, и для direct/zapret/external_socks вне
test-платформы. Для `RequireNonRUEgress` страна `RU` → `RU_EXIT`, пустая/`UNKNOWN`
→ `FAIL`.

### 4. Доказательство маршрута

`beginPathProof` / `finishWithPathProof` заполняют `PathVerified`, `AdapterRevision`,
`CandidateHash`, `ArtifactManifestHash`, `NFTMark`, `ConntrackMark`,
`IPRulePriority`, `RouteTable`, `Interface`, `SocketMark`, `XrayOutboundTag`,
`EvidenceSource`, `PathEvidence` (`evidence.RouteResult`). Полная проверка биндинга
— в `evidence.ValidateRouteProof` (см. `adapter-transaction.md`).

`PathVerified=false` → маршрут `UNVERIFIED`, production не выбирается.
Для route-only preflight verification plan также содержит `candidate_route_proofs`
для всех enabled owned routes. Это позволяет проверить новый маршрут до того,
как политика начнёт на него ссылаться, но не делает неиспользуемые маршруты
обязательным data-plane gate. Старые committed artifacts без этого поля
достраиваются детерминированно из той же committed config после проверки exact
active binding.
Если active binding отсутствует или не совпадает, probe возвращает typed
`INFRA_ERROR` (`active_binding_unavailable`/`active_binding_mismatch`). Это
ошибка инфраструктуры проверки, а не доказательство недоступности сайта через
каждый маршрут; planner останавливает проверку с диагностикой и не создаёт
`NO_SAFE_ROUTE` и не назначает правило.
`external_socks` не выдаётся за встроенный Telegram transport. Preflight проверяет
внешний loopback endpoint, а PathVerified подтверждает binding и фактический поток;
process lifecycle остаётся ответственностью внешнего компонента.

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
- `vless`/`external_socks` — loopback `socks5`, `dns_mode=socks_remote`,
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
