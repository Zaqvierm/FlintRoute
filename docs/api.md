# API And Control Plane

> Основная реализация: `internal/api/*`.

## Planes

| Plane | Contents | Status |
|---|---|---|
| Presentation | Preact/Vite UI embedded into the Go binary | local build works |
| Control | `/api/v1`, auth, ChangeSet, planner, `probe_route`, audit, recovery | tested locally |
| Data | nftables, dnsmasq, fw4, Xray, Zapret, policy routing | requires diagnostics and proof from the target OpenWrt device |

UI никогда не пишет nftables/Xray/dnsmasq/UCI/routes/fw4 напрямую. Любая
state-changing операция идёт через API и ChangeSet.

## Auth

- Default listener `127.0.0.1:8787`. Non-loopback bind требует
  `ROUTER_POLICY_ALLOW_FIREWALLED_BIND=1`; на OpenWrt его включает только
  `/etc/router-policy/config/listener.conf` с `allow_firewalled_bind=1`.
- Нет default admin password. Первый admin — через one-time setup token.
- Пароли — Argon2id hashes, bounded params, concurrency-limited.
- User/setup файлы — atomic (temp + fsync + rename).
- Session — HttpOnly cookie `rp_session`. JSON login не отдаёт session ID.
- CSRF header `X-CSRF-Token` для state-changing `/api/v1/*`.
- Body limit 1 MiB. Responses несут `request_id` + `X-Request-ID`.
- Session ID, CSRF token, setup token, revision/transaction IDs и имена atomic
  temp-файлов создаются только через проверенный `crypto/rand`; ошибка entropy
  source останавливает операцию.
- Security audit различает loopback, wildcard и non-loopback listeners.
  Opt-in разрешает bind, но не создаёт firewall rule: доступ обязан быть
  ограничен management subnet отдельным правилом firewall4.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `/api/v1/health` | unauthenticated local watchdog health |
| `/api/v1/auth/login` `setup` `logout` `me` | session lifecycle |
| `/api/v1/overview` | provider overview |
| `/api/v1/topology` | topology assembled from ubus, leases, neighbours, bridge FDB and wireless stations |
| `/api/v1/devices` | LAN/guest/remote clients; addresses are masked unless `privacy=revealed` is explicitly requested |
| `/api/v1/services` | configured and dynamically observed services |
| `/api/v1/services/classify` | create or edit a domain rule through a draft ChangeSet; optional `allowed_paths` preserves the user-defined fallback order |
| `/api/v1/discovery` | current discovery mode, limits, circuit-breaker state and suggestions |
| `/api/v1/discovery/configure` | persist control-plane discovery mode/limits without changing the data plane; optionally reset rollback pause |
| `/api/v1/domains` | domain policy / decision cache |
| `/api/v1/policies` | policy + overrides |
| `/api/v1/routes` | system default route, managed route descriptors and unclassified traffic as separate records |
| `/api/v1/components` `/components/{kind}` | managed Xray, Zapret and TG WS Proxy install/version/service/health status |
| `/api/v1/components/action` | install, check, check updates, update, restart, rollback or uninstall a pinned component |
| `/api/v1/tgws` | managed TG WS Proxy status without secret material |
| `/api/v1/tgws/configure` | create safe config, start procd, verify listener/DC and return one one-time client link |
| `/api/v1/traffic` | cumulative RX/TX bytes, packets and errors from `/proc/net/dev` |
| `/api/v1/probes` | persisted probe evidence; `domain`/`service`/`route`/`limit` filters |
| `/api/v1/route-health` | VLESS health matrix, selected/standby/quarantine roles |
| `/api/v1/proxies` | proxy/VLESS server status |
| `/api/v1/diagnostics` | network diagnostics provenance (source/hash/expiry/simulation) |
| `/api/v1/lifecycle` | procd ownership, PID/start time/executable/config и test-run manifests |
| `/api/v1/storage` | storage sizes, rollback state и логические write counters |
| `/api/v1/smart-dns` | redacted Smart DNS state and fallback order |
| `/api/v1/smart-dns/configure` | validate resolver IP/port over UDP+TCP DNS and HTTP/TLS, then create a draft ChangeSet |
| `/api/v1/zapret` | managed Zapret/nfqws state and pin status |
| `/api/v1/zapret/setup/check` | verify pinned source/version/SHA, binary, architecture, NFQUEUE and nfqws dry-run without changing config |
| `/api/v1/zapret/setup/activate` | repeat preflight and create one managed Zapret ChangeSet with the enabled route |
| `/api/v1/zapret/calibration` | GET status, POST bounded blockcheck run, DELETE cancellation and owned cleanup |
| `/api/v1/zapret/adaptive/runtime` | production scheduler budget, fingerprint and live ranking |
| `/api/v1/zapret/adaptive/evaluate` | bounded profile evaluation and transactional bundle switch |
| `/api/v1/zapret/adaptive/state` | persisted active profile, cooldown, pin and quarantine state |
| `/api/v1/zapret/adaptive/pin` | set a validated bundle-local manual pin and allowed fallbacks |
| `/api/v1/zapret/adaptive/unpin` | clear the manual pin without changing unrelated bundles |
| `/api/v1/xray/subscription/secret` | store up to five subscription sources without returning their URLs |
| `/api/v1/xray/subscription/prepare` | merge and verify VPN subscriptions; candidate check only offers activation, explicit managed mode creates one ChangeSet with mode, bundle and routes |
| `/api/v1/xray/manual-servers` | list safe metadata, add or delete manual VLESS outbounds; UUID and source URI are never returned |
| `/api/v1/xray/pool` `/pool/settings` | logical servers, credential sources, tariff and explainable score |
| `/api/v1/xray/pool/speedtest` | bounded manual throughput measurement through one verified loopback VLESS SOCKS path |
| `/api/v1/events` | persisted history merged with live epoch |
| `/api/v1/events/stream` | SSE stream |
| `/api/v1/changes` `GET/POST` | list/create ChangeSet |
| `/api/v1/changes/{id}/{action}` | validate/apply/confirm/rollback/delete |
| `/api/v1/revisions` | committed revisions + active revision identity |
| `/api/v1/backups` | bbolt backup metadata, live size, SHA-256 verify |
| `/api/v1/settings` | safe projection of active typed config (secrets omitted) |
| `/api/v1/security` `/api/v1/security/audit` | security audit |
| `/api/v1/system` | system/provider status |
| `/api/v1/telegram` | notification state without token or chat ID |
| `/api/v1/telegram/configure` | verify bot/chat and atomically store notification settings |
| `/api/v1/telegram/test` | send a real test notification |
| `/api/v1/external-socks` | external dependency and route status |
| `/api/v1/external-socks/check` | TCP/SOCKS5/remote-connect/TLS/HTTP preflight without config changes |
| `/api/v1/external-socks/activate` | create one explicit ChangeSet for Xray, route and test-domain binding |

VLESS and Zapret setup endpoints are the normal user-facing control surface.
`/api/v1/changes` remains the transaction engine and an Advanced/Developer
interface; users do not need to construct JSON pointers for either provider.
Both activation endpoints only create a draft. The standard
`validate → apply → VerifyManagementPath → VerifyDataPlane → confirm` path is
still authoritative; a failed proof rolls the transaction back.

Manual VLESS input uses a separate secret store under the Xray state directory.
The API accepts a `vless://` URI, validates supported transport/security fields,
and persists only the generated outbound with mode `0600`. Listing returns safe
metadata only. Subscription and manual outbounds are merged before the same
candidate health check; adding a manual server does not silently enable managed
Xray or change routing.

Device privacy is enforced by the provider, not CSS. In the default response
raw `ip`/`mac` are `null`; masks exist only in `ip_display`/`mac_display`.
`privacy=revealed` is an explicit authenticated
request used by the temporary reveal control; the hidden values are therefore
absent from the DOM in normal mode.

`/api/v1/lifecycle` различает `router-policy-xray` и штатный OpenWrt-сервис
`xray`. `inactive` у системного сервиса не считается ошибкой, если production
процесс принадлежит FlintRoute procd instance и его полная identity совпадает.
То же правило применяется к `router-policy-zapret` и системным Zapret/nfqws.

Lifecycle/storage endpoints доступны роли diagnostician и выше. Они не
изменяют persistent state. Возвращаются только hashes, размеры, счётчики и
allowlisted metadata; subscription URL, VLESS UUID, rollback capability и auth
tokens не включаются.

Telegram notifications работают отдельно от routing bootstrap; статус строится
по проверенной конфигурации, а не по наличию пути к secret-файлу. Component
Manager управляет OpenWrt package TG WS Proxy, но этот upstream является
server-side MTProxy/WebSocket transport и не притворяется локальным SOCKS5
client. `GET /api/v1/tgws` возвращает состояние без секрета, а
`POST /api/v1/tgws/configure` атомарно создаёт конфигурацию, включает procd и
один раз возвращает клиентскую `tg://proxy` ссылку. Проверяются listener и
доступность Telegram DC; клиентский PASS требует открытия ссылки в Telegram.
`external_socks` остаётся явным Advanced-маршрутом и проверяется до ChangeSet.
Подробности — в
[`telegram-notifications.md`](telegram-notifications.md).

`/api/v1/routes` не называет системный default route управляемым Direct.
Синтетические записи `system_default` и `unclassified` имеют `managed=false`;
настроенный route `direct` имеет `managed=true` и список доменов, для которых
созданы FlintRoute sets/rules. Baseline не создаёт catch-all правило.

Discovery по умолчанию работает в `observe_only`. `suggest` сохраняет
классифицированное предложение в bounded RAM cache (до 256 доменов), `locked`
останавливает probe, а
`auto_apply_verified` требует `PathVerified`, свободный transaction slot и
rollback timer. Часовой лимит задаётся policy, management/firewall operations
не допускаются, а серия rollback открывает circuit breaker. Direct/Drop
наблюдения автоматически не закрепляются: блокировка и захват прямого трафика
остаются явным действием администратора.

Смена режима и лимитов Discovery является control-plane настройкой. Она
сохраняется отдельно от route config и не создаёт ChangeSet, не перезапускает
dnsmasq и не трогает data plane.

Успешный Smart DNS preflight сохраняет короткоживущий proof для конкретного
resolver endpoint. Candidate validation и apply требуют непротухший proof;
одинаковый уже активный resolver не блокирует несвязанный ChangeSet.

## ChangeSet

```text
draft -> validated -> prepared -> applying -> verifying
      -> awaiting_confirmation -> committing -> committed
rolling_back -> rolled_back | rollback_failed
failed | expired | requires_device
```

`validate` клонирует active typed config, применяет все операции, запускает
`config.Validate()`, persist полный canonical candidate, SHA-256. Неподдержанные
операции → `draft` + error.

Создание ChangeSet требует непустой список явных операций и текущий
`config_version` из `/api/v1/revisions`. UI не подставляет скрытую операцию или
фиксированную базовую версию.

`apply` создаёт revision/transaction metadata и вызывает adapter contract:
`Prepare → ValidateCandidate → SnapshotCurrent → ApplyCandidate →
VerifyManagementPath → VerifyDataPlane`. `SKIPPED`/`UNVERIFIED` →
`requires_device`.

Для обычного LAN-запроса `POST .../apply` автоматически формирует подписанный
management proof из фактических remote/local адресов HTTP-соединения,
LAN-интерфейса и подсети. Необязательное поле `management_mode` принимает `lan`
(значение по умолчанию) или `headless`. В headless-режиме proof сначала выдаётся
локальной CLI из активной SSH-сессии; apply только проверяет его и расширяет
rollback window.

`confirm` вызывает `Adapter.Commit` только после обоих verification flags, expiry,
candidate hash, adapter revision match и повторной проверки management proof.
LAN confirm должен прийти через тот же интерфейс и подсеть. Headless confirm
требует явное `{"management_mode":"headless"}` и loopback API. Proof от другой
revision/transaction, прошлого boot или с истёкшим TTL отклоняется.

## SSE

```text
id: 12
event: change.created
data: {"id":12,"time":"...","type":"change.created",...}
```

Каждый event + header несёт process-unique stream epoch. Клиенты шлют
`Last-Event-ID` + `Last-Event-EPoch`; после restart mismatched epoch сбрасывает
in-memory replay. `/api/v1/events` читает prior epochs из bbolt. HTTP server без
global WriteTimeout — SSE не режется после 60 секунд.

Events: `system.start`, `admin.login`, `route.decision`, `security.guard`,
`change.created`, `change.validated`, `change.awaiting_confirmation`,
`change.committed`, `change.rolled_back`. Concurrent streams — bounded.

## Recovery (P6)

При старте сервера `recoverCommittedDataplane` восстанавливает committed
dataplane через `adapter.Reconcile(RecoveryTarget)` и проверяет bindings через
`adapter.Status`. Результат — в `meta/recovery_status` (bbolt) и отражается в
`/api/v1/system`. См. `adapter-transaction.md`.

## OpenWrt Provider Truth Model

Production uses fixed-command, read-only OpenWrt provider. `ubus`/`ip`/`uci`/
`/proc`/`/sys`/`fw4`/`nft`/DHCP leases/process state — без shell fragments из HTTP.
Каждый ответ несёт source, collection time, freshness/status, `simulation=false`.
Missing/malformed → unavailable; production не подставляет dev-mock.
Simulation devices never receive fabricated raw identity, even when reveal is
requested. `simulation=true` is not accepted as deployment evidence.

Provider доказывает observed config/process state. Он не превращает HTTP 200 или
имя route в route evidence. Direct/Zapret/Smart DNS/VLESS остаются `UNVERIFIED`
пока probe result не bound к active adapter revision + packet/route evidence.

## Четыре уровня в API

API/SSE/ChangeSet отдаёт route evidence по тем же четырём уровням, что probe:
DNS resolution, классификация, фактический egress, доказательство маршрута.
`/api/v1/probes` и `/api/v1/route-health` несут `path_verified`,
`adapter_revision`, `candidate_hash`, `external_country`, `egress_consensus`.

## Current Limits

- Provider fixture-tested; сохранённое hardware evidence относится к активному
  Flint 2 dataplane. Код не блокирует другие модели по имени, но их
  совместимость не доказана.
- Zapret/Xray `NOT_CONFIGURED` на устройстве без бинарника.
- Direct/Zapret/Drop/VLESS и два Smart DNS resolver ранее доказаны на Flint 2;
  factory config намеренно не содержит resolver endpoints.
- External bind проверен за source-restricted firewall rule. TLS termination
  пока не встроен; для недоверенной сети нужен reverse proxy/VPN.
- Telegram delivery и внешний SOCKS endpoint требуют аппаратной проверки с
  пользовательскими credentials; собственный TGWS transport не поставляется.
- Роли кроме admin.
