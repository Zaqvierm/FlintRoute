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
| `/api/v1/topology` | topology |
| `/api/v1/devices` | LAN/guest/remote clients |
| `/api/v1/services` | configured and dynamically observed services |
| `/api/v1/services/classify` | create or edit a domain rule through a draft ChangeSet; optional `allowed_paths` preserves the user-defined fallback order |
| `/api/v1/discovery` | current discovery mode, limits, circuit-breaker state and suggestions |
| `/api/v1/discovery/configure` | create a ChangeSet for discovery mode/limits; optionally reset rollback pause |
| `/api/v1/domains` | domain policy / decision cache |
| `/api/v1/policies` | policy + overrides |
| `/api/v1/routes` | system default route, managed route descriptors and unclassified traffic as separate records |
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
| `/api/v1/zapret/adaptive/runtime` | production scheduler budget, fingerprint and live ranking |
| `/api/v1/zapret/adaptive/evaluate` | bounded profile evaluation and transactional bundle switch |
| `/api/v1/zapret/adaptive/state` | persisted active profile, cooldown, pin and quarantine state |
| `/api/v1/zapret/adaptive/pin` | set a validated bundle-local manual pin and allowed fallbacks |
| `/api/v1/zapret/adaptive/unpin` | clear the manual pin without changing unrelated bundles |
| `/api/v1/xray/subscription/secret` | store up to five subscription sources without returning their URLs |
| `/api/v1/xray/subscription/prepare` | merge and verify VPN subscriptions; candidate check only offers activation, explicit managed mode creates one ChangeSet with mode, bundle and routes |
| `/api/v1/events` | persisted history merged with live epoch |
| `/api/v1/events/stream` | SSE stream |
| `/api/v1/changes` `GET/POST` | list/create ChangeSet |
| `/api/v1/changes/{id}/{action}` | validate/apply/confirm/rollback/delete |
| `/api/v1/revisions` | committed revisions + active revision identity |
| `/api/v1/backups` | bbolt backup metadata, live size, SHA-256 verify |
| `/api/v1/settings` | safe projection of active typed config (secrets omitted) |
| `/api/v1/security` `/api/v1/security/audit` | security audit |
| `/api/v1/system` | system/provider status |
| `/api/v1/telegram` | read-only `not_implemented` status for Telegram notifications and `tg_ws_proxy` |

VLESS and Zapret setup endpoints are the normal user-facing control surface.
`/api/v1/changes` remains the transaction engine and an Advanced/Developer
interface; users do not need to construct JSON pointers for either provider.
Both activation endpoints only create a draft. The standard
`validate → apply → VerifyManagementPath → VerifyDataPlane → confirm` path is
still authoritative; a failed proof rolls the transaction back.

`/api/v1/lifecycle` различает `router-policy-xray` и штатный OpenWrt-сервис
`xray`. `inactive` у системного сервиса не считается ошибкой, если production
процесс принадлежит FlintRoute procd instance и его полная identity совпадает.
То же правило применяется к `router-policy-zapret` и системным Zapret/nfqws.

Lifecycle/storage endpoints доступны роли diagnostician и выше. Они не
изменяют persistent state. Возвращаются только hashes, размеры, счётчики и
allowlisted metadata; subscription URL, VLESS UUID, rollback capability и auth
tokens не включаются.

Telegram/TGWS пока не является рабочей частью control plane. Конфиг содержит
поля secret path, а route/proof schema знает тип `tg_ws_proxy`, но sender,
managed proxy process, installer и end-to-end verification отсутствуют.
`/api/v1/settings` показывает только наличие настроенного пути к secret-файлу,
не готовность доставки. Основной маршрутизатор от этой подсистемы не зависит.

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
- Telegram notifications и `tg_ws_proxy` runtime не реализованы.
- Роли кроме admin.
