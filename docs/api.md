# API And Control Plane

> Основная реализация: `internal/api/*`.

## Planes

| Plane | Contents | Status |
|---|---|---|
| Presentation | Preact/Vite UI embedded into the Go binary | local build works |
| Control | `/api/v1`, auth, ChangeSet, planner, `probe_route`, audit, recovery | tested locally |
| Data | nftables, dnsmasq, fw4, Xray, Zapret, policy routing | gated until Flint 2 proof |

UI никогда не пишет nftables/Xray/dnsmasq/UCI/routes/fw4 напрямую. Любая
state-changing операция идёт через API и ChangeSet.

## Auth

- Default listener `127.0.0.1:8787`. Non-loopback bind требует
  `ROUTER_POLICY_ALLOW_UNSAFE_LAN_BIND=...` (bootstrap guard).
- Нет default admin password. Первый admin — через one-time setup token.
- Пароли — Argon2id hashes, bounded params, concurrency-limited.
- User/setup файлы — atomic (temp + fsync + rename).
- Session — HttpOnly cookie `rp_session`. JSON login не отдаёт session ID.
- CSRF header `X-CSRF-Token` для state-changing `/api/v1/*`.
- Body limit 1 MiB. Responses несут `request_id` + `X-Request-ID`.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `/api/v1/health` | unauthenticated local watchdog health |
| `/api/v1/auth/login` `setup` `logout` `me` | session lifecycle |
| `/api/v1/overview` | provider overview |
| `/api/v1/topology` | topology |
| `/api/v1/devices` | LAN/guest/remote clients |
| `/api/v1/services` | configured services |
| `/api/v1/domains` | domain policy / decision cache |
| `/api/v1/policies` | policy + overrides |
| `/api/v1/routes` | route descriptors, including disabled |
| `/api/v1/probes` | persisted probe evidence; `domain`/`service`/`route`/`limit` filters |
| `/api/v1/route-health` | VLESS health matrix, selected/standby/quarantine roles |
| `/api/v1/proxies` | proxy/VLESS server status |
| `/api/v1/diagnostics` | network diagnostics provenance (source/hash/expiry/simulation) |
| `/api/v1/smart-dns` | smart DNS state |
| `/api/v1/zapret` | managed Zapret/nfqws plan state |
| `/api/v1/zapret/adaptive/evaluate` | bounded profile evaluation and transactional bundle switch |
| `/api/v1/xray/subscription/prepare` | authenticated VPN-подписка → draft ChangeSet |
| `/api/v1/events` | persisted history merged with live epoch |
| `/api/v1/events/stream` | SSE stream |
| `/api/v1/changes` `GET/POST` | list/create ChangeSet |
| `/api/v1/changes/{id}/{action}` | validate/apply/confirm/rollback/delete |
| `/api/v1/revisions` | committed revisions + active revision identity |
| `/api/v1/backups` | bbolt backup metadata, live size, SHA-256 verify |
| `/api/v1/settings` | safe projection of active typed config (secrets omitted) |
| `/api/v1/security` `/api/v1/security/audit` | security audit |
| `/api/v1/system` | system/provider status |
| `/api/v1/telegram` | telegram notification config (secrets in files) |

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

`apply` создаёт revision/transaction metadata и вызывает adapter contract:
`Prepare → ValidateCandidate → SnapshotCurrent → ApplyCandidate →
VerifyManagementPath → VerifyDataPlane`. `SKIPPED`/`UNVERIFIED` →
`requires_device`.

`confirm` вызывает `Adapter.Commit` только после обоих verification flags, expiry,
candidate hash, adapter revision match.

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

- Provider fixture-tested и проверен на активном Flint 2 dataplane.
- Zapret/Xray `NOT_CONFIGURED` на устройстве без бинарника.
- Direct/Zapret/Drop/VLESS доказаны на Flint 2 до и после reboot; Smart DNS
  требует отдельной проверки с production resolver.
- API external LAN binding — refused до TLS/firewall LAN-only/WAN-deny checks.
- Роли кроме admin.
