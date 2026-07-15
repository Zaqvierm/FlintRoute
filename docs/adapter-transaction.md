# Контракт транзакции адаптера

> Основные реализации: `internal/adapter/adapter.go`,
> `internal/api/recovery.go`, `internal/adapter/openwrt.go`.

Go control plane владеет durable state machine. Продакшн-изменения сети — только
через инжектируемый `adapter.Interface`.

## `adapter.Interface`

```go
Diagnose(context.Context) StepResult
Prepare(context.Context, Transaction) StepResult
ValidateCandidate(context.Context, Transaction) StepResult
SnapshotCurrent(context.Context, Transaction) StepResult
ApplyCandidate(context.Context, Transaction) StepResult
VerifyManagementPath(context.Context, Transaction) StepResult
VerifyDataPlane(context.Context, Transaction) StepResult
Commit(context.Context, Transaction) StepResult
Rollback(context.Context, Transaction) StepResult
Reconcile(context.Context, RecoveryTarget) StepResult
Status(context.Context) StepResult
```

`StepResult`: `Step`, `Status`, `OK`, `ManagementVerified`, `DataPlaneVerified`,
`Reason`, `Evidence`, `StartedAt`, `FinishedAt`. `Reconcile` — единственный
метод с `RecoveryTarget` вместо `Transaction` (post-reboot recovery).

## Dependency injection

`api.Options.ProductionAdapter` обязателен. API никогда не создаёт
filesystem-адаптер сам. `cmd/router-policy` инжектирует `adapter.OpenWrt` для
продакшена и `adapter.Filesystem` для локальной разработки. Тесты инжектируют
`fakeAdapter` и проверяют реальные `Commit`/`Rollback`/`Reconcile`.

`adapter.OpenWrt` выполняет только фиксированные helper-глаголы через `exec`,
без shell-фрагментов: `diagnose`, `prepare`, `validate-candidate`,
`snapshot-current`, `apply-candidate`, `verify-management`, `verify-data-plane`,
`commit`, `rollback`, `reconcile`, `status`. `allowedGlobalCommand` /
`allowedTransactionCommand` — allowlist. `validateTransaction` проверяет
`transactionIDPattern` + `revisionIDPattern`.

Единственный конфиг-аргумент — абсолютный путь к продакшн-конфигу. Candidate path
детерминирован и не принимается из helper-ввода. Для `command != "prepare"`
требуется валидный `ReadCapability(tx)` (mode-0600 rollback capability).

`Filesystem` — local-only: `ApplyCandidate` → `SKIPPED` (requires_device),
`VerifyManagementPath`/`VerifyDataPlane` → `UNVERIFIED`. Никогда не достигает
`awaiting_confirmation`.

## Transaction / RecoveryTarget

`Transaction`: `ID` (`tx_<hex8>`), `RevisionID`, `ChangeID`, `BaseVersion`,
`CandidateVersion`, `CandidateHash`, `CandidatePath`, `ArtifactRoot`,
`ArtifactManifestHash`, `ArtifactsReady`, `ArtifactsSimulation`,
`RollbackTokenHash`, `CapabilityPath`, `BindingPath`, `RollbackToken` (не
сериализуется), `CreatedAt`, `ExpiresAt`, verification timestamps.

`RecoveryTarget` (P6): `TransactionID`, `RevisionID`, `CandidateHash`,
`ArtifactManifestHash`. `validateRecoveryTarget` проверяет полноту.

## State machine

```text
draft -> validated -> prepared -> applying -> verifying
      -> awaiting_confirmation -> committing -> committed
rolling_back -> rolled_back | rollback_failed
failed | expired | requires_device
```

`SKIPPED` и `UNVERIFIED` — не успешные шаги. Filesystem заканчивает на
`requires_device`. Если data plane уже применён, а verification стала
`UNVERIFIED`, адаптер откатывается до `requires_device`.

`confirm` требует оба verification flag, незавершённую транзакцию, совпадение
candidate hash и adapter revision/transaction. Вызывает `Adapter.Commit` до
атомарного продвижения candidate config, version и revision в bbolt.

## Четыре уровня в транзакции

Транзакция разделяет проверку маршрута на четыре независимых уровня:

1. **DNS resolution**: verification plan требует resolver, resolved IP, DNS
   protocol. Smart DNS проверяет safe/unsafe ответ (`DNSResponseSafe`,
   `HostPreserved`, `SNIPreserved`).
2. **Классификация**: HTTP status, content markers, regional block, TSPU
   detection — внутри `probe`, не внутри adapter. `HTTPResult`/`ContentResult`.
3. **Фактический egress**: `ExternalIPHash` + `ExternalCountry` + consensus.
   Для `GEO_LOCKED` — non-RU обязательно. `RequiresEgress` в `RouteProof`.
4. **Доказательство маршрута**: `NFTMark`/`ConntrackMark`/`IPRulePriority`/
   `RouteTable`/`Interface`/`SocketMark`/`XrayOutboundTag`. Per-type proof в
   `evidence.ValidateRouteProof`: direct (bypass Xray/Zapret + cleared mark),
   zapret (installed + flow + TCP443 + QUIC policy), smart_dns (response safe +
   Host/SNI), vless (SOCKS5 loopback + bound outbound tag), tg_ws_proxy (proxy
   flow), drop (IPv4/IPv6/DNS enforcement). Биндинг к `RevisionID`/`CandidateHash`/
   `ArtifactManifestHash`.

## Durable state

Buckets: `changes`, `candidates`, `revisions`, `transactions`, `probes`,
`events`, `meta`. Schema version и migration state — в `meta`. Retention по
bounded probe count и time-based event/ChangeSet/transaction policies.
Maintenance: daily backups, `max_state_backups`, compact backup не чаще compact
interval, active compaction только если размер > `max_database_bytes`.
Compaction валидирует новый bbolt файл до atomic swap, хранит `.precompact` до
reopen. Startup восстанавливает `.precompact` при прерванном swap.

## Rollback capability

Raw rollback token — только в mode-0600 файле `rollback.cap` под transaction
directory. bbolt и `binding.env` хранят только SHA-256 hash.
`VerifyRollbackToken` — constant-time (`subtle.ConstantTimeCompare`).
`ReadCapability` требует regular + mode 0600 (не windows) + hash match.
`RetireCapability` удаляет после commit. API responses никогда не раскрывают
token.

## Shell transaction safety

Helper имеет один `transaction.lock`. Метаданные: PID, process start time,
transaction ID, revision ID, creation time. Stale lock удаляется только после
того, как `/proc` докажет, что точный PID/start-time владелец больше не существует.

Snapshots покрывают: active router-policy config, nft include, dnsmasq include,
Xray active config, Zapret active config, active transaction metadata, UCI
flow-offloading state. Manifest SHA-256 + каждый file hash/size проверяются до
изменения любого target. Restore атомарен. Absent markers удаляют только
hardcoded project-owned targets. `last-good` = full snapshot + committed
transaction metadata.

Rollback timer — transaction-bound и revision-bound, PID + process start time
для wrapper и sleeper. Никогда не ищет process command lines.

## Post-reboot recovery (P6)

`api.recoverCommittedDataplane` при старте сервера:

1. Загружает active revision из bbolt. Если `configVersion>1` без active
   revision → `active_revision_missing`.
2. Проверяет `revision.State=committed` + полноту binding.
3. Загружает transaction record, проверяет `State=committed` + hash match
   (`constantEqual` для `CandidateHash`/`ArtifactManifestHash`).
4. Проверяет ChangeSet `committed` + binding match.
5. `loadVerifiedCandidate` + canonical hash совпадение с active config.
6. `adapter.Reconcile(ctx, RecoveryTarget)`. Временный `adapter_busy` от
   параллельного boot guard повторяется с bounded timeout; остальные ошибки →
   `adapter_reconcile_failed`.
7. `adapter.Status(ctx)` — evidence должен совпадать: `active_revision`,
   `active_transaction`, `active_candidate_hash`,
   `active_artifact_manifest_hash`, `transaction_state=committed`. Иначе
   `adapter_recovery_binding_mismatch`.

Любое расхождение → `failedRecovery` с явным `reason_code`, persisted в bbolt
`meta/recovery_status`. Ни одна частичная ревизия не активируется. Boot guard:
`openwrt/init.d/router-policy-boot-guard`.

## Аппаратная проверка

P0/P0.5 flow integration-tested с production adapter fixtures. На Flint 2
committed и доказаны Direct, Zapret, Drop и VLESS/Xray. Физический reboot
восстановил persistent state, controller, Xray, nfqws, nftables и IPv4/IPv6
policy rules; повторный bound route probe после старта прошёл strict verifier.
Hard-crash, power-loss и длительные fault-injection сценарии остаются в P13.
