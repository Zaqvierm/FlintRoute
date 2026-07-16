# Реализация и оставшаяся работа

> Фактическое поведение определяют реализация и тесты. Этот документ описывает
> оставшиеся этапы и критерии их завершения.

## Устройство

FlintRoute — Go control plane + Preact/Vite UI + транзакционный OpenWrt data-plane
адаптер. Shell остаётся только как fixed-command helper под `exec` адаптера;
сетевой логики в shell нет.

## Текущее основание

### Control plane (Go)

- `probe.ProbeRoute(ctx, cfg, domain, service, svc, route)` — единый pipeline для
  всех route types: `direct`, `zapret`, `smart_dns`, `vless`, `tg_ws_proxy`,
  `drop`. Анти-паттерн `check_direct()`/`check_vless()` отсутствует.
- `probe.RouteResult` делит проверку на четыре независимых уровня (см. ниже).
- Path proof: `evidence.RouteResult` + `evidence.ValidateRouteProof` связывает
  intent → artifact → live kernel/process state. Биндинг к `adapter.RevisionID`,
  `CandidateHash`, `ArtifactManifestHash`.
- Planner/health: `health.Service.RunCycle` — bounded parallelism, control
  quorum (≥2 control-сервисов, majority OK, consensus по revision/candidate/
  manifest/country/IP), `probe.HealthTracker` (EWMA, hysteresis, quarantine),
  `AssignVLESSRoles` (selected/standby/quarantine).
- `tspu` Cache v2: multi-source, `SourceReport` (ETag/Last-Modified/drop-ratio/
  confidence), `Entry` с `Provenance`/`MatchType` (suffix/wildcard), SHA-256
  integrity, `PreviousSHA256`, `FreshSources`, bounded 32 MiB.
- VPN-подписка: `vpnsub.Normalize` (summary без секретов), `GenerateRoutesFile`,
  `GenerateXrayConfigFile` — extract → deduplicate (identity SHA-256) →
  classify (validateVLESSOutbound) → retag collision-safe → SOCKS inbound per
  outbound → routing rule.
- GeoIP: MMDB + two-source consensus (`country_is`, `ipwho_is`) через тот же
  egress path.
- `artifact.Generate`: nft, dnsmasq, Xray, nfqws, IP plan, verification plan —
  всё bound к `Binding{TransactionID,RevisionID,CandidateHash}`, manifest v6.
- Config validation: mark/table collision detection, fail-closed drop required,
  smart_dns/vless/zapret/transparent guards, SHA-256 outbound bundle binding.

### Data plane (OpenWrt adapter)

- `adapter.Interface`: Diagnose, Prepare, ValidateCandidate, SnapshotCurrent,
  ApplyCandidate, VerifyManagementPath, VerifyDataPlane, Commit, Rollback,
  Reconcile, Status.
- `adapter.OpenWrt`: fixed-command `exec`, строгий allowlist (`transactionIDPattern`,
  `revisionIDPattern`), единственный конфиг-аргумент. `Filesystem` — local-only,
  заканчивает на `SKIPPED`/`UNVERIFIED`/`requires_device`.
- Rollback: mode-0600 capability, `VerifyRollbackToken` constant-time, SHA-256
  binding в bbolt, atomic swap с `.replace-backup`.
- Managed Xray TPROXY + Zapret/nfqws lifecycle: procd services, `xray run -test`,
  nfqws `--dry-run` before apply, NFQUEUE fail-closed (no `bypass`), flow
  offloading preserve/disable.

### Post-reboot recovery

- `api.recoverCommittedDataplane` при старте сервера: загружает active revision
  → transaction → ChangeSet → candidate, проверяет canonical hash совпадение,
  вызывает `adapter.Reconcile(RecoveryTarget)`, затем `adapter.Status` проверяет
  bindings (`active_revision`, `active_transaction`, `active_candidate_hash`,
  `active_artifact_manifest_hash`, `transaction_state=committed`).
- `openwrt/init.d/router-policy-boot-guard` — boot guard.
- Любое расхождение → `failedRecovery` с явным `reason_code`, persisted в bbolt
  `meta/recovery_status`. Ни одна частичная ревизия не активируется.
- На Flint 2 persistent state и committed dataplane восстановлены после
  физического reboot; post-reboot Direct/Zapret/Drop/VLESS evidence прошёл
  strict verification.

### Проверено на Flint 2 / GL-MT6000

- Direct + fail-closed Drop доказаны на
  физическом роутере. nft counter movement, mark/rule/table, conntrack, DNS/IPv6
  leak checks, намеренный rollback с восстановлением nft/IP rules/routes/dnsmasq/
  flow offload/management path. Live Xray process hash-preserved.
- Zapret `discord.com` — nfqws v72.12 arm64
  `--dry-run` + `nft -c` passed (syntax proof). Live transaction committed:
  NFQUEUE counter, HTTP 200, `path_verified=true`.
- Managed VLESS/Xray и fail-closed Drop включены в тот же committed route set;
  после reboot controller, Xray, nfqws, nftables и policy rules восстановлены.
- OpenWrt 24.10.4, firewall4/nftables queue/tproxy support подтверждены.
- TSPU cache обновляется фоновым планировщиком с jitter/backoff и сохранением
  последнего валидного состояния. На Flint 2 приняты 2/2 живых источника,
  получена матрица Direct 5/5 `NO_MATCH` и TSPU 5/5 `MATCH`.

## Четыре уровня проверки маршрута

Везде в проекте проверка маршрута разделена на четыре независимых уровня.
`http_ok=true` без `path_verified=true` → `UNVERIFIED`, маршрут не выбирается.

1. **DNS resolution** — resolver, протокол (`system`/`udp`/`tcp`/`socks5_tcp`),
   resolved IP, safe/unsafe ответ (`isUnsafeAddr`, smart_dns guard). A/AAAA
   отдельно, CNAME loop/limit/size checks.
2. **Классификация** — HTTP status (`ExpectedCodeMatched`), content markers,
   `RegionalBlock`, `SuspectedTSPU`. Внутри `probeOne`, не внутри adapter.
3. **Фактический egress** — `ExternalIPHash` (SHA-256), `ExternalCountry`,
   `ExternalCountrySources`, `EgressConsensus`. Для `RequireNonRUEgress` —
   non-RU обязательно, иначе `RU_EXIT`/`FAIL`.
4. **Доказательство маршрута** — `PathVerified`, `NFTMark`, `ConntrackMark`,
   `IPRulePriority`, `RouteTable`, `Interface`, `SocketMark`, `XrayOutboundTag`,
   `EvidenceSource`, `PathEvidence`. `evidence.ValidateRouteProof` проверяет
   binding к revision/candidate/manifest и per-type proof.

## Открытые задачи

- **P12**: Adaptive Zapret. Дизайн готов (`adaptive-zapret-strategy.md`), код не
  начат. Bounded catalog, ranking, hysteresis, per-service switching.
- **P13**: Full hardware matrix. Все route types × TCP/UDP × IPv4/IPv6 ×
  reboot/crash × multi-client × 72h soak. План в `flint2-hardware-validation.md`.
- Smart DNS: не доказан на железе (placeholder resolver).
- `tg_ws_proxy`: route type определён в evidence proof, реализации транспорта нет.
- API external LAN binding: заблокирован до TLS/firewall checks.
- Роли кроме admin.

## Следующие этапы

| Этап | Содержание | Gate |
|---|---|---|
| P12 | Adaptive Zapret: bounded catalog, ranking, hysteresis, switching | два bundles одновременно на железе |
| P13 | Full hardware matrix: fault injection, reboot/crash, 72h soak | evidence-backed PASS по всей матрице |

## Принципы

- Один data-plane хозяин: FlintRoute владеет nft/dnsmasq/procd lifecycle.
- Никаких shell fragments из внешних запросов. Только фиксированные команды.
- `path_verified=false` → маршрут не production-ready, даже если HTTP 200.
- Доказательство связывает: intent → generated artifact → live state → traffic.
- Recovery перед рискованными операциями. Version snapshot после этапа.
