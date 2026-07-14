# Flint 2 Hardware Report (обезличенный)

> Доказанные результаты на физическом GL.iNet Flint 2 / GL-MT6000.
> Обезличено: IP/MAC/UUID/URL подписки/токены удалены. Хеши транзакций и commit
> SHA оставлены — это не секреты.

## Среда

| Параметр | Значение |
|---|---|
| Устройство | GL.iNet Flint 2 / GL-MT6000 |
| SoC | MediaTek Filogic 830, 4×ARM Cortex-A53 2.0 GHz, aarch64 |
| RAM / eMMC | 1 GB / 8 GB |
| OS | OpenWrt 24.10.4 |
| Kernel | 6.6.110 |
| Firewall | firewall4 / nftables (queue + tproxy support подтверждены) |
| Flow offloading | software+hardware (1/1 baseline; намеренно 0/0 при policy) |
| IPv6 | не настроен |
| Xray | 25.1.30 (opkg) — manual live process; локальная сборка 26.3.27 (upstream commit `d2758a023cd7`) для `xray run -test` |
| nfqws | Zapret v72.12 arm64 (внешний pinned provider, не вендорится) |

## Git state на момент отчёта

- Branch: `main`.
- Key commits:
  - `6e2a08b` — safe IP rule replacement
  - `a256daf` — hardware dataplane (P1)
  - `f88a99d` — P1 docs
  - `194465d` — managed Xray and Zapret dataplane (P3.1)
  - `77d0b83` — Zapret strategy validation on Flint
  - `4634515` — post-reboot recovery

## P1 — Direct + fail-closed Drop (committed)

- Коммиты: `a256daf` (hardware dataplane), `f88a99d` (closure docs).
- Scope: только `github.com`, маршруты Direct + fail-closed Drop.
- Доказано на железе:
  - Direct proof = OK: nft mark/rule/table, conntrack mark, WAN egress, content.
  - Drop proof = OK: реальный nft counter movement, IPv4/IPv6/DNS enforcement.
  - DNS leak check = true, IPv6 leak check = true.
  - Built-in data-plane verifier = OK.
  - Flow offload по плану 1/1 → 0/0; live Xray process/config hash-preserved.
- Намеренный rollback прогнан отдельно: таблицы/rules/временные файлы удалены,
  flow 1/1, Xray/API/GitHub живы. Внешний backup скачан, SHA-256 совпал.
- Финальная транзакция committed: rollback token/timer retired, table active.
- Баги пойманы и починены на железе: `ip rule replace` не поддерживается
  (iproute2 6.3.0) → project-owned priority + fail-closed snapshot; standalone
  nft/fw4 load; DNS redirect в NAT-chain; dnsmasq readiness; реальный Drop probe;
  `probe-route --no-persist` при занятой bbolt.

## P3.1 — Managed Zapret dataplane (committed)

### Syntax gate (read-only / temp files)

- OpenWrt 24.10.4 имеет nft queue/tproxy support.
- `/usr/bin/nfqws` не установлен в base firmware.
- Официальный arm64 nfqws v72.12 `--dry-run` принял сгенерированный config.
- `nft -c` принял сгенерированную table.
- Никакой бинарник/service/queue/traffic rule не устанавливался persistently в
  этой read-only проверке.

### Zapret hardware gate — `discord.com` (committed)

- Подтверждение пользователя получено перед apply.
- Fresh sysupgrade backup скачан в ignored `.local/`; local/router SHA-256
  совпали.
- 2 rehearsal прогона: service/NFQUEUE/rule lifecycle откатились чисто.
- `blockcheck.sh` (IPv4 TLS 1.2, `discord.com`, внешний watchdog) нашёл рабочую
  стратегию: `--dpi-desync=fake --dpi-desync-ttl=3 --orig-ttl=1
  --orig-mod-start=s1 --orig-mod-cutoff=d1`. Blockcheck temp-файлы удалены.
- Fixed project strategy: `tls-fake-ttl3-v1` (TCP 443), `fake,fakedsplit`
  (TCP 80). UDP 443 → DROP (force TCP fallback). NFQUEUE 200, no `bypass`
  (fail-closed).
- **Committed transaction**:
  - transaction: `tx_7777777777777777`
  - revision: `rev_10_777777777777`
  - candidate: `sha256:baa44ee015b952c960c0ea732798d90eaaab93bad06d80d75265d8312f514c45`
  - manifest: `sha256:2001c80426d9d9b4f068ad8c1b14869d91cac6be5e7bf708b70da65801cb41ef`
- Live route proofs:
  - Direct `github.com` = OK.
  - Zapret `discord.com` = OK: HTTP 200, `path_verified=true`,
    `zapret_flow_processed=true`, TCP/443 verified, **NFQUEUE counter 23 packets**.
  - Drop = OK: IPv4/IPv6/DNS enforcement.
  - Management + built-in data-plane verification = OK.
- Post-commit: API, DNS, GitHub, fresh Discord probe healthy.
- Manual Xray baseline SHA `387dfaff04d8a23e6ad24b89729330ddae8cf687cbfcafde6de245c7800999ea`
  не изменился. Zapret priority 10020 / table 101 alongside P1 Direct rules.
- Child dataplane services намеренно **не boot-enabled** — reboot recovery это P6.

## P6 — Post-reboot recovery (код + локальные тесты)

- Коммит `4634515`: `internal/api/recovery.go`, `adapter.Reconcile(RecoveryTarget)`,
  `openwrt/init.d/router-policy-boot-guard`, `adapter.Status` binding checks.
- `recoverCommittedDataplane` при старте: active revision → transaction →
  ChangeSet → candidate hash check → `Reconcile` → `Status` binding verify.
  Любое расхождение → `failedRecovery` с `reason_code`, persisted в
  `meta/recovery_status`.
- Локальные тесты зелёные: `TestRestartReconcilesCommittedDataplane`,
  `TestRecoveryFinalizesAdapterCommittedTransaction`,
  `TestRecoveryFailClosedBetweenStateMachineSteps`,
  `TestRestartKeepsManagementAvailableWhenCommittedReconcileFails`,
  `TestValidateRecoveryTarget`.
- **Физический reboot Flint 2 с восстановлением committed dataplane — НЕ доказан.**
  Это P13 hardware matrix gate.

## VPN-провайдер / VLESS (live, обезличено)

- Реальная подписка: 31 VLESS запись → 12 unique supported, 19 exact duplicates
  (dedup by identity SHA-256).
- Локальная сборка Xray 26.3.27 принимает 12-server bundle + TPROXY inbounds
  (`xray run -test`).
- Health cycle (live): 10/12 exit non-RU OK, 1 UNVERIFIED (GeoIP endpoints
  unreachable), 1 rejected (RU egress), 1 selected (≈656 ms). Bundle hash
  неизменен при пере-проверке.
- Persistent per-exit activation на Flint 2 (procd lifecycle, external IP proof,
  route production-ready) — не доказано, часть P3/P13.

## Что НЕ доказано на железе

- Smart DNS activation (placeholder resolver).
- VLESS/Xray persistent activation + per-exit route proof.
- `tg_ws_proxy` transport (route type определён в proof, реализации нет).
- Физический reboot/crash recovery (P6 код есть, reboot — P13).
- Multi-client, 72h soak, fault injection matrix, install/upgrade/downgrade.
- Full route × protocol × AF матрица.

## Честный итог

Direct + fail-closed Drop и Zapret (`discord.com`) — реально committed и доказаны
на Flint 2 с bound evidence. Recovery код написан и локально тестирован, но
reboot-safe claim требует физического reboot (P13). Проект остаётся Alpha: UI и
локальные тесты зелёные — не доказательство production-readiness для полной
матрицы.