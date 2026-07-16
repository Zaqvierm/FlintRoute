# Flint 2 Hardware Report (обезличенный)

> Доказанные результаты на физическом GL.iNet Flint 2 / GL-MT6000.
> IP, MAC, UUID, subscription URLs и credentials исключены. Для воспроизводимой
> сверки оставлены только безопасные хеши транзакционных артефактов.

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

## P1 — Direct + fail-closed Drop (committed)

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

- Перед apply пройден обязательный confirmation gate.
- Перед активацией создан fresh sysupgrade backup; SHA-256 локальной и
  маршрутизаторной копий совпали.
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

## P3.2 — Полный headless route set (committed)

- Активная транзакция: `tx_2169c2c6a0349d73`, ревизия:
  `rev_3_3fa9fd0e4c15`.
- Direct: `OK`, RU egress, IPv4/IPv6, Xray/Zapret bypass.
- Zapret: `OK`, RU egress, обработанный NFQUEUE flow.
- VLESS/Xray: `OK`, NL egress, IPv4/IPv6, loopback SOCKS binding к выбранному
  outbound.
- Drop: `OK`, IPv4/IPv6/DNS блокировка.
- Итоговые флаги: DNS leak free, IPv6 leak free и geo kill switch — `true`.
- Candidate:
  `sha256:8097fdb95da546df2fbd77518646e6e1a0ef9f2c00f83b4d28dfcf0cbec09cab`.
- Manifest:
  `sha256:08c6d59e70bc5043cd12a4c3d854ce7229a7c6bdf269e28e730ebd567d2a631d`.

Smart DNS не входил в этот route set: для него нужен отдельный production
resolver, а подставлять тестовый адрес в аппаратное доказательство нельзя.

## P6 — Post-reboot recovery (доказано на железе)

- Реализация включает `internal/api/recovery.go`,
  `adapter.Reconcile(RecoveryTarget)`,
  `openwrt/init.d/router-policy-boot-guard` и binding checks в `adapter.Status`.
- `recoverCommittedDataplane` при старте: active revision → transaction →
  ChangeSet → candidate hash check → `Reconcile` → `Status` binding verify.
  Любое расхождение → `failedRecovery` с `reason_code`, persisted в
  `meta/recovery_status`.
- Локальные тесты зелёные: `TestRestartRetriesBusyCommittedDataplaneReconcile`,
  `TestRestartReconcilesCommittedDataplaneAfterStateRootMigration`,
  `TestRecoveryFinalizesAdapterCommittedTransaction`,
  `TestRecoveryFailClosedBetweenStateMachineSteps`,
  `TestRestartKeepsManagementAvailableWhenCommittedReconcileFails`,
  `TestValidateRecoveryTarget`.
- State перенесён из volatile `/var` в `/etc/router-policy/state`; после reboot
  bbolt и last-good artifacts сохранились без compatibility symlink в
  `/var/lib/router-policy`.
- Controller восстановил `rev_3_3fa9fd0e4c15`. Xray, nfqws, nftables, четыре
  IPv4 и четыре IPv6 policy rule поднялись автоматически; flow offload остался
  0/0, recovery status — `ok`.
- На первом контрольном reboot выявлена гонка boot guard/controller за adapter
  lock. Повтор `adapter_busy` ограничен 30 секундами; следующий физический
  reboot прошёл без ручного restart.
- После reboot заново собран и строго проверен bound evidence report для всех
  четырёх маршрутов. SHA-256 evidence:
  `3664f1f7477e4565cd3a498782266d1ce35930cdfcc27f03de2b0713a48c53c6`.

## VPN-провайдер / VLESS (live, обезличено)

- Реальная подписка: 31 VLESS запись → 12 unique supported, 19 exact duplicates
  (dedup by identity SHA-256).
- Локальная сборка Xray 26.3.27 принимает 12-server bundle + TPROXY inbounds
  (`xray run -test`).
- Health cycle (live): 10/12 exit non-RU OK, 1 UNVERIFIED (GeoIP endpoints
  unreachable), 1 rejected (RU egress), 1 selected (≈656 ms). Bundle hash
  неизменен при пере-проверке.
- Persistent VLESS activation на Flint 2 доказана для выбранного выхода; полная
  матрица выходов остаётся в P13.

## P10 — Upgrade из OpenWrt-пакета

- ARM64-пакет проверен по `SHA256SUMS` до установки. SHA-256 архива:
  `aabd400e7ddb86769602521d684957609c5aea34a558dd8df8b07b0a5c8c8721`.
- Перед upgrade созданы и локально проверены полный sysupgrade backup и
  отдельный архив project-owned файлов.
- Повторная установка сохранила пользовательский конфиг, admin state, активную
  транзакцию и ревизию. Хеш `/usr/bin/router-policy` совпал с бинарником из
  пакета.
- Уже работающие controller, watchdog, Xray и nfqws перезапустились через
  procd. Installer дождался `control_plane_health=ok`; одного состояния
  `procd running` недостаточно для успешного завершения.
- После upgrade строгая проверка снова подтвердила Direct `github.com`, Zapret
  `discord.com`, Drop и VLESS `chatgpt.com`. `path_verified=true`, simulation
  выключена, DNS/IPv6 leak flags и geo kill switch — `true`. SHA-256 evidence:
  `29dd802388febef4db8dc76e3b6f004ebab4be7c62766e5ea3080dcdddbfc0ae`.
- С LAN-клиента открылись все контрольные адреса: Direct-набор `yandex.ru`,
  `vk.com`, `ozon.ru`, `gosuslugi.ru`, `mail.ru`; TSPU-набор `discord.com`,
  `signal.org`, `instagram.com`, `facebook.com`, `x.com`; GEO-набор
  `chatgpt.com`, `claude.ai`, `gemini.google.com`, `copilot.microsoft.com`,
  `youtube.com`. Ответы 403 у ChatGPT и Claude считаются HTTP-доступностью, а
  не доказательством пользовательской сессии.

Clean install, downgrade и uninstall на отдельном чистом OpenWrt пока не
выполнялись. Локальные lifecycle-тесты этих сценариев зелёные, но аппаратный
gate остаётся открытым.

## Что НЕ доказано на железе

- Smart DNS activation (placeholder resolver).
- `tg_ws_proxy` transport (route type определён в proof, реализации нет).
- Hard-crash/power-loss recovery и timer fault injection.
- Multi-client, 72h soak, fault injection matrix, clean install, downgrade и
  uninstall.
- Full route × protocol × AF матрица.

## Подтверждённое состояние

Direct, fail-closed Drop, Zapret и VLESS/Xray подтверждены на Flint 2 с bound
evidence до и после физического reboot. P3 и P6 закрыты по своим аппаратным
критериям. In-place upgrade из проверяемого OpenWrt-пакета тоже пройден. Проект
остаётся Alpha: Smart DNS, hard-crash/power-loss, multi-client, установка на
чистое устройство и soak-test ещё не пройдены.
