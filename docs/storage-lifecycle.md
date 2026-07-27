# Lifecycle и ресурс записи

Этот документ задаёт границы владения процессами, сетевыми объектами и
постоянным состоянием FlintRoute. Главный принцип простой: удалить или
остановить можно только ресурс, чья принадлежность доказана. Совпадения имени
процесса или одного PID недостаточно.

## Кто запускает production-процессы

Production supervisor — `procd`. FlintRoute не поднимает второй универсальный
supervisor поверх него.

| Компонент | Сервис FlintRoute | Ожидаемая конфигурация |
|---|---|---|
| control plane | `router-policy` | `/etc/router-policy/config/default.json` |
| Xray | `router-policy-xray` | `/etc/router-policy/xray/active.json` |
| Zapret/nfqws | `router-policy-zapret` | `/etc/router-policy/zapret/nfqws.conf` |
| watchdog | `router-policy-watchdog` | Go watchdog внутри `router-policy` |
| boot recovery | `router-policy-boot-guard` | committed `last-good` и transaction binding |

Штатный `/etc/init.d/xray status` может показывать `inactive`, пока
`router-policy-xray` работает нормально. Это разные procd instances.
Диагностика поэтому выводит FlintRoute-managed и system service отдельно и
проверяет PID, `/proc/<pid>/stat` start time, executable, command line и config
path. Для Zapret действует тот же контракт.

## Владельцы

Typed manifest schema v1 поддерживает пять классов:

- `production`;
- `transaction:<id>`;
- `test-run:<id>`;
- `installer:<id>`;
- `recovery:<id>`.

Manifest test-run хранит lease, baseline, процессы, файлы, listeners,
nftables/IP resources, состояние cleanup и итог теста. Процесс разрешено
завершить только после совпадения PID, start time, executable, run ID и
ожидаемого config path. Поэтому PID reuse и чужой процесс с именем `xray` не
проходят ownership gate.

Network cleanup ограничен отдельным test namespace:

- nft table: `router_policy_test_<run-id>`;
- IPv4/IPv6 route table и rule priority: диапазон `30000..30999`;
- route удаляется по точному family/table/CIDR;
- listener разрешён только на loopback и после остановки его owned process;
- production table `router_policy` и обычные routing priorities не подходят
  под cleanup contract.

Неоднозначный ресурс остаётся на месте и попадает в отчёт. Глобальные
`pkill`, `killall` и wildcard cleanup не используются.

## Production и test-run

`router-policy lifecycle begin` снимает read-only baseline до теста. В manifest
попадают только hashes и количество строк результатов `ubus`, `ss`, `nft` и
`ip`; содержимое сетевой конфигурации в manifest не копируется.

```sh
router-policy lifecycle begin --id hardware-001 --lease 45m
router-policy lifecycle add-process --id hardware-001 --resource xray-test \
  --pid PID --executable /usr/bin/xray \
  --config /tmp/router-policy/test-runs/hardware-001/xray.json
router-policy lifecycle add-network --id hardware-001 --resource nft-test \
  --kind nft-table --family inet --table router_policy_test_hardware_001
router-policy lifecycle finish --id hardware-001 --result passed
router-policy cleanup stale --dry-run --json
router-policy cleanup stale --apply --json
```

`cleanup stale` по умолчанию ничего не меняет. Apply идемпотентен: уже
отсутствующий owned resource считается очищенным. Test-run получает состояние
`complete` только после удаления зарегистрированных ресурсов и совпадения
post-cleanup baseline. Production procd instances в этот cleanup не входят.

## Watchdog

`router-policy-watchdog` запускает Go controller через procd. Он учитывает
startup grace и требует несколько последовательных ошибок health endpoint до
restart. Бесконечного shell-цикла с `wget`, `sleep` и безусловным restart больше
нет.

На install, uninstall, upgrade, intentional shutdown и rollback ставится
maintenance inhibit с owner, причиной и сроком. Максимальная lease — два часа;
просроченный inhibit не отключает watchdog навсегда. Watchdog управляет только
`/etc/init.d/router-policy`.

## Размещение данных

### Immutable installed

`/usr/bin/router-policy`, init scripts, schema и factory defaults. Installer
сравнивает content и mode до замены.

### Durable committed/recovery

- `/etc/router-policy/config` — active и factory config;
- `/etc/router-policy/state/router-policy.bbolt` — committed control state;
- `/etc/router-policy/state/last-good` — одна проверенная рабочая копия;
- `/etc/router-policy/state/transactions/<revision>/<transaction>` —
  минимальный journal текущей committed revision;
- `/etc/router-policy/secrets` — ссылки и authentication material.

Candidate и generated manifest активной revision пока сохраняются рядом с
journal: boot recovery повторно проверяет их hashes. Pre-apply snapshot и
rollback capability удаляются после успешного commit.

### Bounded operational history

- terminal ChangeSets — 90 дней по умолчанию;
- terminal transactions — 30 дней;
- durable security/config events — 30 дней и максимум 4096 записей;
- domain decisions — bounded LRU, максимум из `max_auto_domains`;
- adaptive observations — checkpoint не чаще одного раза в 15 минут;
- bbolt backups — по умолчанию максимум 7;
- test-run manifests — максимум 32 завершённых;
- installer fallbacks — максимум два verified backup и 128 MiB.

### Runtime tmpfs

`/tmp/router-policy` содержит locks, rollback timers, heartbeat, текущие probe
results, SSE buffers, adaptive live observations, test-run files и bounded
`write-events.log`. Потеря этого каталога после reboot допустима. Durable
journal остаётся достаточным для fail-closed recovery.

### Exported diagnostics

Support bundles и аппаратные отчёты создаются только явно. Они не являются
частью автоматической истории и перед публикацией должны быть обезличены.

## Аудит постоянных записей

| Путь или bucket | Инициатор | Частота и верхняя граница | Переживает reboot | Защита от лишней записи |
|---|---|---|---:|---|
| bbolt `meta` | config/recovery/maintenance | только transition или редкое обслуживание | да | exact encoded bytes перед `Update` |
| `changes` | ChangeSet API | bounded terminal retention 90 дней | да | batch compare-before-write |
| `candidates` | validate | один candidate на ChangeSet; orphan cleanup | да, пока нужен transaction | canonical config hash и no-op gate |
| `revisions` | commit | одна запись на реальный commit | да | identical apply не создаёт revision |
| `transactions` | apply/commit/recovery | один активный, terminal retention 30 дней | да | batch compare-before-write |
| `route_health` | health transition | state transition или редкий checkpoint | да | heartbeat/checked_at не считаются transition |
| probe details | health/probe engine | RAM ring, `max_probe_results` | нет | bbolt не открывается |
| `events` | security/config audit | 4096 и 30 дней | только durable audit | operational events остаются в RAM broker |
| `zapret_switch` | adaptive controller | transition и checkpoint не чаще 15 минут | да | exact bytes + coalescing |
| adaptive probe checkpoint | health scheduler | не чаще 15 минут | да | live observations в RAM |
| `domain_decisions` | planner | bounded LRU; checkpoint не чаще 15 минут | да | lookup/last_used не пишет |
| TSPU cache + previous | scheduled refresh | только при изменении entry set | да | identical list не заменяет большие файлы; freshness хранится отдельно |
| TSPU freshness checkpoint | успешная revalidation | один bounded JSON на текущий cache hash | да | content-aware replace; TTL продлевается только для fresh sources |
| content-addressed Xray bundle | subscription prepare | один файл на digest | да | hash path + byte comparison |
| generated transaction artifacts | validate/apply | один набор на реальный transaction | да для active revision | atomic writer сравнивает bytes; no-op apply не генерирует |
| active nft/dnsmasq/Xray/Zapret config | adapter apply | только при отличии content/mode | да | `cmp`, same-filesystem temp, fsync, rename |
| исходный flow-offloading baseline | первая transaction перед изменением UCI | один mode-0600 manifest на installation ownership | да | создаётся один раз; последующие transaction не перезаписывают |
| `last-good` | commit | один verified snapshot | да | новый snapshot проверяется до удаления прошлого |
| bbolt backups | daily maintenance | максимум 7 | да | interval, hash verify, bounded pruning |
| installer/uninstall backup registry | install lifecycle | максимум 2 verified / 128 MiB | да | manifest + hashes до удаления старого |
| rollback timers, locks, heartbeat | transaction/watchdog | bounded runtime | нет | `/tmp/router-policy` |
| hardware reports | явный harness | один bounded bundle на run | экспорт | не создаются health cycle |

bbolt использует собственный transaction/fsync contract. Atomic files пишутся
во временный файл на том же filesystem, синхронизируются и переименовываются;
security-sensitive target не может быть symlink.

Исходные UCI-значения software/hardware flow offloading принадлежат не
transaction, а installation lifecycle. Первая transaction сохраняет их в
`state/ownership/flow-offloading.env`; manifest принимается только как regular
mode-0600 file с тем же владельцем, что и защищённый ownership directory.
Rollback использует собственный transaction snapshot, а uninstall возвращает
этот исходный persistent baseline даже при отсутствии `last-good`. Uninstall не
вызывает глобальный `fw4 reload`: применение persistent flow-offload baseline к
runtime firewall откладывается до отдельно контролируемого service transition.

## Write budget и диагностика

`GET /api/v1/storage` возвращает:

- размер bbolt, runtime, transactions, snapshots и backup roots;
- bbolt write transactions, encoded bytes и no-op count;
- Go file create/replace/delete, bytes и fsync count за время процесса;
- adapter events из bounded tmpfs-журнала;
- active transaction и pending rollback без capability/token;
- last cleanup и last recovery result.

`GET /api/v1/lifecycle` показывает managed/system services, точную process
identity, test-runs и повреждённые manifests. Оба endpoint read-only: UI polling
и SSE subscribe не открывают persistent write transaction.

Аппаратный idle gate сначала обнаружил, что стабильный `unhealthy` route каждые
пять минут продлевал `HoldUntil`, а сравнение принимало это за durable
изменение. В persistent comparison теперь входят state, role, reason и
deployment identity, но не скользящий quarantine deadline. Реальный переход
по-прежнему сохраняет полный health record. После исправления 1000 API GET и
35 минут фоновых health cycles дали нулевой прирост bbolt transactions/bytes и
не изменили inode, size или SHA persistent artifacts.

Счётчики отражают логические операции, а не физические NAND writes. После
reboot runtime counters обнуляются — это ожидаемо.

## Backup migration

```sh
router-policy storage migrate --dry-run
router-policy storage migrate --apply
```

Dry-run классифицирует runtime, durable journal, backup и неизвестные файлы.
`tspu-cache.json`, единственный `tspu-cache.previous.json` и проверяемый
`tspu-cache.freshness.json` относятся к bounded operational cache.
Apply переносит только legacy directories с allowlisted именем: сначала делает
проверенную копию в `/root/router-policy-backups`, создаёт typed manifest и
повторно сверяет hashes; лишь после этого удаляет точный legacy source.
Неизвестные файлы всегда пропускаются.

## Результат на Flint 2

Локальные tests доказывают ownership gates, PID reuse protection, bounded
history, no-write health cycles, no-op apply и fault paths atomic install. На
Flint 2 отдельно прошли 100 изолированных test-run, stale cleanup, SIGKILL, SSH
disconnect, foreign-process protection и возврат к baseline.

Повторный проход после factory recovery закрыл control-plane часть аппаратного
gate: clean install, upgrade, controlled restart, `SIGKILL`, maintenance inhibit,
bounded boot guard и reboot прошли без изменения nft/IP baseline. Stale cleanup
после reboot вернул 0 runs и 0 ambiguous resources; backup registry сохранил
один verified fallback размером около 72 MiB и уложился в лимит 128 MiB.

На этом же проходе обнаружена write amplification: два поколения TSPU cache
общим размером около 64 MiB заменялись после каждого старта controller, хотя
набор из 86 781 entry не менялся. Теперь entry set хранится в тяжёлом cache,
а успешная revalidation обновляет маленький hash-bound freshness checkpoint.
На Flint 2 SHA и inode обоих тяжёлых файлов сохранились после refresh, restart
и reboot; checkpoint занял 1840 байт.

Production Xray/Zapret lifecycle с committed dataplane также повторно прошёл
restart, `SIGKILL`, controller restart и 11 bound route proofs при непрерывном
внешнем SSH/web monitor.

Финальный lifecycle tail подтвердил expiration/rollback timer, compatible
downgrade, восстановление текущего пакета, полное удаление project-owned
processes, nftables, policy rules/routes и runtime files, возврат исходного
flow-offload baseline и последующий reinstall/reconcile committed dataplane.
Uninstall registry сохранил 2 verified operations общим размером 66.7 MiB.
Первый uninstall выявил readiness race сразу после `dnsmasq restart`; fixed
uninstaller ждёт PID и успешный loopback DNS до возврата. Повторный hardware
uninstall и финальный reinstall прошли при непрерывном внешнем SSH/web monitor.

P14 закрыт. Имитация физического отключения питания в этот этап не входила.
