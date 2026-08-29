# Forensic-разбор безопасности и планировщик probes

> **Статус на `e97f8dd`:** это forensic-описание причин и локальных regression
> tests. Наблюдения старого Flint 2 не являются текущим hardware PASS.

Документ фиксирует три цепочки отказов, найденные при ревью Flint 2. Наблюдения
железа считаются evidence; утверждение о втором `ubusd` не приписывается
FlintRoute без отдельного воспроизведения.

## A. Rollback installer и права системных каталогов

**Факт.** `install.sh` задавал `umask 077`. Старая
`snapshot_installation` копировала allowlisted пути в искусственное staging-дерево
и архивировала `.`. `restore_installation` извлекала архив командой
`tar -C / -xf`, поэтому в архив попадали synthetic `etc`, `usr` и другие
родительские каталоги с restrictive metadata. На живом роутере это меняло mode
`/`, `/etc`, `/usr`, `/usr/bin`, `/usr/lib` и service-каталогов на `0700`; ujail
получал `EACCES` при запуске hostapd.

**Control flow.** Старые участки: `install.sh:408`
(`snapshot_installation`) и `install.sh:472` (`restore_installation`). Опасной
операцией был `tar -C / -xf "$archive"`.

**Воспроизведение.** `tests/installer-lifecycle.sh` создаёт mock OpenWrt tree,
где критические parents имеют `0755`, строит snapshot под `umask 077`, имитирует
failed install и restore, а затем проверяет содержимое и mode каждого parent.
Тест ломается, если metadata архива снова накладывается на mock root.

**Исправление.** Manifest snapshot теперь хранит mode/uid/gid каждого
allowlisted объекта. Копии архива сохраняют nested metadata. Restore извлекает
архив только в private rollback directory, удаляет и устанавливает заново только
allowlisted targets и применяет записанные metadata к самому target. Архив больше
никогда не извлекается в `/`, staging root не становится restore target, а
критические системные каталоги отклоняются в manifest.

Старый двухколоночный manifest принимается только после получения metadata из
private extracted target; он всё равно никогда не извлекается поверх `/`.
`preflight_install` проверяет mode критических каталогов и, если доступен `/rom`,
сравнивает их с `/rom`. Несовпадение блокирует операцию с диагнозом и не чинится
автоматически.

## B. Timeout Zapret и orphan `nfqws`

**Факт.** Прежний runner убивал shell process group, но upstream blockcheck мог
daemonize `nfqws` в новую session. После timeout оставался `nfqws` с `PPid=1`, а
иногда и состояние NFQUEUE.

**Control flow.** `internal/zapret/calibration_runner_linux.go:49` ограничивает
runner process group. Trap cleanup находится в `scripts/calibrate-zapret.sh:236`,
а blockcheck session стартует в `scripts/calibrate-zapret.sh:327`.

**Исправление.** Calibration запускает blockcheck в отдельной session, если
доступен `setsid`, записывает process identity и выполняет cleanup при success,
error, timeout и signal. Cleanup завершает только принадлежащую process group,
затем ищет новые `nfqws` по PID/start-time/executable и обязательному
`ROUTER_POLICY_CALIBRATION_RUN_ID`, если provider daemonize создал новую session.
PID reuse отклоняется. Немаркированный процесс считается чужим: cleanup
завершается fail-closed и не пытается угадать, что его можно убить. Marker
передаётся и через upstream `NFQWS`, и через `NFQWS_BIN`.

Cleanup проверяет calibration NFQUEUE/table namespace до restart ранее managed
Zapret и сравнивает snapshot `ip route`/`ip rule` до и после запуска. Глобальные
`pkill`, `killall` и nft flush не используются.

`tests/zapret-calibration-runtime.sh` покрывает success, failure, timeout и
blockcheck, который запускает скопированный `nfqws` daemon и возвращает `124`.
Daemon не должен пережить cleanup; оставленный temporary route также делает тест
красным.

## C. Background probing и нагрузка на sockets

**Факт.** `startOperationalSchedulers` запускал полный VLESS health cycle сразу
после старта и повторял его по короткому глобальному интервалу.
`startDNSDiscovery` вызывал `discoverDomain` для каждой observation. В старом
`discoverDomain` проверка `observe_only` выполнялась *после* `domainChecker`,
поэтому passive mode всё равно запускал DNS/TLS/HTTP/SOCKS probes.
`fetchTextViaRoute` создавал новый `http.Transport` без закрытия idle connections,
в отличие от `runHTTPAttempt`.

**Исправление.** `observe_only` теперь пишет bounded observation event и выходит
до `domainChecker`; повторные DNS observations deduplicate без route probe. DNS
events попадают в очередь максимум на 32 элемента и обслуживаются одним worker.
Старый цикл `router-policy daemon`, который раз в пять минут проверял три
захардкоженных сервиса, удалён: procd его не использовал и безопасным production
scheduler он не был.

Все route-health и discovery jobs используют process-wide probe semaphore с
жёстким максимумом четырёх активных jobs. Inventory health cycle откладывается
после boot и запускается раз в сутки с jitter 21–27 часов для стандартных 24 ч,
а не превращается в пятиминутный нагрузочный тест. `fetchTextViaRoute` закрывает
idle connections после каждого запроса.

Regression-покрытие включает zero-probe для observe-only, baseline/discovery,
общий probe budget и runtime-тесты installer/Zapret. Тест
`TestDiscoveryStormIsBoundedAndDrainsToBaseline` подаёт 1000 синтетических
observations, подтверждает принятие только 32 элементов и возвращение очереди к
нулю после drain. Health-тесты запускают восемь routes через semaphore на четыре
слота и доказывают, что active route jobs никогда не превышают четыре.

Idle CPU, стабильность FD/socket и рост thread/goroutine нельзя честно доказать
Windows unit-тестом. Это отдельные hardware-gate измерения в
`docs/hardware-read-only-gate.md`; hardware PASS не заявляется, пока не сохранены
одноминутные idle samples и before/after FD/socket counts.

### Один logical check и fan-out

`planner.CheckDomain` один раз проходит конечный список candidates и останавливается
на первом verified result. Один `probeRoute` проверяет только заданные probe URLs,
затем выполняет не более одной external-egress проверки. DNS answers, HTTP
redirects и SOCKS dials ограничены probe context и реализацией route; они не
добавляют новые discovery observations.

Unknown-domain discovery удерживает один global probe-budget token на время
последовательной цепочки candidates. Один logical job не может размножиться в
неограниченное число route jobs; общий потолок остаётся равен четырём.

## Контракт планировщика

| Событие | Работа | Максимум route probes | Timeout / следующий запуск |
|---|---|---:|---|
| Cold start | recovery и готовность control plane | 0 сразу; один отложенный inventory cycle | jitter старта 30–90 с |
| Первое неизвестное доменное имя | только observation/cache; decision job лишь в suggest/auto modes | 0 в observe-only; иначе 1 job | 10–15 с, dedupe по eTLD+1 |
| Повторный DNS-запрос | обновить счётчики observation | 0 | без probe |
| Отказ выбранного VLESS | selected route, затем один fallback candidate | 2 последовательно | 3–5 с, circuit breaker |
| Восстановление failed route | один probe для route после cooldown | 1 | 5 мин → 15 мин → 1 ч → 6 ч |
| Refresh подписки | fetch/parse; candidate verification ограничена общим budget | 4 global jobs | timeout 2 мин, без overlap |
| Известное expiry | только refresh подписки | 0, если ничего не изменилось | одно refresh window |
| TSPU/GEO revalidation | targeted Direct check названного домена | 1 | раз в неделю или вручную; без VLESS fan-out |
| Ручная проверка пути | selected path указанного сервиса | 1 | 10 с |

Жёсткий process-wide максимум — четыре concurrent route-check jobs. Discovery
job удерживает один slot и последовательно проверяет свою цепочку, поэтому число
routes не увеличивает concurrency. Unknown-domain queue ограничена 32. При
backpressure отбрасываются только повторные observations и публикуется
`discovery_queue_full`; бесконтрольная работа не запускается.

## Аудит операций с файлами и процессами

Проверены `chmod`, `chown`, `umask`, `mkdir`/`MkdirAll`, recursive copy, `tar`,
`rm -rf`, `os.Chmod`, `os.Chown`, `os.MkdirAll`, `exec.Command`, timeout wrappers
и все snapshot/rollback call sites.

- Installer rollback теперь привязан к allowlist и manifest; архив не извлекается
  на `/`.
- Backup roots install/uninstall валидируются, path components не могут быть
  symlink, export archives содержат только allowlisted descendants.
- Runtime/component directories используют private roots `0700`; публичные
  binary/script явно получают `0755`.
- Перед завершением process calibration проверяются PID, start time и executable.
- Lifecycle cleanup остаётся namespace-specific; глобальной очистки процессов или
  nft не добавлено.
- Остальные найденные архивы — producers backup/export, а не restore поверх
  системных parents; они подчиняются registry и allowlist.

## Runtime boundary

Refresh подписки учитывает expiry metadata: известный expiry планирует одно окно
refresh до истечения, а source без expiry получает jittered daily refresh. Это не
часть route-health cycle.

Reactive failover имеет явный ingress `ReportSelectedRouteFailure` и один worker.
Нужны три последовательные transport failures, затем выполняется одна
bounded confirmation probe с timeout около пяти секунд; после подтверждения можно
проверить не более одного известного standby, а смена route идёт обычным
transaction/rollback path. Повторные reports объединяются на 10 секунд, failed
route удерживается пять минут. Текущие dataplane adapters ещё не посылают этот
ingress автоматически: вызывающий код должен подключить реальную ошибку request
path; scheduler не угадывает её по периодическому inventory.

Unhealthy route восстанавливается отдельно: не более одного route после cooldown
проверяется в минуту, первая попытка через 5 минут, затем caps 15 минут, 45 минут,
135 минут и 6 часов. Успешный probe очищает retry state, но не перехватывает
трафик молча у текущего selected route.

TSPU/GEO revalidation отделена от health: `RevalidateClassifiedDomain` выполняет
один Direct probe и создаёт suggestion, если Direct снова доступен. Background
scheduler запускает не более одной такой job в час и разделяет проверки одного
service на семь дней. Существующая bypass policy никогда не снимается молча.
