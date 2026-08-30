# Контракт калибровки Zapret

## Что делает текущий код

`POST /api/v1/zapret/calibration` нормализует домен, получает verified
network fingerprint и запускает `CalibrationManager`. До этого изменения
режим `quick` и режим `exhaustive` отличались только значением
`SCANLEVEL` (`quick`/`force`) и бюджетом времени. Это не доказывало, что
quick является curated-набором стратегий, и не доказывало, что curl-запрос
прошёл именно через тестируемый nfqws/NFQUEUE path.

Старое утверждение о «примерно 900 вариантах» и гипотеза о прямом выходе
curl не считаются подтверждёнными этим кодом: отчёт blockcheck не содержал
счётчиков NFQUEUE, route binding или идентификатора nfqws, обслужившего
конкретный запрос.

## Контракт режимов

### Quick Check

Quick — пользовательский bounded check. Он обязан перечислять каждую
curated strategy и возвращать для неё `PASS`, `FAIL`, `TIMEOUT` или
`INFRA_ERROR`. `PASS` допустим только при наличии всех доказательств:

- strategy действительно активирована в тестовом dataplane;
- target/domain/protocol зафиксированы;
- запрос завершился через подтверждённый nfqws/NFQUEUE path;
- latency и полная длительность verification сохранены раздельно;
- cleanup подтверждён (process group, nfqws, nft/NFQUEUE, routes/rules);
- нет foreign-resource mutation.

Если у runtime нет curated runner с таким evidence-контрактом, quick должен
завершиться понятным `zapret_quick_evidence_unavailable`, а не запускать
широкий upstream blockcheck под видом быстрого теста.

### Exhaustive blockcheck

Exhaustive — отдельная явная maintenance-операция. Она может использовать
закреплённый upstream `blockcheck.sh` с `SCANLEVEL=force` и бюджетом до шести
часов. Его curl evidence остаётся evidence только для конкретного target;
это не универсальная гарантия браузерного или клиентского трафика. Результат
exhaustive создаёт кандидатов/черновик, но не активирует production ChangeSet.

## Безопасность выполнения

Все попытки последовательны, потому что текущие upstream resources делят
nft/NFQUEUE и process state. Никакой фоновой calibration не применяет
production ChangeSet. Каждый внешний runner обязан использовать bounded
timeout, process-group cleanup и ownership proof; неизвестный процесс или
сетевой объект означает `INFRA_ERROR` и остановку, а не best-effort cleanup.

## Acceptance criteria

1. Quick без curated/evidence runner не может завершиться `PASS`.
2. Exhaustive не появляется под кнопкой quick и явно предупреждает о
   длительности.
3. Парсер отбрасывает quick-result без target, path proof или cleanup proof.
4. UI показывает `curl evidence` отдельно от `Path verified`.
5. Unit/runtime tests покрывают четыре результата попытки и очистку.
6. Linux namespace/process-group tests являются отдельным evidence level;
   Windows mock PASS не заменяет их.

## Семантика результата evidence

Quick-runner возвращает полную bounded-таблицу проверенных curated-попыток.
У каждой попытки есть уникальный ID профиля, нормализованные target/protocol и
доказательство cleanup. `PASS`, `FAIL` и `TIMEOUT` требуют доказательства, что
запрос прошёл через тестируемый путь; `INFRA_ERROR` предназначен только для
ошибок инфраструктуры и обязан содержать код или диагностику. Запуск, в котором
все кандидаты упали, является корректным terminal result с нулём рекомендаций;
это не ложный успех и не должно превращаться в `NO_SAFE_ROUTE` доменного решения.

Production связывает `ExecCalibrationRunner.QuickScript` со
`scripts/quick-zapret-check.sh`. Runner последовательно выполняет шесть
встроенных проверенных профиля, выделяет bounded private NFQUEUE, создаёт только
свою временную output-table для отдельного probe UID и запускает одну
принадлежащую ему process group `nfqws` на попытку. В отчёт попадают delta
счётчика, target IP, kernel route lookup до запроса, HTTP-результат, latency и
cleanup proof. Запрос принудительно идёт без переменных HTTP-прокси
(`--noproxy '*'`), иначе локальный proxy мог бы дать ложное доказательство пути.
Ответ HTTP 200 при
неизменившемся счётчике собственной NFQUEUE — `INFRA_ERROR`, а не `PASS`.
Профиль, который публикуется в каталоге, и профиль конкретной попытки хранятся
в разных файлах: первый привязан к production NFQUEUE, второй — к выделенной
временной очереди. Поэтому digest/queue каталога никогда не маскируют другую
стратегию, реально использованную в probe.

На embedded OpenWrt `su` часто отсутствует. Это не блокирует quick-check:
если `/bin/su` (или эквивалентный доверенный helper) недоступен, runner
переходит в явно обозначенный `probe_privilege_mode=root_fallback`, запускает
ограниченный curl от root и ставит в owned output rule `meta skuid 0`. Такой
результат всё равно обязан содержать NFQUEUE counter/path evidence и cleanup
proof; отсутствие privilege-drop helper не превращается в «PASS по старту
nfqws».

Quick и exhaustive используют один runtime lock
`/tmp/router-policy/zapret-calibration.lock` (или настроенный runtime-каталог).
Это не позволяет curated-проверке конфликтовать с upstream scan, NFQUEUE/nft
transition или управляемым сервисом Zapret. Устаревший lock блокирует запуск и
не удаляется молча. После успешного запуска каталог профилей привязывается к
production NFQUEUE; временная queue не сохраняется в active config.

API получает до четырёх безопасных публичных IPv4-целей из проверенного Smart
DNS resolver, если он настроен, иначе использует системный resolver роутера.
Пустой или private-ответ блокирует запуск до старта `nfqws`. Если runner,
инструменты, process-group proof или cleanup proof недоступны, API остаётся
fail-closed и возвращает `zapret_quick_evidence_unavailable` либо явный
инфраструктурный результат; upstream `SCANLEVEL=quick` не подменяется.

Встроенный набор намеренно небольшой и версионируется кодом; выдуманное число
«21 стратегий» не заявляется. Полный upstream blockcheck — отдельная
maintenance-операция.

## Route-check fan-out budget

The same safety boundary applies to every logical route check: a service may
declare at most four probe URLs, each DNS answer contributes at most four
address targets, and egress verification has at most two GeoIP sources. These
limits are enforced by config validation and again at the probe boundary.
Malformed in-memory configuration therefore fails closed before starting
remote GeoIP requests; one DNS observation cannot turn into an unbounded
DNS/HTTP/SOCKS fan-out.

## Cancellation and signal semantics

Calibration has one finally-style cleanup path for normal completion, failure,
timeout, and termination. `SIGTERM`, `SIGINT`, and `SIGHUP` are recorded as
non-successful outcomes (`143`, `130`, and `129` respectively); cleanup still
validates the owned process group, nfqws/NFQUEUE objects, nft state, routes, and
rules before removing the run lock. A cancelled run therefore cannot be
reported as a successful calibration merely because its cleanup completed.

The exhaustive wrapper snapshots the complete `nft list ruleset` output and the
complete route/rule state before starting the provider. The same configured
`NFT_BIN`/`IP_BIN` tools are used after cleanup and the snapshots must compare
byte-for-byte. This deliberately fails closed if a provider leaves an
unregistered NFQUEUE rule/table or if another actor changes the network while
calibration is running; it is not a claim that concurrent mutation is safe.
An nfqws process that was not present in the baseline is killable only with a
matching process-group or per-run ownership marker. An unmarked process is
reported as a foreign-resource conflict and is left alive.
