# Zapret calibration contract

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

## Evidence result semantics

The quick runner returns the complete bounded curated attempt table. Every
attempt has one unique profile ID, the normalized target and protocol, and a
cleanup proof. `PASS`, `FAIL`, and `TIMEOUT` require proof that the request
traversed the tested path; `INFRA_ERROR` is reserved for runner failures and
must carry an error code or diagnostic. A run with only failures is a valid
terminal result with zero recommended candidates; it is not a false success
and it must not be converted into `NO_SAFE_ROUTE` for a domain decision.

Production now wires `ExecCalibrationRunner.QuickScript` to
`scripts/quick-zapret-check.sh`. The runner executes four built-in reviewed
profiles sequentially, allocates a bounded private NFQUEUE, installs only its
own temporary output table for a dedicated probe UID, and starts one owned
`nfqws` process group per attempt. It records the counter delta, target IP,
HTTP result, latency and cleanup proof. A request that returns HTTP 200 while
the owned NFQUEUE counter remains unchanged is `INFRA_ERROR`, never `PASS`.
The catalog emitted after a successful run is rebound to the configured
production NFQUEUE; the temporary test queue is never persisted into the
active configuration.
The API obtains up to four safe public IPv4 targets from a verified Smart DNS
resolver when one is configured, otherwise from the router's system resolver;
an empty or private answer blocks the run before any nfqws process starts.
If the runner, required tools, process-group proof or cleanup proof is missing,
the API still fails closed with `zapret_quick_evidence_unavailable` or an
explicit infrastructure result; it never aliases upstream `SCANLEVEL=quick`.

The built-in set is intentionally small and versioned by code, not presented
as a fabricated "21 strategies" claim. The exhaustive upstream blockcheck
remains a separate maintenance action.

## Route-check fan-out budget

The same safety boundary applies to every logical route check: a service may
declare at most four probe URLs, each DNS answer contributes at most four
address targets, and egress verification has at most two GeoIP sources. These
limits are enforced by config validation and again at the probe boundary.
Malformed in-memory configuration therefore fails closed before starting
remote GeoIP requests; one DNS observation cannot turn into an unbounded
DNS/HTTP/SOCKS fan-out.
