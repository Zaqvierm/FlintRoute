# Evidence remediation

Этот документ — текущий источник истины по software/CI-проверкам remediation.
Каждая запись привязана к точному SHA; evidence другого commit считается stale.

## Область проверки

- Текущий проверяемый HEAD: `4e9d45f`.
- Текущая ветка: `integration/discovery-smartdns-local-dod`.
- Этот документ не наследует hardware evidence от старых SHA.

- Базовый SHA аудита: `d45a779dfa9dc024b426cef358d3df4d32478897`.
- Ветка: `remediation/transaction-and-privilege-boundaries-consolidated`.
- Проверенный code baseline до текущего onboarding delta: `f7a36e63542ef92047c17cca0d5be90987cdd1a4`.
- Software/CI claims ниже относятся только к указанному текущему HEAD; старые
  строки и run IDs, привязанные к другим code heads, считаются историческими.
- Документация обновляется в отдельном содержательном commit после code push;
  code evidence ниже привязано именно к SHA выше.
- Предыдущий docs-head `501d27518dadc829175534a4d8eaf7a1d11699a8` сохранён как
  историческая точка. Этот документ обновляется вместе с текущим docs-аудитом;
  его итоговый commit фиксируется в release handoff, а code evidence не
  считается новым только из-за изменения Markdown.
- Flint 2 в этом цикле не подключался: не было SSH, install, apply, reboot или
  изменения runtime.
- Уровни evidence независимы: local unit/mock, Linux namespace/CI и hardware.
  Нижний уровень не превращается в верхний.
- Старые hardware-записи, включая `docs/flint2-hardware-report.md` и
  `H:\LAN\Versions\FlintRoute 0.2.0-alpha.1\hardware\summary.txt`, имеют статус
  `STALE FOR CURRENT SHA`, пока не будет нового прогона на текущем коде.

## Краткий acceptance summary

| Область | Результат | Доказательство |
|---|---|---|
| Go unit/integration, race, vet, форматирование | PASS (локально на текущем HEAD, 2026-08-28) | `go test ./...`, `go test -race ./...`, `go vet ./...`, `gofmt` |
| Frontend unit/typecheck/build | PASS | 44 Vitest-теста, `npm run typecheck`, `npm run build` |
| Browser/responsive UI | PASS | CI run [32615235578](https://github.com/Zaqvierm/FlintRoute/actions/runs/32615235578) |
| Linux nft transition | STALE FOR CURRENT SHA | CI run [32615235570](https://github.com/Zaqvierm/FlintRoute/actions/runs/32615235570) |
| Linux Zapret process-group и Quick contract | STALE FOR CURRENT SHA | CI run [32615235591](https://github.com/Zaqvierm/FlintRoute/actions/runs/32615235591) |
| Linux-only harness на Windows | NOT RUN LOCALLY | namespace/procfs/mode требуют Linux |
| Root-helper privilege split | PASS (service contract; runtime proof pending) | production init запускает controller как `daemon`, root startup и отсутствие helper socket отвергаются; typed helper покрывает global/transaction paths |
| Route-only assignment dataplane | PARTIAL | revision-bound decision cache и post-probe есть; nft/dnsmasq runtime consumer не доказан |
| Flint 2 hardware | NOT RUN / STALE | hardware не трогалось |

## Acceptance matrix

| Проверка | Команда/тест | Результат | Уровень |
|---|---|---|---|
| Семантический ответ transaction adapter | `go test ./internal/adapter ./internal/helper ./internal/api` | PASS | local |
| Fault boundaries transaction | fault-injection в `internal/api/transaction_test.go` | PASS | local |
| Recovery mutation allowlist | `go test ./internal/api -run 'TestRecovery|TestAutomaticDomainCommit|TestHealthScheduler'` | PASS | local |
| Onboarding durable write fence | `TestOnboardingMutationRespectsRecoveryFence` | PASS | local |
| Ошибка сохранения recovery status | `TestRecoveryStatusPersistenceFailureInstallsMemoryFence` | PASS | local |
| Запрещённый `not_required` identity | `TestRecoveryMutationFenceRejectsUnprovenNotRequiredIdentity` | PASS | local |
| Гонка recovery/apply | `TestRecoveryTransitionExcludesConcurrentMutation` | PASS | local |
| Immutable bootstrap | `tests/openwrt-adapter-integration.sh` | PASS | mock |
| Права родителей installer | `tests/installer-lifecycle.sh` | PASS | mock |
| Typed health response parsing | `go test ./internal/healthjson`, `router-policy internal-health-field` | PASS | local |
| HTML/portal response rejection | `go test ./internal/vpnsub -run TestFetchSubscriptionRejectsHTML` | PASS | local |
| Канонические ownership paths | `tests/installer-lifecycle.sh`, `tests/installer-backup.sh` | PASS | mock |
| Boot guard | `tests/boot-guard-policy.sh`, `tests/boot-guard-service.sh` | PASS | mock |
| Typed helper boundary | `tests/helper-service.sh`, `go test ./internal/helper` | PASS | local/mock |
| Чужой helper socket не удаляется | `TestServeUnixDoesNotRemoveForeignSocketPathObject` | PASS | local/mock |
| Typed recovery reconcile | `go test ./internal/adapter ./internal/helper` | PASS | local; controller status PARTIAL |
| Atomic nft transition | `tests/nft-transition-namespace.sh` | PASS | Linux CI |
| Hotplug boundedness | `tests/hotplug-bounded.sh` | PASS | mock |
| Cleanup Zapret process group | `tests/zapret-calibration-runtime.sh` | PASS | Linux CI |
| SSRF и decompression limits | `go test ./internal/remotefetch ./internal/vpnsub ./internal/tspu ./internal/geoip` | PASS | local |
| Typed Xray input | `go test ./internal/vpnsub` | PASS | local |
| Resource budget | `go test ./internal/api ./internal/probe` | PASS | local |
| Запрет unvalidated probe fan-out | `go test ./internal/probe -run TestProbeRouteRejectsUnvalidatedProbeURLFanout` и race-вариант | PASS | local |
| `NO_SAFE_ROUTE` terminal semantics | planner cancellation/exhaustion и API probe-state tests | PASS | local |
| Classification/route confidence разделены | `TestClassificationConfidenceIsIndependentFromRouteConfidence` | PASS | local |
| Latency/duration разделены | probe/API separation tests | PASS | local |
| Неизвестная latency не считается нулём | `TestSelectBestDoesNotTreatUnknownLatencyAsZero` | PASS | local |
| ShellCheck | `.tools/shellcheck-v0.11.0/shellcheck.exe -x <tracked shell>` | PASS | local |
| Полный локальный runner | `tests/run-all.ps1` | PASS, `all_tests_ok=true`, 303.3 s | Windows; Linux части NOT RUN LOCALLY |
| `git diff --check` | `git diff --check` | PASS | local |

### Installer health parser boundary

`install.sh` no longer extracts health fields with `tr`/`sed` heuristics. It
delegates to the typed `router-policy internal-health-field` command, which
accepts only the allowlisted health fields, bounds the response to 1 MiB,
rejects symlinks/non-regular files and malformed/trailing JSON, and supports
both the API `data` envelope and a bare fixture. A missing parser or malformed
response fails the installer health gate closed.

## Запуски CI на текущей ветке

Для исторического code head `b43d56a45ba26fb93ee3609c5eb190ef60bac29a` после push прошли:

- nft transition: [32615235570](https://github.com/Zaqvierm/FlintRoute/actions/runs/32615235570);
- Zapret process-group и Quick contract: [32615235591](https://github.com/Zaqvierm/FlintRoute/actions/runs/32615235591);
- UI browser/responsive: [32615235578](https://github.com/Zaqvierm/FlintRoute/actions/runs/32615235578).

Эти три run ID относятся к историческому code SHA и не являются evidence для
текущего `4e9d45f`. Для текущего HEAD обязательный Linux CI ещё не запускался;
до его выполнения строки выше остаются `STALE FOR CURRENT SHA`.

Исторические запуски для старых code/docs SHA сохранены ниже только для
археологии и не считаются доказательством текущего кода:

- nft transition: [32608938460](https://github.com/Zaqvierm/FlintRoute/actions/runs/32608938460);
- Zapret process-group: [32608938469](https://github.com/Zaqvierm/FlintRoute/actions/runs/32608938469);
- UI browser/responsive: [32608938490](https://github.com/Zaqvierm/FlintRoute/actions/runs/32608938490).

После docs-only HEAD `501d27518dadc829175534a4d8eaf7a1d11699a8` workflows были
повторены; после перевода документации на `effa938` они также прошли:

- nft transition: [32609130868](https://github.com/Zaqvierm/FlintRoute/actions/runs/32609130868);
- Zapret process-group: [32609130871](https://github.com/Zaqvierm/FlintRoute/actions/runs/32609130871);
- UI browser/responsive: [32609130865](https://github.com/Zaqvierm/FlintRoute/actions/runs/32609130865).

Для исторического SHA `effa938`:

- nft transition: [32611131546](https://github.com/Zaqvierm/FlintRoute/actions/runs/32611131546);
- Zapret process-group: [32611131536](https://github.com/Zaqvierm/FlintRoute/actions/runs/32611131536);
- UI browser/responsive: [32611131534](https://github.com/Zaqvierm/FlintRoute/actions/runs/32611131534).

Аннотация о Node 20 deprecation не влияет на результат; все jobs завершились
успешно.

## Что именно закрыто remediation

- Commit protocol проверяет semantic response, token/revision/hash и переводит
  неоднозначность в `RECOVERY_REQUIRED`; silent `rolled_back` запрещён.
- Bootstrap отделён от candidate/active artifact; uncommitted candidate не
  используется после рестарта.
- Boot guard получает marks typed-путём и не снимается по голому timeout.
- Owned nft transition выполняется атомарным batch; global `fw4 reload` для
  собственной таблицы не используется.
- Hotplug только coalesces bounded observation и не имеет права на global repair.
- Rescue и recovery fence блокируют mutation при `starting`, `error`, пустом или
  неизвестном status; read-only diagnostics остаются доступны.
- Helper использует Unix socket `0600`, typed commands и ownership checks; полный
  non-root controller пока не закрыт и честно отмечен `PARTIAL`.
- SSRF, raw provider Xray JSON, process ownership и Zapret cleanup покрыты
  отдельными regression/CI проверками.
- `observe_only` действительно не вызывает active probe/adapter; discovery queue
  ограничена 32, общий route-probe budget — четыре concurrent jobs.
- `NO_SAFE_ROUTE` — только terminal exhaustion; `VERIFYING` не превращается в
  ложный отказ. `route_latency_ms` отделён от `verification_duration_ms`.
- DNS watcher отслеживает inode/rotation и никогда не обнуляет live dnsmasq log;
  provider snapshot отдаёт `freshness=stale` во время долгого refresh вместо
  выдачи старых данных как live.
- Login limiter имеет глобальное bounded-окно до дорогого Argon2, поэтому
  вращение username/source не создаёт неограниченный hash DoS.
- Route-bound remote fetch больше не падает обратно на непроверенный hostname:
  отсутствие резолва и private/bogon resolved endpoint дают fail-closed error;
  subscription/GeoIP/TSPU/component downloads закрывают idle connections.
- Quick Zapret не может запрашивать restart managed production service; для
  exhaustive режима UI теперь тоже явно отказывается от скрытого restart и
  требует maintenance-safe условия.

## Quick Zapret и exhaustive blockcheck

`quick` — bounded default с шестью встроенными curated profiles (`general`,
`general-alt`, `general-alt2`, `general-alt4`, `general-alt6`, `general-alt10`). Для PASS
обязательны owned NFQUEUE counter, target, process group и полный cleanup; один
успешный curl без path evidence считается `INFRA_ERROR`. Quick не активирует
production profile молча.

`exhaustive` — отдельная maintenance-операция с `SCANLEVEL=force` и лимитом шесть
часов. В репозитории нет подтверждённого набора ровно из 21 стратегии, поэтому
UI не выдумывает это число.

## Ограничения

- Полное отсутствие split-brain не заявляется до reboot/fault matrix и hardware
  evidence; текущая гарантия — fencing подтверждённых ambiguous states.
- Production controller запускается от dedicated `daemon` account и требует
  fixed helper socket; root/без-helper запуск отвергается. Runtime Linux/OpenWrt
  и hardware proof ещё не выполнены. LAN exposure остаётся явным opt-in.
- Automatic route-only assignment разрешён только в явном
  `auto_apply_verified` режиме и только для уже enabled route с доказанным
  `PathVerified`; topology/component apply из discovery запрещён.
- CPU/FD/socket idle, реальное восстановление после power loss и пользовательский
  hardware flow требуют отдельного read-only gate и не наследуются от CI.

## Правило актуальности

Перед ссылкой на эту матрицу проверяй `git rev-parse HEAD`, branch и дату CI.
Любой результат с другим code SHA помечай `STALE FOR CURRENT SHA`, даже если все
тесты когда-то прошли.
