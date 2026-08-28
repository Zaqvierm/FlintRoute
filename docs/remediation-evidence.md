# Evidence remediation

Этот документ — текущий источник истины по software/CI-проверкам remediation.
Каждая запись привязана к точному SHA; evidence другого commit считается stale.

## Область проверки

- Текущий проверяемый code HEAD: `4fec55d41adae0cf907b8e56aa80f91c776a974c` (route-only assignment is fenced without a registered runtime consumer; semantic, revision-bound receipts and idempotent rollback are required before persisting an applied mapping; discovery suggestion/control-state persistence failures are surfaced and block unsafe auto-assignment; installer rollback lease remains armed through post-install checks; DNS observer target is manifest-bound; Quick JSON channel is isolated from nft diagnostics; transient HTTP transports close both wrapper and pinned dial pools; prefix renames flush their containing directory; corrupt-state rescue artifacts are synced and atomically renamed with unique names; failed Zapret calibration retains at most three private bounded forensic bundles after cleanup; end-to-end latency is measured from DNS/network path and never derived from full verification duration; probe terminal statuses are canonicalized case-insensitively; strict JSON decoders reject trailing documents in kernel command and IP state parsers; privileged adapter success now requires an independent operation/generation/transaction/revision/candidate/artifact/rollback-token evidence binding; reconcile receipts expose the same direct binding fields as every other adapter operation; candidate_valid=false is rejected even with exit code 0; baseline recovery clears the all-transit boot fence only through a typed revision/candidate-bound operation with semantic evidence; production adapter accepts only the fixed root-helper socket; helper responses reject unknown fields and trailing JSON).
- Текущая ветка: `integration/discovery-smartdns-local-dod`.
- Этот документ не наследует hardware evidence от старых SHA.

- Базовый SHA аудита: `d45a779dfa9dc024b426cef358d3df4d32478897`.
- Историческая ветка remediation: `remediation/transaction-and-privilege-boundaries-consolidated`.
- Проверенный code baseline до текущего onboarding delta: `f7a36e63542ef92047c17cca0d5be90987cdd1a4`.
- Software/CI claims ниже относятся только к указанному текущему HEAD; старые
  строки и run IDs, привязанные к другим code heads, считаются историческими.
- Документация по изменённому safety-контракту обновляется в том же
  содержательном commit; CI evidence привязывается после завершения workflow.
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
| Frontend unit/typecheck/build | PASS | 47 Vitest-тестов, `npm run typecheck`, `npm run build` |
| Browser/responsive UI | PASS | exact-SHA CI run [33145350784](https://github.com/Zaqvierm/FlintRoute/actions/runs/33145350784) |
| Linux nft transition | PASS | exact-SHA CI run [33145350768](https://github.com/Zaqvierm/FlintRoute/actions/runs/33145350768) |
| Linux Zapret process-group и Quick contract | PASS | exact-SHA CI run [33145350760](https://github.com/Zaqvierm/FlintRoute/actions/runs/33145350760) |
| Linux-only harness на Windows | NOT RUN LOCALLY | namespace/procfs/mode требуют Linux |
| Root-helper privilege split | PARTIAL (production contract; runtime peer proof pending) | production init запускает controller как `daemon`, root startup и отсутствие helper socket отвергаются; production adapter принимает только фиксированный `/var/run/router-policy/helper.sock`; typed helper покрывает global/transaction paths и ограничивает concurrent connections; Linux peer-credential/runtime evidence ещё не получено |
| Route-only assignment dataplane | PARTIAL | revision-bound decision cache и post-probe есть; nft/dnsmasq runtime consumer не доказан |
| Route-only runtime-consumer fence | PASS | `go test ./internal/api -run 'TestAutomaticDomainCommit|TestDiscoverySuggestionApply'`; absent consumer and invalid semantic receipt cannot produce `applied=true` |
| Flint 2 hardware | NOT RUN / STALE | hardware не трогалось |

## Acceptance matrix

| Проверка | Команда/тест | Результат | Уровень |
|---|---|---|---|
| Семантический ответ transaction adapter | `go test ./internal/adapter ./internal/helper ./internal/api`; `TestAdapterExecutorRejectsSuccessWithoutExactSemanticBinding` | PASS | local + exact-SHA CI [33140362889](https://github.com/Zaqvierm/FlintRoute/actions/runs/33140362889) |
| Fault boundaries transaction | fault-injection в `internal/api/transaction_test.go` | PASS | local |
| Recovery mutation allowlist | `go test ./internal/api -run 'TestRecovery|TestAutomaticDomainCommit|TestHealthScheduler'` | PASS | local |
| Onboarding durable write fence | `TestOnboardingMutationRespectsRecoveryFence` | PASS | local |
| Ошибка сохранения recovery status | `TestRecoveryStatusPersistenceFailureInstallsMemoryFence` | PASS | local |
| Запрещённый `not_required` identity | `TestRecoveryMutationFenceRejectsUnprovenNotRequiredIdentity` | PASS | local |
| Гонка recovery/apply | `TestRecoveryTransitionExcludesConcurrentMutation` | PASS | local |
| Immutable bootstrap | `tests/openwrt-adapter-integration.sh` | PASS | mock |
| Права родителей installer | `tests/installer-lifecycle.sh` | PASS | mock |
| Installer durability sync failure | `tests/installer-durability.sh` | PASS; failure is surfaced and install cannot report success | mock |
| Export backup synthetic-directory exclusion | `tests/installer-backup.sh` | PASS; archive carries files only, never staging parent modes | mock |
| Durable prefix renames | `tests/installer-prefix-switch.sh` | PASS; each prefix rename calls the containing-directory sync helper; ambiguous crash layouts remain fenced | mock/static |
| Durable corrupt-state forensic artifact | `go test ./internal/state -run TestOpenPreservesUnreadableDatabaseForRescue` | PASS; artifact content is preserved through a synced temporary file and atomic rename; partial temp files are removed | local |
| Bounded Zapret failure evidence | `tests/zapret-calibration-runtime.sh`, `scripts/calibrate-zapret.sh` | PASS; failed runs retain status, bounded report tail and process/network baselines in at most three 0700 bundles while success removes staging | Linux CI run [33123611490](https://github.com/Zaqvierm/FlintRoute/actions/runs/33123611490); Windows local runner reports NOT RUN LOCALLY |
| Installer post-install rollback fence | `tests/installer-lifecycle.sh` | PASS; rollback is not disarmed before observer/prefix verification, and incomplete verification aborts before backup pruning | mock |
| DNS observer install rollback ownership | `tests/installer-lifecycle.sh`, `tests/dns-observer-bootstrap.sh` | PASS; configured observer target is included in the exact snapshot and restored after simulated failure | mock |
| Quick runner machine-output isolation | `tests/zapret-quick-contract.sh`, `scripts/quick-zapret-check.sh` | PASS; nft load diagnostics are stderr-only, preventing BusyBox/nft output from corrupting bounded JSON | mock/static |
| Typed health response parsing | `go test ./internal/healthjson`, `router-policy internal-health-field` | PASS | local |
| HTML/portal response rejection | `go test ./internal/vpnsub -run TestFetchSubscriptionRejectsHTML` | PASS | local |
| Канонические ownership paths | `tests/installer-lifecycle.sh`, `tests/installer-backup.sh` | PASS | mock |
| Boot guard | `tests/boot-guard-policy.sh`, `tests/boot-guard-service.sh` | PASS | mock |
| Baseline boot-fence release | `tests/boot-guard-baseline.sh`; `TestBaselineRecoveryClearsOnlyThroughBaselineBoundAdapterOperation`; `TestAdapterExecutorAcceptsOnlySemanticallyProvenBaselineBootGuardClear` | PASS; baseline recovery cannot clear the all-transit fence through an unbound command and rejects mismatched semantic evidence | local/mock + exact-SHA CI [33143980734](https://github.com/Zaqvierm/FlintRoute/actions/runs/33143980734) |
| Typed helper boundary | `tests/helper-service.sh`, `go test ./internal/helper` | PASS | local/mock |
| Fixed production helper socket | `go test ./internal/adapter -run TestNewOpenWrtRequiresFixedHelperSocket` | PASS; missing and foreign socket paths are rejected before production adapter construction | local |
| Strict helper response schema/framing | `go test ./internal/helper -run 'TestCallRejects(TrailingResponseDocument|UnknownResponseField)'` | PASS; unknown fields, trailing JSON and malformed trailing bytes are rejected before semantic acceptance | local |
| Helper connection budget | `TestServeUnixBoundsConcurrentHelperWork` | PASS (Linux-only test; Windows skips) | local/Linux semantics |
| Generation-bound boot-guard clear | `TestAdapterExecutorAcceptsOnlyGenerationBoundBootGuardClear`, `openwrt-adapter-integration.sh` | PASS | local/mock + exact-SHA CI [33140362889](https://github.com/Zaqvierm/FlintRoute/actions/runs/33140362889) |
| Чужой helper socket не удаляется | `TestServeUnixDoesNotRemoveForeignSocketPathObject` | PASS | local/mock |
| Typed recovery reconcile | `go test ./internal/adapter ./internal/helper` | PASS | local; controller status PARTIAL |
| Atomic nft transition | `tests/nft-transition-namespace.sh` | PASS | Linux CI |
| Hotplug boundedness | `tests/hotplug-bounded.sh` | PASS | mock |
| Cleanup Zapret process group | `tests/zapret-calibration-runtime.sh` | PASS | Linux CI |
| SSRF и decompression limits | `go test ./internal/remotefetch ./internal/vpnsub ./internal/tspu ./internal/geoip` | PASS | local |
| HTTP transport/socket cleanup | `go test ./internal/remotefetch -run TestNewClientCloseIdleConnectionsClosesPinnedDialTransport` | PASS; `CloseIdleConnections` closes both wrapper and pinned dial pools; one-shot management/watchdog clients close their idle pools | local |
| Typed Xray input | `go test ./internal/vpnsub` | PASS | local |
| Resource budget | `go test ./internal/api ./internal/probe` | PASS | local |
| Запрет unvalidated probe fan-out | `go test ./internal/probe -run TestProbeRouteRejectsUnvalidatedProbeURLFanout` и race-вариант | PASS | local |
| `NO_SAFE_ROUTE` terminal semantics | planner cancellation/exhaustion и API probe-state tests | PASS | local |
| Classification/route confidence разделены | `TestClassificationConfidenceIsIndependentFromRouteConfidence` | PASS | local |
| Latency/duration разделены | probe/API separation tests | PASS | local |
| End-to-end latency is not verification duration | `TestFinalizeCheckResultDoesNotDeriveE2EFromVerificationDuration`, `TestProbeHTTP200WithMarker` | PASS | local + exact-SHA CI `33131911565` (full safety), `33131911510` (nft), `33131911534` (UI), `33131911507` (Zapret) |
| Strict JSON document boundaries | `go test -race ./internal/probe ./internal/dataplane` | PASS; trailing JSON after the first document is rejected in kernel-command and route/rule state parsers | local + exact-SHA CI `33137838195` |
| Неизвестная latency не считается нулём | `TestSelectBestDoesNotTreatUnknownLatencyAsZero` | PASS | local |
| ShellCheck | `.tools/shellcheck-v0.11.0/shellcheck.exe -x <tracked shell>` | PASS | local |
| Полный локальный runner | `tests/run-all.ps1` | PASS, `all_tests_ok=true`; включает 47 Vitest и 26 Playwright tests | Windows; Linux части NOT RUN LOCALLY |
| Clean-clone POSIX runner | `sh tests/run-all.sh` в отдельном clone `6af2754` | PASS, `all_tests_ok=true`; shellcheck отсутствовал, Linux-only части `NOT RUN LOCALLY` | clean clone + externally pinned Go |
| `git diff --check` | `git diff --check` | PASS | local |

### Installer health parser boundary

`install.sh` no longer extracts health fields with `tr`/`sed` heuristics. It
delegates to the typed `router-policy internal-health-field` command, which
accepts only the allowlisted health fields, bounds the response to 1 MiB,
rejects symlinks/non-regular files and malformed/trailing JSON, and supports
both the API `data` envelope and a bare fixture. A missing parser or malformed
response fails the installer health gate closed.

## Запуски CI и clean-clone evidence

Для предыдущего code head `43d889775e9960383450b23e351a712fbca1a03f` после push прошли:

- exact-SHA full safety gate: [33137838195](https://github.com/Zaqvierm/FlintRoute/actions/runs/33137838195);
- nft transition: [33137838187](https://github.com/Zaqvierm/FlintRoute/actions/runs/33137838187);
- Zapret process-group и Quick contract: [33137838154](https://github.com/Zaqvierm/FlintRoute/actions/runs/33137838154);
- UI browser/responsive: [33137838184](https://github.com/Zaqvierm/FlintRoute/actions/runs/33137838184).

Эти исторические run ID привязаны к exact code SHA `43d889775e9960383450b23e351a712fbca1a03f`.
Документационный HEAD может отличаться от code HEAD, но не меняет исходный
результат тестов; при изменении кода evidence снова становится stale.

Для текущего code head `4fec55d41adae0cf907b8e56aa80f91c776a974c`
после docs-only push `c932cf69b742215ee0a34bbbcb52c4b0ffcb102a` также прошли
все PR workflows:

- exact-SHA full safety gate: [33145350754](https://github.com/Zaqvierm/FlintRoute/actions/runs/33145350754);
- nft transition: [33145350768](https://github.com/Zaqvierm/FlintRoute/actions/runs/33145350768);
- Zapret process-group и Quick contract: [33145350760](https://github.com/Zaqvierm/FlintRoute/actions/runs/33145350760);
- UI browser/responsive: [33145350784](https://github.com/Zaqvierm/FlintRoute/actions/runs/33145350784).

Это software/CI evidence. Она не заменяет Linux-local запуск и hardware proof.

Для исторического code head `dfcdbb41f36c939a63ad7bac05450af0370628dc` локальный
полный runner завершился `all_tests_ok=true`; его exact-SHA CI evidence была
pending на момент следующего code delta и потому не наследуется текущим SHA.

Для исторического code head `f056c73b5772ce89b957ad1023f90e1f9c3867d1` все обязательные
workflows завершились успешно:

- exact-SHA full safety gate: [33140362889](https://github.com/Zaqvierm/FlintRoute/actions/runs/33140362889);
- nft transition: [33140362873](https://github.com/Zaqvierm/FlintRoute/actions/runs/33140362873);
- Zapret process-group и Quick contract: [33140362852](https://github.com/Zaqvierm/FlintRoute/actions/runs/33140362852);
- UI browser/responsive: [33140362845](https://github.com/Zaqvierm/FlintRoute/actions/runs/33140362845).

Full gate включает `go test ./...`, `go test -race ./...`, `go vet ./...`,
frontend typecheck/unit/build, browser tests, ShellCheck, installer/adapter/
recovery fixtures, Zapret ownership, Linux nft namespace и secret/diff checks.

Для исторического code head `38a0ad343aa1f4f53ef4f1825815ce1cf2eaff05` все обязательные
workflows завершились успешно:

- exact-SHA full safety gate: [33140683396](https://github.com/Zaqvierm/FlintRoute/actions/runs/33140683396);
- nft transition: [33140683434](https://github.com/Zaqvierm/FlintRoute/actions/runs/33140683434);
- Zapret process-group и Quick contract: [33140683443](https://github.com/Zaqvierm/FlintRoute/actions/runs/33140683443);
- UI browser/responsive: [33140683401](https://github.com/Zaqvierm/FlintRoute/actions/runs/33140683401).

Этот full gate также покрывает `candidate_valid=false` rejection в typed helper
и legacy adapter execution tests.

Для текущего code head `ff8ad247d2f6eed254d461e5c1331b0dca026295` после push все
обязательные workflows завершились успешно:

- exact-SHA full safety gate: [33143980734](https://github.com/Zaqvierm/FlintRoute/actions/runs/33143980734);
- nft transition: [33143980738](https://github.com/Zaqvierm/FlintRoute/actions/runs/33143980738);
- Zapret process-group и Quick contract: [33143980727](https://github.com/Zaqvierm/FlintRoute/actions/runs/33143980727);
- UI browser/responsive: [33143980729](https://github.com/Zaqvierm/FlintRoute/actions/runs/33143980729).

Этот delta добавляет отдельную baseline-bound операцию снятия boot fence.
Она проверяет revision/candidate binding и semantic evidence `boot_guard=cleared`
и `transaction_state=baseline_confirmed`; обычный unbound clear для controller
не используется. Это не является доказательством раннего classifier до WAN и
не заменяет hardware cold-boot validation.

Предыдущие run ID для исторического code head `1118e6594476fc05f8b52ad4c800327a916cb110`
сохранены ниже как археологическое evidence и не наследуются текущим SHA.

Кодовый delta `e6203e3` дополнительно прошёл локальные `go test ./...`,
`go test -race ./...`, `go vet ./...` и `git diff --check`. Exact-SHA Linux
workflows для этого delta ещё не запускались; старые CI run IDs выше не
перенаследуются автоматически.

Локальный clean-clone прогон текущего SHA выполнен в
`H:\LAN\Scratch\flintroute-clean-clone-20260828-055346` после `npm ci` и
установки Chromium. Полный `tests/run-all.ps1` с явно указанными внешними
`GO_BINARY`, `SHELLCHECK_BINARY` и `GIT_BASH` завершился `all_tests_ok=true`;
это воспроизводимое доказательство исходного дерева, но не hermetic toolchain
proof. Linux process-group и nft namespace проверки на Windows честно помечены
`NOT RUN LOCALLY`; их PASS получен отдельными exact-SHA Linux CI runs выше.

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
- Privileged helper теперь требует, чтобы stdout adapter независимо подтвердил
  operation, generation, transaction/revision и candidate/artifact/rollback-token
  hashes; отсутствующее или неверное поле отклоняется даже при exit code 0.
- Bootstrap отделён от candidate/active artifact; uncommitted candidate не
  используется после рестарта.
- Boot guard использует all-transit `forward policy drop`, поэтому новые
  unmarked flows не проходят до reconcile; снятие для committed transaction и
  baseline выполняется только через typed generation-bound operation с
  semantic evidence. Это не доказывает ранний classifier до WAN.
- Owned nft transition выполняется атомарным batch; global `fw4 reload` для
  собственной таблицы не используется.
- Hotplug только coalesces bounded observation и не имеет права на global repair.
- Rescue и recovery fence блокируют mutation при `starting`, `error`, пустом или
  неизвестном status; read-only diagnostics остаются доступны.
- Helper использует Unix socket `0600`, typed commands и ownership checks;
  production init требует non-root controller и helper socket, но runtime
  peer-credential/Linux/hardware evidence ещё отделены и отмечены `PARTIAL`.
- Снятие boot guard после commit теперь идёт только через transaction-bound
  helper command с совпадающими transaction/revision/candidate/artifact hashes;
  unbound global clear больше не принимается. Старая idempotent shell-команда
  оставлена только для procd boot-guard stop path.
- SSRF, raw provider Xray JSON, process ownership и Zapret cleanup покрыты
  отдельными regression/CI проверками.
- `observe_only` действительно не вызывает active probe/adapter; discovery queue
  ограничена 32, общий route-probe budget — четыре concurrent jobs.
- Export backup archives omit synthetic staging directories, so even an
  accidental future restore cannot replay installer umask modes onto system
  parents; `tests/installer-backup.sh` asserts the exact file-only member set.
- Installer rollback remains armed through observer reload and prefix
  finalization. If either post-install check fails, the install exits through
  the automatic rollback trap and retention pruning is skipped; the lifecycle
  fixture asserts the ordering.
- The DNS observer fragment is an explicit install target. The lifecycle
  fixture mutates it after snapshot and proves automatic rollback restores its
  prior bytes, without touching the dnsmasq parent directory.
- Corrupt bbolt rescue evidence is written through a private temporary file,
  synced before rename, then the containing directory is synced on Unix. A
  failed copy/close/rename/sync leaves no partial forensic artifact and never
  modifies the unreadable source.
- Quick Zapret keeps stdout reserved for its bounded JSON result. Diagnostics
  from the temporary nft batch are redirected to stderr, so an nft/BusyBox
  usage message cannot become `malformed bounded JSON` at the API boundary.
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
- Route-only assignment не называется применённым без runtime consumer:
  controller требует typed request и semantic receipt с request ID, revision,
  route identity и mapping hash; при ошибке после внешнего шага вызывает
  idempotent rollback, а без consumer оставляет suggestion.

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
  fixed helper socket; root/без-helper запуск отвергается. Helper принимает
  ограниченное число concurrent connections и закрывает новые соединения при
  насыщении. Runtime Linux/OpenWrt и hardware proof ещё не выполнены. LAN
  exposure остаётся явным opt-in.
- Automatic route-only assignment сейчас gated: controller сохраняет
  revision-bound decision и делает post-probe, но production nft/dnsmasq
  consumer, который материализует mapping, не доказан. Поэтому API не должен
  выдавать это за фактически применённое dataplane assignment; topology/component
  apply из discovery запрещён.
- CPU/FD/socket idle, реальное восстановление после power loss и пользовательский
  hardware flow требуют отдельного read-only gate и не наследуются от CI.

## Правило актуальности

Перед ссылкой на эту матрицу проверяй `git rev-parse HEAD`, branch и дату CI.
Любой результат с другим code SHA помечай `STALE FOR CURRENT SHA`, даже если все
тесты когда-то прошли.
