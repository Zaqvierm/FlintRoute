# Evidence remediation

## Current evidence binding (2026-08-29)

Current code/docs HEAD: `90ce6a644f58e59be3b441289c02b938dba37ed8` on
`integration/discovery-smartdns-local-dod`. The worktree is clean and the branch
is pushed. Local `tests/run-all.ps1` completed `all_tests_ok=true`; Linux
namespace/process-group/filesystem checks remain `NOT RUN LOCALLY` on Windows.
Exact-SHA CI for this docs-bound tree passed: full safety `33241417230`, UI and
browser `33241417236`, nft transition `33241417229`, and Zapret process-group
`33241417232`.

These are software/CI results only. No Flint 2 connection, installation,
dataplane mutation, reboot, or hardware validation was performed. Every older
section in this document is historical evidence for its named SHA and is
`STALE FOR CURRENT SHA` unless explicitly rebound above.

## 2026-08-29 remaining system-screen decomposition

Current grouped checkpoint: `90ce6a6` (`docs: bind current UI orchestration evidence`).
The preceding `3d3f910` commit moved App/refresh orchestration; the `8248c01`
commit contains the route/location parser,
shared fallback messages, screen dispatcher/error boundary extraction, public UI
docs, and the regenerated embedded frontend bundle. The exact-SHA runs listed
for `3d3f910` remain evidence for that code SHA only; the current docs binding
is `90ce6a6`. The older CI runs listed below are historical evidence for their
own SHAs only.

The operational screen set is now feature-local in `ui/src/features/system.tsx`;
`ui/src/features/setup.tsx` owns the setup wizard, and `ui/src/app/routes.ts`
owns navigation/location parsing. `ui/src/app/messages.ts` owns shared
unavailable/stale-state fallbacks. `ui/src/app/App.tsx` retains shell, refresh
orchestration, setup wiring, and screen dispatch; `main.tsx` only mounts `App`.
The grouped commit includes the generated embedded bundle and the UI contract
documentation. `npm run typecheck`, `npm test -- --run`, `npm run build`, and
`git diff --check` passed. This remains software-only evidence; Linux and Flint 2
hardware proof are not inferred.

## 2026-08-29 route-screen decomposition implementation (`c1940be1994fe44215fb150d6909818e09205bcb`)

VLESS, Zapret, Smart DNS, and route display screens now live in feature-local
modules; `main.tsx` retains shell/data orchestration and the remaining system
screens. Local `npm run typecheck`, `npm test -- --run`, `npm run build`, and
`git diff --check` passed. This refactor does not change dataplane semantics and
does not provide Linux or Flint 2 evidence.

## 2026-08-29 UI decomposition checkpoint (`bf0c1aa`)

The network topology/device screens, rules/operations screens, and shared UI
primitives were moved out of the monolithic `ui/src/main.tsx` into feature-local
modules. `npm run typecheck`, `npm test -- --run`, `npm run build`, and
`git diff --check` passed for this commit. This is a software-only refactor;
Linux namespace and Flint 2 evidence remain separate and are not inferred.

## 2026-08-29 current code checkpoint (`61731755f454baae8135582e6e271fa52cae4c88`)

The current tree is `integration/discovery-smartdns-local-dod` at
`61731755f454baae8135582e6e271fa52cae4c88`, version `0.2.0-alpha.4`. The
formal version/changelog commit keeps hardware claims out of the release and
does not create a tag. Its current-SHA full safety gate [33234703300](https://github.com/Zaqvierm/FlintRoute/actions/runs/33234703300),
nft transition [33234703299](https://github.com/Zaqvierm/FlintRoute/actions/runs/33234703299),
Zapret process-group [33234703296](https://github.com/Zaqvierm/FlintRoute/actions/runs/33234703296),
and UI/responsive [33234703302](https://github.com/Zaqvierm/FlintRoute/actions/runs/33234703302)
are PASS. These remain software/CI evidence only; Linux-only local checks and
all Flint 2 hardware evidence are separate and are not inherited.

## 2026-08-29 current code checkpoint (`c9b17d10f28d35fda66e3dc33d67282eb48cdc4f`)

The current tree is `integration/discovery-smartdns-local-dod` at
`c9b17d10f28d35fda66e3dc33d67282eb48cdc4f`. In addition to the helper startup
and rollback lifecycle fixes, the uninstaller now requires a typed read-only
`internal-verify-no-owned-ip-state` proof before claiming `verified-empty` when
no committed transaction binding exists. Matching project marks, reserved
rule priorities, non-empty project route tables, unreadable `ip` output, or
missing controller all block teardown. Local full safety, race, vet,
ShellCheck, installer lifecycle, and `git diff --check` pass. Current-SHA CI is
green for full safety [33234073044](https://github.com/Zaqvierm/FlintRoute/actions/runs/33234073044),
nft transition [33234073081](https://github.com/Zaqvierm/FlintRoute/actions/runs/33234073081),
Zapret process-group [33234073075](https://github.com/Zaqvierm/FlintRoute/actions/runs/33234073075),
and UI/responsive [33234073079](https://github.com/Zaqvierm/FlintRoute/actions/runs/33234073079).
These are software/CI results only; Linux-only local checks and all Flint 2
hardware evidence remain separate and are not inferred from CI.

This evidence proves atomic replacement of the owned nft transaction only. It
does not claim that the complete dataplane (artifacts, listeners, IP policy,
nft, and DNS) changes as one indivisible hardware operation; that boundary
remains covered by the transition guard, recovery fence, and the separate
Linux/runtime/hardware matrix.

## 2026-08-29 current code checkpoint (`e97f8ddeca93de6dc6032edcbb88063f52abbea9`)

The current tree is `integration/discovery-smartdns-local-dod` at
`e97f8ddeca93de6dc6032edcbb88063f52abbea9`. The helper-startup dependency
fix is included: `install.sh --enable-services` enables and starts
`router-policy-helper` before the non-root controller, and upgrades refuse to
resurrect a controller that was running without its helper. Local
`tests/run-all.ps1` completed `all_tests_ok=true`; current-SHA CI is green for
full safety [33232513879](https://github.com/Zaqvierm/FlintRoute/actions/runs/33232513879),
nft transition [33232513865](https://github.com/Zaqvierm/FlintRoute/actions/runs/33232513865),
Zapret process-group [33232513945](https://github.com/Zaqvierm/FlintRoute/actions/runs/33232513945),
and UI/responsive [33232513931](https://github.com/Zaqvierm/FlintRoute/actions/runs/33232513931).
These are software/CI results only; Linux-only local checks and all Flint 2
hardware evidence remain separate and are not inferred from CI.

## 2026-08-29 current code checkpoint

The current code HEAD is
`f177ca5ad705d19beb076b77d7890661e405afc7` on
`integration/discovery-smartdns-local-dod`. The worktree was clean before
this checkpoint and the branch is pushed. The current exact-SHA CI evidence
for that code is full safety [33230838569](https://github.com/Zaqvierm/FlintRoute/actions/runs/33230838569),
nft transition [33230838558](https://github.com/Zaqvierm/FlintRoute/actions/runs/33230838558),
Zapret process-group [33230838562](https://github.com/Zaqvierm/FlintRoute/actions/runs/33230838562),
and browser/responsive [33230838623](https://github.com/Zaqvierm/FlintRoute/actions/runs/33230838623).
These are software/CI results only; Linux-only execution on this Windows host
and all Flint 2 evidence remain separate and are not inferred from CI.

The boot-guard policy fixture now also models an existing foreign
`inet router_policy` table. When ownership cannot be proven, the transition
does not copy or delete that table and emits a DROP-only guard with no mark
admission. `tests/boot-guard-policy.sh` reports
`boot_guard_foreign_classifier_fenced=true` for this case. This is a local
mock ownership proof; the namespace workflow remains the Linux-level proof.

## Boot guard namespace gate

`tests/boot-guard-namespace.sh` is a Linux-only network-namespace harness for
the cold-boot ordering invariant. It keeps an unrelated `foreign` nft table
outside the owned transition, loads the committed classifier and mark-scoped
DROP guard in separate owned batches, exercises protected forwarding, removes
the classifier to model an early reboot, and proves that an unmarked flow is
then dropped. Restoring the owned batch must recover the protected path without
redeclaring or modifying the foreign table. The harness reports
`NOT RUN LOCALLY — requires Linux network namespace/nftables` on Windows; that
is not a PASS. The GitHub Actions nft workflow runs this harness as a separate
step, so Linux namespace evidence remains distinct from mock and hardware
evidence.

## 2026-08-29 early committed-classifier delta

The boot-fence implementation for code commit
`2924b63be7f16610c28e5d47f6aace77254e885d` now verifies the durable committed
binding, candidate hash, artifact manifest hash, and owned `inet router_policy`
artifact before staging an early classifier. The classifier and the
mark-scoped admission guard are applied in one nft batch; missing, ambiguous,
foreign, or unverifiable state falls back to transit DROP. The typed managed
mark command is the only source for non-DROP marks admitted by the early guard.

Local evidence for that code commit:

- `tests/boot-guard-policy.sh`: PASS;
- `tests/openwrt-adapter-integration.sh`: PASS;
- `tests/run-all.ps1`: PASS (`all_tests_ok=true`);
- `git diff --check`: PASS;
- ShellCheck: PASS after replacing negated standalone grep assertions with
  explicit checked branches.

Linux network-namespace/nft and Linux process-group/procfs tests remain
`NOT RUN LOCALLY` on Windows. Exact-SHA CI for the pushed docs tree
`ea770a7d0d45026ca4d5d1bacaf987c6a7222921` passed: full safety
[33208980709](https://github.com/Zaqvierm/FlintRoute/actions/runs/33208980709),
nft transition
[33208980671](https://github.com/Zaqvierm/FlintRoute/actions/runs/33208980671),
Zapret process-group
[33208980693](https://github.com/Zaqvierm/FlintRoute/actions/runs/33208980693),
and UI browser/responsive
[33208980692](https://github.com/Zaqvierm/FlintRoute/actions/runs/33208980692).
The preceding docs tree `fc99c200c1c154081475c3655f53e6954dd16b74` also passed
the same four workflows (`33208651816`, `33208651877`, `33208651828`,
`33208652024`).
These are software/CI evidence only; hardware was not accessed.

Этот документ — текущий источник истины по software/CI-проверкам remediation.
Каждая запись привязана к точному SHA; evidence другого commit считается stale.

## Область проверки

- Текущий проверяемый code HEAD: `235688a` (`235688a` — helper startup dependency fix) on `integration/discovery-smartdns-local-dod` (route-only assignment имеет production consumer через typed helper и остаётся ограниченным exact-owned overlay; hardware/runtime evidence по физическому OpenWrt ещё не получено). Historical rows in this document remain useful only as evidence for their named SHA and are stale for the current tree.
- Текущая ветка: `integration/discovery-smartdns-local-dod`.
- Этот документ не наследует hardware evidence от старых SHA.

- Базовый SHA аудита: `d45a779dfa9dc024b426cef358d3df4d32478897`.
- Историческая ветка remediation: `remediation/transaction-and-privilege-boundaries-consolidated`.
- Проверенный code baseline до текущего onboarding delta: `f7a36e63542ef92047c17cca0d5be90987cdd1a4` (historical).
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
- На текущем HEAD локальный Windows `tests/run-all.ps1` завершился
  `all_tests_ok=true`. Exact-SHA CI для этого HEAD: full safety
  `33229028717`, UI `33229028725`, Zapret process-group `33229028721`, nft
  transition `33229028720`. Linux-only checks PASS только в CI; локально они
  остаются `NOT RUN LOCALLY`. Hardware не использовалось.
- Старые hardware-записи, включая `docs/flint2-hardware-report.md` и
  `H:\LAN\Versions\FlintRoute 0.2.0-alpha.1\hardware\summary.txt`, имеют статус
  `STALE FOR CURRENT SHA`, пока не будет нового прогона на текущем коде.

## Краткий acceptance summary

| Область | Результат | Доказательство |
|---|---|---|
| Go unit/integration, race, vet, форматирование | PASS (локально на текущем HEAD, 2026-08-28) | `go test ./...`, `go test -race ./...`, `go vet ./...`, `gofmt` |
| Frontend unit/typecheck/build | PASS | 47 Vitest-тестов, `npm run typecheck`, `npm run build` |
| Browser/responsive UI | PASS | exact-SHA CI run [33146835401](https://github.com/Zaqvierm/FlintRoute/actions/runs/33146835401) |
| Linux nft transition | PASS | exact-SHA CI run [33146835429](https://github.com/Zaqvierm/FlintRoute/actions/runs/33146835429) |
| Linux Zapret process-group и Quick contract | PASS | exact-SHA CI run [33146835444](https://github.com/Zaqvierm/FlintRoute/actions/runs/33146835444) |
| Exact-SHA full safety for subscription operation gate | PASS | code `94357db4ff64a8f8ebf65409f1ef526d468ef760`; run [33147559928](https://github.com/Zaqvierm/FlintRoute/actions/runs/33147559928) |
| Exact-SHA nft transition for subscription operation gate | PASS | run [33147559510](https://github.com/Zaqvierm/FlintRoute/actions/runs/33147559510) |
| Exact-SHA Zapret process-group for subscription operation gate | PASS | run [33147559526](https://github.com/Zaqvierm/FlintRoute/actions/runs/33147559526) |
| Exact-SHA browser/responsive for subscription operation gate | PASS | run [33147559531](https://github.com/Zaqvierm/FlintRoute/actions/runs/33147559531) |
| Exact-SHA full safety for transaction cleanup error surfacing | PASS | code `fdfcbb809ff197cc8bde03d5d1c5977f60140573`; run [33149785464](https://github.com/Zaqvierm/FlintRoute/actions/runs/33149785464) |
| Exact-SHA nft transition for transaction cleanup error surfacing | PASS | run [33149785448](https://github.com/Zaqvierm/FlintRoute/actions/runs/33149785448) |
| Exact-SHA Zapret process-group for transaction cleanup error surfacing | PASS | run [33149785452](https://github.com/Zaqvierm/FlintRoute/actions/runs/33149785452) |
| Exact-SHA browser/responsive for transaction cleanup error surfacing | PASS | run [33149785447](https://github.com/Zaqvierm/FlintRoute/actions/runs/33149785447) |
| Exact-SHA full safety for durable event persistence diagnostics | PASS | code `3e10c02918cfb05d81895501c6ccd4fe29db27ef`; run [33150611303](https://github.com/Zaqvierm/FlintRoute/actions/runs/33150611303) |
| Exact-SHA nft transition for durable event persistence diagnostics | PASS | run [33150610876](https://github.com/Zaqvierm/FlintRoute/actions/runs/33150610876) |
| Exact-SHA Zapret process-group for durable event persistence diagnostics | PASS | run [33150610834](https://github.com/Zaqvierm/FlintRoute/actions/runs/33150610834) |
| Exact-SHA browser/responsive for durable event persistence diagnostics | PASS | run [33150610840](https://github.com/Zaqvierm/FlintRoute/actions/runs/33150610840) |
| Exact-target dnsmasq observer confdir ownership | `tests/installer-lifecycle.sh`, `tests/dns-observer-bootstrap.sh` | PASS; installer and root bootstrap reject UCI/override `/etc/shadow`, target symlinks, and symlinked parent components before anything can enter the rollback manifest or be written | local/mock + Linux CI |
| Installer secret ownership allowlist | `tests/installer-secret-ownership.sh`, `tests/installer-lifecycle.sh` | PASS; only the four managed secret files are chowned/chmodded, foreign files are untouched, and symlinked managed secrets are rejected | local/mock + exact-SHA CI |
| Exact-SHA full safety for installer secret ownership | PASS | docs-bound tree `b0e8e19ead5d247fd09fed25b54db33977bcdb0c`; full run [33156902721](https://github.com/Zaqvierm/FlintRoute/actions/runs/33156902721) |
| Exact-SHA nft transition for installer secret ownership | PASS | run [33156902712](https://github.com/Zaqvierm/FlintRoute/actions/runs/33156902712) |
| Exact-SHA Zapret process-group for installer secret ownership | PASS | run [33156902702](https://github.com/Zaqvierm/FlintRoute/actions/runs/33156902702) |
| Exact-SHA browser/responsive for installer secret ownership | PASS | run [33156902700](https://github.com/Zaqvierm/FlintRoute/actions/runs/33156902700) |
| Exact-SHA full safety for deterministic prefix recovery and HWID persistence | PASS | code `d7077a657f63e3372ef6d05882bb46dbdecac4cf`; run [33159908174](https://github.com/Zaqvierm/FlintRoute/actions/runs/33159908174) |
| Exact-SHA nft transition for deterministic prefix recovery and HWID persistence | PASS | run [33159908065](https://github.com/Zaqvierm/FlintRoute/actions/runs/33159908065) |
| Exact-SHA Zapret process-group for deterministic prefix recovery and HWID persistence | PASS | run [33159908055](https://github.com/Zaqvierm/FlintRoute/actions/runs/33159908055) |
| Exact-SHA browser/responsive for deterministic prefix recovery and HWID persistence | PASS | run [33159908069](https://github.com/Zaqvierm/FlintRoute/actions/runs/33159908069) |
| Linux-only harness на Windows | NOT RUN LOCALLY | namespace/procfs/mode требуют Linux |
| Root-helper privilege split | PARTIAL (code contract; runtime peer proof pending) | production init запускает controller как `daemon`, явно включает и запускает helper до controller, блокирует controller без helper, root startup и отсутствие helper socket отвергаются; production adapter принимает только фиксированный `/var/run/router-policy/helper.sock`; typed helper покрывает global/transaction/owned paths, проверяет peer UID и ограничивает concurrent connections; component mutation без helper-backed executor теперь fail-closed, read-only inventory остаётся доступным; Linux peer-credential/runtime evidence ещё не получено |
| Route-only assignment dataplane | PARTIAL | production consumer и revision-bound post-apply proof реализованы; Linux/OpenWrt runtime и hardware path evidence не получены |
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
| Prefix final-rename recovery | `tests/installer-prefix-switch.sh` | PASS; a durable `ready_to_activate` marker recovers either side of the final rename, while genuinely ambiguous old/new layouts remain blocked | mock/static + exact-SHA CI [33159908174](https://github.com/Zaqvierm/FlintRoute/actions/runs/33159908174) |
| Durable corrupt-state forensic artifact | `go test ./internal/state -run TestOpenPreservesUnreadableDatabaseForRescue` | PASS; artifact content is preserved through a synced temporary file and atomic rename; partial temp files are removed | local |
| Bounded Zapret failure evidence | `tests/zapret-calibration-runtime.sh`, `scripts/calibrate-zapret.sh` | PASS; failed runs retain status, bounded report tail and process/network baselines in at most three 0700 bundles while success removes staging | Linux CI run [33123611490](https://github.com/Zaqvierm/FlintRoute/actions/runs/33123611490); Windows local runner reports NOT RUN LOCALLY |
| Installer post-install rollback fence | `tests/installer-lifecycle.sh` | PASS; rollback is not disarmed before observer/prefix verification, and incomplete verification aborts before backup pruning | mock |
| DNS observer install rollback ownership | `tests/installer-lifecycle.sh`, `tests/dns-observer-bootstrap.sh` | PASS; configured observer target is included in the exact snapshot and restored after simulated failure | mock |
| Quick runner machine-output isolation | `tests/zapret-quick-contract.sh`, `scripts/quick-zapret-check.sh` | PASS; nft load diagnostics are stderr-only, preventing BusyBox/nft output from corrupting bounded JSON | mock/static |
| Typed health response parsing | `go test ./internal/healthjson`, `router-policy internal-health-field` | PASS | local |
| HTML/portal response rejection | `go test ./internal/vpnsub -run TestFetchSubscriptionRejectsHTML` | PASS | local |
| HWID persistence ordering | `go test ./internal/api -run TestSubscriptionHWIDFailedFingerprintPreservesPreviousSettings` | PASS; fingerprint resolution/preview is completed before writing settings, and a failed generated source preserves the prior preset | local + exact-SHA CI [33159908174](https://github.com/Zaqvierm/FlintRoute/actions/runs/33159908174) |
| Канонические ownership paths | `tests/installer-lifecycle.sh`, `tests/installer-backup.sh` | PASS | mock |
| Static installer-file ownership on uninstall | `install.sh`, `uninstall.sh`, `tests/installer-lifecycle.sh` | PASS (local fixture + exact-SHA full gate [33191636975](https://github.com/Zaqvierm/FlintRoute/actions/runs/33191636975)); install writes a root-owned, mode-0600 hash manifest for controller binary/helper/init/hotplug files; uninstall validates every present target before teardown and fences modified/foreign content | local/mock + exact-SHA CI; Linux/OpenWrt runtime pending |
| Project-prefix ownership on uninstall | `uninstall.sh`, `tests/installer-lifecycle.sh` | PASS (focused local fixture + exact-SHA full gate [33229028717](https://github.com/Zaqvierm/FlintRoute/actions/runs/33229028717)); prefix top-level entries are allowlisted, nested symlinks/special files fence before teardown, ownership-walk errors are fatal, and removal uses enumerated files plus `rmdir` instead of recursive deletion | local/mock + exact-SHA CI; Linux/OpenWrt runtime pending |
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
| Resource budget | `go test ./internal/api ./internal/probe`; `go test ./internal/health ./internal/vpnsub -run 'Bounded|Budget'` | PASS; discovery queue is capped at 32, shared route jobs at 4, and health/subscription worker counts are clamped to the shared budget | local + exact-SHA CI [33146835417](https://github.com/Zaqvierm/FlintRoute/actions/runs/33146835417) |
| Запрет unvalidated probe fan-out | `go test ./internal/probe -run TestProbeRouteRejectsUnvalidatedProbeURLFanout` и race-вариант | PASS | local |
| Transaction cleanup status persistence | `go test ./internal/api -run TestSaveCleanupStatus` | PASS; canonical `meta/last_cleanup_result` writes return errors to callers for explicit event publication | local + exact-SHA CI [33149785464](https://github.com/Zaqvierm/FlintRoute/actions/runs/33149785464) |
| Durable event persistence failure visibility | `go test ./internal/api -run TestPublishEventSurfacesDurablePersistenceFailure` | PASS; failed durable event writes emit a non-durable diagnostic while retaining the original in-memory event | local + exact-SHA CI [33150611303](https://github.com/Zaqvierm/FlintRoute/actions/runs/33150611303) |
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

Для текущего code head `d7077a657f63e3372ef6d05882bb46dbdecac4cf` после push
прошли все обязательные PR workflows:

- exact-SHA full safety gate: [33159908174](https://github.com/Zaqvierm/FlintRoute/actions/runs/33159908174);
- nft transition: [33159908065](https://github.com/Zaqvierm/FlintRoute/actions/runs/33159908065);
- Zapret process-group и Quick contract: [33159908055](https://github.com/Zaqvierm/FlintRoute/actions/runs/33159908055);
- UI browser/responsive: [33159908069](https://github.com/Zaqvierm/FlintRoute/actions/runs/33159908069).

Full gate включает новый тест порядка HWID persistence и восстановление
prefix после crash boundary. Это software/CI evidence; Linux-local и hardware
proof по-прежнему отдельные уровни.

Для предыдущего code head `43d889775e9960383450b23e351a712fbca1a03f` после push прошли:

- exact-SHA full safety gate: [33137838195](https://github.com/Zaqvierm/FlintRoute/actions/runs/33137838195);
- nft transition: [33137838187](https://github.com/Zaqvierm/FlintRoute/actions/runs/33137838187);
- Zapret process-group и Quick contract: [33137838154](https://github.com/Zaqvierm/FlintRoute/actions/runs/33137838154);
- UI browser/responsive: [33137838184](https://github.com/Zaqvierm/FlintRoute/actions/runs/33137838184).

Эти исторические run ID привязаны к exact code SHA `43d889775e9960383450b23e351a712fbca1a03f`.
Документационный HEAD может отличаться от code HEAD, но не меняет исходный
результат тестов; при изменении кода evidence снова становится stale.

Для предыдущего code head `4fec55d41adae0cf907b8e56aa80f91c776a974c`
после docs-only push `c932cf69b742215ee0a34bbbcb52c4b0ffcb102a` также прошли
все PR workflows:

- exact-SHA full safety gate: [33145350754](https://github.com/Zaqvierm/FlintRoute/actions/runs/33145350754);
- nft transition: [33145350768](https://github.com/Zaqvierm/FlintRoute/actions/runs/33145350768);
- Zapret process-group и Quick contract: [33145350760](https://github.com/Zaqvierm/FlintRoute/actions/runs/33145350760);
- UI browser/responsive: [33145350784](https://github.com/Zaqvierm/FlintRoute/actions/runs/33145350784).

Это software/CI evidence. Она не заменяет Linux-local запуск и hardware proof.

Для текущего code head `6d71518049a935ad5c2901d6b869a19ff6e95721` обязательные
PR workflows также завершились успешно:

- exact-SHA full safety gate: [33146835417](https://github.com/Zaqvierm/FlintRoute/actions/runs/33146835417);
- nft transition: [33146835429](https://github.com/Zaqvierm/FlintRoute/actions/runs/33146835429);
- Zapret process-group и Quick contract: [33146835444](https://github.com/Zaqvierm/FlintRoute/actions/runs/33146835444);
- UI browser/responsive: [33146835401](https://github.com/Zaqvierm/FlintRoute/actions/runs/33146835401).

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
- Один логический route-check имеет дополнительные hard bounds: не более 4
  service probe checks, 4 address targets на check и 2 GeoIP источников. Эти
  пределы проверяются до сетевого fan-out; они не являются доказательством
  hardware CPU/FD/socket поведения.
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
- Installer discovery of the dnsmasq `confdir` is fail-closed: only the
  platform-owned `/tmp/dnsmasq.d` or `/etc/dnsmasq.d` directories are accepted.
  A UCI value such as `/etc/shadow` cannot expand the rollback manifest or turn
  the installer into a generic root file writer.
- The root `ensure-dns-observer.sh` bootstrap enforces the same allowlist on
  every later start, so a changed UCI value cannot bypass installer ownership.
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

## Current exact-SHA CI checkpoint

Для code HEAD `e97f8ddeca93de6dc6032edcbb88063f52abbea9` все обязательные
software workflows завершились успешно:

- exact-SHA full safety gate: [33230838569](https://github.com/Zaqvierm/FlintRoute/actions/runs/33230838569);
- UI browser/responsive: [33230838623](https://github.com/Zaqvierm/FlintRoute/actions/runs/33230838623);
- Zapret process-group: [33230838562](https://github.com/Zaqvierm/FlintRoute/actions/runs/33230838562);
- nft transition: [33230838558](https://github.com/Zaqvierm/FlintRoute/actions/runs/33230838558).

The full gate includes the installer lifecycle regression that injects a failed
ownership enumeration and proves the project prefix is preserved; the prefix
switch fixture also proves stale cleanup fences unknown top-level entries. These runs
are software/CI evidence only; Linux-local and Flint 2 hardware evidence remain
separate and are not implied by this checkpoint.

## Ограничения

- Полное отсутствие split-brain не заявляется до reboot/fault matrix и hardware
  evidence; текущая гарантия — fencing подтверждённых ambiguous states.
- Production controller запускается от dedicated `daemon` account и требует
  fixed helper socket; root/без-helper запуск отвергается. Helper принимает
  ограниченное число concurrent connections и закрывает новые соединения при
  насыщении. Runtime Linux/OpenWrt и hardware proof ещё не выполнены. LAN
  exposure остаётся явным opt-in.
- Automatic route-only assignment сейчас gated: controller и production
  `cmd/router-policy` consumer сохраняют revision-bound binding, атомарно
  материализуют только owned dnsmasq overlay и выполняют post-apply proof.
  При отсутствии consumer API fail closed; topology/component apply из
  discovery запрещён. Linux/OpenWrt runtime и hardware path evidence остаются
  отдельным gate.
- CPU/FD/socket idle, реальное восстановление после power loss и пользовательский
  hardware flow требуют отдельного read-only gate и не наследуются от CI.

## Правило актуальности

Перед ссылкой на эту матрицу проверяй `git rev-parse HEAD`, branch и дату CI.
Любой результат с другим code SHA помечай `STALE FOR CURRENT SHA`, даже если все
тесты когда-то прошли.
