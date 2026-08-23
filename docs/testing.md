# Тестирование

> Список отражает проверки, включённые в локальный test suite.
>
> Любые упоминания прогона на Flint 2 ниже — исторические и не являются PASS
> для текущей ветки без нового exact-SHA hardware evidence.

## Полный локальный набор

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\run-all.ps1
```

Текущий локальный baseline: `all_tests_ok=true`. Этот результат не включает SSH,
применение на роутере или повторную аппаратную проверку.

Набор включает Go tests/vet, frontend typecheck/build, Windows и Linux arm64
builds, ShellCheck (если бинарник доступен), отказоустойчивость installer,
целостность rollback snapshot, mock-интеграцию OpenWrt transaction, CLI fixtures,
проверку секретов и поиск дубликатов route-check.

`go test -race ./...` запускается отдельной командой ниже. Hardware runners из
`tests/hardware` также не входят в `run-all.ps1` и требуют явного запуска на
целевом устройстве.

## Детектор гонок

```powershell
$mingw = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin"
$env:Path = "$mingw;$env:Path"
$env:CGO_ENABLED = "1"
.\.tools\go1.26.5\go\bin\go.exe test -race ./...
```

Проверено: все Go-пакеты прошли.

## Доказательные тесты P0

- `TestChangeSetCommitPersistsAcrossRestart`
- `TestVerificationFailureRollsBackAndPersistsAcrossRestart`
- `TestUnsupportedOperationBlocksValidate`
- `TestImmutableAdapterPathBlocksValidate`
- `TestSkippedApplyRequiresDeviceAndCannotConfirm`
- `TestFilesystemAdapterCannotReachAwaitingConfirmation`
- `TestFilesystemTransactionStopsBeforeRealDataPlane`
- `TestRollbackActionCallsAdapterRollback`
- `TestCorruptRollbackCapabilityIsForbidden`
- `TestAdapterErrorTriggersAutomaticRollback`
- `TestCommitErrorTriggersRollback`
- `TestRollbackErrorProducesRollbackFailed`
- `TestExpiredTransactionAutomaticallyRollsBack`
- `TestRestartRecoversAwaitingConfirmation`
- `TestParallelApplyOnlyOneSucceeds`
- `TestStaleChangeSetVersionReturns409`
- `TestSchemaRetentionAndCompactBackup`

## Доказательные тесты P0.5

- `TestGenerateVerifyAndRejectTamper`
- `TestMissingDiagnosticsProducesBlockedIPPlan`
- `TestApplyIPPlanUsesFixedArguments`
- `TestApplyIPPlanRejectsUnresolvedDiagnostics`
- `TestMissingNetworkDiagnosticsRequiresDeviceBeforeAdapter`
- `TestProductionRefusesSimulatedNetworkDiagnostics`
- `TestUnverifiedVerificationRollsBackAppliedCandidate`
- `TestArtifactEvidenceMismatchCannotAwaitConfirmation`
- `TestConfirmRejectsAdapterArtifactMismatch`
- `TestExpiryAndManualRollbackCallAdapterOnce`
- `TestActionLocksAreReleasedAfterWaitersFinish`
- `TestEventBrokerUsesNewEpochAfterRestart`
- `TestServerCloseIsIdempotent`
- `TestMaintainPrunesBackupsAndCompactsActiveDatabase`
- `TestOpenRecoversInterruptedActiveCompaction`
- `TestValidateRefreshesProviderDiagnosticsAndBindsGeneratedArtifacts`

## Базовые маршруты, Smart DNS и discovery

- `TestBaselineLeavesUnclassifiedTrafficOnSystemDefault` — baseline не создаёт
  route jump/mark для обычного трафика;
- `TestRoutesSeparateSystemManagedDirectAndUnclassified` — API не
  смешивает system default с managed Direct;
- `TestDropDNSUsesLocalNXDOMAINWithoutUpstream` — один generated scenario
  содержит NXDOMAIN, nftset/route mark и forward drop guard;
- `TestSmartDNSConfigureCreatesDraft` — draft появляется только после UDP/TCP
  DNS и HTTP/TLS proof; протухший proof блокирует apply;
- `TestNormalizeSmartDNSEndpointRejectsUnsafeAddresses` — private, loopback,
  multicast, unspecified и bogon resolver не принимаются;
- `TestDiscoveryObserveOnlyNeverCreatesSuggestionOrChange`,
  `TestDiscoverySuggestKeepsBoundedSuggestionWithoutApply`,
  `TestDiscoveryLockedDoesNotProbe` и
  `TestDiscoveryAutoApplyRequiresPathVerifiedAndCommits` проверяют разные
  side effects четырёх режимов;
- `TestDiscoveryAutoApplySafetyLimits` и
  `TestDiscoveryRollbackCircuitBreakerStopsFurtherApply` —
  PathVerified, transaction lock, rate limit, rollback timer, operation
  allowlist и rollback circuit breaker обязательны.
- `TestDiscoveryRuntimeSettingsOverrideConfigWithoutAdapterWork` проверяет, что
  смена режима и лимитов не создаёт ChangeSet и не вызывает OpenWrt adapter;
- `TestConfigureTGWSCreatesManagedConfigAndOneTimeLink` проверяет безопасную
  генерацию конфигурации, запуск сервиса и одноразовую ссылку;
- `TestConfigureTGWSRestoresFilesWhenServiceStartFails` проверяет возврат старых
  файлов при неудачном старте;
- `TestRequestHostAcceptsRouterAddressAndRejectsLoopbackOrInjection` не даёт
  подставить loopback или управляющие символы в TGWS link.
- `TestOpenWrtStepNamesMatchTransactionContract`

## Тесты flow offloading (P3)

- `TestEnabledFlowOffloadingBlocksPolicyCandidateWithoutExplicitDisable`
- `TestExplicitFlowOffloadingDisableProducesBoundApplyPlanAndWarning`
- `TestApplyIPPlanDisablesFlowOffloadingWithFixedUCIKeysBeforeRoutes`
- `TestApplyIPPlanStopsBeforeRoutesWhenFlowOffloadingDisableFails`
- `TestFlowOffloadingDisableChangeSetIsExplicitlyWarned`
- `TestOverrideChangeSetPersistsFullCanonicalCandidate`

## Тесты recovery (P6)

- `TestRestartReconcilesCommittedDataplane`
- `TestRestartRecoversAwaitingConfirmation`
- `TestRecoveryFinalizesAdapterCommittedTransaction`
- `TestRecoveryFailClosedBetweenStateMachineSteps`
- `TestRestartKeepsManagementAvailableWhenCommittedReconcileFails`
- `TestValidateRecoveryTarget`

## Тесты API / probe / health / VPN-подписки

- `TestAuthAndOverview`, `TestLoginRequiresConfiguredAdmin`, `TestChangeSetRequiresCSRF`
- `TestUnknownAPIIsJSON404`, `TestSSEStream`, `TestEventsEndpointMergesPersistedHistoryAcrossRestart`
- `TestBackupsEndpointReadsVerifiedStoreMetadata`, `TestBackupMetadataSurvivesRestartAndDetectsCorruption`
- `TestProbesEndpointReadsPersistedResultsAndRedactsIPs`, `TestListProbeResultsReturnsNewestFirstAndHonorsLimit`
- `TestRouteHealthPersistsAcrossRestart`, `TestServerHealthCycleCallsInjectedEnginePersistsAndExposesStatus`
- `TestXraySubscriptionPrepareOffersManagedActivationWithoutChangeSet`,
  `TestXrayManagedActivationBindsModeBundleAndRoutesInOneChangeSet` and
  `TestXraySubscriptionPrepareFailureCreatesNoChangeSet`;
- `TestZapretSetupCheckDoesNotCreateChangeSet`,
  `TestZapretSetupActivationCreatesOnePinnedManagedChangeSet` and
  `TestZapretSetupFailureCreatesNoChangeSet`;
- `TestLocalSetupCheckerVerifiesPinnedBinaryDryRunAndNFQueue` and
  `TestLocalSetupCheckerRejectsMutableSourceAndNFQueueFailure`;
- `TestProductionAdaptiveCycleCollectsActiveAndCandidateEvidence`, `TestAdaptiveNetworkFingerprintInvalidatesOldRanking`
- `TestEventBrokerFailsWhenEntropyIsUnavailable`, `TestRequestIDFailsClosedWhenEntropyIsUnavailable`
- `TestCreateChangeSetRejectsEmptyOperations`, `TestWildcardAPIListenerFailsClosed`
- `TestParseProcNetDev`, `TestParseProcNetDevRejectsTruncatedCounters`
- `TestStorePersistsJSONAcrossReopen`, `TestMigratesLegacyDatabaseWithoutSchemaVersion`
- storage/write budget: 100 одинаковых health cycles не увеличивают persistent
  transaction counter; один route transition создаёт одну запись; probe ring и
  durable events ограничены; 1000 overview/SSE reads дают zero persistent writes;
- lifecycle: exact PID/start-time/executable/config/run identity, PID reuse,
  foreign `xray`, corrupt owner manifest, network namespace gates, idempotent
  stale cleanup и 100 последовательных test-runs;
- watchdog: startup grace, failure threshold, bounded inhibit lease и expiry;
- backup/storage migration: count/size retention, corrupt fallback protection,
  verified-copy-before-delete, TSPU freshness classification и сохранение
  неизвестных файлов;
- TSPU write budget: одинаковый entry set не заменяет current/previous cache,
  freshness checkpoint hash-bound, retained source не получает новый TTL,
  startup scheduler откладывает refresh до persisted expiry.

## Тесты поведения shell

- `tests/adapter-rollback.sh` — corrupted snapshot refusal, pre-restore hash
  verification, project-owned absent markers, Xray restore, wrong token.
- `tests/openwrt-adapter-integration.sh` — real shell helper с заменой только
  fw4/nft/dnsmasq/Xray/nfqws/ip/router health. Доказывает generated files/hashes
  через prepare/validate/snapshot/apply/verify/commit, verification-failure
  restore, подписанный LAN management proof, отказ при отсутствующем proof,
  игнорирование legacy `management.env`, потерю маршрута к management-клиенту,
  stale/duplicate rollback, transaction exclusion,
  simulated-diagnostics refusal, candidate/artifact mismatch refusal. Managed
  Zapret: nfqws `--dry-run` before apply, service start before nft load,
  rollback active config + prior service state. Включает P6 reconcile path,
  запускается с отсутствующим external `stat` и проверяет, что первоначальный
  flow-offloading ownership baseline не перезаписывается поздней transaction.
- `internal/managementproof` — подпись и проверка LAN/headless proof, expiry,
  boot/revision/transaction binding, защита от редактирования и проверка
  интерфейса/подсети при confirm. Transaction tests отдельно проверяют
  автоматический rollback при потере management path и явный headless confirm с
  увеличенным rollback window.
- `tests/installer-backup.sh` — empty archive останавливает install/uninstall до удаления файлов и не пишет `last-backup-path`;
- `tests/installer-lifecycle.sh` — clean install, повторный upgrade, compatible
  downgrade, rollback невалидной версии, verified uninstall, запрет
  service-manager side effects в sandbox, удаление только bound IP plan и
  возврат исходного persistent flow-offloading baseline с `last-good` и без
  него, отказ от нестандартного recursive-delete root;
- `tests/content-aware-install.sh` — identical content не заменяет target,
  changed content проходит через same-filesystem atomic rename, symlink
  отклоняется, ошибка перед rename сохраняет прежний target и удаляет temp;
- `tests/hardware/run-p13.ps1` — recovery baseline, UDP/TCP-проверка двух
  production Smart DNS resolvers, route matrix и обязательный proxy-recursion
  gate: установленный Xray config должен маркировать outbounds, nft bypass
  должен присутствовать, а live VLESS probe — увеличить его counter;
- `tests/hardware/run-p13-faults.ps1` — SIGKILL только PID, который procd
  привязал к ожидаемому project service и executable, затем controlled reboot
  с проверкой целой committed revision; общий `pidof xray/nfqws` запрещён.
  `-SkipControlledReboot` отделяет process matrix от reboot и всё равно
  завершает evidence manifest и удаляет проверенный remote run directory;
- `tests/hardware/run-p13-state-corruption.ps1` — создаёт и полностью проверяет
  ограниченную bbolt-копию, повреждает только активную базу FlintRoute, сохраняет
  committed dataplane и управляемые providers, автономно восстанавливает state,
  затем повторяет Direct/Zapret/VLESS/Smart DNS path proofs;
- `tests/hardware/run-p13-adaptive.ps1 -VerifyProductionCalibration` — получает
  live active/challenger evidence из production health cycle, проверяет
  сохранение scheduler/ranking после restart, catalog-bound fingerprint
  isolation, transaction-bound switch, cooldown, pin, quarantine и возврат
  static baseline;
- `tests/package-openwrt.sh` — состав, SHA-256 manifest, отказ при повреждении и
  одинаковый archive hash для двух последовательных упаковок без изменения
  исходников.

## Четыре уровня covered

> Сведения о 23 клетках Flint 2 в этом разделе относятся к историческому
> прогону. Для текущего SHA это не hardware evidence.

Тесты покрывают все четыре уровня route проверки: DNS resolution
(`smart_dns_unsafe_answer`, CNAME/size/limit), классификация (regional/TSPU
markers), egress (`RU_EXIT`, consensus mismatch в health quorum), path proof
(`ValidateRouteProof` per-type: direct bypass, zapret flow/QUIC, smart DNS
Host/SNI, vless SOCKS loopback, drop enforcement).

P13 matrix plan перечисляет полный декартов набор из пяти route types, пяти
transport cases и двух address families. Harness отклоняет отсутствующую,
лишнюю или продублированную клетку. Каждая активная клетка требует отдельный
protocol-specific packet proof и bound route evidence; один HTTPS PASS не может
закрыть соседний protocol. На Flint 2 прошли все 23 применимые клетки. Из 27
`NOT_APPLICABLE` 25 требуют отсутствующий WAN6, а Zapret DNS UDP/TCP
перехватываются раньше route classification.

## Оставшиеся аппаратные проверки

> Этот список применяется к текущей ветке; старые PASS из последующих абзацев
> сохранены только как историческая запись и не наследуются автоматически.

- multi-client и 72h soak (P13).
- Linux namespace/container behavior (нет локального Linux runtime; shell
  integration cross-platform, готов для Linux CI).
- P14 isolated lifecycle: 100 test-run, expired lease, SIGKILL, SSH disconnect,
  repeated cleanup, foreign-process protection и baseline comparison пройдены.
  На factory OpenWrt также пройдены clean install/upgrade, controller
  restart/SIGKILL, watchdog inhibit, bounded boot guard, reboot, active
  Xray/Zapret/dataplane lifecycle, 1000 read-only API GET и 35-minute idle
  write observation. Rollback timer, compatible downgrade, fixed uninstall,
  внешний management proof и финальный reinstall/reconcile также PASS.
- Физическое отключение питания пройдено с внешним монитором: boot ID сменился,
  committed revision, managed Xray/nfqws, nftables, policy rules и Web API
  восстановились. Control plane стал доступен примерно через 3 минуты 47 секунд
  после первого зафиксированного offline sample.

Подготовка и критерии 72-часового прогона описаны в
[`soak-test.md`](soak-test.md).
