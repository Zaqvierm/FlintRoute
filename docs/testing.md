# Testing

> Список отражает проверки, включённые в локальный test suite.

## Full local suite

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\run-all.ps1
```

Verified result: `all_tests_ok=true`.

Suite: Go tests/vet, frontend typecheck/build, Windows и Linux arm64 builds,
ShellCheck, installer failure behavior, rollback snapshot integrity, mocked
OpenWrt transaction integration, CLI fixtures, secret scan, duplicate
route-check scan.

## Race detector

```powershell
$mingw = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source.8wekyb3d8bbwe\mingw64\bin"
$env:Path = "$mingw;$env:Path"
$env:CGO_ENABLED = "1"
.\.tools\go1.26.5\go\bin\go.exe test -race ./...
```

Verified: every Go package passed.

## P0 proof tests

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

## P0.5 proof tests

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
- `TestOpenWrtStepNamesMatchTransactionContract`

## Flow-offloading tests (P3)

- `TestEnabledFlowOffloadingBlocksPolicyCandidateWithoutExplicitDisable`
- `TestExplicitFlowOffloadingDisableProducesBoundApplyPlanAndWarning`
- `TestApplyIPPlanDisablesFlowOffloadingWithFixedUCIKeysBeforeRoutes`
- `TestApplyIPPlanStopsBeforeRoutesWhenFlowOffloadingDisableFails`
- `TestFlowOffloadingDisableChangeSetIsExplicitlyWarned`
- `TestOverrideChangeSetPersistsFullCanonicalCandidate`

## Recovery tests (P6)

- `TestRestartReconcilesCommittedDataplane`
- `TestRestartRecoversAwaitingConfirmation`
- `TestRecoveryFinalizesAdapterCommittedTransaction`
- `TestRecoveryFailClosedBetweenStateMachineSteps`
- `TestRestartKeepsManagementAvailableWhenCommittedReconcileFails`
- `TestValidateRecoveryTarget`

## API / probe / health / VPN-подписка tests

- `TestAuthAndOverview`, `TestLoginRequiresConfiguredAdmin`, `TestChangeSetRequiresCSRF`
- `TestUnknownAPIIsJSON404`, `TestSSEStream`, `TestEventsEndpointMergesPersistedHistoryAcrossRestart`
- `TestBackupsEndpointReadsVerifiedStoreMetadata`, `TestBackupMetadataSurvivesRestartAndDetectsCorruption`
- `TestProbesEndpointReadsPersistedResultsAndRedactsIPs`, `TestListProbeResultsReturnsNewestFirstAndHonorsLimit`
- `TestRouteHealthPersistsAcrossRestart`, `TestServerHealthCycleCallsInjectedEnginePersistsAndExposesStatus`
- `TestXraySubscriptionPrepareCreatesValidatableChangeSet`, `TestXraySubscriptionPrepareFailureCreatesNoChangeSet`
- `TestStorePersistsJSONAcrossReopen`, `TestMigratesLegacyDatabaseWithoutSchemaVersion`

## Shell behavior tests

- `tests/adapter-rollback.sh` — corrupted snapshot refusal, pre-restore hash
  verification, project-owned absent markers, Xray restore, wrong token.
- `tests/openwrt-adapter-integration.sh` — real shell helper с заменой только
  fw4/nft/dnsmasq/Xray/nfqws/ip/router health. Доказывает generated files/hashes
  через prepare/validate/snapshot/apply/verify/commit, verification-failure
  restore, LAN `UNVERIFIED`, stale/duplicate rollback, transaction exclusion,
  simulated-diagnostics refusal, candidate/artifact mismatch refusal. Managed
  Zapret: nfqws `--dry-run` before apply, service start before nft load,
  rollback active config + prior service state. Включает P6 reconcile path.
- `tests/installer-backup.sh` — empty archive останавливает install/uninstall до удаления файлов и не пишет `last-backup-path`;
- `tests/installer-lifecycle.sh` — clean install, повторный upgrade, compatible downgrade, rollback невалидной версии, verified uninstall и запрет service-manager side effects в sandbox;
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
- `tests/package-openwrt.sh` — состав, SHA-256 manifest и отказ при повреждении OpenWrt-пакета.

## Четыре уровня covered

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

- физическое power-loss recovery;
- multi-client, hardware install/upgrade/downgrade/uninstall и 72h soak (P13).
- Linux namespace/container behavior (нет локального Linux runtime; shell
  integration cross-platform, готов для Linux CI).
