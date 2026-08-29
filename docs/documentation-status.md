# Актуальность документации

Проверено: `2026-08-29`, база production-кода
`f177ca5ad705d19beb076b77d7890661e405afc7`.
Документационный commit фиксирует этот code SHA; hardware claims для него не
наследуются.
Ветка: `integration/discovery-smartdns-local-dod`.

Это не декоративная таблица процентов. Статус означает, можно ли использовать
документ как описание текущего software-кода. Исторические аппаратные PASS не
переносятся на новый SHA: для текущего кода у Flint 2 статус `NOT RUN / STALE`.
Реестр покрывает все 34 файла `docs/*.md`, включая этот самоконтрольный документ.

Обозначения:

- **АКТУАЛЕН** — контракт и названные пути сверены с текущим кодом; отдельные
  hardware-разделы могут быть историческими.
- **ЧАСТИЧНО** — документ одновременно описывает реализованный контракт и
  целевую/незакрытую часть; это явно отмечено в самом документе или ниже.
- **ПЛАН** — критерии следующего этапа, не обещание готовой функции.
- **ИСТОРИЯ** — сохранённый отчёт или старое состояние, не текущий evidence.

## Полный реестр

| Документ | Статус на code `f177ca5` | Что подтверждено / что нельзя обещать |
|---|---|---|
| `adapter-transaction.md` | АКТУАЛЕН | Typed adapter, recovery и fail-closed состояния; hardware-абзацы исторические. |
| `adaptive-zapret-strategy.md` | ЧАСТИЧНО | Bounded health/calibration contract есть; старые Flint 2/P12 PASS требуют нового прогона. |
| `algorithm-flow.md` | АКТУАЛЕН с оговорками | CheckDomain, TSPU и bounded route-only consumer описаны; hardware proof отсутствует. |
| `api.md` | АКТУАЛЕН software | Endpoint-контракты и gated route-only assignment сверены; hardware claims не наследуются. |
| `architecture.md` | АКТУАЛЕН software | OpenWrt boundary, ownership и узкий route-only consumer актуальны; аппаратный раздел исторический. |
| `component-manager.md` | АКТУАЛЕН | Lifecycle компонентов и TGWS contract; hardware activation не доказана на текущем SHA. |
| `domain-flow.md` | ЧАСТИЧНО | Нормализация, кеш, probe и production route-only consumer описаны; hardware assignment proof отсутствует. |
| `documentation-status.md` | АКТУАЛЕН | Этот реестр — текущая точка проверки документации; его статус обновляется вместе с заметным docs-аудитом. |
| `failure-model.md` | АКТУАЛЕН software | Recovery/fail-closed модель актуальна; аппаратные заявления требуют нового evidence. |
| `flint2-diagnostics.md` | АКТУАЛЕН как процедура | Это read-only checklist, а не доказательство выполненного запуска. |
| `flint2-hardware-report.md` | ИСТОРИЯ | Исторический redacted report; `STALE FOR CURRENT SHA`. |
| `flint2-hardware-validation.md` | ИСТОРИЯ/ПЛАН | Матрица hardware acceptance; hardware PASS для текущего delta отсутствует. |
| `forensic-safety-and-scheduling.md` | АКТУАЛЕН как forensic note | Причины и safety findings сохранены; новые hardware claims не добавлять без прогона. |
| `hardware-read-only-gate.md` | АКТУАЛЕН как gate | Разрешены только read-only проверки перед deployment. |
| `headless-dataplane.md` | ЧАСТИЧНО | Service/TPROXY contract есть; реальный hardware dataplane текущего SHA не подтверждён. |
| `implementation-plan.md` | ПЛАН | Список следующих этапов; не считать пункты «готовыми» без evidence matrix. |
| `incidents.md` | ИСТОРИЯ | Исторические инциденты и уроки; не доказательство текущей безопасности. |
| `installation.md` | ЧАСТИЧНО | Сборка и безопасные gate описаны; deployment на Flint 2 для этого SHA не выполнялся. |
| `network-platform-audit.md` | АКТУАЛЕН | Hardcode/GL.iNet audit; generic OpenWrt поддерживаемым не объявлен. |
| `probe-route.md` | АКТУАЛЕН software | Единый route proof и раздельные latency/duration; hardware proof отсутствует. |
| `README.md` | АКТУАЛЕН | Навигация по контрактам, evidence и ограничениям. |
| `remediation-design.md` | АКТУАЛЕН | Safety design и privilege model; code-level root-helper contract закрыт, runtime/hardware acceptance остаётся PARTIAL. |
| `remediation-evidence.md` | АКТУАЛЕН | Текущий SHA, локальные gates и CI run IDs; исторические строки помечены STALE. |
| `soak-test.md` | ПЛАН | 72-часовой прогон не выполнен на текущем SHA. |
| `status-matrix.md` | ИСТОРИЯ | Старая фазовая матрица; использовать только вместе с текущим evidence. |
| `storage-lifecycle.md` | АКТУАЛЕН software | Ownership, retention и write budget сверены; hardware не заявляется. |
| `telegram-notifications.md` | ЧАСТИЧНО | Notification/TGWS контракт описан; клиентский/hardware transport gate не закрыт. |
| `testing.md` | АКТУАЛЕН software | Команды и локальные тесты актуальны; Linux-only и hardware уровни разделены. |
| `tspu-cache.md` | АКТУАЛЕН software | Cache v2, hash, expiry, atomic save и stale semantics реализованы; старый Flint 2 refresh — история. |
| `tspu-sources.md` | АКТУАЛЕН | Реально используются только `refilter-domains` и `allow-domains-raw`; Antifilter не подключён. |
| `ui-v2.md` | АКТУАЛЕН software | Truthful UI и browser evidence; hardware не трогался. |
| `vpn-subscription.md` | АКТУАЛЕН software | Typed VLESS model, deduplication и secret redaction; hardware pool не доказан. |
| `web-ui.md` | ЧАСТИЧНО | UI/API contract актуален; старые factory/hardware утверждения помечать историческими. |
| `zapret-calibration-design.md` | АКТУАЛЕН как контракт | Quick/exhaustive разделены, path/cleanup proof обязателен; hardware PASS отсутствует. |

## Что исправлено этим аудитом

1. `algorithm-flow.md`, `api.md` и `architecture.md` теперь различают
   зарегистрированный route-only consumer и fenced режим без consumer; полный
   topology apply из discovery по-прежнему запрещён.
2. `tspu-sources.md` больше не выдаёт Antifilter за активный источник. Фактическая
   конфигурация — Re:filter и allow-domains; оба проходят `UpdateWithPrevious`,
   а match используется как evidence перед `ProbeRoute`.
3. `tspu-cache.md` и `tspu-sources.md` явно отделяют старый Flint 2 report от
   текущего software/CI evidence.
4. `remediation-evidence.md` привязан к текущему code HEAD `f177ca5` и отдельно отмечает исторические SHA.
   и содержит свежие CI run IDs.
5. DNS rotation, stale freshness, bounded login pressure, route-fetch SSRF
   fallback и Quick maintenance restart policy отражены в evidence matrix.

## Невыполненная очередь

- Подтвердить безопасный route-only assignment на отдельном hardware gate с TTL,
  atomic rollback и post-apply path proof; local/CI consumer реализован,
  hardware assignment proof отсутствует.
- Провести новый read-only gate и затем отдельную hardware validation на
  текущем SHA; старые PASS не переиспользовать.
- Для TSPU при необходимости добавить отдельный typed source-provider API,
  если потребуется больше двух настроенных доменных источников. Не добавлять
  IP/CDN-списки в классификацию без отдельного false-positive gate.

Если документ противоречит этой таблице или коду, приоритет такой: код и тесты,
затем `remediation-evidence.md`, затем этот реестр, затем исторические отчёты.
