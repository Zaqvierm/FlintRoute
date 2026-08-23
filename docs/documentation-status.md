# Актуальность документации

Проверено: `2026-08-23`, база code/docs `effa938cf67a7fb3c6013982995b287e22228831`.
Итоговый commit этого аудита будет указан в финальном отчёте после проверки.
Ветка: `remediation/transaction-and-privilege-boundaries-consolidated`.

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

| Документ | Статус на `effa938` | Что подтверждено / что нельзя обещать |
|---|---|---|
| `adapter-transaction.md` | АКТУАЛЕН | Typed adapter, recovery и fail-closed состояния; hardware-абзацы исторические. |
| `adaptive-zapret-strategy.md` | ЧАСТИЧНО | Bounded health/calibration contract есть; старые Flint 2/P12 PASS требуют нового прогона. |
| `algorithm-flow.md` | АКТУАЛЕН с оговорками | Добавлена сверка с `CheckDomain`, TSPU и disabled route-only auto-apply. |
| `api.md` | АКТУАЛЕН software | Endpoint-контракты сверены; hardware claims не наследуются текущим SHA. |
| `architecture.md` | АКТУАЛЕН software | OpenWrt boundary и ownership актуальны; раздел «Проверенные аппаратные факты» исторический. |
| `component-manager.md` | АКТУАЛЕН | Lifecycle компонентов и TGWS contract; hardware activation не доказана на текущем SHA. |
| `domain-flow.md` | ЧАСТИЧНО | Нормализация, кеш и probe описаны; automatic route-only assignment пока отсутствует. |
| `documentation-status.md` | АКТУАЛЕН | Этот реестр — текущая точка проверки документации; его статус обновляется вместе с заметным docs-аудитом. |
| `failure-model.md` | АКТУАЛЕН software | Recovery/fail-closed модель актуальна; аппаратные заявления требуют нового evidence. |
| `flint2-diagnostics.md` | АКТУАЛЕН как процедура | Это read-only checklist, а не доказательство выполненного запуска. |
| `flint2-hardware-report.md` | ИСТОРИЯ | Исторический redacted report; `STALE FOR CURRENT SHA`. |
| `flint2-hardware-validation.md` | ИСТОРИЯ/ПЛАН | Матрица hardware acceptance; не PASS для `effa938`. |
| `forensic-safety-and-scheduling.md` | АКТУАЛЕН как forensic note | Причины и safety findings сохранены; новые hardware claims не добавлять без прогона. |
| `hardware-read-only-gate.md` | АКТУАЛЕН как gate | Разрешены только read-only проверки перед deployment. |
| `headless-dataplane.md` | ЧАСТИЧНО | Service/TPROXY contract есть; реальный hardware dataplane текущего SHA не подтверждён. |
| `implementation-plan.md` | ПЛАН | Список следующих этапов; не считать пункты «готовыми» без evidence matrix. |
| `incidents.md` | ИСТОРИЯ | Исторические инциденты и уроки; не доказательство текущей безопасности. |
| `installation.md` | ЧАСТИЧНО | Сборка и безопасные gate описаны; deployment на Flint 2 для этого SHA не выполнялся. |
| `network-platform-audit.md` | АКТУАЛЕН | Hardcode/GL.iNet audit; generic OpenWrt поддерживаемым не объявлен. |
| `probe-route.md` | АКТУАЛЕН software | Единый route proof и раздельные latency/duration; hardware proof отсутствует. |
| `README.md` | АКТУАЛЕН | Навигация по контрактам, evidence и ограничениям. |
| `remediation-design.md` | АКТУАЛЕН | Safety design и privilege model; root-helper split остаётся PARTIAL. |
| `remediation-evidence.md` | АКТУАЛЕН | Текущий SHA, локальные gates и CI run IDs; старое evidence помечено STALE. |
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

1. `algorithm-flow.md` больше не обещает, что `auto_apply_verified` уже
   меняет production dataplane: код пока намеренно оставляет suggestion.
2. `tspu-sources.md` больше не выдаёт Antifilter за активный источник. Фактическая
   конфигурация — Re:filter и allow-domains; оба проходят `UpdateWithPrevious`,
   а match используется как evidence перед `ProbeRoute`.
3. `tspu-cache.md` и `tspu-sources.md` явно отделяют старый Flint 2 report от
   текущего software/CI evidence.
4. `remediation-evidence.md` привязан к `effa938` и содержит свежие CI run IDs.

## Невыполненная очередь

- Реализовать безопасный route-only assignment с TTL и атомарным rollback;
  до этого `auto_apply_verified` остаётся fenced.
- Провести новый read-only gate и затем отдельную hardware validation на
  текущем SHA; старые PASS не переиспользовать.
- Для TSPU при необходимости добавить отдельный typed source-provider API,
  если потребуется больше двух настроенных доменных источников. Не добавлять
  IP/CDN-списки в классификацию без отдельного false-positive gate.

Если документ противоречит этой таблице или коду, приоритет такой: код и тесты,
затем `remediation-evidence.md`, затем этот реестр, затем исторические отчёты.
