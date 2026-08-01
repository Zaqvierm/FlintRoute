# Матрица состояния

> Здесь отдельно указаны реализация, локальная проверка и подтверждение на
> реальном роутере.

## Фазы

Процент показывает готовность по критериям конкретной фазы. Это не оценка всего
проекта и не обещание релизной готовности.

| Фаза | Готовность | Коротко |
|---|---:|---|
| P0 | 100% | Машина состояний транзакции, bbolt и адаптер |
| P0.5 | 100% | Привязанные к кандидату артефакты и shell-адаптер |
| P1 | 100% | Доказательство маршрута, Smart DNS, VPN/Xray, проверка VLESS и GeoIP |
| P2 | 100% | TSPU cache, плановое обновление и проверка живых источников на Flint 2 |
| P3 | 100% | Headless dataplane Direct/Zapret/Drop/VLESS доказан на Flint 2 |
| P4 | 80% | Telegram delivery и external SOCKS setup реализованы локально; аппаратная проверка ещё не выполнена |
| P5 | 85% | Рабочий провайдер OpenWrt и API |
| P6 | 100% | Постоянное состояние и восстановление после перезагрузки доказаны на Flint 2 |
| P7 | 70% | Авторизация, fail-closed entropy handling и аудит listener bind |
| P8 | 75% | Карточный Web UI, decision flow, topology/privacy, high-level VLESS/Zapret/Smart DNS и Advanced mode готовы локально; аппаратный UI pass и часть device/update actions ещё нужны |
| P9 | 60% | Loopback по умолчанию и source-restricted доступ к панели из отдельной upstream-сети проверены; TLS ещё не встроен |
| P10 | 100% | Clean install, upgrade, rollback timer, compatible downgrade, uninstall и reinstall/reconcile пройдены на Flint 2 |
| P11 | 85% | Автоматические тесты |
| P12 | 100% | Adaptive Zapret привязан к OpenWrt transaction; два bundle-профиля и независимые выходы проверены на Flint 2 |
| P13 | 85% | Маршруты, Smart DNS, recursion guard, crash/reboot и physical power-loss доказаны; multi-client и soak остаются |
| P14 | 100% | Ownership, cleanup, bounded storage, provider/dataplane recovery, idle write budget и полный lifecycle tail доказаны на Flint 2 |

### Последняя аппаратная точка и текущая ветка

Commit `af8d81893d94434135d3cc942b27518c06a241d0` clean-installed на GL-MT6000
после factory recovery. На нём подтверждены безопасная baseline
revision, отсутствие автоматического dataplane, control-plane health,
source-restricted Web listener и восстановление того же committed state после
controlled reboot. Более новые изменения текущей ветки, включая runtime network
discovery без имён `lan`/`wan`/`br-lan`, пока проверены только локально и не
наследуют этот аппаратный PASS. Direct/Drop/Smart DNS/VLESS/Zapret matrix и
legacy in-place upgrade на указанном commit не повторялись: соответствующие
строки ниже используют сохранённое evidence более ранних revisions. Код не
проверяет модель роутера, но ARM64 package и hardware acceptance пока относятся
только к Flint 2.

| Область | Локально | Flint 2 |
|---|---|---|
| Dynamic DNS observation и классификация без заводского service catalog | unit/API/artifact tests | повторный apply ещё не выполнялся |
| Discovery modes и safe auto-apply gates | unit/API tests; clean default `observe_only` | auto-apply на текущем dataplane не запускался |
| System default, managed Direct и unclassified разделены | API/artifact tests | clean baseline сохранил system default и не создал managed rules; Direct apply на текущем commit не повторялся |
| Drop: NXDOMAIN + nft set/mark + forward guard | единый artifact regression test | прежний Drop evidence сохранён; этот commit не применялся |
| Smart DNS resolver preflight и apply proof | UDP/TCP/HTTP/TLS validator tests, bogon guard и expiry gate | требуется повторный тест с выбранным production resolver |
| Opt-in static rules и редактируемый fallback порядок | API tests и UI typecheck/build | требуется пользовательский apply на текущем Flint 2 |
| TSPU fallback `Zapret → Smart DNS → VLESS → Direct → DROP` | planner test доказывает, что VLESS не вызывается до Smart DNS | требуется проверка с production resolver |
| Пять VPN subscription slots и объединённая проверка outbound | API/UI/typecheck/build | требуется повторный subscription prepare |
| Ручной VLESS URI без возврата UUID/URI через API | parser/store/API/UI tests; manual outbound входит в общий candidate bundle | требуется проверка с пользовательским сервером |
| Карточный UI, decision flow, privacy mode и runtime topology | Vitest, typecheck/build, desktop/mobile browser smoke; Wi-Fi/Ethernet берутся из station/FDB evidence | требуется установка текущего commit и проверка на реальных клиентах |
| Явный candidate-only → managed Xray | mode, bundle и routes в одном ChangeSet; TPROXY/bypass/blackhole regression tests | требуется повторный apply/confirm и rollback test на текущем Flint 2 |
| Managed Zapret setup | pinned source/version/SHA, architecture, NFQUEUE, kernel state и nfqws dry-run; high-level API/UI | требуется preflight/apply/confirm на текущем Flint 2 |
| Top-3 blockcheck import, domain binding и atomic catalog | parser/catalog/CLI tests | calibration runner ещё не запускался |
| Telegram notifications и `external_socks` | sender/queue/retry, secret store, API/UI, external endpoint preflight и transactional activation | требуется проверка реальной доставки и endpoint на роутере |

### Блокеры полностью рабочего clean install

- installer устанавливает FlintRoute control plane, но не поставляет Xray и
  `nfqws`; Zapret setup требует immutable source URL, точную версию и SHA-256
  уже установленного binary;
- VLESS требует пользовательскую VPN-подписку, Smart DNS — проверенные
  production resolver endpoints;
- готовый package рассчитан на Linux arm64, а hardware acceptance — на
  GL-MT6000; другие OpenWrt target требуют отдельной сборки, диагностики и acceptance;
- локальные installer tests не доказывают конкретную прошивку или железо;
- Telegram notifications не входят в routing bootstrap. Собственный TGWS не
  реализован намеренно: поддерживается явно внешний SOCKS5 endpoint.

### P14: lifecycle и storage

| Критерий | Локально | Flint 2 |
|---|---|---|
| FlintRoute-managed Xray/Zapret отделены от system services | unit tests и API/CLI | active production instances прошли restart и SIGKILL recovery; system `xray` отображается отдельно |
| Typed owner manifest и PID reuse protection | да | изолированный hardware runner PASS |
| Stale cleanup dry-run/apply и повторный cleanup | process/file/nft table/IP rule/route/listener contracts | hardware PASS для test namespace; fixed uninstall удалил production processes/nft/policy routes |
| 100 test-runs возвращаются к baseline | локальный deterministic test | PASS: 100/100, production processes сохранены, foreign process защищён |
| Одинаковые health cycles не пишут bbolt | да | 1000 API GET + 35 минут/35 samples: persistent transactions/bytes и persistent file identity не изменились |
| Identical config/artifact install — no-op | Go и shell tests | unchanged TSPU entry set сохранил SHA/inode 64 MiB cache после refresh/restart/reboot |
| Runtime telemetry в tmpfs, durable recovery journal сохранён | да | controlled reboot PASS; runtime root восстановлен в tmpfs |
| Snapshot/backup count и size bounded | unit/shell tests | после uninstall/reinstall сохранены 2 verified operations, 66.7 MiB < 128 MiB |
| Watchdog maintenance lease и expiry | unit tests | controller оставался stopped >180 s, затем восстановлен; boot guard завершил bounded 120 s lease |

### P13 по подэтапам

| Подэтап | Состояние | Подтверждено | Остаётся |
|---|---|---|---|
| P13.0 | завершён | Harness, metadata, route cases, evidence parsing и bounded result bundle | финальный публичный redacted bundle после soak |
| P13.1 | завершён | Полный 50-cell manifest `route × protocol × AF`: 23 PASS, 0 FAIL, 0 NOT_TESTED, 27 NOT_APPLICABLE; каждая применимая клетка имеет protocol-specific packet proof и bound route evidence | 25 IPv6-клеток требуют отсутствующий WAN6; Zapret × DNS UDP/TCP неприменимы, потому что LAN DNS перехватывается до route classification |
| P13.2 | завершён | Production health cycle собирает раздельные active/challenger probes, сохраняет scheduler/ranking в bbolt и не переносит evidence между fingerprint; transaction-bound switch, safe-fallback pin, cooldown, quarantine и возврат static baseline пройдены на Flint 2 | повторять acceptance после изменения каталога nfqws или сетевой схемы |
| P13.3 | завершён | SIGKILL managed nfqws/Xray/controller, controlled reboot, реальный 180-second rollback timer, восстановление повреждённой bbolt и физическое отключение питания пройдены; после загрузки восстановились committed revision, managed providers, nftables, policy routing и Web API | повторять после изменения boot/recovery logic |
| P13.4 | начат | Bounded sampler и локальная проверка resource limits | три одновременных клиента и реальные throughput/latency/resource пределы |
| P13.5 | завершён | После factory recovery прошли clean install, upgrade, controlled reboot, rollback timer, compatible downgrade, uninstall, reinstall/reconcile и active provider/dataplane lifecycle; предыдущий инцидент сохранён в журнале | — |
| P13.6 | не начат | — | 72-часовой soak и финальный audit |

| Область | Реализовано | Проверено локально | Требуется Flint 2 |
|---|---:|---:|---:|
| Полный канонический кандидат с настоящим diff и хешем | да | интеграционные тесты | нет |
| Генерация nft/dnsmasq/Xray/nfqws/IP и привязка манифеста v6 | да | модульные и shell-интеграция | нет |
| План `IP route`, затем `IP rule`, с фиксированными аргументами | да | модульные, shell integration и доказательство Direct/Zapret/VLESS/Drop на Flint | нет для активного набора маршрутов |
| Отсутствующая или симулированная сетевая диагностика закрывается безопасно | да | модульные, API, shell-интеграция и диагностика Flint | нет |
| Подмена зависимостей адаптера | да | модульные и интеграционные тесты | нет |
| Тестовый apply/verify/commit рабочего контура | да | интеграционные тесты и race | нет |
| Filesystem-адаптер закрывается безопасно при `SKIPPED`, `UNVERIFIED`, `requires_device` | да | модульные и интеграционные тесты | нет |
| Confirm вызывает `adapter.Commit` | да | интеграционные тесты | нет |
| Ручной и автоматический rollback вызывают адаптер | да | интеграционные тесты | нет |
| Таймер истечения и восстановление незавершённого ChangeSet после перезапуска | да | интеграционные тесты и race | нет |
| **Восстановление committed dataplane после перезагрузки через `Reconcile`** | да | модульные, интеграционные и физическая перезагрузка Flint 2 | нет |
| Идемпотентный rollback в Go/shell и защита от устаревшего таймера | да | API, shell-интеграция и race | матрица перезагрузок и аварийных завершений |
| Блокировка параллельных apply/action с очисткой lock | да | интеграционные тесты и race | нет |
| Bounded-каталог Zapret и проверка nfqws по version/digest pins | да | модульные тесты и race | `nfqws` v72.12 принял config-embedded `--dry-run`; активный config не изменился |
| Service bundles и DNS provenance с блокировкой shared IP | да | модульные, race и отрицательные routing-тесты | не требуется до проверки переключения профилей |
| Rolling windows и ranking профилей по Wilson/latency | да | детерминированные модульные тесты, race и live active/challenger probes | нет |
| Bounded scheduler и переключение Zapret-профилей с cooldown/pin/quarantine | да | модульные, rollback, race; production scheduler, persistence, switch/pin/cooldown/quarantine/bad-candidate на Flint 2 | нет |
| Схема bbolt, retention, очистка backup и восстановление active compaction | да | модульные тесты | нет |
| Эпоха SSE-потока и долгоживущий ответ | да | модульные и API-тесты | нет |
| OpenWrt adapter с фиксированными командами | да | модульные, mocked shell integration и Flint apply/rollback/commit | остальные типы маршрутов |
| Общий helper lock с проверкой устаревшего владельца | да | shell-интеграция, ShellCheck и транзакции Flint | матрица перезагрузок и аварийных завершений |
| Проверка хеша снимка и маркеров отсутствующих файлов | да | shell-интеграция и rollback на Flint | матрица перезагрузок и аварийных завершений |
| Восстановление config/nft/dnsmasq/Xray/Zapret/active revision | да | shell-интеграция и Flint rollback с сохранением хеша рабочего Xray | нет |
| Управляемый жизненный цикл Xray TPROXY через procd | да | модульные, shell-интеграция и постоянный VLESS на Flint | расширенная матрица выходов и протоколов |
| Управляемый Zapret/nfqws, фиксированный preset и безопасный отказ NFQUEUE | да | модульные, shell-интеграция, nfqws dry-run/nft syntax на Flint и committed Zapret для `discord.com` | полная матрица |
| Транзакционное сохранение и отключение flow offloading | да | модульные, shell integration и Flint UCI 1/1 -> 0/0 | нет |
| VPN-подписка: извлечение, дедупликация, классификация, смена тегов и пакет | да | модульные и живая подписка, 12 поддерживаемых маршрутов | постоянное доказательство для каждого выхода |
| Цикл проверки VLESS: quorum, EWMA и роли | да | модульные, race и живая проверка | постоянный выбранный маршрут |
| Защита от рекурсии через конечную точку proxy | да | Xray `SO_MARK`, ранний nft bypass, fail-closed unit tests и Flint 2 runtime gate: 13 marked outbounds, bound VLESS path, live nft counter increment | нет |
| TSPU cache v2: несколько источников, ETag, drop-ratio, wildcard и SHA-256 | да | модульные, httptest, race и живое обновление 2/2 источников на Flint 2 | нет |
| GeoIP MMDB и согласование двух источников | да | модульные и живая проверка | нет |
| Кэш решений по доменам: ограниченный LRU, привязка к revision и TTL | да | модульные тесты | нет |
| SHA-256 пакета OpenWrt, откат установки/обновления и проверенное удаление | да | shell-проверка жизненного цикла; clean install, upgrade, compatible downgrade и uninstall на Flint 2 | нет |
| Полный локальный набор тестов | да | `run-all.ps1` | нет |
| Полный Go race suite | да | `go test -race ./...` | нет |

## Сохранённые аппаратные результаты и оставшиеся проверки

- Direct, Zapret, fail-closed Drop и VLESS/Xray применены и доказаны на Flint 2.
  После физической перезагрузки повторный связанный сбор доказательств прошёл строгую
  проверку; флаги DNS, IPv6 и geo kill-switch имеют ожидаемые значения.
- Восстановление после перезагрузки доказано с состоянием в
  `/etc/router-policy/state`, без совместимого псевдонима `/var/lib/router-policy`.
  Контроллер, Xray, nfqws, nftables и правила IPv4/IPv6 восстановились
  автоматически.
- После двух инцидентов с U-Boot recovery исправленный preflight, rollback,
  startup no-op и ограниченный lifecycle runner повторно проверены на Flint 2.
  Clean install, upgrade, rollback timer, compatible downgrade, uninstall и
  reinstall/reconcile прошли при непрерывном внешнем SSH/web monitor.
- Последовательный SIGKILL managed nfqws, Xray и controller пройден на Flint 2.
  После каждого сбоя procd поднял новый PID, соответствующий route proof прошёл,
  а committed artifacts и active transaction binding не изменились. Timer fault,
  повреждение bbolt и физическое отключение питания также пройдены. После
  power-loss внешний монитор увидел возврат SSH/router UI, затем FlintRoute Web;
  та же committed revision и owned dataplane восстановились без ручного ремонта.
- Production Smart DNS resolver выбран; оба endpoint дали безопасные A/AAAA
  через UDP/53 и TCP/53 непосредственно на Flint 2. Два route транзакционно
  committed; оба bound path proof и соседние Direct/Zapret/VLESS proofs прошли.
- Полная матрица содержит 23 PASS, 0 FAIL и 0 NOT_TESTED. Из 27
  `NOT_APPLICABLE` 25 относятся к отсутствующему WAN6, ещё две — к Zapret DNS:
  LAN DNS перехватывается до Zapret route classification.
- Защита от рекурсии proxy endpoint прошла отдельный runtime gate на Flint 2.
  Все 15 неблокирующих Xray outbound имеют configured bypass mark, активные nft
  rules стоят до policy classification, bound VLESS probe подтверждён, а live
  bypass counter вырос во время проверки. Этот release blocker закрыт.
- Изолированный P14 lifecycle runner выполнил 100 последовательных test-run:
  baseline восстановлен, stale cleanup идемпотентен, SIGKILL и SSH disconnect
  пережиты, foreign process и production processes сохранены. Эти результаты не
  заменяют повторный hardware pass после будущих изменений lifecycle/data plane.
