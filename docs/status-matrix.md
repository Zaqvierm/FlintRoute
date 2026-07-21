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
| P4 | 0% | Уведомления Telegram и tg-ws-proxy |
| P5 | 85% | Рабочий провайдер OpenWrt и API |
| P6 | 100% | Постоянное состояние и восстановление после перезагрузки доказаны на Flint 2 |
| P7 | 60% | Авторизация и аудит безопасности |
| P8 | 15% | Встроенный Web UI |
| P9 | 40% | Loopback и доступ к панели из LAN |
| P10 | 85% | Проверяемый OpenWrt-пакет, обновление и чистая установка доказаны на Flint 2; downgrade/uninstall остаются |
| P11 | 85% | Автоматические тесты |
| P12 | 100% | Adaptive Zapret привязан к OpenWrt transaction; два bundle-профиля и независимые выходы проверены на Flint 2 |
| P13 | 65% | Production Smart DNS, recursion guard, rollback timer, controlled reboot и SIGKILL managed-процессов доказаны; 21 IPv4 matrix cell, расширенные faults, multi-client, lifecycle и soak остаются |

### P13 по подэтапам

| Подэтап | Состояние | Подтверждено | Остаётся |
|---|---|---|---|
| P13.0 | завершён | Harness, metadata, route cases, evidence parsing и bounded result bundle | финальный публичный redacted bundle после soak |
| P13.1 | частично | Полный 50-cell manifest `route × protocol × AF`; 4 PASS, 0 FAIL, 21 NOT_TESTED и 25 NOT_APPLICABLE; Direct/Zapret/VLESS/Smart DNS HTTPS, UDP/TCP resolver transport и production Smart DNS activation доказаны | LAN DNS, TCP/80, QUIC и transport-specific DROP; native IPv6 неприменим, пока WAN6 отсутствует |
| P13.2 | частично | Два bundle scope, независимые Direct/Zapret/VLESS paths и transaction-bound adaptive apply | деградация активного профиля, quarantine/cooldown/pin и bad challenger на железе |
| P13.3 | частично | SIGKILL managed nfqws/Xray/controller, controlled reboot и реальный 180-second rollback timer пройдены; config/binding и route proofs восстановлены | power loss и повреждение state на железе |
| P13.4 | начат | Bounded sampler и локальная проверка resource limits | три одновременных клиента и реальные throughput/latency/resource пределы |
| P13.5 | частично | In-place upgrade, factory clean install, первая активация и post-reboot recovery | аппаратные downgrade, rollback upgrade и uninstall |
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
| Rolling windows и ranking профилей по Wilson/latency | да | детерминированные модульные тесты и race | требуется вместе с bounded switch |
| Bounded scheduler и переключение Zapret-профилей с cooldown/pin/quarantine | да | модульные, rollback и race | два bundles и bundle-scoped nfqws config приняты; Zapret/VLESS/Direct path proof прошёл |
| Схема bbolt, retention, очистка backup и восстановление active compaction | да | модульные тесты | нет |
| Эпоха SSE-потока и долгоживущий ответ | да | модульные и API-тесты | нет |
| OpenWrt adapter с фиксированными командами | да | модульные, mocked shell integration и Flint apply/rollback/commit | остальные типы маршрутов |
| Общий helper lock с проверкой устаревшего владельца | да | shell-интеграция, ShellCheck и транзакции Flint | матрица перезагрузок и аварийных завершений |
| Проверка хеша снимка и маркеров отсутствующих файлов | да | shell-интеграция и rollback на Flint | матрица перезагрузок и аварийных завершений |
| Восстановление config/nft/dnsmasq/Xray/Zapret/active revision | да | shell-интеграция и Flint rollback с сохранением хеша рабочего Xray | реальная активация и rollback Xray |
| Управляемый жизненный цикл Xray TPROXY через procd | да | модульные, shell-интеграция и постоянный VLESS на Flint | расширенная матрица выходов и протоколов |
| Управляемый Zapret/nfqws, фиксированный preset и безопасный отказ NFQUEUE | да | модульные, shell-интеграция, nfqws dry-run/nft syntax на Flint и committed Zapret для `discord.com` | полная матрица |
| Транзакционное сохранение и отключение flow offloading | да | модульные, shell integration и Flint UCI 1/1 -> 0/0 | нет |
| VPN-подписка: извлечение, дедупликация, классификация, смена тегов и пакет | да | модульные и живая подписка, 12 поддерживаемых маршрутов | постоянное доказательство для каждого выхода |
| Цикл проверки VLESS: quorum, EWMA и роли | да | модульные, race и живая проверка | постоянный выбранный маршрут |
| Защита от рекурсии через конечную точку proxy | да | Xray `SO_MARK`, ранний nft bypass, fail-closed unit tests и Flint 2 runtime gate: 13 marked outbounds, bound VLESS path, live nft counter increment | нет |
| TSPU cache v2: несколько источников, ETag, drop-ratio, wildcard и SHA-256 | да | модульные, httptest, race и живое обновление 2/2 источников на Flint 2 | нет |
| GeoIP MMDB и согласование двух источников | да | модульные и живая проверка | нет |
| Кэш решений по доменам: ограниченный LRU, привязка к revision и TTL | да | модульные тесты | нет |
| SHA-256 пакета OpenWrt, откат установки/обновления и проверенное удаление | да | shell-проверка жизненного цикла, обновление и чистая установка на Flint 2 | аппаратные понижение версии и удаление |
| Полный локальный набор тестов | да | `run-all.ps1` | нет |
| Полный Go race suite | да | `go test -race ./...` | нет |

## Оставшиеся проверки на железе

- Direct, Zapret, fail-closed Drop и VLESS/Xray применены и доказаны на Flint 2.
  После физической перезагрузки повторный связанный сбор доказательств прошёл строгую
  проверку; флаги DNS, IPv6 и geo kill-switch имеют ожидаемые значения.
- Восстановление после перезагрузки доказано с состоянием в
  `/etc/router-policy/state`, без совместимого псевдонима `/var/lib/router-policy`.
  Контроллер, Xray, nfqws, nftables и правила IPv4/IPv6 восстановились
  автоматически.
- Factory clean install, первая транзакционная активация и controlled reboot
  доказаны. Реальный 180-second timer rollback также пройден; power-loss, несколько
  клиентов, понижение версии и удаление ещё требуют аппаратного прогона.
- Последовательный SIGKILL managed nfqws, Xray и controller пройден на Flint 2.
  После каждого сбоя procd поднял новый PID, соответствующий route proof прошёл,
  а committed artifacts и active transaction binding не изменились. Timer fault,
  power-loss и проверка повреждённого state остаются в P13.
- Production Smart DNS resolver выбран; оба endpoint дали безопасные A/AAAA
  через UDP/53 и TCP/53 непосредственно на Flint 2. Два route транзакционно
  committed; оба bound path proof и соседние Direct/Zapret/VLESS proofs прошли.
- Матрица больше не маскирует непройденные тесты как неприменимые: текущий
  результат — 4 PASS, 0 FAIL, 21 NOT_TESTED и 25 NOT_APPLICABLE из-за отсутствия WAN6.
- Защита от рекурсии proxy endpoint прошла отдельный runtime gate на Flint 2.
  Все 13 неблокирующих Xray outbound имеют configured bypass mark, активные nft
  rules стоят до policy classification, bound VLESS probe подтверждён, а live
  bypass counter вырос во время проверки. Этот release blocker закрыт.
