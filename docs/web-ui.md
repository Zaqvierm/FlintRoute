# Web UI

> Реализация: `ui/src/main.tsx`, `ui/src/view-models.ts`, `internal/web`.

Встроенная панель рассчитана на один понятный интерфейс: новичок видит короткие
статусы и причины ошибок, а технические поля открываются в той же карточке. Нет
отдельной «упрощённой» и «администраторской» версии экрана. Права API по-прежнему
ограничивают опасные действия, но структура навигации для всех одна.

## Сборка и запуск

- TypeScript, Preact и Vite;
- CSS без CDN;
- production bundle в `internal/web/dist`;
- Go `embed` отдаёт интерфейс из `router-policy serve` и `router-policy run`.

```powershell
npm ci
npm run typecheck
npm test
npm run build
powershell -ExecutionPolicy Bypass -File .\scripts\build-go.ps1
.\dist\router-policy.exe serve --listen 127.0.0.1:8787
```

На OpenWrt listener настраивается отдельно от основной конфигурации:

```text
# /etc/router-policy/config/listener.conf
listen_address=0.0.0.0:8787
allow_firewalled_bind=1
```

Non-loopback bind сам не открывает firewall. TCP-порт должен быть разрешён только
из доверенной management subnet. Значение по умолчанию остаётся
`127.0.0.1:8787`.

## Общий UX

Основные сущности используют один паттерн:

```text
карточка с понятным состоянием → Открыть → подробности → сырые данные
```

На кратком уровне не показываются transaction ID, nft mark, Xray tag, JSON
Pointer и полный evidence. Они находятся в drawer. Raw JSON закрыт отдельным
`Открыть сырые данные`.

Для загрузки, пустого ответа, ошибки API и устаревших данных есть отдельные
состояния. Верхняя строка показывает только Internet, data plane, DNS, текущий
маршрут и критические ошибки. CPU, RAM и температура не подставляются, если
backend не дал достоверного значения. Объекты не преобразуются через неявный
`String()`, поэтому `[object Object]` не попадает в интерфейс.

Навигация и выбранный экран сохраняются между reload. На телефоне меню становится
горизонтальным, карточки и drawers занимают доступную ширину без переполнения.

## Поток решений

`Поток решений` отделяет сетевые решения от системного журнала. На основном
экране остаются события, содержащие домен, устройство, выбранный маршрут или
route evidence. `system.change.*`, lifecycle и rollback bookkeeping доступны в
`Административном журнале`.

Карточка решения показывает:

- устройство и адрес в текущем privacy mode;
- время, домен, сервис и категорию;
- стратегию, правило, route и fallback;
- PathVerified, конечный статус и длительность.

Drawer показывает кандидатов и причины отказа, DNS addresses, destination IP,
probe latency, HTTP/TLS evidence, nft mark, routing table, egress interface,
Xray/SOCKS binding, policy/revision/transaction и timeline. Поля отображаются
только если backend действительно прислал их.

Интерфейс держит выбранное окно 15, 30, 60 или 120 минут; значение хранится
локально. Значение по умолчанию — 30 минут. Доступны фильтры по устройству, IP,
домену, сервису, категории, route, status, PathVerified и fallback.

## Карта и устройства

Название и модель центрального узла берутся из `/api/v1/system`. Production UI
не содержит названия конкретного роутера, адреса управления, интерфейса или
подсети.

OpenWrt provider объединяет:

- `ubus` interface и device state;
- DHCP leases и neighbour table;
- bridge FDB;
- `hostapd.* get_clients` для реальных Wi-Fi stations;
- interface counters.

Ethernet определяется по bridge FDB/интерфейсу, Wi-Fi — только по данным
wireless station. Имя устройства и IP для этого не используются. Поддерживаются
несколько LAN/SSID, guest/mesh-пути, unknown connection и недавно отключённые
клиенты; неполные данные не превращаются в выдуманное подключение.

MAC и IP по умолчанию удаляются из raw API fields на backend. Полные значения не
лежат в DOM; маски приходят отдельно как `ip_display`/`mac_display` и никогда не
используются как network identity. Кнопка privacy mode запрашивает раскрытую
выдачу на пять минут и затем снова получает только display-маски. Simulation
provider не выдумывает raw IP/MAC даже при reveal. Карточка устройства содержит тип подключения, interface,
SSID, RSSI, трафик, first/last seen, policy и последние решения. Действия без
готового API честно disabled.

## Сервисы

Домены группируются по каноническому service ID, а не только по eTLD+1. Поэтому
один сервис может включать разные корневые домены. Карточка показывает категорию,
число доменов, route и health; drawer — домены, источники, overrides, fallback и
последние решения. Заводской список сайтов не зашит в UI.

Service board сохраняет четыре понятных класса: GEO, TSPU, Direct и Drop.
Перетаскивание одиночного правила создаёт обычный ChangeSet. Низкоуровневое
редактирование остаётся в `Advanced`.

## VLESS/Xray

Экран разделяет:

- до пяти HTTPS-подписок;
- VLESS-серверы, добавленные вручную.

Ручной `vless://` URI разбирается на backend и сохраняется как Xray outbound в
файле режима `0600`. UUID и исходный URI не возвращаются через API. Безопасная
выдача содержит имя, hostname/IP, порт, transport и security. Ручные и
subscription outbounds объединяются в один candidate bundle и проходят одну
проверку внешнего пути.

`Сохранить и проверить` не включает маршрутизацию. Явный managed activation
повторяет проверку и создаёт одну транзакцию с Xray mode, TPROXY/bypass binding и
VLESS routes. Подтверждение возможно только после management/data-plane proof.

`Обновить health` запускает лёгкую проверку задержки и выхода. Недавний speedtest
переиспользуется 24 часа и не запускается на каждом refresh. Ручная кнопка в
подробностях проверенного logical server скачивает через его loopback SOCKS
2–16 MiB, показывает bytes/duration и отдельно хранит raw/effective throughput.

## Компоненты и Zapret

Экран `Компоненты` показывает install/version/service/health/update/rollback для
Xray, Zapret и TG WS Proxy. URL/version/SHA не являются основным сценарием и
видны только в Advanced.

Экран Zapret устанавливает закреплённый пакет через Component Manager, а затем
запускает отдельную calibration для выбранного домена. Progress и причина
concurrency отображаются явно. Upstream blockcheck использует общие nft/NFQUEUE
ресурсы, поэтому production runner последовательный. Найденные кандидаты не
включаются молча: apply проходит через ChangeSet и PathVerified.

## Smart DNS

Resolver принимается как `IPv4`, `IPv4:port`, `IPv6` или `[IPv6]:port`. Порт
необязателен, по умолчанию используется 53. Private, loopback, multicast,
unspecified и bogon адреса отклоняются.

До создания ChangeSet backend выполняет UDP DNS, TCP DNS, проверяет полученные
адреса и HTTP/TLS подключение к выбранному домену. Результаты и код ошибки
показываются по шагам. Smart DNS всегда называется conditional DNS, а не VPN.

## Диагностика и recovery

Security checks, diagnostics, revisions, backups и recovery представлены
карточками. Подробности и raw JSON открываются вручную. Настройки пока являются
честным read-only projection. ChangeSet editor находится только в `Advanced` и
перед apply группирует diff по routing, firewall/data plane и management.

Telegram events отображаются отдельными карточками; настройка уведомлений не
смешана с routing bootstrap. External SOCKS остаётся явно внешней зависимостью.
Для managed TG WS Proxy есть отдельный экран: порт, необязательный Fake TLS,
procd/listener/DC health и одноразовая ссылка подключения. UI прямо говорит,
что TGWS — MTProto proxy для клиента, а не outbound SOCKS и не прозрачный
перехват трафика телефона.

## Безопасность

- subscription URL, VLESS UUID/URI, Reality credentials и Telegram token не
  возвращаются через API;
- client IP/MAC редактируются на backend до отправки в privacy mode;
- `/api/v1/settings` отдаёт safe projection;
- CSRF обязателен для state-changing запросов;
- production UI не использует simulation fallback.

## Подтверждённое состояние

Typecheck, Vitest, production build и API tests выполняются локально. Текущая
переработка карты, Component Manager, Zapret calibration и VLESS pool ещё не
наследуют старый hardware PASS: нужен install/smoke текущего commit.

Остаются read-only или disabled:

- изменение настроек устройства без отдельного backend API;
- автоматическое подтверждение TGWS client path без открытия ссылки в Telegram;
- TLS termination самой панели.
