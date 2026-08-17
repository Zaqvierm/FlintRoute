# Внешние сетевые компоненты

FlintRoute управляет установкой Xray, Zapret/nfqws и TG WS Proxy через единый
Component Manager. Пользовательский путь не требует искать asset, подбирать
архитектуру или вручную вычислять SHA-256.

## Контракт установки

Для каждого компонента в коде закреплены upstream, поддерживаемая версия,
архитектурные assets, размер и SHA-256. Установка выполняет:

```text
platform detection -> preflight -> pinned release -> download -> SHA-256
-> atomic/package install -> service setup -> health check
```

Download разрешён только с allowlisted GitHub release URL, привязанного к
конкретной версии. `latest` используется только для read-only проверки
обновлений. Новая upstream-версия не устанавливается, пока её asset и checksum
не добавлены в проверенный каталог.

| Компонент | Закреплённая версия | Upstream | Пакет |
|---|---|---|---|
| Xray | `v26.3.27` | `XTLS/Xray-core` | Linux arm64 zip |
| Zapret | `v72.13` | `bol-van/zapret` | embedded OpenWrt tar.gz |
| TG WS Proxy | `0.9.3-rev2` | `spatiumstas/tg-ws-proxy-go` | OpenWrt ipk по `opkg` architecture |

Update сохраняет предыдущий бинарник/config. Если новый процесс не проходит
health check, версия откатывается. Uninstall требует явного подтверждения,
останавливает сервис и удаляет только принадлежащие компоненту файлы. Xray и
Zapret нельзя молча удалить при активных маршрутах.

Каталог `/usr/lib/router-policy/components` принадлежит Component Manager. Upgrade
самого FlintRoute переносит его в новое installed tree без копирования и проверяет,
что корень и содержимое не являются symlink. Если обязательный runtime Zapret
пропал или повреждён, обычная повторная установка ремонтирует его вместо ложного
`noop`.

## Zapret и калибровка

Установка извлекает `nfqws`, `blockcheck.sh` и минимальный runtime из
закреплённого архива. Калибровка запускается отдельно для фактического домена и
fingerprint текущей production-сети. Она не меняет маршрут автоматически.

Upstream `blockcheck.sh` использует общие firewall, NFQUEUE и временные ресурсы.
Число комбинаций определяется его версией, режимом scan и capabilities роутера;
FlintRoute не рисует фиксированное «28». Надёжной полной изоляции параллельных
workers в этом контракте нет, поэтому production runner использует один worker.
UI показывает число реально завершённых вариантов из bounded runtime-log. Это
медленнее, зато не создаёт гонки за nft/NFQUEUE и не рискует management path.
Результат ограничен тремя проверенными кандидатами; raw shell strategy не
возвращается через API.

Выбранный профиль включается только обычным ChangeSet:

```text
preflight -> apply -> management proof -> data-plane proof -> confirm/rollback
```

## Xray и VLESS pool

Подписки и ручные `vless://` URI нормализуются в logical servers. Fingerprint
содержит endpoint и transport/security identity, но не UUID/token. Поэтому один
узел с разными credentials не дублируется как несколько физических серверов.
Источники доступа и их expiry хранятся отдельно; URL и credentials не
возвращаются через API.

Сервер eligible для выбора только при `PathVerified`, без quarantine и серии
ошибок. Score учитывает latency, jitter, stability и throughput. Для throughput
используется `min(measured, configured tariff)`, поэтому скорость выше тарифа не
перетягивает выбор на сервер с плохой задержкой.

Первый verified candidate может получить bounded speed measurement. Результат
переиспользуется 24 часа: обычный health refresh не скачивает тестовый файл
повторно. Ручной speedtest не доверяет сохранённому адресу временного listener:
он проверяет content-addressed bundle, поднимает отдельный candidate Xray,
дожидается loopback SOCKS конкретного logical server, выполняет измерение и
обязательно останавливает candidate. Тест использует 2–16 MiB и сохраняет
raw/effective throughput, bytes и duration.

## TG WS Proxy

Используется upstream `spatiumstas/tg-ws-proxy-go` и его OpenWrt package/procd
контракт. Component Manager умеет безопасно установить, обновить, откатить и
удалить пакет. После установки сервис остаётся выключенным со статусом
`needs_configuration`, пока пользователь не завершит отдельный setup.

Экран TG WS Proxy задаёт порт и необязательный Fake TLS domain. Backend
генерирует 32-hex secret на роутере, атомарно записывает `config.conf` и
`secret.conf` с mode `0600`, включает UCI/procd service и проверяет локальный
listener и доступность настроенного Telegram DC. Секрет не возвращается через
обычный status API. Ссылка `tg://proxy` выдаётся один раз после настройки.

Важно: этот upstream является Telegram MTProxy/WebSocket server, а не локальным
outbound SOCKS5 client. Поэтому наличие пакета не создаёт автоматически маршрут
LAN-клиентов к Telegram и не считается end-to-end PASS. До появления
проверенного client-side transport такой маршрут остаётся `external_socks` в
Advanced и требует реальной SOCKS/TLS/HTTP проверки. Router-side TGWS health
также не равен клиентскому PASS: после проверки listener и DC пользователь
должен открыть одноразовую ссылку в Telegram. До этого
`client_path_verified=false`.

## Проверка на железе

Новый Component Manager, калибровка, logical pool, speedtest API и UI сначала
проверяются локально. Аппаратный PASS относится только к commit, который реально
установлен на роутер, и фиксируется после backup, component preflight и runtime
smoke. Недоступные внешние credentials отмечаются `SKIP`, а не заменяются mock.
