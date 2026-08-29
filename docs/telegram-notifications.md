# Telegram-уведомления, TG WS Proxy и внешний SOCKS

> **Статус на `f177ca5`:** software-контракт и локальные проверки актуальны.
> Реальная доставка/клиентский TGWS path на железе текущего SHA не доказаны.

Доставка в Telegram — необязательная подсистема control plane. Начальная
маршрутизация, health checks и rollback от неё не зависят.

## Уведомления

`PUT /api/v1/telegram/configure` принимает bot token, chat ID, enabled flag и
event allowlist. При включении FlintRoute проверяет `getMe` и `getChat` до
сохранения. `POST /api/v1/telegram/test` отправляет настоящее тестовое сообщение.

Secret file — обычный non-symlink файл mode `0600` в directory mode `0700`.
Token и chat ID никогда не возвращаются через API, events или status. Пустые
поля сохраняют прежние значения, поэтому delivery можно отключить без удаления
настроек.

Состояния runtime: `not_configured`, `configured`, `verified`, `degraded`,
`failed`. Доставка использует bounded queue, дедупликацию, timeout, минимальный
интервал отправки и bounded exponential retry. Разрешённые события:
`apply_succeeded`, `rollback`, `route_loss`, `recovery`, `auto_apply_blocked`,
`storage_critical`.

## Managed TG WS Proxy

Component Manager устанавливает pinned OpenWrt package из
`spatiumstas/tg-ws-proxy-go`. Сама установка service не включает.
`POST /api/v1/tgws/configure` проверяет port и optional Fake TLS domain, генерирует
secret на роутере, пишет только regular config files `0600`, включает package
procd service и проверяет local listener и заданный Telegram DC.

Secret отсутствует в status, events и diagnostics. Ответ configure один раз
возвращает ссылку `tg://proxy`. Router-side checks дают `ready_for_client`, но не
end-to-end PASS: пользователь должен открыть ссылку в Telegram, только после
этого `client_path_verified` становится authoritative.

TG WS Proxy — client-facing MTProto/WebSocket proxy server. Это не outbound SOCKS5
и не transparent interception произвольного Telegram traffic от LAN clients.

## Внешний SOCKS

FlintRoute не поставляет и не supervises Telegram WebSocket transport. Тип route
называется `external_socks`: оператор указывает уже существующий loopback SOCKS5.
FlintRoute владеет только Xray route, направляющим трафик к этому endpoint.

Setup API проверяет loopback addressing, TCP reachability, unauthenticated SOCKS5
handshake, remote-domain CONNECT, TLS и HTTP. Успешная проверка не меняет routing.
Явная activation создаёт обычный ChangeSet для Xray mode, route и test-domain
binding; authoritative остаётся цепочка validate → apply → PathVerified →
confirm/rollback.

Старые persisted route type `tg_ws_proxy` и tag `tg-ws-proxy` при validation
нормализуются в `external_socks` и `external-socks`. Процессы не убиваются, не
устанавливаются и не перезапускаются. Hardware notification delivery, TGWS client
activation и внешний transport требуют отдельного теста с реальным client или
credentials/operator endpoint.
