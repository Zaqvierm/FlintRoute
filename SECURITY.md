# Политика безопасности

## Границы доверия

- Browser UI → локальный API;
- локальный API → control plane;
- control plane → OpenWrt adapter;
- OpenWrt adapter → dataplane: dnsmasq, nftables, firewall4, Xray, Zapret;
- secret files в `/etc/router-policy/secrets`.

## Экспозиция по умолчанию

Web/API listener в development слушает localhost и не должен быть открыт в WAN.
LAN bind разрешается только явно и должен быть защищён authentication, CSRF и
firewall rules.

Пароля администратора по умолчанию нет. Первый setup использует одноразовый
token, созданный `router-policy auth setup-token`; в state хранится только hash с
ограниченными правами, после создания администратора token уничтожается.

State-changing API требует заголовок `X-CSRF-Token`, совпадающий с HttpOnly
session cookie.

## Management proof

Production apply не принимается по одному вручную поддерживаемому boolean-файлу.
FlintRoute выпускает короткоживущий HMAC-SHA256 proof, связанный с boot ID,
transaction, revision, management interface, subnet, client address и listener
address. Adapter проверяет binding и после применения candidate повторно проверяет
живой controller, LAN route, HTTP health и доступный router-admin HTTP path.

Signing key — обычный persistent-state файл mode `0600`; API его не возвращает.
Proofs живут в tmpfs, истекают в rollback window и недействительны после reboot или
смены revision. Редактирование proof ломает подпись. Legacy
`state/diagnostics/management.env` не является authority, даже если содержит
похожие на успешные flags.

Headless apply требует proof, выданный из активного `SSH_CONNECTION`, использует
более длинное bounded rollback window и всё равно требует явного loopback API
confirm. Отсутствующий, устаревший или потерянный management path fail-closed;
восстановлением управляет обычная transaction model.

## Секреты

API никогда не возвращает:

- VPN subscription URLs;
- VLESS UUID;
- REALITY operational keys;
- Telegram bot tokens;
- passwords;
- полный Xray config с credentials.

В UI секреты отображаются только замаскированными значениями.

Telegram config принимается только после проверки bot token и chat access, если
delivery включена. Она атомарно хранится в regular non-symlink file mode `0600`
под configured secret root. API status выдаёт только booleans, delivery state и
counters; token, chat ID и bodies ответов Telegram исключены из API errors,
events и notification text.

`external_socks` принимает только loopback endpoint и пока поддерживает SOCKS5
no-auth. FlintRoute не владеет таким процессом и никогда не применяет глобальную
очистку процессов.

Secret-bearing scripts и diagnostics не используют `set -x`, не печатают полный
Xray config и не помещают raw subscription payload в logs, crash bundles, API
responses или event stream. Public diagnostics перед публикацией sanitise.

## Локальный аудит

```sh
router-policy security audit
```

Команда не меняет состояние; она проверяет config gates, известные unsafe defaults
и неразрешённые device-dependent items.

## Владение процессами и ресурсами

Production Xray и Zapret supervises dedicated procd services
`router-policy-xray` и `router-policy-zapret`. Состояние отдельной системной
службы `xray`, `zapret` или `nfqws` сообщается отдельно.

Cleanup не полагается только на process name или PID. Test process должен совпасть
с owner manifest, PID, `/proc` start time, executable, run identity и expected
config path. Network cleanup ограничен FlintRoute test namespace и reserved
routing range. Ambiguous resources только сообщаются и не трогаются.

Installer и transaction writers отклоняют symlink targets. Replacement использует
временный файл на той же файловой системе, file sync, atomic rename и попытку
синхронизации parent directory. Одинаковое содержимое не заменяется.

Installation-owned flow-offloading baseline принимается только из non-symlink
ownership directory и regular mode-0600 файла с тем же owner. Uninstall
восстанавливает только записанные UCI values и не делает unscoped firewall reload.
Recursive uninstall cleanup ограничен фиксированным FlintRoute prefix и runtime
root; environment override не может направить его в другую tree.

## Публичные отчёты

Не включать live subscription URLs, UUID, tokens или полные diagnostic archives.

Lifecycle/storage diagnostics показывают hashes, sizes, process identity,
bounded logical write counters и cleanup result. Они не раскрывают raw config,
subscription URLs, rollback capabilities, setup tokens, auth cookies и private
keys.

TSPU freshness metadata принимается только из regular bounded file, чей cache hash
совпадает с проверенным cache. Она не может продлевать entries источника, который
не прошёл повторную проверку.
