# Web UI (Aegis Console)

> Основные реализации: `ui/src/main.tsx`, `internal/web`.

## Стек

- TypeScript + Preact + Vite;
- CSS без CDN;
- production build в `internal/web/dist`;
- Go `embed` отдаёт UI из `router-policy serve`/`run`.

Node.js нужен только на машине сборки. На Flint 2 кладётся собранный
binary/static bundle — никакого Node runtime на устройстве.

## Запуск

```powershell
npm install
npm run typecheck
npm run build
powershell -ExecutionPolicy Bypass -File .\scripts\build-go.ps1
.\dist\router-policy.exe serve --listen 127.0.0.1:8787
```

Открыть `http://127.0.0.1:8787/`.

На OpenWrt listener настраивается отдельно от основного JSON:

```text
# /etc/router-policy/config/listener.conf
listen_address=0.0.0.0:8787
allow_firewalled_bind=1
```

После изменения перезапустите только `router-policy`. Этот opt-in не открывает
порт сам: firewall4 rule должен разрешать TCP/8787 только из доверенной
management subnet. Default-файл остаётся `127.0.0.1:8787` и
`allow_firewalled_bind=0`; installer не перезаписывает локальную настройку при
upgrade.

## Экраны (`Content` в `ui/src/main.tsx`)

- вход (`LoginScreen`);
- первичная настройка (`SetupScreen`);
- обзор (`OverviewScreen`);
- карта сети (`NetworkMap`, topology);
- трафик (`Traffic`) — RX/TX bytes, текущая скорость, packets/errors по интерфейсам;
- устройства (`Devices`, `DeviceCard`);
- сервисы (`Services`, `ServiceGroup`);
- политики (таблица/доска, `Policies`);
- очередь изменений (`Changes`, refresh);
- маршруты (`Routes`, `Vless`, `RouteType`);
- Smart DNS и Zapret; Telegram — отдельный status-only экран незавершённой
  подсистемы;
- поток решений (`DecisionFlow`, events);
- диагностика (`Diagnostics`);
- безопасность (`Security`);
- система (`system`), настройки (`Settings`);
- generic-карточки для прочих данных.

Главный экран держит сетевую карту крупным блоком и правую колонку с критичными
сервисами, предупреждениями и последними решениями.

## API-контракт

UI не пишет nft/Xray/dnsmasq/UCI/routes напрямую. Все state-changing операции —
через `/api/v1/changes` (ChangeSet: validate → apply → confirm/rollback). UI
слушает SSE (`/api/v1/events/stream`) с `Last-Event-ID` + `Last-Event-EPoch`.

## Fallback

Production UI не подставляет mock-данные. API недоступен → ошибка API и
stale/unavailable состояния. После загрузки UI вызывает `/auth/me`: 401 → форма
входа; 428/первый запуск — admin через setup token. После входа —
overview/topology/devices/services/routes/traffic/events/system/revisions + SSE.
`security/audit` загружается только для diagnostician/admin, а `changes` — только
для admin; 403 на дополнительном экране не валит общий dashboard.

Service board строится из текущего конфига и bounded decision cache. Заводского
списка сайтов нет. Карточку можно перетащить между GEO, TSPU и Direct; UI
создаёт, проверяет, применяет и подтверждает ChangeSet.

Статические правила не активируются сами. Администратор выбирает необязательный
шаблон или вводит домен вручную, затем задаёт класс и порядок `direct`,
`zapret`, `smart_dns`, `vless`, `drop`. Тем же редактором меняется автоматически
обнаруженное правило. Порядок сохраняется как `allowed_paths`; небезопасные для
GEO комбинации отклоняются API до apply.

Отключённый IPv6 показывается как необязательное состояние, а не как
предупреждение: отсутствие WAN6 само по себе не означает поломку IPv4 data
plane.

Экран Smart DNS принимает публичные `IP:port`, не показывает resolver как
готовый до route health proof и явно отображает порядок:
`Zapret → Smart DNS → VLESS → Direct` для TSPU и
`Smart DNS → VLESS → DROP` для GEO. Экран VPN содержит пять независимых слотов
подписок и показывает результат проверки каждого объединённого outbound.

Default admin и default password отсутствуют. Installer печатает one-time setup
token только пока администратор ещё не создан. После setup используются данные
созданного владельцем аккаунта; FlintRoute не хранит и не показывает исходный
пароль.

Development simulation — только отдельной командой:

```powershell
.\dist\router-policy.exe serve-dev --listen 127.0.0.1:8787
```

Production `run/serve` использует `OpenWrtProvider` и не выдаёт simulated
topology за реальные данные.

## Безопасность

- Секреты (UUID VPN-серверов, адреса, REALITY-ключи, URL подписки, токены) не
  попадают в UI/SSE/API responses;
- `/api/v1/settings` отдаёт safe projection (secret paths omitted);
- `/api/v1/probes` редактит IP;
- CSRF `X-CSRF-Token` для state-changing `/api/v1/*`;
- non-loopback bind требует явного env guard.

## Размер production build

Последняя проверенная сборка:

```text
index.html  ~0.40 kB
CSS         ~10 kB (gzip ~2.8 kB)
JS          ~45 kB (gzip ~16 kB)
```

Нормально для роутера: статические файлы внутри Go binary.

## Что ещё надо доделать

- Telegram notifications и managed `tg_ws_proxy` runtime; текущий экран только
  честно показывает `not_implemented`;
- реальные edit controls для policies/routes/devices;
- подтверждение опасных операций отдельным modal;
- отдельные состояния disabled/read-only для каждого role-specific control;
- группировка интерфейсов и графики скорости вместо базовой таблицы counters;
- live topology из `ubus`/DHCP leases/wireless clients;
- отображение recovery status (`/api/v1/system`).
