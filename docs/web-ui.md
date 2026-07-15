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

## Экраны (`Content` в `ui/src/main.tsx`)

- вход (`LoginScreen`);
- первичная настройка (`SetupScreen`);
- обзор (`OverviewScreen`);
- карта сети (`NetworkMap`, topology);
- устройства (`Devices`, `DeviceCard`);
- сервисы (`Services`, `ServiceGroup`);
- политики (таблица/доска, `Policies`);
- очередь изменений (`Changes`, refresh);
- маршруты (`Routes`, `Vless`, `RouteType`);
- Smart DNS, Zapret, Telegram;
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
overview/topology/devices/services/routes/events/security/system/changes + SSE.

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
CSS         ~5–6 kB
JS          ~29–30 kB (gzip ~11 kB)
```

Нормально для роутера: статические файлы внутри Go binary.

## Что ещё надо доделать

- реальные edit controls для policies/routes/devices;
- подтверждение опасных операций отдельным modal;
- роли кроме admin;
- отображение реальных counters из OpenWrt adapter;
- live topology из `ubus`/DHCP leases/wireless clients;
- отображение recovery status (`/api/v1/system`).
