# API и плоскость управления

> **Статус на `7e7f8bf`:** API-контракт и локальные проверки актуальны. Любые
> аппаратные результаты, упомянутые ниже, относятся к старым SHA и имеют
> `STALE FOR CURRENT SHA`.

> Основная реализация: `internal/api/*`.

## Плоскости

| Плоскость | Содержимое | Состояние |
|---|---|---|
| Представление | Preact/Vite UI встроен в бинарный файл Go | локальная сборка работает |
| Управление | `/api/v1`, auth, ChangeSet, планировщик, `probe_route`, аудит, восстановление | проверено локально |
| Данные | nftables, dnsmasq, fw4, Xray, Zapret, маршрутизация политики | требует диагностики и подтверждения от целевого устройства OpenWrt |

UI никогда не пишет nftables/Xray/dnsmasq/UCI/routes/fw4 напрямую. Любая
state-changing операция идёт через API и ChangeSet.

## Аутентификация

- Default listener `127.0.0.1:8787`. Для доступа из LAN можно явно указать
  адрес самого LAN-интерфейса, например `192.168.0.1:8787`, и установить
  `allow_firewalled_bind=1` в `/etc/router-policy/config/listener.conf`.
  Init-скрипт включает узкий `ROUTER_POLICY_ALLOW_LAN_BIND`; бинарник принимает
  только private unicast-адреса (не wildcard, loopback или link-local).
- Нет default admin password. Первый admin — через one-time setup token.
- Пароли — Argon2id hashes, bounded params, concurrency-limited.
- User/setup файлы — atomic (temp + fsync + rename).
- Session — HttpOnly cookie `rp_session`. JSON login не отдаёт session ID.
- CSRF header `X-CSRF-Token` для state-changing `/api/v1/*`.
- Body limit 1 MiB. Responses несут `request_id` + `X-Request-ID`.
- Session ID, CSRF token, setup token, revision/transaction IDs и имена atomic
  temp-файлов создаются только через проверенный `crypto/rand`; ошибка entropy
  source останавливает операцию.
- Security audit различает loopback, wildcard и non-loopback listeners.
  LAN opt-in не создаёт firewall rule: адрес должен быть точным адресом LAN, а
  входящий TCP/8787 всё равно обязан быть ограничен trusted management subnet
  правилами firewall4. Значение по умолчанию остаётся loopback-only.

## Конечные точки

| Конечная точка | Цель |
|---|---|
| `/api/v1/health` | неаутентифицированный health локального watchdog |
| `/api/v1/auth/login` `setup` `logout` `me` | жизненный цикл сессии |
| `/api/v1/overview` | обзор провайдера |
| `/api/v1/topology` | топология, собранная из ubus, аренды, соседей, мостовой FDB и беспроводных станций; `privacy=hidden` редактирует адреса клиентов |
| `/api/v1/devices` | LAN/гостевые/удаленные клиенты; адреса видны по умолчанию, и `privacy=hidden` удаляет необработанные значения перед сериализацией |
| `/api/v1/services` | сконфигурированные и динамически наблюдаемые сервисы |
| `/api/v1/services/classify` | создание или редактирование правила домена через черновик ChangeSet; необязательный `allowed_paths` сохраняет определенный пользователем резервный порядок |
| `/api/v1/discovery` | текущий режим discovery, лимиты, состояние circuit breaker и suggestions |
| `/api/v1/discovery/configure` | сохранение режима/ограничений обнаружения плоскости управления без изменения плоскости данных; при необходимости сбросить паузу отката |
| `/api/v1/domains` | кэш политики / решения домена |
| `/api/v1/policies` | политика + переопределения |
| `/api/v1/routes` | системный маршрут по умолчанию, дескрипторы управляемых маршрутов и неклассифицированный трафик в виде отдельных записей |
| `/api/v1/components` `/components/{kind}` | состояние установки, версии, службы и health управляемых Xray, Zapret и TG WS Proxy |
| `/api/v1/components/action` | установка, проверка, проверка обновлений, обновление, перезапуск, откат или удаление закрепленного компонента |
| `/api/v1/tgws` | управляемый статус TG WS Proxy без секретного материала |
| `/api/v1/tgws/configure` | создать безопасную конфигурацию, запустить procd, проверить listener/DC и один раз вернуть ссылку клиенту |
| `/api/v1/traffic` | накопленные байты RX/TX, пакеты и ошибки из `/proc/net/dev` |
| `/api/v1/probes` | evidence probes; фильтры `domain`/`service`/`route`/`limit` |
| `/api/v1/route-health` | Матрица работоспособности VLESS, выбранные/резервные/карантинные роли |
| `/api/v1/proxies` | статус сервера proxy/VLESS |
| `/api/v1/diagnostics` | Происхождение диагностики сети (источник/хэш/срок действия/моделирование) |
| `/api/v1/lifecycle` | procd ownership, PID/start time/executable/config и test-run manifests |
| `/api/v1/storage` | storage sizes, rollback state и логические write counters |
| `/api/v1/smart-dns` | отредактированное состояние и резервный порядок Smart DNS |
| `/api/v1/smart-dns/configure` | проверить преобразователь IP/Port по UDP+ TCP DNS и HTTP/TLS, затем создать черновик ChangeSet |
| `/api/v1/zapret` | управляемое состояние Zapret/nfqws И состояние контактов |
| `/api/v1/zapret/setup/check` | проверить закрепленный источник/версию/SHA, двоичный, архитектура, NFQUEUE и nfqws сухой запуск без изменения конфигурации |
| `/api/v1/zapret/setup/activate` | повторите предполет и создайте один управляемый Zapret ChangeSet с включенным маршрутом |
| `/api/v1/zapret/calibration` | ПОЛУЧИТЬ СТАТУС, выполнить ограниченную проверку блока, УДАЛИТЬ отмену и собственную очистку |
| `/api/v1/zapret/adaptive/runtime` | бюджет планировщика производства, отпечатки пальцев и рейтинг в реальном времени |
| `/api/v1/zapret/adaptive/evaluate` | оценка ограниченного профиля и переключатель транзакционного пучка |
| `/api/v1/zapret/adaptive/state` | постоянный активный профиль, перезарядка, PIN-код и состояние карантина |
| `/api/v1/zapret/adaptive/pin` | установите проверенный локальный ручной PIN-код пучка и допустимые запасные варианты |
| `/api/v1/zapret/adaptive/unpin` | снять ручной pin без изменения несвязанных bundles |
| `/api/v1/xray/subscription/secret` | храните до пяти источников подписки, не возвращая их URL |
| `/api/v1/xray/subscription/prepare` | объединить и проверить подписки на VPN; проверка кандидатов предлагает только активацию, явный управляемый режим создает один ChangeSet с режимом, пакетом и маршрутами |
| `/api/v1/xray/manual-servers` | список безопасных метаданных, добавление или удаление внешних границ VLESS вручную; UUID и исходный URI никогда не возвращаются |
| `/api/v1/xray/pool` `/pool/settings` | логические серверы, источники учетных данных, тариф и объяснимая оценка |
| `/api/v1/xray/pool/speedtest` | ограниченное ручное измерение пропускной способности через один проверенный канал обратной связи VLESS SOCKS |
| `/api/v1/routes/revalidate` | вручную запустите одну ограниченную повторную проверку Direct для настроенной службы TSPU/GEO |
| `/api/v1/events` | Персистентная история, объединенная с живой эпохой |
| `/api/v1/events/stream` | Поток SSE |
| `/api/v1/changes` `GET/POST` | список/создание ChangeSet |
| `/api/v1/changes/{id}/{action}` | проверка/применение/подтверждение/откат/удаление |
| `/api/v1/revisions` | фиксированные ревизии + идентификатор активной ревизии |
| `/api/v1/backups` | bbolt резервные метаданные, живой размер, SHA-256 проверить |
| `/api/v1/settings` | безопасная проекция активной типизированной конфигурации (секреты опущены) |
| `/api/v1/security` `/api/v1/security/audit` | аудит безопасности |
| `/api/v1/system` | статус системы/поставщика |
| `/api/v1/telegram` | состояние уведомления без токена или идентификатора чата |
| `/api/v1/telegram/configure` | проверить бота/чат и атомарно сохранить настройки уведомлений |
| `/api/v1/telegram/test` | отправить настоящее тестовое уведомление |
| `/api/v1/external-socks` | внешняя зависимость и статус маршрута |
| `/api/v1/external-socks/check` | TCP/SOCKS5/удаленное соединение/TLS/HTTP предполет без изменений конфигурации |
| `/api/v1/external-socks/activate` | создать один явный ChangeSet для связывания Xray, маршрута и тестового домена |

Конечные точки настройки VLESS и Zapret являются нормальной поверхностью управления, обращенной к пользователю.
`/api/v1/changes` остается механизмом транзакций и продвинутым/разработчиком
интерфейс; пользователям не нужно создавать указатели JSON для любого провайдера.
Обе конечные точки активации создают только черновик. Стандарт
Путь `validate → apply → VerifyManagementPath → VerifyDataPlane → confirm`
по-прежнему является авторитетным; неудачное доказательство откатывает транзакцию назад.

Ручной ввод VLESS использует отдельное секретное хранилище в каталоге состояния Xray.
API принимает URI `vless://`, проверяет поддерживаемые поля транспорта/безопасности,
и сохраняется только сгенерированный исходящий с режимом `0600`. Объявление возвращается безопасным
только метаданные. Подписка и ручные границы объединяются перед тем же
проверка состояния кандидата; добавление ручного сервера не позволяет автоматически включать управляемый
Xray или изменить маршрутизацию.

Конфиденциальность устройства обеспечивается провайдером, а не CSS. Аутентифицированные ответы
показать реальные адреса клиентов по умолчанию. `privacy=hidden` устанавливает необработанный `ip`/`mac` в
`null` и сохраняет маски только в `ip_display`/`mac_display`; скрытые значения
поэтому отсутствует в DOM. UI хранит эти настройки отображения локально.

`/api/v1/lifecycle` различает `router-policy-xray` и штатный OpenWrt-сервис
`xray`. `inactive` у системного сервиса не считается ошибкой, если production
процесс принадлежит FlintRoute procd instance и его полная identity совпадает.
То же правило применяется к `router-policy-zapret` и системным Zapret/nfqws.

Lifecycle/storage endpoints доступны роли diagnostician и выше. Они не
изменяют persistent state. Возвращаются только hashes, размеры, счётчики и
allowlisted metadata; subscription URL, VLESS UUID, rollback capability и auth
tokens не включаются.

Telegram notifications работают отдельно от routing bootstrap; статус строится
по проверенной конфигурации, а не по наличию пути к secret-файлу. Component
Manager управляет OpenWrt package TG WS Proxy, но этот upstream является
server-side MTProxy/WebSocket transport и не притворяется локальным SOCKS5
client. `GET /api/v1/tgws` возвращает состояние без секрета, а
`POST /api/v1/tgws/configure` атомарно создаёт конфигурацию, включает procd и
один раз возвращает клиентскую `tg://proxy` ссылку. Проверяются listener и
доступность Telegram DC; клиентский PASS требует открытия ссылки в Telegram.
`external_socks` остаётся явным Advanced-маршрутом и проверяется до ChangeSet.
Подробности — в
[`telegram-notifications.md`](telegram-notifications.md).

`/api/v1/routes` не называет системный default route управляемым Direct.
Синтетические записи `system_default` и `unclassified` имеют `managed=false`;
настроенный route `direct` имеет `managed=true` и список доменов, для которых
созданы FlintRoute sets/rules. Baseline не создаёт catch-all правило.

Discovery по умолчанию работает в `observe_only`: он только принимает DNS-наблюдения и
не запускает активные route probes. `suggest` сохраняет
классифицированное предложение в bounded RAM cache (до 256 доменов), `locked`
останавливает probe, а
`auto_apply_verified` — узкий route-only writer для уже существующего enabled
route. При зарегистрированном consumer он допускает автоматическое назначение
только после `PathVerified`, service/egress evidence, свободного transaction
slot, rate/circuit-breaker и post-apply proof; consumer меняет лишь
revision-bound exact-owned dnsmasq overlay. Если consumer отсутствует, API
возвращает `route_assignment_runtime_unavailable` и оставляет результат
suggestion. Полный ChangeSet, topology, Xray/Zapret, marks, IP rules и сервисы
из DNS-события не запускаются. Direct/Drop наблюдения автоматически не
закрепляются: блокировка и захват прямого трафика остаются явным действием
администратора.

Смена режима и лимитов Discovery является control-plane настройкой. Она
сохраняется отдельно от route config и не создаёт ChangeSet, не перезапускает
dnsmasq и не трогает data plane.

Успешный Smart DNS preflight сохраняет короткоживущий proof для конкретного
resolver endpoint. Candidate validation и apply требуют непротухший proof;
одинаковый уже активный resolver не блокирует несвязанный ChangeSet.

## ChangeSet

```text
draft -> validated -> prepared -> applying -> verifying
      -> awaiting_confirmation -> committing -> committed
rolling_back -> rolled_back | rollback_failed
failed | expired | requires_device
```

`validate` клонирует active typed config, применяет все операции, запускает
`config.Validate()`, persist полный canonical candidate, SHA-256. Неподдержанные
операции → `draft` + error.

Создание ChangeSet требует непустой список явных операций и текущий
`config_version` из `/api/v1/revisions`. UI не подставляет скрытую операцию или
фиксированную базовую версию.

`apply` создаёт revision/transaction metadata и вызывает adapter contract:
`Подготовить → ValidateCandidate → SnapshotCurrent → ApplyCandidate →
VerifyManagementPath → VerifyDataPlane`. `SKIPPED`/`UNVERIFIED` →
`requires_device`.

Для обычного LAN-запроса `POST .../apply` автоматически формирует подписанный
management proof из фактических remote/local адресов HTTP-соединения,
LAN-интерфейса и подсети. Необязательное поле `management_mode` принимает `lan`
(значение по умолчанию) или `headless`. В headless-режиме proof сначала выдаётся
локальной CLI из активной SSH-сессии; apply только проверяет его и расширяет
окно отката.

`confirm` вызывает `Adapter.Commit` только после обоих verification flags, expiry,
candidate hash, adapter revision match и повторной проверки management proof.
LAN confirm должен прийти через тот же интерфейс и подсеть. Headless confirm
требует явное `{"management_mode":"headless"}` и loopback API. Proof от другой
revision/transaction, прошлого boot или с истёкшим TTL отклоняется.

## SSE

```text
id: 12
event: change.created
data: {"id":12,"time":"...","type":"change.created",...}
```

Каждый event + header несёт process-unique stream epoch. Клиенты шлют
`Last-Event-ID` + `Last-Event-EPoch`; после restart mismatched epoch сбрасывает
in-memory replay. `/api/v1/events` читает prior epochs из bbolt. HTTP server без
global WriteTimeout — SSE не режется после 60 секунд.

События: `system.start`, `admin.login`, `route.decision`, `security.guard`,
`change.created`, `change.validated`, `change.awaiting_confirmation`,
`change.committed`, `change.rolled_back`. Параллельные потоки — ограничены.

## Восстановление (P6)

При старте сервера `recoverCommittedDataplane` восстанавливает committed
dataplane через `adapter.Reconcile(RecoveryTarget)` и проверяет bindings через
`adapter.Status`. Результат — в `meta/recovery_status` (bbolt) и отражается в
`/api/v1/system`. См. `adapter-transaction.md`.

## Модель правды поставщика OpenWrt

Производство использует фиксированную команду, только для чтения провайдера OpenWrt. `ubus`/`ip`/`uci`/
`/proc`/`/sys`/`fw4`/`nft`/DHCP leases/process state — без shell fragments из HTTP.
Каждый ответ несёт source, collection time, freshness/status, `simulation=false`.
Missing/malformed → unavailable; production не подставляет dev-mock.
Устройства моделирования никогда не получают сфабрикованную идентификацию RAW, даже когда раскрывается
запрошено. `simulation=true` не принимается в качестве доказательства развертывания.

Provider доказывает observed config/process state. Он не превращает HTTP 200 или
имя route в route evidence. Direct/Zapret/Smart DNS/VLESS остаются `UNVERIFIED`
пока probe result не bound к active adapter revision + packet/route evidence.

## Четыре уровня в API

API/SSE/ChangeSet отдаёт route evidence по тем же четырём уровням, что probe:
DNS resolution, классификация, фактический egress, доказательство маршрута.
`/api/v1/probes` и `/api/v1/route-health` несут `path_verified`,
`adapter_revision`, `candidate_hash`, `external_country`, `egress_consensus`.

## Пределы тока

- Provider fixture-tested; сохранённое hardware evidence относится к активному
  Flint 2 dataplane. Код не блокирует другие модели по имени, но их
  совместимость не доказана.
- Zapret/Xray `NOT_CONFIGURED` на устройстве без бинарника.
- Direct/Zapret/Drop/VLESS и два Smart DNS resolver ранее доказаны на Flint 2;
  factory config намеренно не содержит resolver endpoints.
- External bind проверен за source-restricted firewall rule. TLS termination
  пока не встроен; для недоверенной сети нужен reverse proxy/VPN.
- Telegram delivery и внешний SOCKS endpoint требуют аппаратной проверки с
  пользовательскими credentials; собственный TGWS transport не поставляется.
- Роли кроме admin.
