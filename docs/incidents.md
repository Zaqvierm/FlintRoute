# Инциденты и дефекты аппаратной проверки

Это краткий русский журнал ошибок, найденных при hardware/recovery review.
Никакая запись ниже не означает hardware PASS для текущего SHA: доказательство
должно быть привязано к commit, firmware и сохранённому raw output.

## Правила чтения журнала

- факт, гипотеза и исправление разделены;
- старое hardware evidence помечается `STALE FOR CURRENT SHA` после изменения
  production-кода;
- reboot, install и apply нельзя использовать как «диагностику на удачу»;
- после любого опасного сбоя сохраняются backup, process list, permissions,
  nft/route state и доступ к recovery.

## Сводка инцидентов

| Дата | Инцидент | Главный риск | Результат |
|---|---|---|---|
| 2026-08-17 | startup recovery превысил installer health window | сервисы могли быть объявлены готовыми слишком рано | readiness и recovery разделены; старое evidence stale |
| 2026-08-17 | clean baseline не имел источника DNS observation | discovery не видел LAN-запросы | источник логов проверяется отдельно от UI |
| 2026-08-01 | upgrade переписал committed legacy route в памяти | control plane и dataplane расходились | upgrade обязан строить состояние из durable revision |
| 2026-07-27 | rollback external listener не был armed | незащищённое окно после сбоя | rollback capability проверяется до изменения listener |
| 2026-07-27 | factory adapter потерял management при recovery | router UI/SSH могли исчезнуть | management proof стал обязательным gate |
| 2026-07-27 | uninstall имел гонку готовности DNS | сеть оставалась в полуготовом состоянии | dnsmasq readiness проверяется до завершения операции |
| 2026-07-22 | неудачный P14 upgrade оставил procd/ubus недоступными | management plane мог не подняться после reboot | rescue и cold-boot checks обязательны |
| 2026-07-18 | lifecycle sandbox управлял реальными services | тест менял production | тестовые ownership namespace и mock tree отделены |
| 2026-07-19 | recursion gate читал неправильное transport field | проверка маршрута давала ложный PASS | schema и transport mapping типизированы |
| 2026-07-19 | timer runner использовал file schema version | rollback timer мог работать с неверной схемой | runtime timer version отделена от file version |
| 2026-07-19 | rollback терял эквивалентные default routes | direct path мог пропасть или измениться | route identity учитывает все равные маршруты |
| 2026-07-19 | Smart DNS path одновременно разрешался и запрещался | UI показывал зелёный check при failed apply | resolver check, config save, dnsmasq и dataplane разделены |
| 2026-07-19 | backup metadata существовала без backup file | recovery считался доступным без файла | hash и наличие backup проверяются вместе |
| 2026-07-19 | state rescue предполагал `nohup` | rescue мог не стартовать на OpenWrt | запуск проверяет реальный process state |
| 2026-07-19 | protocol matrix повторно использовала HTTPS evidence | UDP/TCP proof был ложным | для каждого протокола требуется собственный evidence |
| 2026-07-19 | scoped Zapret profile терял pre-SNI setup | стратегия считалась применённой без нужной подготовки | setup, interception и request path проверяются отдельно |
| 2026-08-09 | upgrade остановился на повторном procd delete | idempotency lifecycle нарушалась | повторное удаление чужого service не разрешено |
| 2026-08-09 | dnsmasq упал при изменении control-plane settings | пользователь терял DNS | change проходит readiness и rollback gate |
| 2026-08-17 | DNS observer поздно перезапускал DHCP/DNS | boot recovery менял чужой service | observer только сообщает событие, controller решает drift |

## Критические уроки

### Rollback не должен менять права ОС

Synthetic staging, созданный под `umask 077`, нельзя архивировать вместе с
родительскими каталогами и извлекать в `/`. Installer хранит mode/uid/gid только
для allowlisted объектов, восстанавливает их в private directory и проверяет
критические parents до операции. Ошибка preflight блокирует deploy, а не чинит
систему вслепую.

### Recovery не равен process liveness

Живой procd/nginx или HTTP `2xx` не доказывает согласованность bbolt, adapter и
dataplane. Для PASS нужны active revision, generation, marks, services и
management proof. Неоднозначность означает `RECOVERY_REQUIRED` и fail-closed
guard.

### Наблюдение не должно запускать нагрузочный тест

`observe_only` только сохраняет observation. Discovery queue ограничена, route
probe budget общий, а VLESS health и revalidation имеют независимые редкие
расписания. Нельзя превращать DNS traffic домашней сети в бесконечный fan-out.

### Аппаратные записи стареют

Результат Flint 2 от старого SHA полезен как история инцидента, но не является
подтверждением нового кода. В evidence всегда указываются exact SHA, firmware,
команда, raw-log path, digest, дата и уровень PASS/FAIL/SKIP.

## Текущий статус

На code head `effa938cf67a7fb3c6013982995b287e22228831` локальные и Linux CI
gates записаны в `docs/remediation-evidence.md`; последующий docs-аудит не меняет
production-код. Flint 2 в этом цикле не трогался; hardware status —
`NOT RUN / STALE`.
