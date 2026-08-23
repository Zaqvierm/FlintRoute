# Установка на OpenWrt

> **Статус на `effa938`:** это процедура и safety-gate. Установка на Flint 2
> в этом цикле не выполнялась; старые deployment PASS не наследуются.

FlintRoute устанавливается из готового Linux arm64-архива. На роутере не нужны Go,
Node.js, npm, Git или отдельный `coreutils-stat`: сборка и упаковка выполняются
на рабочем компьютере, а проверки mode/owner используют штатные BusyBox
`ls`/`awk`. После запуска control plane Xray, Zapret и TG WS Proxy можно
установить из Web UI через Component Manager. Он использует только закреплённые
release assets и проверяет SHA-256 до установки.

Код не проверяет, что устройство обязательно является GL.iNet Flint 2. При этом
factory config, пути хранения и опубликованное аппаратное evidence рассчитаны на
GL-MT6000. Установка на другой OpenWrt target требует отдельного профиля,
совместимой архитектуры CPU и собственной аппаратной приёмки.

## Сборка пакета

На Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-go.ps1
```

Скрипт использует Git Bash с GNU tar, gzip и `sha256sum` для воспроизводимой
упаковки.

На Linux или в Git Bash:

```sh
sh scripts/build-go.sh
```

Готовый пакет находится в `dist/flintroute-openwrt-arm64.tar.gz`. Внутри есть
`SHA256SUMS`; installer проверяет все файлы до изменения системы.
Упаковка нормализует порядок, timestamps, owner/group и gzip header, поэтому две
сборки из одинакового дерева дают одинаковый SHA-256 архива.

Listener по умолчанию устанавливается как loopback-only в
`/etc/router-policy/config/listener.conf`. При upgrade существующий regular file
сохраняется; symlink вместо listener config отклоняется.

## Первая установка

Скопируйте архив на роутер и распакуйте его во временный каталог:

```sh
scp dist/flintroute-openwrt-arm64.tar.gz root@<router-ip>:/tmp/
ssh root@<router-ip>
mkdir -p /tmp/flintroute-install
tar -C /tmp/flintroute-install -xzf /tmp/flintroute-openwrt-arm64.tar.gz
cd /tmp/flintroute-install
```

Сначала выполните read-only проверки:

```sh
sh install.sh --diagnose
sh install.sh --dry-run
```

Установка с автозапуском control plane:

```sh
sh install.sh --install --enable-services
```

Команда устанавливает ARM64-бинарник, OpenWrt adapter, init-скрипты и hotplug
hooks. DNS observer, `router-policy`, boot guard и watchdog включаются для
следующей загрузки; control plane и watchdog запускаются сразу. Одноразовый
observer bootstrap выполняется до штатного dnsmasq и не перезапускает DHCP/DNS
в конце загрузки. Xray и nfqws не включаются вслепую: ими управляет
подтверждённая dataplane-транзакция.

Установщик также ставит `scripts/calibrate-zapret.sh` и
`scripts/quick-zapret-check.sh`. Заводского домена для
`blockcheck` нет: после установки калибровка имеет состояние
`pending-observed-domain`. Runner принимает только фактически замеченный
TSPU-домен, по умолчанию работает как dry-run, хранит максимум три
allowlisted-кандидата и не активирует их в обход ChangeSet. Если managed
`router-policy-zapret` уже работает, его остановка требует явного
`--allow-managed-restart`.

Перед первым изменением installer требует доступные `ubus` и procd, отсутствие
активного forwarding boot guard и, для уже запущенного control plane, рабочий
loopback health endpoint. Каждый вызов ubus/init ограничен timeout. Провал
preflight останавливает установку до snapshot и записи файлов.
Factory OpenWrt не требует отдельного `coreutils-stat`: режим существующего
regular file проверяется переносимо штатными `ls` и `awk`.
In-place upgrade работающего controller также требует поддержку maintenance
lease установленной версией. Старый controller без этого контракта нужно заранее
явно остановить вместе с watchdog; installer не будет автоматически оживлять
неизвестную legacy-версию.

Installer сохраняет backup и печатает его путь. Если проверка конфига, запуск
сервиса, ожидание `/api/v1/health` или другой шаг завершается ошибкой,
предыдущие файлы и состояния сервисов восстанавливаются автоматически. Строка
`install_rollback=restored` печатается только после подтверждённого service
recovery; частичный откат возвращает ненулевой код и
`files-restored-services-unverified`.
Перед остановкой сервисов или удалением старых targets rollback проверяет hash
архива и требует, чтобы manifest содержал ровно allowlisted файлы и сервисы
FlintRoute. Неизвестная или повреждённая запись блокирует откат без изменений.

Для существующей установки одного HTTP-ответа недостаточно. Installer принимает
перезапущенный controller только при `status=ok`, отсутствии recovery error,
непустой active revision и совпадении с revision, зафиксированной preflight.
Degraded-ответ или смена revision оставляют rollback включённым.

До копирования bbolt installer фиксирует состояния сервисов, включает
maintenance lease, останавливает watchdog и controller. Rollback проверяет, что
оба процесса действительно остановлены, и только потом заменяет файлы. Если
procd не подтверждает остановку, файлы не трогаются, а результат содержит
`blocked-managed-services-still-running`. Это лучше, чем собирать на живом
роутере смесь старой базы и нового бинарника.

Временный boot guard блокирует только пакеты с настроенными марками FlintRoute.
Безусловного drop для всего forwarding и обычного трафика OpenWrt больше нет.

## Обновление

Распакуйте новый пакет в новый временный каталог и снова выполните:

```sh
sh install.sh --install --enable-services
```

Пользовательский `config/default.json`, secrets и persistent state не
перезаписываются. Новый штатный конфиг сохраняется как
`config/factory-default.json`. Обновление перезапускает control plane, ждёт его
health и только после этого возвращает watchdog. Production Xray и Zapret не
перезапускаются; installer проверяет, что их исходное running/stopped состояние
не изменилось.

Сохранённый GL-MT6000 evidence включает повторный clean install, upgrade,
rollback timer, compatible downgrade, uninstall и reinstall/reconcile после
исправления инцидента с потерей procd/ubus. Подробности и границы доказательства
записаны в [`flint2-hardware-report.md`](flint2-hardware-report.md) и
[`incidents.md`](incidents.md). Этот локальный цикл не повторяет hardware pass,
поэтому будущие изменения installer/data plane требуют новой проверки до
unattended production upgrade.

## Что clean install не делает

Первый запуск на пустом state store создаёт committed baseline revision версии
1. Это только control-plane anchor для scheduler/discovery: он не создаёт
ChangeSet/transaction, не вызывает OpenWrt adapter, не запускает Xray/`nfqws` и
не меняет route или flow offloading. Повторный запуск использует тот же baseline;
любое существующее, частичное или повреждённое revision state не
перезаписывается. Observation-only dnsmasq include включает журналирование
запросов в tmpfs, но не добавляет доменные правила и не перехватывает трафик.
На boot include создаётся отдельным ранним init-шагом до запуска dnsmasq.
Baseline first start и observation от LAN-клиента проверены на factory OpenWrt;
повторный reboot пакета после исправления порядка запуска остаётся отдельным
аппаратным gate.

- не устанавливает Xray и `nfqws`;
- не добавляет VPN-подписку и не выбирает production Smart DNS resolver;
- не подтверждает совместимость с произвольным OpenWrt-устройством;
- не включает TG WS Proxy автоматически; managed transport устанавливается и
  настраивается отдельно через Component Manager. `external_socks` остаётся
  Advanced-интеграцией для уже существующего SOCKS5 endpoint. Telegram bot/chat
  настраиваются отдельно после установки.

То есть control plane устанавливается чисто и транзакционно, но полноценные
Zapret/VLESS/Smart DNS маршруты требуют внешних бинарников, пользовательской
конфигурации и route proof. Telegram notifications — отдельная необязательная
подсистема; внешний SOCKS не является зависимостью базового маршрутизатора.

## Удаление

Сначала можно посмотреть план:

```sh
sh uninstall.sh --dry-run
```

Удаление:

```sh
sh uninstall.sh --uninstall
```

Перед удалением создаётся и проверяется архив `/etc/router-policy`. Ошибка
backup останавливает операцию до удаления файлов. Бинарник, init-скрипты,
hotplug hooks, project-owned firewall/DNS artifacts и bound policy routes/rules
удаляются. Исходные persistent UCI-значения flow offloading восстанавливаются
из installation-owned manifest. Uninstaller не делает глобальный `fw4 reload`;
runtime firewall применит эти значения при следующем отдельно контролируемом
reload/reboot. Конфиг, secrets и persistent state остаются в
`/etc/router-policy` и в backup.

## Граница безопасности

Installer не активирует маршруты напрямую. Первое применение dataplane идёт
через ChangeSet: validate, apply, route proof, commit или rollback. Параметры
`install.sh --activate` и `install.sh --rollback` намеренно не обходят эту
транзакцию.
