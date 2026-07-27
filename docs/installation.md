# Установка на OpenWrt

FlintRoute устанавливается из готового ARM64-архива. На роутере не нужны Go,
Node.js, npm, Git или отдельный `coreutils-stat`: сборка и упаковка выполняются
на рабочем компьютере, а проверки mode/owner используют штатные BusyBox
`ls`/`awk`. Xray и совместимый `nfqws` устанавливаются отдельно до первой
dataplane-транзакции.

## Сборка пакета

На Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-go.ps1
```

На Linux или в Git Bash:

```sh
sh scripts/build-go.sh
```

Готовый пакет находится в `dist/flintroute-openwrt-arm64.tar.gz`. Внутри есть
`SHA256SUMS`; installer проверяет все файлы до изменения системы.

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
hooks. `router-policy`, boot guard и watchdog включаются для следующей загрузки;
control plane и watchdog запускаются сразу. Xray и nfqws не включаются вслепую:
ими управляет подтверждённая dataplane-транзакция.

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

Текущий Alpha package после этих изменений ещё не прошёл повторный аппаратный
upgrade. Предыдущая попытка потеряла procd/ubus и закончилась U-Boot recovery;
подробности и ограничения записаны в [`incidents.md`](incidents.md). До нового
hardware pass команды выше считаются процедурой проверки, а не рекомендацией
для unattended production upgrade.

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
hotplug hooks и project-owned firewall/DNS artifacts удаляются; конфиг,
secrets и persistent state остаются в `/etc/router-policy` и в backup.

## Граница безопасности

Installer не активирует маршруты напрямую. Первое применение dataplane идёт
через ChangeSet: validate, apply, route proof, commit или rollback. Параметры
`install.sh --activate` и `install.sh --rollback` намеренно не обходят эту
транзакцию.
