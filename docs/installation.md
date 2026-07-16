# Установка на OpenWrt

FlintRoute устанавливается из готового ARM64-архива. На роутере не нужны Go,
Node.js, npm или Git: сборка и упаковка выполняются на рабочем компьютере.

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

Installer сохраняет backup и печатает его путь. Если проверка конфига, запуск
сервиса или другой шаг завершается ошибкой, предыдущие файлы и состояния
сервисов восстанавливаются автоматически.

## Обновление

Распакуйте новый пакет в новый временный каталог и снова выполните:

```sh
sh install.sh --install --enable-services
```

Пользовательский `config/default.json`, secrets и persistent state не
перезаписываются. Новый штатный конфиг сохраняется как
`config/factory-default.json`. Уже работающие сервисы перезапускаются после
проверки новой версии; при ошибке возвращаются предыдущие файлы.

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
