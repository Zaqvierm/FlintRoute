# Read-only gate Flint 2 (только чтение)

Это чек-лист, а не installer. Первый проход на железе не должен устанавливать,
перезапускать, перезагружать роутер или менять firewall/routing.

## Перед подключением

- записать точный FlintRoute commit SHA и hash сборки;
- подтвердить независимый recovery path;
- не закрывать текущую management-сессию во время сбора evidence;
- хранить вывод вне роутера и удалить credentials, tokens, UUID и private endpoints.

## Базовая проверка только для чтения

Запустить по заранее разрешённому SSH path и сохранить raw output:

```sh
ubus call system board
ubus call system info
ubus call service list
cat /etc/openwrt_release
uname -a
df -h
free
ps w
```

Зафиксировать ownership процессов FlintRoute, Xray, Zapret/nfqws, dnsmasq,
netifd, procd, ubusd, rpcd, uhttpd/nginx и dropbear. Для каждого PID:

```sh
pid=<pid>
cat /proc/$pid/stat
readlink /proc/$pid/exe
tr '\0' ' ' < /proc/$pid/cmdline; echo
ls /proc/$pid/fd | wc -l
```

Слушатели и sockets только читаются:

```sh
ss -lntup 2>/dev/null || netstat -lntup
ss -tan 2>/dev/null || netstat -tan
```

Текущий dataplane:

```sh
ip -o addr
ip -o rule
ip -o route show table all
nft list ruleset
ubus call network.interface dump
ubus call dhcp ipv4leases
ubus call network.wireless status
```

## Инвариант прав

До deploy записать numeric mode, owner и group критических parents; если есть
`/rom`, сравнить с ним:

```sh
for p in / /etc /usr /usr/bin /usr/lib /etc/init.d /etc/hotplug.d; do
  stat -c '%a %u %g %n' "$p"
done
for p in / /etc /usr /usr/bin /usr/lib /etc/init.d /etc/hotplug.d; do
  [ -e "/rom$p" ] && stat -c '%a %u %g %n' "/rom$p"
done
```

Отсутствующий или подозрительный parent блокирует deploy. Автоматически его не
чинить и не перезагружать роутер «для проверки».

## Resource baseline

Два одноминутных sample без генерации трафика:

```sh
top -bn1 2>/dev/null || top -n 1
cat /proc/loadavg
cat /proc/stat | head -n 1
```

Сохранить CPU FlintRoute, число threads, открытые FD, established loopback
sockets и число активных probes. После deploy не должно быть необъяснимого роста
в idle.

## Граница deploy

Только после проверки baseline можно планировать deploy. После установки вручную
повторить permission loop и подтвердить те же modes до любого reboot. Reboot —
отдельный gate и запрещён, пока не записаны permission checks и доказательства
management/data-plane.
