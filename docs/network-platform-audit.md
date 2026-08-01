# Сетевые параметры и платформенная граница

Этот аудит описывает исполняемый код текущей ветки. Он не объявляет generic
OpenWrt поддерживаемым: единственная завершённая аппаратная приёмка пока
относится к GL-MT6000.

## Убранный production-хардкод

| Место | Было | Теперь |
|---|---|---|
| `platform.collectOpenWrtSnapshot` | только logical interfaces `lan`, `wan`, `wan6` | полный `ubus call network.interface dump`; WAN определяется по main default route, LAN — по активным адресованным интерфейсам без default route |
| `platform.Topology` | эвристика `br-lan`, `lan*`, `wlan*`, `br-guest`, `br-iot` | фактические UBUS interfaces, route devices и wireless interface inventory |
| `managementproof.IssueAutomatic` | только `lan`/`br-lan` и выдуманный client IP — первый адрес подсети | реальные interface addresses, default routes и reachable neighbor table; без наблюдаемого клиента proof не выдаётся |
| hotplug `95-router-policy` | события только `wan`/`wan6` | любое валидное logical interface событие `ifup`/`ifupdate`; reconcile идемпотентен |
| read-only diagnostics | отдельные вызовы `network.interface.lan/wan/wan6` | `network.interface dump` |
| packaged target | `glinet-flint2` | нейтральный `openwrt`; старое значение продолжает читаться |
| storage/catalog validation | safety checks только при имени `glinet-flint2` | одинаковые production-инварианты для `openwrt` и совместимого legacy target |
| dnsmasq bootstrap fixture | статические реальные домены | пустой bootstrap; домены появляются только из committed revision |

В tracked production-файлах не найдено адресов среды разработки
`192.168.0.93`, `192.168.0.1`, `192.168.0.0/24`, `192.168.1.0/24` или
`192.168.8.0/24`. Go regression test сканирует production Go, shell, JSON и UI
sources и запрещает новые RFC1918 literals вне узкого allowlist.

## Допустимые константы

| Значение | Категория | Почему оставлено |
|---|---|---|
| `127.0.0.1` и loopback listeners | protocol/security constant | control plane, Xray SOCKS и `external_socks` намеренно локальны; endpoint извне запрещён |
| `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `172.16.0.0/12`, `192.168.0.0/16` и прочие bogon ranges | protocol constants | Smart DNS и generated nft collision guard обязаны отбрасывать private/bogon resolver results |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` | test/documentation fixtures | IANA documentation networks, не адреса реального окружения |
| `1.1.1.1:53` | безопасное значение по умолчанию | публичный probe resolver; это не management address и не Smart DNS route placeholder |
| route tables `100..102`, marks и NFQUEUE `200` | configurable namespace defaults | проверяются на конфликты и входят в canonical config/artifact manifest |
| `/sbin/ip`, `/bin/ubus`, `/sbin/uci`, `/usr/sbin/nft`, `/sbin/fw4` | OpenWrt runtime contract | фиксированные command paths исключают shell injection; наличие проверяется диагностикой |

## Откуда берётся сеть

- logical interfaces, address families и DNS: `ubus network.interface dump`;
- default gateway и WAN device: IPv4/IPv6 main routing table через `ip -j route`;
- links, bridge membership, counters и carrier: `ip -j link` и UBUS device status;
- management client: HTTP/SSH socket endpoints плюс фактический neighbor table;
- DHCP clients: dnsmasq/odhcpd leases и neighbor table; UBUS wireless inventory
  используется только для классификации интерфейсов, не как полный station list;
- firewall zones: UCI diagnostics. FlintRoute пока не строит автоматическую
  policy из произвольной zone topology — это остаётся блокером generic OpenWrt;
- marks, routing table IDs, NFQUEUE и local listener ports: canonical config,
  с collision validation до generation/apply.

Разные IPv4 и IPv6 WAN devices сейчас отклоняются как `UNVERIFIED`: artifact
contract имеет один authoritative WAN interface. Это честный fail-closed, а не
поддержка произвольного multi-WAN.

## Карта зависимости от GL.iNet

| Место | Зависимость | Категория | Поведение без GL.iNet | Решение |
|---|---|---|---|---|
| README и hardware docs/runners | имя Flint 2/GL-MT6000 | документация/evidence | runtime не меняется | оставить как область фактически пройденной приёмки |
| legacy `platform.target=glinet-flint2` | строка старых revisions | compatibility metadata | конфиг валиден | принимать, новые установки используют `openwrt` |
| `/etc/glversion`, `/etc/glinet/*` в diagnose script | vendor release metadata | optional integration | файлы пропускаются | оставить как необязательную диагностику |
| UBUS `system`, `network.interface`, UCI, procd, fw4, nftables, dnsmasq | стандартные OpenWrt interfaces | обязательная runtime-зависимость | без них provider/apply fail closed | не является GL.iNet-specific |
| uhttpd probe | стандартный OpenWrt admin HTTP, optional | optional integration | отсутствие не блокирует headless proof | имя GL.iNet удалено из диагностики |
| package/build | Linux arm64 | критический блокер других архитектур | готового install artifact нет | добавить target matrix на следующем этапе |
| hardware acceptance | только GL-MT6000/OpenWrt 24.10.4 | критический блокер заявления generic support | совместимость неизвестна | прогнать clean install и recovery matrix на других boards |

## Блокеры generic OpenWrt

1. Готовый пакет собирается только для Linux arm64; нет package/architecture matrix.
2. Не доказана работа installer/procd/fw4/dnsmasq contracts на других версиях
   OpenWrt и package layouts.
3. Произвольные firewall zone names и несколько WAN видны диагностике, но ещё
   не имеют отдельной пользовательской policy/mapping model.
4. Раздельные IPv4/IPv6 WAN и weighted/failover multi-WAN не поддерживаются
   artifact schema и поэтому закрываются как `UNVERIFIED`.
5. Gatewayless point-to-point default routes пока не могут сформировать
   authoritative gateway proof и закрываются как `UNVERIFIED`.
6. Vendor GUI/update/backup interactions вне GL-MT6000 не проверены.
7. Нет аппаратных clean-install, rollback, reboot и recovery evidence на других boards.

Следующий платформенный этап должен вынести эти различия в явный capability
profile/adapter и расширить acceptance matrix. До этого формулировка остаётся
простой: код использует стандартные OpenWrt primitives и больше не требует имя
модели Flint 2, но generic OpenWrt support не доказан.
