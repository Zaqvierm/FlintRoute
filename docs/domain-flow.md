# Поток домена и трафика

> Соответствует `internal/probe`, `internal/domaincache`, `internal/artifact`,
> `internal/policy` на commit `4634515`.

## Новый DNS-запрос

1. Принять запрос от LAN (53/tcp/udp перехват в nft `rp_dns_redirect`).
2. Проверить корректность имени.
3. Отбросить локальные зоны: `lan`, `local`, reverse DNS, DHCP hostnames.
4. Нормализовать: IDN→ASCII (`idna`), lowercase, без финальной точки.
5. Определить registrable domain через `publicsuffix.EffectiveTLDPlusOne`
   (не «последние две метки» — это ломается на `co.uk`).
6. Проверить ручные политики/overrides (precedence: exact_domain → device_domain
   → device_service → service → category).
7. Проверить известные сервисы (`config.Services`).
8. Проверить TSPU evidence (`tspu.Find`).
9. Проверить domain decision cache (bounded LRU, revision-bound, TTL).
10. Вернуть DNS быстро.
11. Если запись новая/устаревшая — поставить домен в фоновую очередь проверки.

## Неизвестный домен

- если домен не похож на защищённую категорию, первый запрос можно пустить
  напрямую (`policy.unknown_domain_first_path`);
- параллельно — фоновая проверка direct/zapret/smart_dns/VLESS;
- при подтверждённой блокировке — обновить маршрут для следующих соединений;
- существующее TCP-соединение не переносится между маршрутами (новое решение
  применяется к новым соединениям; conntrack purge — только для критических
  переключений).

Для `GEO_LOCKED` прямой маршрут запрещён даже при `UNKNOWN` — нужен ручной
список и fail-closed.

## Полная проверка неизвестного домена

Логика не дублируется по путям:

1. Ручная политика.
2. Сервис и категория.
3. TSPU-списки.
4. Единая очередь кандидатов (`allowed_paths`/category/TSPU).
5. Каждый кандидат → `probe.ProbeRoute(domain, service, route)`.
6. По результату добавлять fallback без повторной сетевой проверки.
7. Сохранить результат каждого пути (bbolt `probes`).
8. Выбрать лучший разрешённый `path_verified` маршрут.
9. Нет безопасного маршрута → DROP/ошибка по политике.

`probe_route` внутри себя ищет и региональный отказ, и признаки ТСПУ. Отдельных
`check_regional_block_*` быть не должно.

## Четыре уровня в потоке домена

1. **DNS resolution** — `resolveForRoute`: какой resolver, протокол, resolved IP,
   safe/unsafe. A/AAAA отдельно.
2. **Классификация** — `probeOne`: HTTP/content/regional/TSPU markers.
3. **Фактический egress** — `probeExternalIP`: hash + country consensus.
4. **Доказательство маршрута** — bound path proof; без него → `UNVERIFIED`,
   маршрут не выбирается и nft set не обновляется.

## Обновление маршрута

Через транзакцию адаптера, не ad-hoc:

1. `validate` candidate → `config.Validate()` → canonical SHA-256.
2. `artifact.Generate` — nft/dnsmasq/Xray/nfqws/IP plan, manifest v6.
3. `SnapshotCurrent` → `ApplyCandidate` (routes → rules → fw4, start services).
4. `VerifyManagementPath` + `VerifyDataPlane` (4 уровня).
5. OK → `Commit` (promote bbolt); не OK → `Rollback` (restore snapshot).
6. Post-reboot — `Reconcile` восстанавливает committed dataplane.

Не `fw4 restart` без необходимости. Только project-owned targets.

## Привязка домена к трафику

FlintRoute перехватывает DNS, сохраняет `domain → IP` с TTL/provenance/service
bundle, атомарно обновляет nft sets. Марка — только пакетам к IP из конкретного
bundle и только по разрешённым протоколам.

- TTL не растягивается бесконечно;
- A и AAAA ведутся независимо;
- shared IP для bundles с несовместимыми маршрутами → collision guard fail-closed
  (`DOMAIN_IP_POLICY_COLLISION` drop);
- DoH/DoT/QUIC, обходящие контролируемый DNS, блокируются политикой или
  обрабатываются доказанным путём;
- существующий conntrack flow не переносится между маршрутами посреди сессии.

## IPv6

Либо полноценный, либо отключённый для защищённых категорий. Минимум: отдельные
`ip6`/`inet` sets, DHCPv6/RA отдаёт Flint 2 как DNS, DoT/DoH блок по IPv6,
policy routing для IPv6, `GEO_LOCKED` не утекает через AAAA. Полувключенный IPv6
— дырка, не фича.

## QUIC / UDP 443

- `GEO_LOCKED`: UDP/443 только через TProxy/VLESS или DROP;
- `TSPU_RESTRICTED`: можно блокировать UDP/443 → клиент откатится на TCP
  (Zapret preset: UDP 443 → DROP);
- `DIRECT_ONLY`: не трогать без причины;
- игры: не применять грубую блокировку глобально.