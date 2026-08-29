# Headless-плоскость данных

> **Статус на `7e7f8bf`:** contract и mock/CI проверки актуальны; реальный
> OpenWrt dataplane текущего SHA не устанавливался и не проверялся.

P3.1 владеет прозрачными процессами Xray и Zapret; сам факт наличия binary не
доказывает рабочий route. Оба процесса запускаются project procd services и
участвуют в одной snapshot/apply/verify/rollback-транзакции с nftables, dnsmasq и
policy routing.

## Xray

Managed mode включается явно:

- binary: `/usr/bin/xray`;
- service: `/etc/init.d/router-policy-xray`;
- active config: `/etc/router-policy/xray/active.json`;
- command: `xray run -config /etc/router-policy/xray/active.json`.

`candidate_only` генерирует и проверяет конфигурацию, но запрещает transparent
activation. `managed` разрешает deploy только если IP plan содержит TPROXY
route/rule, построенные по live non-simulated diagnostics.

## Zapret

Репозиторий не содержит nfqws. Установка должна предоставить совместимый Linux
arm64 binary `/usr/bin/nfqws`. Первый hardware syntax gate использовал официальный
Zapret v72.12 arm64 build; release archive и binary не входят в проект или
transaction bundle.

Candidate содержит только проверенный preset:

- service: `/etc/init.d/router-policy-zapret`;
- active config: `/etc/router-policy/zapret/nfqws.conf`;
- NFQUEUE: `200`;
- strategy ID: `tls-fake-ttl3-v1`;
- TCP 80: `fake,fakedsplit`;
- TCP 443: `fake`, `ttl=3`, rewrite TTL первого original packet (`orig-ttl=1`, `s1..d1`);
- UDP 443: DROP, чтобы следующий запрос пошёл через nfqws по TCP.

Произвольные nfqws arguments из user config запрещены. Adapter копирует candidate
в transaction directory, добавляет `--dry-run` и запускает тот же binary до
изменения active file/rule. В nft queue rule нет `bypass`: при падении nfqws
matching traffic fail-closed, а не уходит Direct.

## Порядок транзакции

Для enabled managed route adapter:

1. проверяет generated artifacts и binary dry-run;
2. снимает snapshot active config и exact project-service state;
3. атомарно устанавливает active configs;
4. запускает/перезапускает нужные project services;
5. применяет IP routes/rules, затем nftables и dnsmasq;
6. выполняет transaction-bound verification;
7. commit либо сначала возвращает старый firewall/config, затем service state и routes/rules.

Процессы стартуют до queue/TPROXY rules, чтобы правило не ссылалось на отсутствующий
consumer. Restore идёт в обратном порядке. Installer устанавливает init scripts,
но пока не включает их на boot без validated transaction; durable enablement и
recovery после reboot относятся к отдельному hardware gate.

## Доказанная граница

Local unit/race/mock OpenWrt tests покрывают generation, порядок, failure и
rollback. Ранее на Flint 2 nfqws config прошёл `--dry-run`, а table — `nft -c`;
это были только temporary files. Persistent install, procd lifecycle, counters,
route proof, management survival и rollback на роутере остаются обязательными
hardware gates.
