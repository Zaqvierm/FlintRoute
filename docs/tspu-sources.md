# Источники списков TSPU

> Основные реализации: `internal/tspu/tspu.go`, `config.TSPUSource`.

## Вывод

В коде есть два реально настроенных доменных источника. Они не являются
доказательством блокировки сами по себе: список только добавляет
классификационное evidence, после чего кандидат обязан пройти `ProbeRoute` и
полный `PathVerified`.

Фактический приоритет данных в планировщике:

1. Ручной override пользователя.
2. Известная запись `config.Services`.
3. Совпадение локального TSPU-кеша (`tspu.Find`), если кеш валиден и не
   истёк; устаревшее совпадение явно помечается `STALE_MATCH`.
4. Если совпадения нет или кеш недоступен — обычная классификация и route
   probes. Никакой внешний список не подменяет результат проверки пути.

## Источники

### Re:filter
https://github.com/1andrevich/Re-filter-lists — доменные списки, IP-списки,
`geoip.dat`/`geosite.dat`, `domains_all.lst`, `ipsum.lst`. Ближе всего к обходу
ограничений в РФ, регулярные releases. Минус: внешний проект, IP-часть опасна
из-за CDN, нужны ручные исключения.

### allow-domains
https://github.com/itdoginfo/allow-domains — RAW-листы, SRS/MRS/JSON/DAT/geosite.
Удобно для dnsmasq/nftset. Минус: реальные false positives, нужно фиксировать
URL/релиз и валидировать формат.

### Antifilter
`antifilter.download` рассматривается только как возможный будущий источник
исследований. В текущем `config/default.json` он **не настроен** и в runtime
не загружается. IP-ориентированный источник нельзя silently добавить в
классификацию: общие CDN дают слишком много ложных срабатываний.

## Конфигурация (`config.TSPUSource`)

```json
{
  "name": "refilter",
  "type": "domains",
  "url": "https://...",
  "min_entries": 100,
  "max_drop_ratio": 0.25
}
```

- `name`: `[A-Za-z0-9_-]{1,64}`, уникальный.
- `type`: только `domains`.
- `url`: только `https`, без credentials/fragment, редиректы только `https` (≤3).
- `min_entries`: отказ при слишком малом числе записей.
- `max_drop_ratio`: отказ при резком проседании (`(old-new)/old`).

## Обновление (`tspu.UpdateWithPrevious`)

1. Conditional fetch: `If-None-Match`/`If-Modified-Since` от предыдущего
   `SourceReport`. `304` → `NotModified`, домены из предыдущего кеша.
2. Размер ответа ≤ `policy.max_tspu_list_bytes` (`+1` проверка).
3. `ParseDomains`: stripping `||`/`^`/`.` , IP-line → второе поле, отбрас `/:@?`,
   IDN-нормализация, public-suffix проверка.
4. `min_entries` / `max_drop_ratio` gates; при отказе → `retainPrevious`.
5. `BuildCache`: `Entry` с `Provenance`/`MatchType`/`Confidence`, `finalizeCache`
   считает SHA-256.
6. `FreshSources == 0` → error, previous cache retained.
7. `Save`: atomic, current → `.previous` (только если текущий валиден).

## Внутренний формат (Cache v2)

См. `tspu-cache.md`. Ключ — нормализованный pattern (`suffix` eTLD+1 или
`wildcard` `*.example.com`). `SourceReport` несёт `etag`/`last_modified`/
`drop_ratio`/`confidence`/`fresh`/`retained_previous`.

## Форматы для data-plane

Для dnsmasq (генерируется `artifact.renderDNSMasq`):

```conf
nftset=/example.com/4#inet#router_policy#svc_<id>_v4
nftset=/example.com/6#inet#router_policy#svc_<id>_v6
```

Для nftables IP CIDR (генерируется `artifact.renderNFT`):

```nft
add element inet router_policy svc_<id>_v4 { 203.0.113.0/24 timeout 12h }
```

Это пример формата, не команда для текущей машины.

## Фактическое использование на `effa938`

- В `config/default.json` настроены `refilter-domains` и
  `allow-domains-raw`. Другие источники из этого документа не активны по
  умолчанию.
- `internal/tspu/refresh.go` вызывает `UpdateWithPrevious`, сохраняет кеш
  атомарно и оставляет предыдущий валидный кеш при ошибке. Планировщик
  (`runTSPUScheduler`) использует expiry кеша и интервал из policy, а не
  постоянный 30-секундный опрос.
- `internal/api/discovery_control.go` и `selectVerifiedServiceRoute` читают
  кеш через `tspu.Load`/`tspu.Find`; `internal/planner` передаёт результат как
  классификационное поле `TSPUResult`.
- `TSPU_MATCH` не выбирает маршрут автоматически. При совпадении он может
  поставить Zapret первым, но выбор всё равно требует успешного probe и
  path proof. При отсутствии безопасного кандидата terminal result —
  `NO_SAFE_ROUTE`, а не «сервис TSPU».
- Аппаратный результат с 86 781 записью из старого Flint 2 отчёта сохранён в
  истории, но **не является PASS для `effa938`** и не должен использоваться как
  текущая проверка.
