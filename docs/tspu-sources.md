# Источники списков TSPU

> Основные реализации: `internal/tspu/tspu.go`, `config.TSPUSource`.

## Вывод

Один источник брать нельзя. Каскадная модель (приоритет сверху):

1. Ручные правила пользователя.
2. Статические сервисные группы проекта (`config.Services`).
3. Re:filter — основной доменный источник для ограниченных ресурсов.
4. allow-domains — дополнительный доменный источник и готовые форматы.
5. Antifilter/IP lists — вспомогательный (IP/CDN дают ложные срабатывания).

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
https://antifilter.download/ — IP/подсети заблокированных ресурсов. Полезен как
дополнительный сигнал. Минус: IP-ориентированный подход цепляет общие CDN, не
годится как единственный доменный источник.

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

## Проверенное состояние

Control plane обновляет кеш по расписанию. Первый запуск выполняется примерно
через 30 секунд, успешные обновления повторяются по настроенному интервалу, а
ошибки используют ограниченный exponential backoff с jitter. Ошибка загрузки,
валидации или записи не заменяет последний валидный кеш.

На Flint 2 автоматическое обновление приняло оба настроенных HTTPS-источника и
собрало 86 781 уникальную запись. Переданный с роутера кеш совпал по SHA-256.
Контрольный Direct-набор (`yandex.ru`, `vk.com`, `ozon.ru`, `gosuslugi.ru`,
`mail.ru`) дал 5/5 `NO_MATCH`, а TSPU-набор (`discord.com`, `signal.org`,
`instagram.com`, `facebook.com`, `x.com`) — 5/5 `MATCH`.

Сводный список также содержит часть GEO-ограниченных сервисов. Это лишь сигнал
для классификации: сервисная политика с `forbidden_paths: [direct, zapret]`
остаётся приоритетнее и не позволяет отправить GEO-сервис через Zapret.
