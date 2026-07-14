# TSPU Cache And Evidence

> Соответствует `internal/tspu/tspu.go` на commit `4634515`.

## Назначение

TSPU cache — это evidence для упорядочивания кандидатов, а не отдельный route
probe. Он не дублирует `probe.ProbeRoute`.

```text
domain -> service lookup -> TSPU evidence -> candidate queue -> probe_route
```

Если домен матчит TSPU evidence, планировщик может поставить Zapret первым через
`policy`/category. Решение «работает ли путь?» всё равно принимает единый probe
результат с path proof.

## Cache v2 (`tspu.Cache`)

```json
{
  "version": 2,
  "sha256": "sha256:...",
  "previous_sha256": "sha256:...",
  "generated_at": "2026-07-14T12:00:00Z",
  "expires_at": "2026-07-14T18:00:00Z",
  "fresh_sources": 2,
  "sources": [SourceReport],
  "entries": { "<pattern>": Entry }
}
```

- `version = CacheVersion = 2`. Legacy v1 кеши мигрируются с проверкой каждого
  паттерна; кривой legacy-вход → `invalid legacy TSPU cache entry`.
- `sha256` покрывает canonical JSON всего кеша (без самого поля `sha256`).
  `decodeCache` перепроверяет хеш при загрузке — mismatch → `TSPU cache hash
  mismatch`.
- `previous_sha256` связывает с предыдущим удачным кешем.
- `fresh_sources` — число источников, отдавших свежие accepted данные.
- Бинарит: `maxCacheBytes = 32 MiB`. Файл должен быть regular, размер >0 и ≤
  лимита, иначе `invalid TSPU cache file`.

### `Entry`

```json
{
  "domain": "youtube.com",
  "match_type": "suffix",
  "source": "refilter",
  "provenance": ["refilter", "antifilter"],
  "confidence": 0.9,
  "first_seen": "2026-07-14T10:00:00Z",
  "last_seen": "2026-07-14T12:00:00Z",
  "expires_at": "2026-07-14T18:00:00Z"
}
```

- `match_type`: `suffix` (exact eTLD+1) или `wildcard` (`*.example.com`,
  только крайняя левая метка). `normalizePattern` запрещает `*` в других местах.
- `provenance` — отсортированный уникальный список источников. `source` =
  `provenance[0]`.
- `confidence` берётся от источника; при нескольких источниках — максимум.

### `SourceReport`

Каждый источник несёт: `name`, `type` (только `domains`), `url`, `final_url`,
`entries`, `previous_entries`, `bytes`, `sha256`, `etag`, `last_modified`,
`accepted`, `fresh`, `not_modified`, `retained_previous`, `redirects`,
`drop_ratio`, `confidence`, `retrieved_at`, `reason`.

## Обновление (`Update` / `UpdateWithPrevious`)

- Источник: `config.TSPUSource{Name, Type, URL, MinEntries, MaxDropRatio}`.
  `Type` обязан быть `domains`; `Name` — `[A-Za-z0-9_-]{1,64}`, дубликаты
  отклоняются.
- URL только `https`, без credentials/fragment, редиректы только на `https`
  (≤3), иначе `unsafe_source_redirect`.
- Conditional fetch: `If-None-Match`/`If-Modified-Since` от предыдущего отчёта.
  `304 Not Modified` → `NotModified=true`, домены берутся из предыдущего кеша.
  `not_modified_without_previous_entries` если предыдущих нет.
- `ParseDomains`: stripping `||`, `^`, ведущей `.`; IP-line → второе поле;
  отбрасывание `/:@?`; `#`/`!` комментарии. IDN-нормализация через `idna`,
  public-suffix проверка через `publicsuffix`.
- Safety gates:
  - `len(domains) < source.MinEntries` → `too_few_entries:N`, retain previous.
  - drop-ratio = `(old-new)/old`; при `> source.MaxDropRatio` →
    `drop_ratio_exceeded:...`, retain previous.
  - размер ответа > `maxBytes` → `source_size_limit_exceeded`.
- Принятый источник: `Accepted=true`, `Fresh=true`, домены идут в `BuildCache`.
- Если ВСЕ источники упали и `FreshSources == 0` → error `no fresh accepted TSPU
  source entries; previous cache retained`, предыдущий кеш сохраняется.

## Поиск (`Find`)

`Find(cache, domain, now)` нормализует домен и идёт по суффиксам снизу вверх:

1. exact `suffix` match (не wildcard);
2. `wildcard` match `*.<suffix>` (только если i>0 — не apex).

Возвращает `Match`:

```json
{
  "domain": "rr1.sn.googlevideo.com",
  "matched": "googlevideo.com",
  "match_type": "suffix",
  "source": "refilter",
  "provenance": ["refilter", "antifilter"],
  "confidence": 0.9,
  "expired": false,
  "status": "MATCH",
  "evidence": "tspu_cache_match"
}
```

`expired=true` → `status=STALE_MATCH`, `evidence=tspu_cache_stale_match`.

## Persist (`Save` / `Load`)

- `Save` атомарен: `writeAtomic` (tmp + fsync + rename, mode 0600). Перед
  записью текущий валидный кеш копируется в `<name>.previous.<ext>`. Если
  существующий файл невалиден — отказ.
- `Load` → `readBoundedRegular` (regular, размер в лимите) → `decodeCache`
  (no trailing data, hash verify, pattern integrity).
- `PreviousPath` экспортируется для rollback/inspect.

## CLI

```powershell
.\dist\router-policy.exe tspu-update --out .\tspu-cache.json
.\dist\router-policy.exe tspu-check --cache .\tspu-cache.json rr1---sn.googlevideo.com
```

`tspu-update` использует `config.policy.max_tspu_list_bytes` и
`config.policy.tspu_list_update_interval_seconds`. `tspu-check` печатает
`Match` (без raw-секретов — их в кеше нет).

## Честное ограничение

Updater юнит-тестирован с `httptest`, но против live source URLs в этом проходе
не гонялся. Качество live-источников требует drop-ratio/history-проверок перед
автоматическим production-использованием. Cache v2 даёт для этого инструмент
(`SourceReport.DropRatio`, `Fresh`, `RetainedPrevious`), но автоматическая
включалка — за bounded policy P12/P13.