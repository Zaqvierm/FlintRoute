# UI v2: правдивые состояния и адаптивная оболочка

Документ описывает UI на remediation-ветке. При коммите он привязывается к
точному SHA; локальные изменения не являются hardware evidence.

## Правила правдивости

- Завершение первичной настройки хранится в backend bucket `onboarding` bbolt.
  `localStorage` может запоминать экран и локальные предпочтения, но не может
  утверждать, что применены route, source или ChangeSet.
- Режим скрытия privacy включён по умолчанию. Запросы topology и devices идут
  через скрытый API-вариант; старое состояние entity очищается при переходе
  visible→hidden; явное раскрытие автоматически истекает через 10 минут.
- Ошибка одного среза не отменяет остальные dashboard-срезы. Alert center
  показывает недоступный срез и отдельную кнопку повтора; fallback-объект
  помечается stale и не выдаётся за свежий health proof.
- Экран Fast Start сам владеет первым чтением provider и запускает его при
  монтировании. Открытие мастера не оставляет карточки компонентов в ложном
  бесконечном loading. Logout отменяет текущую refresh generation и игнорирует
  поздние ответы до очистки entity state.
- Записи Fast Start — видимые пользователю operations: ошибка шага показывает
  backend error code и нормальное объяснение, не оставляя unhandled promise и
  ложно продвинутый шаг.
- Категории сервисов перечислены явно. `TELEGRAM`, `DIRECT_PREFERRED` и будущие
  значения не превращаются молча в Direct; неизвестные остаются «Не определено».
- Редактирование сервиса создаёт draft ChangeSet и открывает review в
  Operation/Developer Center. Один клик карточки не запускает validate/apply/
  confirm dataplane.

## Навигация и режимы ширины

В desktop-оболочке пять разделов: Обзор, Сеть, Правила, Активность и Система.
Выбор экрана отражается в URL `?screen=`; Back/Forward браузера восстанавливают
активный экран. Неизвестный URL показывает локальное «страница не найдена», а не
молча открывает Обзор.

На телефоне четыре основных действия находятся в нижней навигации, пятый пункт
открывает sheet «Ещё». Панель прикреплена к viewport, а не к rail нулевой высоты,
поэтому доступна на 360–430 px. На compact/tablet rail узкий, topology становится
вертикальным списком групп; desktop-canvas не заставляет мобильный экран
горизонтально прокручиваться. Desktop сохраняет подробную карту, но ограничивает
читаемую ширину на ultrawide. Декоративные анимации пакетов и линий удалены:
линия сама по себе не доказывает трафик.

В разделе Активность есть отдельный Operation Center. Изменения компонентов,
VLESS, Zapret, Smart DNS, External SOCKS и сервисных правил создают draft и
ссылку в этот центр; они не делают validate/apply/confirm dataplane из обработчика
карточки. `Advanced` оставляет JSON-редактор только за явным Developer Mode.

Браузерное покрытие находится в `tests/browser`: deterministic API fixtures
проверяют очистку privacy, частичный API failure, навигацию/back-forward и
матрицу десяти viewport от 360×800 до 3840×2160. Fixture существует только в
тестах и никогда не включается production-сборкой.

Набор также доказывает, что медленный screen-specific запрос отменяется при
смене экрана, а старый ответ не может перезаписать новый экран.

## Лимит запросов и отмена

Обновление Обзора читает только компактные snapshot overview/system/health и
данные активного экрана. Дорогие коллекции не опрашиваются глобально:
topology/devices, services, routes, traffic, events, discovery, diagnostics,
backups и operations загружаются только там, где отображаются. Экран Services
покрыт request-budget тестом и не загружает topology, devices, routes, traffic,
events, discovery, diagnostics или backup collection.

Каждая refresh generation владеет своим `AbortController`. Смена экрана или
privacy отменяет предыдущую generation, а отменённые ответы игнорируются.
30-секундный timer и SSE reconnect используют один in-flight guard и не
умножают команды роутеру. В скрытой вкладке timer остановлен; ускоренный polling
разрешён только для активной operation.

## Объём и ограничения

Это фундамент progressive disclosure, а не заявление о production readiness.
Полное feature-local разделение frontend и Linux/hardware evidence остаются
отдельными gate. Playwright Chromium проходит локально, если установлен browser
binary; authoritative повторяемая проверка выполняется в CI. UI-работа намеренно
не трогает hardware.

### Decomposition checkpoint

Сетевые экраны, правила и route-интеграции вынесены в
`ui/src/features/network.tsx`, `ui/src/features/rules.tsx`,
`ui/src/features/vless.tsx` и `ui/src/features/route-integrations.tsx`, а
повторно используемые UI-примитивы — в `ui/src/components/ui.tsx`.
`main.tsx` отвечает за shell, загрузку данных и маршрутизацию экранов; остаток
системных экранов сохраняет тот же контракт и выносится отдельными
изменениями только вместе с тестами. Это проверено `npm run typecheck`,
`npm test -- --run` и production build; software evidence не является
hardware proof. Текущий decomposition checkpoint фиксируется отдельным
grouped commit и должен быть привязан к его exact SHA в evidence ledger.
