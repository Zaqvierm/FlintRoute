import { useEffect, useMemo, useState } from 'preact/hooks';
import {
  changeAction,
  classifyService,
  createChange,
  getVLESSPool,
  verifyService,
  type ChangeOp,
  type ChangeSet,
  type SessionInfo
} from '../api';
import {
  asArray,
  errorInfo,
  formatDateTime,
  groupServices,
  humanStatus,
  serviceColumnFor,
  textValue,
  verificationPresentationLabel
} from '../view-models';
import {
  Card,
  DetailDrawer,
  EmptyState,
  EntityCard,
  Generic,
  Grid,
  InfoGrid,
  PageHeader,
  RawDisclosure,
  RouteBadge,
  StatusBadge,
  StatusLine,
  statusWithFreshness
} from '../components/ui';

function humanChangeBlock(reason?: string): string {
  const messages: Record<string, string> = {
    flow_offloading_incompatible: 'Аппаратное ускорение пакетов мешает выборочной маршрутизации.',
    transparent_activation_unverified: 'Для этого правила нужен управляемый Xray.',
    lan_interfaces_unverified: 'FlintRoute не смог надёжно определить LAN-интерфейсы.',
    wan_interface_unverified: 'FlintRoute не смог надёжно определить выход в интернет.'
  };
  return messages[reason ?? ''] ?? `Проверка на роутере не завершена${reason ? ` (${reason})` : ''}. Сеть не изменена.`;
}

function humanChangeFailure(change: ChangeSet): string {
  if (change.state === 'requires_device') return humanChangeBlock(change.artifact_block_reason);
  if (change.state === 'rolled_back') return 'Проверка нового правила не прошла. FlintRoute восстановил предыдущую рабочую конфигурацию.';
  if (change.state === 'failed') return 'Не удалось применить правило. FlintRoute остановил изменение и сохранил прежнюю конфигурацию.';
  return `Правило не применено. Техническое состояние: ${change.state}.`;
}

const serviceColumns = [
  { category: 'GEO_LOCKED', title: 'GEO · VPN', hint: 'Smart DNS → VLESS → блокировка' },
  { category: 'TSPU_RESTRICTED', title: 'TSPU', hint: 'Zapret → Smart DNS → VLESS → блокировка' },
  { category: 'TELEGRAM', title: 'Telegram', hint: 'Telegram policy — отдельный маршрут' },
  { category: 'DIRECT_PREFERRED', title: 'Direct предпочтительно', hint: 'Direct → управляемый fallback' },
  { category: 'DIRECT_ONLY', title: 'Direct', hint: 'Только прямое подключение под управлением FlintRoute' },
  { category: 'BLOCKED', title: 'Drop', hint: 'DNS NXDOMAIN и блокировка forwarding' },
  { category: 'UNRESOLVED', title: 'Не определено', hint: 'Категория не распознана; маршрут не угадывается' }
];

const editableServiceColumns = serviceColumns.filter((column) => column.category !== 'TELEGRAM' && column.category !== 'UNRESOLVED');

const serviceRoutePaths = ['direct', 'zapret', 'smart_dns', 'vless', 'drop'];

function defaultServicePaths(category: string): string[] {
  if (category === 'GEO_LOCKED') return ['smart_dns', 'vless', 'drop'];
  if (category === 'TSPU_RESTRICTED') return ['zapret', 'vless', 'drop'];
  if (category === 'BLOCKED') return ['drop'];
  return ['direct'];
}

export function Services({
  services,
  configVersion,
  role,
  mutationLocked,
  refresh,
  navigate
}: {
  services: any[];
  configVersion: number;
  role: SessionInfo['role'];
  mutationLocked: boolean;
  refresh: () => Promise<void>;
  navigate: (screen: string) => void;
}) {
  const [moving, setMoving] = useState('');
  const [message, setMessage] = useState('');
  const [editor, setEditor] = useState<{ domain: string; category: string; paths: string[] } | null>(null);
  const [selectedService, setSelectedService] = useState<any>(null);
  const [verificationBusy, setVerificationBusy] = useState(false);
  const [verificationMessage, setVerificationMessage] = useState('');
  const [serviceView, setServiceView] = useState<'table' | 'board'>('table');
  const [serviceQuery, setServiceQuery] = useState('');
  const grouped = useMemo(() => groupServices(services), [services]);
  const configuredServices = useMemo(() => grouped.filter((item) => Boolean(item.applied) || asArray(item.sources).includes('configured')), [grouped]);
  const observedServices = useMemo(() => grouped.filter((item) => !Boolean(item.applied) && !asArray(item.sources).includes('configured')), [grouped]);
  const filteredConfigured = useMemo(() => {
    const query = serviceQuery.trim().toLowerCase();
    if (!query) return configuredServices;
    return configuredServices.filter((item) => `${textValue(item.id, '')} ${asArray(item.domains).map((domain) => textValue(domain, '')).join(' ')}`.toLowerCase().includes(query));
  }, [configuredServices, serviceQuery]);

  async function commitRule(domain: string, category: string, paths?: string[]) {
    if (role !== 'administrator' || mutationLocked || !configVersion || moving) return;
    setMoving(domain);
    setMessage(`Создаю черновик правила для ${domain}…`);
    try {
      await classifyService(domain, category, configVersion, paths);
      setMessage(`${domain}: черновик создан. Проверь изменения перед применением.`);
      setEditor(null);
      await refresh();
      navigate('Операции');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Не удалось изменить маршрут');
    } finally {
      setMoving('');
    }
  }

  async function verifyConfiguredService(service: any) {
    if (role !== 'administrator' || verificationBusy) return;
    const serviceID = textValue(service?.id, '');
    const domain = textValue(asArray(service?.domains)[0], '');
    if (!serviceID || !domain) {
      setVerificationMessage('Для проверки у сервиса должен быть домен.');
      return;
    }
    setVerificationBusy(true);
    setVerificationMessage('Проверяю текущий путь без изменения правил…');
    try {
      const result = await verifyService(serviceID, domain);
      setSelectedService((current: any) => current ? {
        ...current,
        status: result.path_verified ? 'VERIFIED' : result.status,
        probe_state: result.path_verified ? 'verified_candidate' : result.verification_state,
        verification_state: result.verification_state,
        verification_reason: result.reason ?? result.error,
        selected_route_tag: result.selected_route_tag || current.selected_route_tag,
        selected_route_type: result.selected_route_type || current.selected_route_type,
        checked_at: result.checked_at,
        latest_checked_at: result.checked_at,
        verification_duration_ms: result.verification_duration_ms,
        verification_route_latency_ms: result.route_latency_ms,
        verification_route_latency_available: result.route_latency_ms !== undefined,
        verification_end_to_end_latency_ms: result.end_to_end_latency_ms,
        verification_end_to_end_latency_available: result.end_to_end_latency_available === true,
        selection_score: result.selection_score,
        classification_state: result.classification_state,
        classification_reason: result.classification_reason,
        verification_candidates: result.candidates
      } : current);
      await refresh();
      setVerificationMessage(result.path_verified
        ? `Путь подтверждён: ${result.selected_route_tag || result.selected_route_type || 'маршрут'}${result.end_to_end_latency_available ? `, end-to-end ${result.end_to_end_latency_ms} мс` : ''}. Проверка заняла ${result.verification_duration_ms ?? '—'} мс; правило не изменялось.`
        : `Путь не подтверждён. ${result.error || result.reason || 'Проверка не дала безопасного результата'}. Правило не изменялось.`);
    } catch (error) {
      const info = errorInfo(error);
      setVerificationMessage(`${info.code}: ${info.message}`);
    } finally {
      setVerificationBusy(false);
    }
  }

  function editRule(service?: any) {
    const category = serviceColumnFor(service?.category ?? 'DIRECT_ONLY');
    setEditor({
      domain: service?.domain ?? service?.domains?.[0] ?? '',
      category,
      paths: [...(service?.allowed_paths?.length ? service.allowed_paths : defaultServicePaths(category))]
    });
  }

  function togglePath(path: string) {
    if (!editor) return;
    const included = editor.paths.includes(path);
    setEditor({
      ...editor,
      paths: included ? editor.paths.filter((item) => item !== path) : [...editor.paths, path]
    });
  }

  return (
    <section>
      <div class="service-toolbar">
        <div>
          <b>Правила сервисов</b>
          <span>Изменение сначала попадёт в очередь черновиков. Dataplane меняется только после отдельного review и apply.</span>
        </div>
        <div class="actions">
          <label class="service-search"><span class="sr-only">Поиск сервиса или домена</span><input value={serviceQuery} placeholder="Поиск сервиса или домена" onInput={(event) => setServiceQuery(event.currentTarget.value)} /></label>
          <button class={serviceView === 'table' ? 'selected' : ''} onClick={() => setServiceView('table')}>Таблица</button>
          <button class={serviceView === 'board' ? 'selected' : ''} onClick={() => setServiceView('board')}>Доска</button>
          <button class="primary" disabled={role !== 'administrator' || mutationLocked} onClick={() => editRule()}>+ Новое правило</button>
        </div>
      </div>
      {editor && (
        <form
          class="service-editor"
          onSubmit={(event) => {
            event.preventDefault();
            if (editor.paths.length) void commitRule(editor.domain, editor.category, editor.paths);
          }}
        >
          <label>Домен<input value={editor.domain} placeholder="example.com" onInput={(event) => setEditor({ ...editor, domain: event.currentTarget.value })} /></label>
          <label>
            Класс
            <select
              value={editor.category}
              onChange={(event) => {
                const category = event.currentTarget.value;
                setEditor({ ...editor, category, paths: defaultServicePaths(category) });
              }}
            >
              {editableServiceColumns.map((column) => <option value={column.category}>{column.title}</option>)}
            </select>
          </label>
          <div>
            <b>Порядок маршрутов</b>
            <small>Нажимай в нужной очередности. Повторный клик удаляет маршрут.</small>
            <div class="route-path-editor">
              {serviceRoutePaths.map((path) => {
                const position = editor.paths.indexOf(path);
                return (
                  <button type="button" class={position >= 0 ? 'selected' : ''} onClick={() => togglePath(path)}>
                    {position >= 0 ? `${position + 1}. ` : ''}{path}
                  </button>
                );
              })}
            </div>
          </div>
          <div class="actions">
            <button class="primary" disabled={mutationLocked || !editor.domain.trim() || editor.paths.length === 0 || Boolean(moving)}>Создать черновик</button>
            <button type="button" onClick={() => setEditor(null)}>Отмена</button>
          </div>
        </form>
      )}
      {serviceView === 'table' && <section class="service-table-card card">
        <div class="table-scroll"><table class="service-table"><thead><tr><th>Сервис</th><th>Домены</th><th>Классификация</th><th>Основной путь</th><th>Состояние</th><th aria-label="Действия" /></tr></thead><tbody>
          {filteredConfigured.map((item) => {
            const domains = asArray(item.domains).map((domain) => textValue(domain, '')).filter(Boolean);
            const paths = asArray(item.allowed_paths).map((path) => textValue(path, '')).filter(Boolean);
            const health = item.health ?? item.status ?? (item.applied ? 'configured' : 'observed');
            return <tr key={String(item.id)}><td><b>{textValue(item.id, 'Неизвестный сервис')}</b><small>{textValue(item.source, 'configured')}</small></td><td>{domains.length || '—'}{domains.length > 0 && <small>{domains.slice(0, 2).join(', ')}{domains.length > 2 ? '…' : ''}</small>}</td><td><StatusBadge value={serviceColumnFor(item.category)} /></td><td>{textValue(item.selected_route_tag ?? paths[0], 'Не выбран')}</td><td><StatusBadge value={statusWithFreshness(health, item)} /></td><td><button onClick={() => setSelectedService(item)}>Открыть</button></td></tr>;
          })}
        </tbody></table></div>
        {!filteredConfigured.length && <EmptyState title="Правил пока нет" text="Настрой сервис или сначала дождись наблюдения Discovery." />}
      </section>}
      {serviceView === 'board' && <div class="service-board">
        {serviceColumns.map((column) => (
          <section
            class={`service-column ${column.category.toLowerCase()}`}
            key={column.category}
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => {
              event.preventDefault();
              const domain = event.dataTransfer?.getData('text/plain');
              if (domain) void commitRule(domain, column.category);
            }}
          >
            <header><h2>{column.title}</h2><small>{column.hint}</small></header>
            {configuredServices
              .filter((item) => serviceColumnFor(textValue(item.category, 'DIRECT_ONLY')) === column.category)
              .map((item) => (
                <ServiceGroup
                  service={item}
                  key={String(item.id)}
                   draggable={role === 'administrator' && !mutationLocked && !moving && asArray(item.domains).length === 1}
                  busy={moving === textValue(asArray(item.domains)[0], '')}
                  onEdit={() => editRule(item)}
                  onOpen={() => setSelectedService(item)}
                />
              ))}
            {!configuredServices.some((item) => serviceColumnFor(textValue(item.category, 'DIRECT_ONLY')) === column.category) && <p class="empty-state">Применённых правил пока нет</p>}
          </section>
        ))}
      </div>}
      {observedServices.length > 0 && <section class="card">
        <h2>Наблюдения Discovery — не применены</h2>
        <p>FlintRoute заметил эти домены и проверил доступные пути. Они не меняют маршрутизацию, пока ты явно не закрепишь правило.</p>
        <div class="grid">
          {observedServices.map((item) => <ServiceGroup
            service={item}
            key={String(item.id)}
            busy={moving === textValue(asArray(item.domains)[0], '')}
            onEdit={() => editRule(item)}
            editLabel="Закрепить правило"
            onOpen={() => setSelectedService(item)}
          />)}
        </div>
      </section>}
       {mutationLocked && <p class="action-status">Изменения заблокированы: FlintRoute ещё не подтвердил безопасное состояние восстановления.</p>}
       <p class={message.includes('создан') ? 'action-status ok' : 'action-status'}>{message || 'Домены появляются после наблюдения и проверки. Перетащи карточку, чтобы создать черновик правила.'}</p>
      <DetailDrawer title={textValue(selectedService?.id, 'Сервис')} open={Boolean(selectedService)} onClose={() => setSelectedService(null)}>
         <ServiceDetails
           service={selectedService}
           onVerify={selectedService?.applied ? () => void verifyConfiguredService(selectedService) : undefined}
           verifyBusy={verificationBusy}
           verifyMessage={verificationMessage}
           onEdit={mutationLocked ? undefined : () => selectedService && editRule(selectedService)}
         />
      </DetailDrawer>
    </section>
  );
}

export function ServiceGroup({
  service,
  draggable = false,
  busy = false,
  onEdit,
  editLabel = 'Настроить',
  onOpen
}: {
  service: any;
  draggable?: boolean;
  busy?: boolean;
  onEdit?: () => void;
  editLabel?: string;
  onOpen?: () => void;
}) {
  if (!service) return <Generic title="Группа сервиса" text="Сервис не выбран." />;
  const observation = !Boolean(service.applied) && asArray(service.sources).includes('automatic') && !asArray(service.sources).includes('configured');
  const verificationState = textValue(service.probe_state, '').toLowerCase().replace(/[._-]+/g, ' ');
  const selectedRoute = textValue(service.selected_route_tag ?? service.selected_route_type, '');
  const routeStatus = observation
    ? (selectedRoute ? `Проверенный кандидат: ${selectedRoute}` : 'Ни один безопасный маршрут не прошёл проверку')
    : verificationState === 'not checked'
      ? 'Настроено · путь ещё не проверен'
      : humanStatus(service.status ?? service.selected_route_tag ?? 'Ожидает проверки');
  return (
    <article
      class={`service-card ${busy ? 'busy' : ''}`}
      draggable={draggable}
      onDragStart={(event) => event.dataTransfer?.setData('text/plain', service.domains?.[0] ?? '')}
    >
      <div class="service-card-title"><b>{textValue(service.display_name ?? service.id, 'Неизвестный сервис')}</b><span class={`source ${observation ? 'automatic' : 'configured'}`}>{observation ? 'наблюдение' : 'применено'}</span></div>
      <small>{asArray(service.domains).length} доменов</small>
      <div class="service-card-route"><RouteBadge type={service.selected_route_type ?? service.category} /><span>{routeStatus}</span></div>
      {service.allowed_paths?.length > 0 && <small>{service.allowed_paths.join(' → ')}</small>}
      {selectedRoute && <small title={observation ? 'Проверка пути прошла, но политика не применена.' : 'Маршрут входит в применённую конфигурацию.'}>{observation ? 'кандидат прошёл проверку пути' : 'маршрут применён'}</small>}
      {observation && <small>Не применено к трафику</small>}
      <div class="actions"><button type="button" onClick={onOpen}>Открыть</button>{onEdit && <button type="button" class="service-edit" onClick={onEdit}>{editLabel}</button>}</div>
    </article>
  );
}

function ServiceDetails({ service, onVerify, verifyBusy = false, verifyMessage = '', onEdit }: { service: any; onVerify?: () => void; verifyBusy?: boolean; verifyMessage?: string; onEdit?: () => void }) {
  if (!service) return null;
  const classificationConfidence = service.classification_confidence ?? service.classificationConfidence ?? service.confidence;
  // The legacy details row reads `confidence`; normalize that compatibility
  // field to classification confidence, never the route-decision confidence.
  service = { ...service, confidence: classificationConfidence };
  const observation = !Boolean(service.applied) && asArray(service.sources).includes('automatic') && !asArray(service.sources).includes('configured');
  const serviceVerificationState = textValue(service.probe_state, '').toLowerCase().replace(/[._-]+/g, ' ');
  const serviceVerification = serviceVerificationState === 'verified candidate'
    ? 'verified'
    : serviceVerificationState === 'verifying' || serviceVerificationState === 'in progress'
      ? 'checking'
      : serviceVerificationState === 'no safe route' || textValue(service.verification_state, '').toLowerCase().replace(/[._-]+/g, ' ') === 'terminal no safe route'
        ? 'no_safe_route'
        : service.policy_state === 'observed' && serviceVerificationState === 'not run observe only'
          ? 'observed'
          : serviceVerificationState === 'not checked' || textValue(service.verification_state, '').toLowerCase().replace(/[._-]+/g, ' ') === 'not checked'
            ? 'not_checked'
          : 'unverified';
  return <><InfoGrid items={[["Политика", observation ? (service.policy_state === 'suggested' ? 'Предложено — не применено' : 'Наблюдение — не применено') : 'Применена'], ["Классификация", service.category ?? 'Не определена'], ["Состояние классификации", service.classification_state ?? 'UNKNOWN'], ["Основание классификации", service.classification_reason ?? 'не указано'], ["Уверенность классификации", Number(service.confidence) > 0 ? service.confidence : 'Нет достаточных данных'], ["Проверка пути", verificationPresentationLabel(serviceVerification as Parameters<typeof verificationPresentationLabel>[0])], ["Источник", asArray(service.sources).join(', ')], [observation ? "Кандидат маршрута" : "Маршрут", service.selected_route_tag ?? service.selected_route_type], ["Health", service.health], ["Fallback", asArray(service.allowed_paths).join(' → ')], ["End-to-end", service.verification_end_to_end_latency_available ? `${service.verification_end_to_end_latency_ms} мс` : null], ["Latency", service.verification_route_latency_available ? `${service.verification_route_latency_ms} мс` : null], ["Последняя проверка", formatDateTime(service.latest_checked_at)]]} />
    <h3>Связанные домены</h3><div class="domain-list">{asArray(service.domains).map((domain) => <span class="chip mono">{textValue(domain)}</span>)}</div>
    <h3>Наследование и исключения</h3><p>{asArray(service.forbidden_paths).length ? `Запрещены: ${asArray(service.forbidden_paths).join(', ')}` : 'Явных конфликтов и исключений нет.'}</p>
    {onVerify && <div class="actions"><button class="primary" disabled={verifyBusy} onClick={onVerify}>{verifyBusy ? 'Проверяю…' : 'Проверить путь сейчас'}</button></div>}
    {verifyMessage && <p class="action-status">{verifyMessage}</p>}
    {onEdit && <button class="primary" onClick={onEdit}>Настроить правило</button>}<RawDisclosure value={service} /></>;
}

export function Policies({ mode }: { mode: string }) {
  const items = ['emergency', 'BLOCKED', 'device+domain', 'device+service', 'domain', 'service', 'category', 'auto', 'default'];
  return <Card title={`Политики: ${mode}`}>{items.map((p, i) => <div class="row"><b>{i + 1}</b><span>{p}</span><small>формальный приоритет</small></div>)}</Card>;
}

export function Changes({ changes, refresh, role, configVersion, mutationLocked, navigate, mode = 'developer' }: { changes: ChangeSet[]; refresh: () => void; role: SessionInfo['role']; configVersion: number; mutationLocked: boolean; navigate: (screen: string) => void; mode?: 'developer' | 'operations' }) {
  const [title, setTitle] = useState('');
  const [operationType, setOperationType] = useState<ChangeOp['type']>('set');
  const [path, setPath] = useState('');
  const [value, setValue] = useState('');
  const [error, setError] = useState('');

  if (role !== 'administrator') {
    return <Generic title={mode === 'operations' ? 'Операции' : 'Advanced'} text="Для этого раздела нужна роль администратора." />;
  }

  async function create() {
    if (mutationLocked) return;
    setError('');
    try {
      const normalizedTitle = title.trim();
      const normalizedPath = path.trim();
      if (!normalizedTitle) throw new Error('Укажи название изменения');
      if (!normalizedPath.startsWith('/')) throw new Error('Путь операции должен начинаться с /');
      const operation: ChangeOp = { type: operationType, path: normalizedPath };
      if (operationType === 'set') {
        if (!value.trim()) throw new Error('Укажи JSON-значение операции');
        operation.value = JSON.parse(value);
      }
      await createChange(normalizedTitle, configVersion, [operation]);
      setTitle('');
      setPath('');
      setValue('');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Не удалось создать ChangeSet');
    }
  }
  async function act(id: string, action: string) {
    if (mutationLocked) return;
    await changeAction(id, action);
    await refresh();
  }
  return (
    <Card title={mode === 'operations' ? 'Центр операций' : 'Advanced · ChangeSet'}>
       <p>{mode === 'operations' ? 'Здесь видны черновики, проверки, применение, окно подтверждения и откат. Ничего не считается применённым, пока backend не подтвердил состояние.' : 'Низкоуровневый редактор. Обычная настройка VLESS, Zapret, Smart DNS и discovery делается в их собственных экранах.'}</p>
       {mutationLocked && <div class="warning-panel"><b>Изменения заблокированы</b><p>Сначала завершите recovery или подтвердите baseline. Просмотр очереди и диагностика остаются доступны.</p></div>}
      {mode === 'developer' && <details>
        <summary>Открыть Developer JSON editor</summary>
        <div class="change-editor">
        <label><span>Название</span><input value={title} onInput={(e) => setTitle((e.target as HTMLInputElement).value)} /></label>
        <label><span>Операция</span><select value={operationType} onChange={(e) => setOperationType((e.target as HTMLSelectElement).value as ChangeOp['type'])}><option value="set">set</option><option value="remove">remove</option></select></label>
        <label><span>Путь</span><input class="mono" placeholder="/services/example/category" value={path} onInput={(e) => setPath((e.target as HTMLInputElement).value)} /></label>
        {operationType === 'set' && <label><span>JSON-значение</span><textarea class="mono" placeholder={'"DIRECT_PREFERRED"'} value={value} onInput={(e) => setValue((e.target as HTMLTextAreaElement).value)} /></label>}
        <small>Базовая версия: {configVersion || 'загрузка...'}</small>
        {error && <p class="auth-error">{error}</p>}
         <button class="primary" disabled={mutationLocked || !configVersion} onClick={create}>Создать ChangeSet</button>
        </div>
      </details>}
      {changes.map((c) => (
        <div class="change" key={c.id}>
          <b>{c.title}</b><StatusBadge value={c.state} />
          {c.data_plane_verified && <small class="verified">Путь проверен backend</small>}
          <ChangeDiff change={c} />
          <div class="actions">
             {actionsForChange(c.state).map((a) => <button disabled={mutationLocked} onClick={() => act(c.id, a)}>{changeActionLabel(a)}</button>)}
          </div>
          {['failed', 'rolled_back', 'requires_device', 'recovery_required'].includes(c.state) && <div class="reason"><p>{humanChangeFailure(c)}</p>{c.state === 'requires_device' && <button type="button" onClick={() => navigate('Диагностика')}>Открыть диагностику</button>}</div>}
        </div>
      ))}
    </Card>
  );
}

function actionsForChange(state: string): string[] {
  if (state === 'draft') return ['validate'];
  if (state === 'validated') return ['apply'];
  if (state === 'awaiting_confirmation') return ['confirm', 'rollback'];
  return [];
}

function changeActionLabel(action: string): string {
  return ({ validate: 'Проверить', apply: 'Применить', confirm: 'Подтвердить', rollback: 'Откатить' } as Record<string, string>)[action] ?? action;
}

function ChangeDiff({ change }: { change: ChangeSet }) {
  const diff = change.diff?.length ? change.diff : change.operations;
  const groups = [
    { title: 'Routing', matches: (path: string) => /^\/(routes|services|policy|overrides)/.test(path) },
    { title: 'Firewall / data plane', matches: (path: string) => /^\/(openwrt|routes|zapret)/.test(path) },
    { title: 'Management', matches: (path: string) => /^\/(xray\/activation_mode|zapret\/activation_mode|storage)/.test(path) }
  ];
  return <div class="change-diff">{groups.map((group) => {
    const items = diff.filter((item) => group.matches(item.path));
    if (!items.length) return null;
    return <section key={group.title}><h4>{group.title}</h4>{items.map((item, index) => <div class="row" key={`${item.path}:${index}`}><b>{item.type}</b><span class="mono">{item.path}</span><small>{summarizeValue(item.value)}</small></div>)}</section>;
  })}</div>;
}

function summarizeValue(value: unknown): string {
  if (value === undefined) return 'удаление';
  const raw = JSON.stringify(value);
  return raw.length > 160 ? `${raw.slice(0, 157)}…` : raw;
}

export function Routes({ routes, navigate }: { routes: any[]; navigate: (screen: string) => void }) {
  const [selected, setSelected] = useState<any>(null);
  const [vlessPool, setVLESSPool] = useState<any>(null);
  useEffect(() => {
    const controller = new AbortController();
    getVLESSPool(controller.signal)
      .then((pool) => setVLESSPool(pool))
      .catch((reason) => {
        if (reason instanceof Error && reason.name === 'AbortError') return;
        setVLESSPool(null);
      });
    return () => controller.abort();
  }, []);
  const poolServers: any[] = Array.isArray(vlessPool?.servers) ? vlessPool.servers : [];
  const activeVLESS: any = poolServers.find((server: any) => server.selected && server.path_verified);
  const withVLESS = routes.some((route) => route.type === 'vless') ? routes : [...routes, {
    type: 'vless', tag: 'VLESS', status: activeVLESS ? 'VERIFIED' : 'UNAVAILABLE', managed: Boolean(activeVLESS),
    scope: activeVLESS ? `Active server: ${textValue(activeVLESS.name ?? activeVLESS.tag)}` : 'Нет проверенных серверов. Открой VLESS-серверы и добавь подписку или свой VPS.'
  }];
  const smartDNSRoutes = withVLESS.filter((route) => route.type === 'smart_dns');
  const configuredSmartDNS = smartDNSRoutes.filter((route) => !route.disabled && String(route.status).toUpperCase() !== 'NOT_CONFIGURED');
  const primaryTypes = new Set(['direct', 'zapret', 'vless', 'drop']);
  const routeItems = withVLESS.filter((route) => primaryTypes.has(route.type));
  const systemItems = withVLESS.filter((route) => ['system_default', 'unclassified', 'external_socks'].includes(route.type));
  if (smartDNSRoutes.length) {
    routeItems.push({
      type: 'smart_dns', tag: 'smart-dns', status: configuredSmartDNS.length ? 'CONFIGURED' : 'NOT_CONFIGURED',
      managed: configuredSmartDNS.length > 0, scope: `${configuredSmartDNS.length} из ${smartDNSRoutes.length} резолверов настроено`,
      resolver_slots: smartDNSRoutes.length, configured_resolvers: configuredSmartDNS.length, members: smartDNSRoutes
    });
  }
  const titles: Record<string, string> = {
    system_default: 'Обычный маршрут роутера',
    direct: 'Direct',
    unclassified: 'Трафик без правила',
    smart_dns: 'Smart DNS',
    external_socks: 'Внешний SOCKS5'
  };
  const actions: Record<string, [string, string]> = {
    direct: ['Настроить правила', 'Сервисы'], drop: ['Настроить блокировку', 'Сервисы'],
    zapret: ['Настроить Zapret', 'Zapret'], smart_dns: ['Настроить Smart DNS', 'Smart DNS'],
    vless: ['Открыть VLESS-серверы', 'VLESS-серверы'], external_socks: ['Настроить внешний SOCKS', 'External SOCKS']
  };
  return <section><PageHeader title="Маршруты" text="Главные способы открыть сервис. FlintRoute покажет, что работает, кто это использует и что настроить дальше." /><Grid>{routeItems.map((route) => (
    <EntityCard title={titles[route.type] ?? textValue(route.tag, 'Маршрут')} status={statusWithFreshness(route.status || (route.disabled ? 'disabled' : 'configured'), route)} onOpen={() => setSelected(route)} key={`${route.type}:${textValue(route.tag, 'route')}`}>
      <RouteBadge type={route.type} />
      <div class="row"><b>{humanStatus(route.status || (route.disabled ? 'выключен' : 'настроен'))}</b><span>{route.managed ? 'FlintRoute управляет этим путём' : 'Требует настройки'}</span></div>
      <p>{textValue(route.scope, 'Область действия не указана')}</p>
      {route.type === 'direct' && <div class="row"><b>{route.managed_domains ?? 0}</b><span>доменов под managed Direct</span></div>}
      {route.type === 'smart_dns' && <small>Это выбор DNS-ответа для домена, а не VPN и не туннель.</small>}
      {route.type === 'vless' && activeVLESS && <small>{textValue(activeVLESS.name ?? activeVLESS.tag)} · {activeVLESS.latency_ms ? `${activeVLESS.latency_ms} мс` : 'latency неизвестна'} · PathVerified</small>}
      {route.type === 'vless' && !activeVLESS && <small>VLESS недоступен: нет проверенных серверов.</small>}
      {actions[route.type] && <button class="route-action" onClick={() => navigate(actions[route.type][1])}>{actions[route.type][0]}</button>}
    </EntityCard>
  ))}</Grid>
  <details class="raw-disclosure"><summary>Системные и дополнительные пути</summary>
    <p>Обычный маршрут роутера обслуживает трафик без правил. Внешний SOCKS5 нужен только если у тебя уже есть отдельный прокси, которым FlintRoute не управляет.</p>
    <Grid>{systemItems.map((route) => <EntityCard title={titles[route.type] ?? textValue(route.tag, 'Маршрут')} status={statusWithFreshness(route.status, route)} onOpen={() => setSelected(route)} key={`${route.type}:${textValue(route.tag, 'system-route')}`}>
      <p>{textValue(route.scope, 'Область действия не указана')}</p>{route.type === 'external_socks' && <button onClick={() => navigate('External SOCKS')}>Добавить внешний SOCKS5</button>}
    </EntityCard>)}</Grid>
  </details>
  <DetailDrawer title={titles[selected?.type] ?? selected?.tag ?? 'Маршрут'} open={Boolean(selected)} onClose={() => setSelected(null)}><InfoGrid items={[["Тип", selected?.type], ["Owner", selected?.owner], ["Состояние", selected?.status], ["Фактический путь", selected?.effective_path], ["Scope", selected?.scope], ["Fallback", selected?.fallback], ["Health", selected?.health]]} /><RawDisclosure value={selected} /></DetailDrawer></section>;
}
