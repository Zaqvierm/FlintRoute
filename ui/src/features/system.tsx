import { ComponentChildren } from 'preact';
import QRCode from 'qrcode';
import { useEffect, useRef, useState } from 'preact/hooks';
import {
  activateExternalSOCKS,
  applyDiscoverySuggestion,
  checkExternalSOCKS,
  componentAction,
  configureDiscovery,
  configureTGWS,
  configureTelegram,
  getComponents,
  getExternalSOCKS,
  getTelegram,
  getTGWS,
  getVLESSPool,
  ignoreDiscoverySuggestion,
  isChangePending,
  runVLESSSpeedTest,
  setVLESSTariff,
  testTelegram,
  waitForChangeTerminal,
  type ChangeSet,
  type ComponentAction,
  type ComponentKind,
  type ComponentStatus,
  type DiscoveryStatus,
  type EventItem,
  type RevisionSummary,
  type SessionInfo,
  type TrafficSnapshot
} from '../api';
import {
  asArray,
  asRecord,
  decisionVerificationPresentation,
  errorInfo,
  formatDateTime,
  humanStatus,
  isAdministrativeEvent,
  isDecisionEvent,
  stringArray,
  textValue,
  toDecisionCard,
  verificationPresentationLabel
} from '../view-models';
import {
  AlertCenter,
  LoadingSkeleton,
  OperationCenterSummary,
  PrivacyBar,
  SessionBar,
  TopBar
} from '../app/shell';
import {
  Card,
  DetailDrawer,
  EmptyState,
  EntityCard,
  EventRow,
  Generic,
  Grid,
  InfoGrid,
  RawDisclosure,
  EvidenceList,
  PageHeader,
  StatusBadge,
  StatusLine,
  statusWithFreshness,
  useConfirmDialog
} from '../components/ui';

function staleFallback<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => item !== null && typeof item === 'object' && !Array.isArray(item)
      ? { ...(item as Record<string, unknown>), freshness: 'stale' }
      : item) as T;
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return { ...(value as Record<string, unknown>), freshness: 'stale' } as T;
  }
  return value;
}

function formatBytesBase(value: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit++;
  }
  return `${amount.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatRateBase(value?: number): string {
  return value === undefined ? 'сбор базовой точки' : `${formatBytes(value)}/с`;
}

const componentNames: Record<ComponentKind, string> = {
  xray: 'Xray',
  zapret: 'Zapret / nfqws',
  tg_ws_proxy: 'TG WS Proxy'
};

function componentNextStep(status: ComponentStatus): string {
  if (status.ownership === 'foreign') {
    return 'Бинарник найден, но FlintRoute им не управляет. Не перезапускайте и не удаляйте его из этого экрана: сначала нужен отдельный план миграции с проверкой listeners, nft/NFQUEUE и rollback.';
  }
  if (!status.installed) return 'Компонент не установлен. FlintRoute сам выберет закреплённый build для архитектуры роутера и проверит SHA-256.';
  if (['stopped', 'disabled', 'not_used'].includes(String(status.service_state).toLowerCase()) && !status.health_ready) {
    return status.kind === 'xray'
      ? 'Xray установлен, но runtime остановлен. Наличие серверов в inventory ещё не означает активный VLESS-маршрут.'
      : 'Компонент установлен, но сейчас не используется. Настрой сервисы, чтобы подключить его к маршрутам.';
  }
  if (!status.health_ready) return status.health_reason || 'Компонент установлен, но health check не пройден.';
  if (status.kind === 'xray') return 'Runtime готов. Активные VLESS-маршруты должны подтверждаться отдельным path evidence.';
  if (status.kind === 'zapret') return 'Готово. Следующий шаг — запустить безопасную калибровку стратегии для текущей сети.';
  return 'Сервис установлен. Для PASS нужна фактическая проверка Telegram transport, а не один открытый TCP-порт.';
}

export function Components({ role, mutationLocked, navigate }: { role: SessionInfo['role']; mutationLocked: boolean; navigate: (screen: string) => void }) {
  const [items, setItems] = useState<ComponentStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<ComponentStatus | null>(null);
  const [busy, setBusy] = useState<ComponentKind | null>(null);
  const [stage, setStage] = useState('');
  const [message, setMessage] = useState('');
  const refreshController = useRef<AbortController | null>(null);
  const confirmDialog = useConfirmDialog();

  async function refresh() {
    refreshController.current?.abort();
    const controller = new AbortController();
    refreshController.current = controller;
    setLoading(true);
    try {
      setItems(await getComponents(controller.signal));
      setMessage('');
    } catch (reason) {
      if (reason instanceof Error && reason.name === 'AbortError') return;
      const info = errorInfo(reason);
      setItems((old) => staleFallback(old));
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      if (refreshController.current === controller) {
        refreshController.current = null;
        setLoading(false);
      }
    }
  }

  useEffect(() => {
    void refresh();
    return () => refreshController.current?.abort();
  }, []);

  async function run(kind: ComponentKind, action: ComponentAction) {
    if (mutationLocked && action !== 'check') {
      setMessage('Изменения компонентов заблокированы до подтверждения recovery state.');
      return;
    }
    const destructive = action === 'uninstall';
    if (destructive && !(await confirmDialog.ask(`${componentNames[kind]} используется сетевыми маршрутами или может содержать рабочую конфигурацию. Продолжить удаление?`))) return;
    setBusy(kind);
    setStage(action === 'install' || action === 'update' ? 'Preflight → платформа → download → SHA-256 → install → service → health' : humanStatus(action));
    setMessage('');
    try {
      const result = await componentAction(kind, action, destructive, true);
      setStage(result.stages.map(humanStatus).join(' → '));
      setMessage(result.rollback_performed ? 'Новая версия не прошла health check. FlintRoute автоматически вернул предыдущую.' : result.changed ? 'Операция завершена.' : 'Изменений не понадобилось.');
      await refresh();
      setSelected(result.status);
    } catch (reason) {
      const info = errorInfo(reason);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(null);
    }
  }

  return <section>
    <PageHeader title="Внешние компоненты" text="Установка, проверка integrity, procd lifecycle, обновление и откат — из одного места. Ручные URL и shell-команды для обычного сценария не нужны." />
    {message && <p class="action-status">{message}</p>}
    {stage && <p class="source-note">Этапы: {stage}</p>}
    <Grid>{items.map((item) => <EntityCard title={componentNames[item.kind]} status={statusWithFreshness(item.ownership === 'foreign' ? 'foreign' : (item.installed ? item.health_state : 'not installed'), item)} onOpen={() => setSelected(item)} key={item.kind}>
      <InfoGrid items={[
        ['Версия', item.version || 'не установлена'],
        ['Поддерживаемая', item.latest_supported_version],
        ['Владелец', item.ownership === 'flintroute' ? 'FlintRoute' : item.ownership === 'foreign' ? 'Внешний ресурс' : 'Нет'],
        ['Сервис', item.service_state],
        ['Архитектура', item.architecture],
        ['Проверка', formatDateTime(item.last_successful_check)]
      ]} />
      <p>{componentNextStep(item)}</p>
      {item.managed && item.kind === 'xray' && <button onClick={() => navigate('VLESS-серверы')}>Добавить VLESS</button>}
      {item.managed && item.kind === 'zapret' && <button onClick={() => navigate('Zapret')}>Открыть настройку Zapret</button>}
      {item.managed && item.kind === 'tg_ws_proxy' && <button onClick={() => navigate('TG WS Proxy')}>Настроить Telegram transport</button>}
      {role === 'administrator' && <div class="actions">
         {item.ownership === 'absent' && <button class="primary" disabled={busy !== null || mutationLocked} onClick={() => run(item.kind, 'install')}>Установить</button>}
        {item.managed && <button disabled={busy !== null} onClick={() => run(item.kind, 'check')}>Проверить</button>}
         {item.managed && <button disabled={busy !== null || mutationLocked} onClick={() => run(item.kind, 'check_updates')}>Проверить обновления</button>}
         {item.managed && item.update_available && <button class="primary" disabled={busy !== null || mutationLocked} onClick={() => run(item.kind, 'update')}>Обновить</button>}
         {item.managed && <button disabled={busy !== null || mutationLocked} onClick={() => run(item.kind, 'restart')}>Перезапустить</button>}
         {item.managed && item.rollback_version && <button disabled={busy !== null || mutationLocked} onClick={() => run(item.kind, 'rollback')}>Откатить {item.rollback_version}</button>}
         {item.managed && <button class="danger" disabled={busy !== null || mutationLocked} onClick={() => run(item.kind, 'uninstall')}>Удалить</button>}
      </div>}
    </EntityCard>)}</Grid>
    {loading && <LoadingSkeleton />}
    {!loading && !items.length && !message && <EmptyState title="Компоненты не найдены" text="Backend не сообщил ни одного управляемого компонента. Повторите проверку или откройте диагностику." />}
    <DetailDrawer title={selected ? componentNames[selected.kind] : 'Компонент'} open={Boolean(selected)} onClose={() => setSelected(null)}>
      <InfoGrid items={[
        ['Обнаружен', selected?.detected ? 'Да' : 'Нет'], ['Управляется FlintRoute', selected?.managed ? 'Да' : 'Нет'], ['Владелец', selected?.ownership], ['Версия', selected?.version], ['Последняя поддерживаемая', selected?.latest_supported_version],
        ['Последняя upstream', selected?.latest_upstream_version], ['Источник', selected?.source], ['SHA-256', selected?.checksum],
        ['Service', selected?.service_state], ['Health', selected?.health_state], ['Причина', selected?.health_reason],
        ['Rollback', selected?.rollback_version], ['Последняя проверка', formatDateTime(selected?.last_checked_at)]
      ]} />
      {selected?.update_blocked_reason && <p class="reason">Обновление заблокировано: {selected.update_blocked_reason}</p>}
      <RawDisclosure value={selected} />
    </DetailDrawer>
    {confirmDialog.dialog}
  </section>;
}

export function Discovery({ data, configVersion, role, mutationLocked, refresh }: { data: DiscoveryStatus | null; configVersion: number; role: SessionInfo['role']; mutationLocked: boolean; refresh: () => Promise<void> }) {
  const [mode, setMode] = useState<DiscoveryStatus['mode']>(data?.mode ?? 'observe_only');
  const [hourly, setHourly] = useState(data?.max_new_rules_per_hour ?? 4);
  const [rollbacks, setRollbacks] = useState(data?.max_consecutive_rollbacks ?? 3);
  const [busy, setBusy] = useState(false);
  const [actionDomain, setActionDomain] = useState('');
  const [routeChoices, setRouteChoices] = useState<Record<string, string>>({});
  const [message, setMessage] = useState('');
  useEffect(() => {
    if (!data) return;
    setMode(data.mode);
    setHourly(data.max_new_rules_per_hour);
    setRollbacks(data.max_consecutive_rollbacks);
  }, [data?.mode, data?.max_new_rules_per_hour, data?.max_consecutive_rollbacks]);
  async function save(resetFailures = false) {
    if (mutationLocked) {
      setMessage('Настройка discovery заблокирована до подтверждения recovery state.');
      return;
    }
    setBusy(true);
    setMessage('Сохраняю режим discovery…');
    try {
      const result = await configureDiscovery(mode, hourly, rollbacks, configVersion, resetFailures);
      if (!result.applied || result.dataplane_changed) throw new Error('Backend не подтвердил безопасное изменение режима.');
      setMessage('Режим discovery применён без перезапуска DNS и маршрутизации.');
      await refresh();
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : 'Настройка discovery не применена.');
    } finally {
      setBusy(false);
    }
  }
  async function actOnSuggestion(item: Record<string, unknown>, action: 'apply' | 'ignore') {
    const domain = String(item.domain ?? '').trim();
    if (!domain || role !== 'administrator' || mutationLocked) return;
    setActionDomain(domain);
    setMessage('');
    try {
      if (action === 'apply') {
        const route = typeof item.route === 'string' ? item.route : undefined;
        const result = await applyDiscoverySuggestion(domain, route);
        if (!result.applied || !result.post_apply_proof) throw new Error('Backend не подтвердил назначение маршрута и post-apply proof.');
        const proof = result.post_apply_proof_kind === 'revision_bound_path_evidence'
          ? 'сохранено подтверждение текущей ревизии'
          : 'путь подтверждён';
        setMessage(`Маршрут ${result.route} назначен для ${result.domain}; ${proof}.`);
      } else {
        await ignoreDiscoverySuggestion(domain);
        setMessage(`Предложение для ${domain} скрыто.`);
      }
      await refresh();
    } catch (reason) {
      const info = errorInfo(reason);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setActionDomain('');
    }
  }
  if (!data) return <Generic title="Discovery" text="Загружаю состояние…" />;
  const autoApplyBlocked = data.mode === 'auto_apply_verified' && data.auto_apply_available === false;
  const effectiveMode = data.effective_mode ?? data.mode;
  return <section class="grid">
    <Card title="Наблюдение за доменами">
      <div class="row"><b>{data.observation_source?.status === 'disabled' ? 'Discovery выключен' : data.observation_source?.status === 'receiving' ? 'Вижу DNS-запросы' : data.observation_source?.status === 'stale' ? 'Последние DNS-записи устарели' : data.observation_source?.status === 'listening' ? 'Жду новые запросы' : data.observation_source?.status === 'waiting' ? 'Журнал DNS ещё не создан' : 'Источник DNS недоступен'}</b><span>{humanStatus(data.observation_source?.status)}</span><small>{data.observation_source?.last_updated ? `последний запрос: ${formatDateTime(data.observation_source.last_updated)}` : textValue(data.observation_source?.reason, 'Источник ещё не создал журнал')}</small></div>
      <div class="row"><span>Очередь проверок</span><b>{data.queue_depth ?? 0} / {data.queue_capacity || '—'}</b><small>Активных route jobs: {data.active_probe_jobs ?? 0}; отброшено наблюдений: {data.observation_source?.dropped ?? 0}</small></div>
      <p>{data.observation_source?.status === 'disabled' ? 'Discovery не включён и не читает журнал dnsmasq. Включи наблюдение ниже, затем открой новый домен с устройства в LAN или Wi-Fi.' : data.observation_source?.status === 'waiting' || data.observation_source?.status === 'unavailable' ? 'Discovery включён, но журнал DNS ещё не создан или недоступен. Это не означает, что весь DNS сломан: проверь, что клиент использует DNS роутера и что dnsmasq запущен.' : data.observation_source?.status === 'stale' ? 'Журнал dnsmasq есть, но новых записей не было больше пяти минут. Discovery наблюдает DNS-запросы, а не все пакеты. Проверь DNS клиента и открой новый домен.' : 'Discovery видит DNS-наблюдения, а не отдельные пакеты. Открывай сайты с устройства в LAN или Wi-Fi — новые домены появятся в Потоке решений.'}</p>
    </Card>
    <Card title="Режим discovery">
      <div class="row"><b>{textValue(data.mode, 'неизвестный режим')}</b><span>{autoApplyBlocked ? `только предложения (${textValue(effectiveMode, 'suggest')})` : data.paused ? `остановлен: ${textValue(data.paused_reason, 'причина не указана')}` : 'активен'}</span><small>{textValue(data.applied_last_hour, '0')} правил за последний час</small></div>
      {autoApplyBlocked && <p class="action-status">Автоназначение недоступно: {textValue(data.auto_apply_reason, 'route-assignment runtime не подключён')}. Discovery оставляет проверенные результаты как предложения и не меняет dataplane.</p>}
      <p>observe_only только журналирует; suggest добавляет предложения; auto_apply_verified применяет лишь PathVerified; locked не запускает проверки.</p>
      {role === 'administrator' && <div class="smart-dns-editor">
        <label><span>Режим</span><select value={mode} onChange={(event) => setMode((event.target as HTMLSelectElement).value as DiscoveryStatus['mode'])}>
          <option value="observe_only">observe_only</option><option value="suggest">suggest</option><option value="auto_apply_verified">auto_apply_verified</option><option value="locked">locked</option>
        </select></label>
        <label><span>Новых правил в час</span><input type="number" min="1" max="1000" value={hourly} onInput={(event) => setHourly(Number((event.target as HTMLInputElement).value))} /></label>
        <label><span>Rollback до остановки</span><input type="number" min="1" max="100" value={rollbacks} onInput={(event) => setRollbacks(Number((event.target as HTMLInputElement).value))} /></label>
         <button class="primary" disabled={busy || mutationLocked || !configVersion} onClick={() => save(false)}>{busy ? 'Применяю…' : 'Применить режим'}</button>
         {data.paused && <button disabled={busy || mutationLocked || !configVersion} onClick={() => save(true)}>Сбросить circuit breaker</button>}
         {mutationLocked && <p class="action-status">Изменения discovery временно заблокированы recovery fence.</p>}
        {message && <p class="action-status">{message}</p>}
      </div>}
    </Card>
    <Card title="Предложения">
      {(data.suggestions ?? []).map((item: Record<string, unknown>) => {
        const domain = String(item.domain ?? '');
        const verified = item.path_verified === true && Boolean(item.route);
        const busySuggestion = actionDomain === domain;
        const candidates = Array.isArray(item.candidates) ? item.candidates.filter((candidate): candidate is Record<string, unknown> => Boolean(candidate && typeof candidate === 'object')) : [];
        const verifiedCandidates = candidates.filter((candidate) => candidate.path_verified === true && typeof candidate.route === 'string' && candidate.route);
        const classificationState = textValue(item.classification_state, 'UNKNOWN');
        const selectedRoute = routeChoices[domain] ?? String(item.route ?? '');
        const applyItem = selectedRoute && selectedRoute !== String(item.route ?? '') ? { ...item, route: selectedRoute } : item;
        return <div class="row discovery-suggestion" key={domain || 'unknown'}><div><b>{textValue(domain, 'Домен не указан')}</b><small>{textValue(item.category, 'Категория не определена')} · classification: {classificationState} · {textValue(item.route_type, 'Маршрут не определён')} · {textValue(item.route, 'не выбран')}</small>{item.classification_reason && <small>Evidence: {textValue(item.classification_reason, '')}</small>}{candidates.length > 0 && <div class="suggestion-candidates">{candidates.map((candidate, index) => <small key={`${String(candidate.route ?? index)}:${index}`}>{textValue(candidate.route, 'Маршрут')} — {candidate.path_verified === true ? 'PASS' : textValue(candidate.status, 'FAIL')}{candidate.selection_score !== undefined ? ` · score ${textValue(candidate.selection_score, '')}` : ''}{candidate.end_to_end_latency_available === true ? ` · e2e ${textValue(candidate.end_to_end_latency_ms, '')} мс` : ''}{candidate.reason ? ` · ${textValue(candidate.reason, '')}` : ''}</small>)}</div>}</div><span>{verified ? 'Путь подтверждён' : textValue(item.probe_state, 'Проверка не завершена')}</span><small>{textValue(item.reason, 'Причина не указана')} · наблюдений: {textValue(item.count, '1')}</small>{role === 'administrator' && <div class="actions">{verifiedCandidates.length > 1 && <label class="inline-select"><span>Изменить маршрут</span><select value={selectedRoute} disabled={mutationLocked || busySuggestion} onChange={(event) => setRouteChoices((old) => ({ ...old, [domain]: (event.target as HTMLSelectElement).value }))}>{verifiedCandidates.map((candidate, index) => <option value={String(candidate.route)} key={`${String(candidate.route)}:${index}`}>{String(candidate.route)}</option>)}</select></label>}<button class="primary" disabled={!verified || mutationLocked || busySuggestion} onClick={() => void actOnSuggestion(applyItem, 'apply')}>{busySuggestion ? 'Проверяю…' : 'Применить'}</button><button disabled={mutationLocked || busySuggestion} onClick={() => void actOnSuggestion(item, 'ignore')}>Игнорировать</button></div>}</div>;
      })}
      {!data.suggestions?.length && <p class="empty-state">Предложений пока нет</p>}
    </Card>
    <Card title="Последние наблюдения">
      <div class="row"><span>Наблюдений в памяти</span><b>{data.observations?.length ?? 0}</b><small>Очередь ограничена; запись DNS не создаёт bbolt write на каждый запрос.</small></div>
      {(data.observations ?? []).slice(0, 20).map((item) => <div class="row" key={`${item.domain}:${item.observed_at}`}><b>{item.domain}</b><span>{item.query_type ?? 'DNS'}</span><small>{item.client || 'клиент скрыт'} · {item.observed_at ? formatDateTime(item.observed_at) : 'время неизвестно'}</small></div>)}
      {!data.observations?.length && <p class="empty-state">Новых DNS-наблюдений пока нет. Устройство должно использовать DNS роутера.</p>}
    </Card>
  </section>;
}

export type TrafficView = Omit<TrafficSnapshot, 'interfaces'> & { interfaces: Array<TrafficSnapshot['interfaces'][number] & { rx_bps?: number; tx_bps?: number }> };

export function withTrafficRates(previous: TrafficView, current: TrafficSnapshot): TrafficView {
  const elapsed = (Date.parse(current.collected_at) - Date.parse(previous.collected_at)) / 1000;
  const old = new Map(previous.interfaces.map((item) => [item.name, item]));
  return {
    ...current,
    interfaces: current.interfaces.map((item) => {
      const before = old.get(item.name);
      if (!before || !Number.isFinite(elapsed) || elapsed <= 0) return item;
      return {
        ...item,
        rx_bps: item.rx_bytes >= before.rx_bytes ? (item.rx_bytes - before.rx_bytes) / elapsed : 0,
        tx_bps: item.tx_bytes >= before.tx_bytes ? (item.tx_bytes - before.tx_bytes) / elapsed : 0
      };
    })
  };
}

export function Traffic({ data }: { data: TrafficView }) {
  return (
    <Card title="Трафик интерфейсов">
      <div class="row"><b>{humanStatus(data.status)}</b><span>{textValue(data.source, 'источник не указан')}</span><small>{data.collected_at ? new Date(data.collected_at).toLocaleTimeString() : textValue(data.reason, 'нет данных')}</small></div>
      {data.interfaces.map((item) => (
        <div class={`traffic-row ${(item.rx_errors || item.tx_errors) ? 'warn' : ''}`} key={item.name}>
          <b class="mono">{item.name}</b>
          <span>RX {formatBytes(item.rx_bytes)} · {formatRate(item.rx_bps)}</span>
          <span>TX {formatBytes(item.tx_bytes)} · {formatRate(item.tx_bps)}</span>
          <small>пакеты {item.rx_packets}/{item.tx_packets} · ошибки {item.rx_errors}/{item.tx_errors}</small>
        </div>
      ))}
      {data.interfaces.length === 0 && <p>{textValue(data.reason, 'Счётчики интерфейсов недоступны')}</p>}
    </Card>
  );
}

function formatBytes(value: number): string {
  if (!Number.isFinite(value)) return 'n/a';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit++;
  }
  return `${amount.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatRate(value?: number): string {
  return value === undefined ? 'сбор базовой точки' : `${formatBytes(value)}/с`;
}

export function ExternalSOCKS({ configVersion, role, mutationLocked, refresh, navigate }: { configVersion: number; role: SessionInfo['role']; mutationLocked: boolean; refresh: () => Promise<void>; navigate: (screen: string) => void }) {
  const [status, setStatus] = useState<any>(null);
  const [endpoint, setEndpoint] = useState('');
  const [domain, setDomain] = useState('');
  const [report, setReport] = useState<any>(null);
  const [checked, setChecked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    getExternalSOCKS(controller.signal)
      .then(setStatus)
      .catch((error) => {
        if (error instanceof Error && error.name === 'AbortError') return;
        setMessage(error instanceof Error ? error.message : 'External SOCKS API недоступен');
      });
    return () => controller.abort();
  }, []);
  async function check() {
    if (!endpoint.trim() || !domain.trim()) {
      setMessage('Укажи адрес уже запущенного внешнего SOCKS5 и домен для проверки. Это дополнительная интеграция: FlintRoute сам прокси не устанавливает.');
      return;
    }
    setBusy(true); setChecked(false); setMessage('Проверяю TCP, SOCKS5, remote DNS, TLS и HTTP…');
    try {
      const result = await checkExternalSOCKS(endpoint.trim(), domain.trim(), configVersion);
      setReport(result.report); setChecked(true); setMessage('Endpoint проверен. Конфигурация ещё не менялась.');
    } catch (error) { setReport(null); setMessage(error instanceof Error ? error.message : 'Проверка external SOCKS провалена.'); }
    finally { setBusy(false); }
  }
  async function activate() {
    if (mutationLocked) { setMessage('Внешний SOCKS-маршрут заблокирован до подтверждения recovery state.'); return; }
    setBusy(true); setMessage('Проверяю и включаю внешний SOCKS-маршрут…');
    try {
      const result = await activateExternalSOCKS(endpoint.trim(), domain.trim(), configVersion, true);
      if (!result.change) throw new Error('Backend не создал транзакцию внешнего SOCKS-маршрута.');
      if (result.auto_apply_started) {
        const change = await waitForChangeTerminal(result.change.id);
        setMessage(change.state === 'committed'
          ? 'Внешний SOCKS-маршрут включён, commit подтверждён.'
          : isChangePending(change.state)
            ? 'Внешний SOCKS всё ещё применяется. Открой «Операции» для текущего этапа.'
            : `Внешний SOCKS не включён: операция завершилась состоянием ${change.state}. Предыдущая конфигурация сохранена.`);
      } else {
        setMessage('Операция внешнего SOCKS создана, но worker не запустился. Открой «Операции» для ручного продолжения.');
        navigate('Операции');
      }
      setChecked(false); await refresh();
    } catch (error) { setMessage(error instanceof Error ? error.message : 'External SOCKS не включён; транзакция откатилась или ждёт устройство.'); }
    finally { setBusy(false); }
  }
  return <section class="grid">
    <Card title="Внешний SOCKS5 · дополнительная интеграция">
      <div class="row"><b>{humanStatus(status?.status ?? 'загрузка')}</b><span>управление процессом: внешнее</span><small>Используй только если у тебя уже есть отдельный SOCKS5. FlintRoute его не устанавливает, не связывает с TGWS и не считает обязательным для работы.</small></div>
      {role === 'administrator' && <div class="change-editor">
        <label><span>Адрес внешнего SOCKS5</span><input class="mono" placeholder="host:port" value={endpoint} onInput={(event) => { setEndpoint((event.target as HTMLInputElement).value); setChecked(false); }} /></label>
        <label><span>Домен для remote DNS + TLS/HTTP</span><input class="mono" placeholder="example.com" value={domain} onInput={(event) => { setDomain((event.target as HTMLInputElement).value); setChecked(false); }} /></label>
        <button class="primary" disabled={busy || !configVersion} onClick={check}>{busy ? 'Проверяю…' : 'Проверить endpoint'}</button>
        <button class="primary" disabled={busy || mutationLocked || !checked || !configVersion} onClick={activate}>Применить маршрут</button>
        {message && <div class="action-status"><p>{message}</p>{message.includes('Операции') && <button type="button" onClick={() => navigate('Операции')}>Открыть центр операций</button>}</div>}
      </div>}
    </Card>
    {report && <Card title="Результат проверки"><div class="row"><b>{report.ready ? 'READY' : 'FAILED'}</b><span>SOCKS5: {report.socks5_handshake ? 'OK' : 'FAIL'}</span><small>TLS: {report.tls_verified ? 'OK' : 'FAIL'} · HTTP {report.http_status || '—'}</small></div></Card>}
  </section>;
}

export function TGWS({ role, mutationLocked, navigate }: { role: SessionInfo['role']; mutationLocked: boolean; navigate: (screen: string) => void }) {
  const [status, setStatus] = useState<any>(null);
  const [port, setPort] = useState(1443);
  const [fakeTLS, setFakeTLS] = useState('');
  const [connectLink, setConnectLink] = useState('');
  const [connectQR, setConnectQR] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  async function load(signal?: AbortSignal) {
    try {
      const value = await getTGWS(signal);
      if (signal?.aborted) return;
      setStatus(value);
      if (value.port) setPort(value.port);
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') return;
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    }
  }
  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, []);
  useEffect(() => {
    let cancelled = false;
    setConnectQR('');
    if (connectLink) {
      void QRCode.toDataURL(connectLink, { width: 256, margin: 2, errorCorrectionLevel: 'M' })
        .then((value) => { if (!cancelled) setConnectQR(value); })
        .catch(() => { if (!cancelled) setMessage('Ссылка готова, но QR-код построить не удалось. Используй кнопку «Открыть в Telegram».'); });
    }
    return () => { cancelled = true; };
  }, [connectLink]);
  async function configure() {
    if (mutationLocked) { setMessage('Настройка TG WS Proxy заблокирована до подтверждения recovery state.'); return; }
    setBusy(true);
    setConnectLink('');
    setMessage('Создаю секрет, запускаю procd-сервис и проверяю listener и доступ к Telegram DC…');
    try {
      const result = await configureTGWS(port, fakeTLS.trim());
      setStatus(result.status);
      setConnectLink(result.connect_link);
      setMessage('Роутерная часть готова. Открой одноразовую ссылку в Telegram: без этого клиентский путь нельзя честно считать проверенным.');
    } catch (error) {
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(false);
    }
  }
  return <section>
    <PageHeader title="TG WS Proxy" text="Управляемый MTProto proxy для Telegram-клиента. Это не SOCKS5 и не прозрачный перехват всего трафика телефона." />
    <div class="grid">
      <Card title="Состояние транспорта">
        <InfoGrid items={[
          ['Компонент', status?.installed ? 'Установлен' : 'Не установлен'],
          ['Конфигурация', status?.configured ? 'Готова' : 'Не настроена'],
          ['procd', status?.running ? 'Работает' : 'Остановлен'],
          ['Локальный listener', status?.local_listener ? 'OK' : 'Не подтверждён'],
          ['Telegram DC', status?.upstream_reachable ? 'Доступен' : 'Не подтверждён'],
          ['Клиентский путь', status?.client_path_verified ? 'Подтверждён' : 'Нужно открыть ссылку в Telegram']
        ]} />
        {status?.reason && <p>{textValue(status.reason, 'Причина не указана')}</p>}
        {!status?.installed && <button onClick={() => navigate('Компоненты')}>Перейти к установке</button>}
      </Card>
      {role === 'administrator' && <Card title="Настройка">
        <div class="change-editor">
          <label><span>Порт</span><input type="number" min="1024" max="65535" value={port} onInput={(event) => setPort(Number((event.target as HTMLInputElement).value))} /></label>
          <label><span>Fake TLS domain (необязательно)</span><input value={fakeTLS} placeholder="например, ваш домен" onInput={(event) => setFakeTLS((event.target as HTMLInputElement).value)} /></label>
          <small>Адрес роутера берётся из текущего соединения с UI. Секрет генерируется на роутере и не возвращается повторно.</small>
          <button class="primary" disabled={busy || mutationLocked || !status?.installed} onClick={configure}>{busy ? 'Проверяю…' : 'Настроить и запустить'}</button>
          {mutationLocked && <p class="action-status">Управление транспортом временно заблокировано recovery fence.</p>}
          {message && <p class="action-status">{message}</p>}
        </div>
      </Card>}
      {connectLink && <Card title="Одноразовая ссылка подключения">
        <p>Ссылка содержит секрет. Она показывается только сейчас и не попадёт в обычный API или журнал.</p>
        {connectQR && <img src={connectQR} width="256" height="256" alt="QR-код для подключения Telegram к TG WS Proxy" />}
        <div class="actions"><a class="button primary" href={connectLink}>Открыть в Telegram</a><button onClick={() => void navigator.clipboard.writeText(connectLink)}>Копировать</button></div>
      </Card>}
    </div>
  </section>;
}

export function Telegram({ role, mutationLocked, events: systemEvents }: { role: SessionInfo['role']; mutationLocked: boolean; events: EventItem[] }) {
  const [overview, setOverview] = useState<any>(null);
  const [token, setToken] = useState('');
  const [chatID, setChatID] = useState('');
  const [enabled, setEnabled] = useState(false);
  const [events, setEvents] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  async function load(signal?: AbortSignal) {
    try {
      const value = await getTelegram(signal);
      if (signal?.aborted) return;
      setOverview(value);
      setEnabled(Boolean(value.notifications?.enabled));
      setEvents(stringArray(value.notifications?.event_types));
    }
    catch (error) {
      if (error instanceof Error && error.name === 'AbortError') return;
      setMessage(error instanceof Error ? error.message : 'Telegram API недоступен');
    }
  }
  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, []);
  async function save() {
    if (mutationLocked) { setMessage('Настройка уведомлений заблокирована до подтверждения recovery state.'); return; }
    setBusy(true); setMessage('Проверяю токен и доступ к чату…');
    try { await configureTelegram(token.trim(), chatID.trim(), enabled, events); setToken(''); setChatID(''); await load(); setMessage(enabled ? 'Конфигурация проверена и сохранена.' : 'Уведомления выключены, настройки сохранены.'); }
    catch (error) { setMessage(error instanceof Error ? error.message : 'Telegram не настроен.'); }
    finally { setBusy(false); }
  }
  async function sendTest() {
    setBusy(true); setMessage('Отправляю тест…');
    try { await testTelegram(); await load(); setMessage('Тестовое сообщение доставлено.'); }
    catch (error) { setMessage(error instanceof Error ? error.message : 'Тест не доставлен.'); }
    finally { setBusy(false); }
  }
  if (!overview) return <Generic title="Telegram" text={message || 'Загружаю состояние…'} />;
  const state = overview.notifications;
  const telegramEvents = systemEvents.filter((event) => event.type.startsWith('telegram.') || event.type.startsWith('notification.')).sort((a, b) => Date.parse(b.time) - Date.parse(a.time));
  return <section><PageHeader title="Telegram" text="Уведомления — отдельная подсистема и не участвуют в routing bootstrap." /><div class="grid"><Card title="Telegram notifications">
    <div class="row"><b>{humanStatus(state.state)}</b><span>{state.enabled ? 'включены' : 'выключены'}</span><small>очередь {textValue(state.queue_depth, '0')}/{textValue(state.queue_capacity, '0')}, ошибок подряд: {textValue(state.consecutive_failures, '0')}</small></div>
    {role === 'administrator' && <div class="change-editor">
      <label><span>Bot token {state.token_configured ? '(уже сохранён; пустое поле оставит прежний)' : ''}</span><input type="password" autocomplete="new-password" value={token} onInput={(event) => setToken((event.target as HTMLInputElement).value)} /></label>
      <label><span>Chat ID {state.chat_configured ? '(уже сохранён; пустое поле оставит прежний)' : ''}</span><input class="mono" value={chatID} onInput={(event) => setChatID((event.target as HTMLInputElement).value)} /></label>
      <label><input type="checkbox" checked={enabled} onChange={(event) => setEnabled((event.target as HTMLInputElement).checked)} /> Включить доставку</label>
      <div class="chips">{overview.event_types.map((name: string) => <label class="chip" key={name}><input type="checkbox" checked={events.includes(name)} onChange={(event) => setEvents((old) => (event.target as HTMLInputElement).checked ? [...old, name] : old.filter((item) => item !== name))} /> {name}</label>)}</div>
      <button class="primary" disabled={busy || mutationLocked} onClick={save}>{busy ? 'Проверяю…' : 'Проверить и сохранить'}</button>
      <button class="primary" disabled={busy || !state.enabled} onClick={sendTest}>Отправить тест</button>
      {message && <p class="action-status">{message}</p>}
    </div>}
  </Card><Card title="Последние доставки">{telegramEvents.slice(0, 10).map((event) => <EventRow event={event} key={`${event.time}:${event.id}`} />)}{!telegramEvents.length && <EmptyState title="Событий Telegram нет" text="После теста или доставки здесь появится статус без токена и chat ID." />}</Card></div></section>;
}

export function DecisionFlow({ events, discovery }: { events: EventItem[]; discovery: DiscoveryStatus | null }) {
  const [retention, setRetention] = useState(() => Number(localStorage.getItem('decision-retention-minutes') || 30));
  const [selected, setSelected] = useState<ReturnType<typeof toDecisionCard> | null>(null);
  const [adminOpen, setAdminOpen] = useState(false);
  const [filters, setFilters] = useState({ device: '', domain: '', service: '', category: '', route: '', status: '', verified: 'all', fallback: 'all' });
  const cutoff = Date.now() - retention * 60 * 1000;
  const decisions = events.filter(isDecisionEvent).map(toDecisionCard)
    .filter((item) => Date.parse(item.time) >= cutoff)
    .filter((item) => {
      const has = (value: string, query: string) => !query || value.toLowerCase().includes(query.toLowerCase());
      return has(`${item.device} ${item.ip}`, filters.device) && has(item.domain, filters.domain) && has(item.service, filters.service) &&
        has(item.category, filters.category) && has(item.route, filters.route) && has(item.status, filters.status) &&
        (filters.verified === 'all' || item.verified === (filters.verified === 'yes')) &&
        (filters.fallback === 'all' || item.fallback === (filters.fallback === 'yes'));
    }).sort((a, b) => Date.parse(b.time) - Date.parse(a.time));
  const adminEvents = events.filter(isAdministrativeEvent).sort((a, b) => Date.parse(b.time) - Date.parse(a.time));
  function updateRetention(value: number) {
    setRetention(value);
    localStorage.setItem('decision-retention-minutes', String(value));
  }
  return <section><PageHeader title="Поток решений" text="Что запросило устройство, какой путь выбрал FlintRoute и чем закончилась проверка.">
    <label class="inline-control">Хранить на экране<select value={retention} onChange={(event) => updateRetention(Number(event.currentTarget.value))}><option value="15">15 минут</option><option value="30">30 минут</option><option value="60">1 час</option><option value="120">2 часа</option></select></label>
    <button onClick={() => setAdminOpen(true)}>Административный журнал</button>
  </PageHeader>
  <div class="filter-bar">
    {([['device', 'Устройство или IP'], ['domain', 'Домен'], ['service', 'Сервис'], ['category', 'Категория'], ['route', 'Маршрут'], ['status', 'Статус']] as const).map(([key, label]) => <label><span>{label}</span><input value={filters[key]} onInput={(event) => setFilters({ ...filters, [key]: event.currentTarget.value })} /></label>)}
    <label><span>PathVerified</span><select value={filters.verified} onChange={(event) => setFilters({ ...filters, verified: event.currentTarget.value })}><option value="all">Все</option><option value="yes">Да</option><option value="no">Нет</option></select></label>
    <label><span>Fallback</span><select value={filters.fallback} onChange={(event) => setFilters({ ...filters, fallback: event.currentTarget.value })}><option value="all">Все</option><option value="yes">Был</option><option value="no">Не было</option></select></label>
  </div>
  <div class="decision-list">{decisions.map((decision) => <article class="decision-card" key={decision.id}>
    <header><div><span>{decision.device}{decision.ip ? ` / ${decision.ip}` : ''}</span><time>{new Date(decision.time).toLocaleTimeString()}</time></div><StatusBadge value={decision.policyState === 'suggested' ? 'Предложение — не применено' : decision.policyState === 'pending_auto_apply' ? 'Ожидает автоматического применения' : decision.status} /></header>
    <div class="decision-main"><div><small>Домен</small><b>{decision.domain}</b><span>{decision.service}</span></div><div><small>Стратегия</small><b>{decision.strategy}</b><span>{decision.category}</span></div><div><small>Маршрут</small><b>{decision.route}</b><span>{decision.fallback ? `Fallback: ${decision.fallbackPath.join(' → ') || 'да'}` : 'Без fallback'}</span></div></div>
    {(() => { const presentation = decisionVerificationPresentation(decision); return <footer><span class={presentation === 'verified' ? 'verified' : presentation === 'no_safe_route' ? 'unverified' : 'pending'}>{verificationPresentationLabel(presentation)}</span><span>{decision.endToEndLatencyAvailable && decision.endToEndLatencyMS !== undefined ? `End-to-end: ${decision.endToEndLatencyMS} мс` : 'End-to-end: не измерена'}</span><span>{decision.routeLatencyAvailable && decision.routeLatencyMS !== undefined ? `Задержка маршрута: ${decision.routeLatencyMS} мс` : 'Задержка маршрута: не измерена'}</span><span>{decision.durationMS !== undefined ? `Проверка: ${decision.durationMS} мс` : 'Время проверки не измерено'}</span><button onClick={() => setSelected(decision)}>Открыть</button></footer>; })()}
  </article>)}</div>
  {!decisions.length && <EmptyState title="Решений за выбранный период нет" text={discovery?.observation_source?.status === 'disabled' ? 'Discovery выключен и пока ничего не наблюдает. Включи его в разделе Discovery.' : discovery?.observation_source?.status === 'waiting' || discovery?.observation_source?.status === 'unavailable' || discovery?.observation_source?.status === 'stale' ? 'Discovery не получает свежие DNS-наблюдения. Открой раздел Discovery и проверь DNS клиента и dnsmasq.' : 'Discovery наблюдает DNS-запросы, а не все пакеты. Открой новый сайт с устройства в LAN или Wi-Fi.'} />}
  <DetailDrawer title={selected ? `${selected.domain} · ${selected.route}` : 'Решение'} open={Boolean(selected)} onClose={() => setSelected(null)}>
    {selected && <DecisionDetails decision={selected} />}
  </DetailDrawer>
  <DetailDrawer title="Административный журнал" open={adminOpen} onClose={() => setAdminOpen(false)} wide>
    <p>Технические события apply, verify, rollback и recovery не смешиваются с пользовательскими сетевыми решениями.</p>
    {adminEvents.map((event) => <EventRow event={event} key={`${event.time}:${event.id}`} />)}
    {!adminEvents.length && <EmptyState title="Журнал пуст" text="Системных событий ещё нет." />}
  </DetailDrawer>
  </section>;
}

function DecisionDetails({ decision }: { decision: ReturnType<typeof toDecisionCard> }) {
  const d = decision.details;
  return <><InfoGrid items={[
    ['Classification confidence', decision.classificationConfidence !== undefined ? `${Math.round(decision.classificationConfidence * 100)}%` : null],
    ['Decision confidence', decision.decisionConfidence !== undefined ? `${Math.round(decision.decisionConfidence * 100)}%` : null]
  ]} /><InfoGrid items={[
    ['Устройство', decision.device], ['IP', decision.ip], ['Время', formatDateTime(decision.time)], ['Домен', decision.domain],
    ['Сервис', decision.service], ['Классификация', decision.category], ['Состояние классификации', decision.classificationState], ['Основание классификации', decision.classificationReason || 'не указано'], ['Состояние проверки', decision.probeState], ['Состояние политики', decision.policyState], ['Правило', decision.rule], ['Стратегия', decision.strategy],
    ['Маршрут', decision.route], ['Fallback', decision.fallbackPath.join(' → ') || (decision.fallback ? 'Выполнен' : 'Нет')],
    ['PathVerified', decision.verified ? 'Да' : 'Нет'], ['Итог', decision.status], ['Решение заняло', decision.durationMS !== undefined ? `${decision.durationMS} мс` : null],
    ['DNS', d.dns_status], ['Destination IP', d.destination_ip], ['Задержка маршрута', decision.routeLatencyMS !== undefined ? `${decision.routeLatencyMS} мс` : null],
    ['HTTP/TLS', d.http_status ?? d.tls_status], ['nft mark', d.nft_mark], ['Routing table', d.routing_table], ['Выходной интерфейс', d.egress_interface],
    ['Xray outbound', d.xray_outbound], ['SOCKS endpoint', d.socks_endpoint], ['Policy ID', d.policy_id], ['Revision', d.revision_id], ['Transaction ID', d.transaction_id],
    ['Route latency evidence', decision.routeLatencyAvailable && decision.routeLatencyMS !== undefined ? `${decision.routeLatencyMS} ms` : 'unavailable'],
    ['End-to-end service latency', decision.endToEndLatencyAvailable && decision.endToEndLatencyMS !== undefined ? `${decision.endToEndLatencyMS} ms` : 'unavailable'],
    ['Selection score', decision.selectionScore !== undefined ? String(decision.selectionScore) : 'unavailable'],
    ['Path verification duration', decision.verificationDurationMS !== undefined ? `${decision.verificationDurationMS} ms` : 'unavailable']
  ]} />
  <h3>Кандидаты</h3><EvidenceList values={decision.candidates} empty="Backend не передал список кандидатов." />
  <h3>Временная шкала</h3><EvidenceList values={decision.timeline} empty="Подробная временная шкала отсутствует." />
  <RawDisclosure value={decision.raw} /></>;
}

export function Diagnostics({ system, diagnostics, lifecycle, storage }: { system: any; diagnostics: any; lifecycle: any; storage: any }) {
  const sections = [
    { title: 'Платформа', value: system, summary: `${textValue(system?.hostname, 'Router')} · ${textValue(system?.model)}${system?.reason ? ` · ${system.reason}` : ''}` },
    { title: 'Сеть и возможности', value: diagnostics, summary: `${humanStatus(diagnostics?.status)}${diagnostics?.reason ? ` · ${diagnostics.reason}` : ''}` },
    { title: 'Lifecycle', value: lifecycle, summary: `${humanStatus(lifecycle?.status)}${lifecycle?.reason ? ` · ${lifecycle.reason}` : ''}` },
    { title: 'Хранилище', value: storage, summary: `${humanStatus(storage?.status)}${storage?.reason ? ` · ${storage.reason}` : ''}` }
  ];
  const [selected, setSelected] = useState<any>(null);
  return <section><PageHeader title="Диагностика" text="Сначала — понятное состояние. Полный технический ответ API открывается отдельно." /><Grid>{sections.map((item) => <EntityCard title={item.title} status={item.value?.status} onOpen={() => setSelected(item)}><p>{item.summary}</p><small>{formatDateTime(item.value?.collected_at)}</small></EntityCard>)}</Grid>
    <DetailDrawer title={selected?.title ?? 'Диагностика'} open={Boolean(selected)} onClose={() => setSelected(null)}><DiagnosticDetails value={selected?.value} /><RawDisclosure value={selected?.value} /></DetailDrawer></section>;
}

function DiagnosticDetails({ value }: { value: any }) {
  const record = asRecord(value);
  const capabilities = asRecord(record.capabilities);
  const rows = Object.entries({ ...record, ...capabilities }).filter(([, item]) => ['string', 'number', 'boolean'].includes(typeof item)).slice(0, 24);
  return <InfoGrid items={rows.map(([key, item]) => [key.replace(/_/g, ' '), item])} />;
}

export function Security({ data, summary }: { data: any; summary: any }) {
  const [selected, setSelected] = useState<any>(null);
  const checks = asArray(data?.checks).map(asRecord);
  return <section><PageHeader title="Безопасность" text="Каждая проверка объясняет риск и действие. Код можно использовать для поиска в документации и логах." />
    <div class="security-summary"><StatusBadge value={data?.status ?? summary?.status} /><span>Секреты: {textValue(summary?.secrets, 'скрыты')}</span><span>Auth: {humanStatus(summary?.auth)}</span></div>
    <Grid>{checks.map((check) => <EntityCard title={textValue(check.name ?? check.id, 'Проверка')} status={check.status ?? check.severity} onOpen={() => setSelected(check)}><StatusLine label="Severity" value={check.severity} /><p>{textValue(check.message ?? check.explanation, 'Описание отсутствует')}</p><small class="mono">{textValue(check.code ?? check.id, 'security_check')}</small></EntityCard>)}</Grid>
    {!checks.length && <EmptyState title="Подробный аудит недоступен" text="Базовая защита API показана выше. Для полного аудита backend должен разрешить диагностический endpoint." />}
    <DetailDrawer title={textValue(selected?.name ?? selected?.id, 'Проверка безопасности')} open={Boolean(selected)} onClose={() => setSelected(null)}><InfoGrid items={[["Код", selected?.code ?? selected?.id], ["Severity", selected?.severity], ["Статус", selected?.status], ["Причина", selected?.message ?? selected?.explanation], ["Что делать", selected?.action ?? selected?.required_action]]} /><RawDisclosure value={selected} /></DetailDrawer>
  </section>;
}

export function Recovery({ revisions, backups, lifecycle }: { revisions: RevisionSummary | null; backups: any; lifecycle: any }) {
  const [selected, setSelected] = useState<any>(null);
  const revisionItems = asArray(revisions?.items);
  const backupItems = asArray(backups?.items);
  return <section><PageHeader title="Ревизии и recovery" text="Активная конфигурация, история подтверждений и проверенные резервные копии." />
    <div class="summary-strip"><StatusLine label="Активная revision" value={revisions?.active_revision} /><StatusLine label="Config version" value={revisions?.config_version} /><StatusLine label="Recovery" value={lifecycle?.recovery?.status ?? lifecycle?.status} /></div>
    <h2>Ревизии</h2><Grid>{revisionItems.map((raw, index) => { const item = asRecord(raw); return <EntityCard title={textValue(item.id ?? item.revision_id, `Revision ${index + 1}`)} status={item.status ?? item.state} onOpen={() => setSelected({ kind: 'revision', ...item })}><p>{formatDateTime(item.committed_at ?? item.created_at)}</p><small>{textValue(item.reason ?? item.description, 'Подтверждённая конфигурация')}</small></EntityCard>; })}</Grid>
    {!revisionItems.length && <EmptyState title="История ревизий пуста" text="Baseline или первая подтверждённая конфигурация ещё не записана." />}
    <h2>Резервные копии</h2><Grid>{backupItems.map((raw, index) => { const item = asRecord(raw); return <EntityCard title={textValue(item.operation_id ?? item.id, `Backup ${index + 1}`)} status={item.status ?? (item.verified ? 'verified' : 'unverified')} onOpen={() => setSelected({ kind: 'backup', ...item })}><p>{formatDateTime(item.created_at)}</p><small>{item.total_size ? formatBytes(Number(item.total_size)) : 'Размер не указан'}</small></EntityCard>; })}</Grid>
    {!backupItems.length && <EmptyState title="Backups не показаны" text="Endpoint может быть недоступен текущей сессии или verified backup ещё не создан." />}
    <DetailDrawer title={selected?.kind === 'backup' ? 'Резервная копия' : 'Ревизия'} open={Boolean(selected)} onClose={() => setSelected(null)}><DiagnosticDetails value={selected} /><RawDisclosure value={selected} /></DetailDrawer>
  </section>;
}

function TariffSettingsCard({ mutationLocked, role }: { mutationLocked: boolean; role: SessionInfo['role'] }) {
  const [pool, setPool] = useState<any>(null);
  const [tariff, setTariff] = useState(300);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    void getVLESSPool(controller.signal).then((value) => { setPool(value); setTariff(Number(value?.tariff_mbps) || 300); }).catch(() => { /* Xray is optional. */ });
    return () => controller.abort();
  }, []);
  async function save() {
    if (role !== 'administrator') { setMessage('Изменение доступно администратору.'); return; }
    if (mutationLocked) { setMessage('Изменения временно заблокированы состоянием recovery.'); return; }
    if (!Number.isFinite(tariff) || tariff < 1 || tariff > 100000) { setMessage('Укажите скорость от 1 до 100000 Мбит/с.'); return; }
    setBusy(true); setMessage('Сохраняю скорость тарифа…');
    try { await setVLESSTariff(tariff); const value = await getVLESSPool(); setPool(value); setTariff(Number(value?.tariff_mbps) || tariff); setMessage('Сохранено. Скорость влияет на оценку VLESS, но не ограничивает интернет.'); }
    catch (error) { const info = errorInfo(error); setMessage(`${info.code}: ${info.message}`); }
    finally { setBusy(false); }
  }
  return <EntityCard title="Скорость интернет-тарифа" status={pool ? 'configured' : 'unavailable'}><p>Первый выбор можно сделать в быстрой настройке. Здесь его можно изменить позже. Значение помогает выбирать VLESS-серверы и не режет сам трафик.</p><label><span>Скорость, Мбит/с</span><input type="number" min="1" max="100000" value={tariff} onInput={(event) => setTariff(Number((event.target as HTMLInputElement).value))} /></label><div class="actions">{[100, 300, 500, 1000].map((value) => <button type="button" disabled={mutationLocked || role !== 'administrator'} class={tariff === value ? 'active' : ''} onClick={() => setTariff(value)} key={value}>{value}</button>)}<button type="button" class="primary" disabled={busy || mutationLocked || role !== 'administrator'} onClick={() => void save()}>{busy ? 'Сохраняю…' : 'Сохранить'}</button></div>{message && <p class="action-status">{message}</p>}</EntityCard>;
}

export function Settings({ data, privacyHidden, onTogglePrivacy, mutationLocked = false, role = 'viewer' }: { data?: any; privacyHidden?: boolean; onTogglePrivacy?: () => void; mutationLocked?: boolean; role?: SessionInfo['role'] }) {
  const hidden = Boolean(privacyHidden);
  return <section><PageHeader title="Настройки" text="Простые настройки FlintRoute. Системные операции по-прежнему проходят через безопасные сценарии и recovery fence." /><Grid><TariffSettingsCard mutationLocked={mutationLocked} role={role} /><EntityCard title="Приватность" status="configured"><p>{hidden ? 'Адреса устройств сейчас скрыты. FlintRoute не запрашивает raw IP и MAC, пока включён скрытый режим.' : 'Адреса устройств сейчас видны. Этот выбор сохраняется в браузере, пока вы не переключите режим обратно.'}</p>{onTogglePrivacy && <button type="button" onClick={onTogglePrivacy} aria-pressed={!hidden}>{hidden ? 'Показать адреса' : 'Скрыть адреса'}</button>}</EntityCard><EntityCard title="Хранение" status={data?.status}><StatusLine label="Events" value={data?.storage?.event_retention_days ? `${data.storage.event_retention_days} дней` : null} /><StatusLine label="Backups" value={data?.storage?.max_state_backups} /></EntityCard><EntityCard title="Обновление" status="not_implemented"><p>Автоматическое обновление из UI не реализовано.</p></EntityCard></Grid><RawDisclosure value={data} /></section>;
}

export function LoginScreen() {
  return <Card title="Вход"><p>Локальный администратор. Сессия защищается HttpOnly cookie и CSRF-токеном.</p><button class="primary">Войти локально</button></Card>;
}
