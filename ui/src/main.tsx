import { render } from 'preact';
import { useEffect, useMemo, useState } from 'preact/hooks';
import {
  APIError,
  changeAction,
  createChange,
  getChanges,
  getDevices,
  getEvents,
  getOverview,
  getRevisions,
  getRoutes,
  getSecurity,
  getServices,
  getSystem,
  getTraffic,
  getTopology,
  login,
  logout,
  me,
  setupAdmin,
  type ChangeSet,
  type ChangeOp,
  type EventItem,
  type SessionInfo,
  type TrafficSnapshot
} from './api';
import './styles.css';

const screens = [
  'Вход',
  'Первичная настройка',
  'Обзор',
  'Карта сети',
  'Трафик',
  'Устройства',
  'Карточка устройства',
  'Сервисы',
  'Группа сервиса',
  'Политики: таблица',
  'Политики: доска',
  'Очередь изменений',
  'Маршруты',
  'VLESS-серверы',
  'Smart DNS',
  'Zapret',
  'Telegram',
  'Поток решений',
  'Диагностика',
  'Безопасность',
  'Ревизии',
  'Удалённые клиенты',
  'Настройки',
  'Обновление',
  'Резервное копирование'
];

const unavailableOverview = {
  internet: 'unavailable',
  external_ipv4: 'unavailable',
  ipv6: 'unavailable',
  dns: 'unavailable',
  zapret: 'unavailable',
  vless_working: 0,
  smart_dns: 0,
  telegram: 'unavailable',
  cpu: 'unavailable',
  memory: 'unavailable',
  temperature: 'unavailable',
  data_plane: 'unavailable',
  source: 'api-unavailable',
  freshness: 'stale'
};

function App() {
  const [screen, setScreen] = useState('Обзор');
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authError, setAuthError] = useState('');
  const [apiError, setApiError] = useState('');
  const [overview, setOverview] = useState<any>(unavailableOverview);
  const [topology, setTopology] = useState<any>({ nodes: [], edges: [], status: 'unavailable', source: 'api-unavailable' });
  const [devices, setDevices] = useState<any[]>([]);
  const [services, setServices] = useState<any[]>([]);
  const [routes, setRoutes] = useState<any[]>([]);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [changes, setChanges] = useState<ChangeSet[]>([]);
  const [security, setSecurity] = useState<any>(null);
  const [system, setSystem] = useState<any>(null);
  const [configVersion, setConfigVersion] = useState(0);
  const [traffic, setTraffic] = useState<TrafficView>({ status: 'unavailable', source: 'api-unavailable', collected_at: '', interfaces: [] });

  async function refresh() {
    try {
      const [nextOverview, nextTopology, nextDevices, nextServices, nextRoutes, nextTraffic, nextEvents, nextSystem, nextRevisions] = await Promise.all([
        getOverview(),
        getTopology(),
        getDevices(),
        getServices(),
        getRoutes(),
        getTraffic(),
        getEvents(),
        getSystem(),
        getRevisions()
      ]);
      setOverview(nextOverview);
      setTopology(nextTopology);
      setDevices(nextDevices);
      setServices(nextServices);
      setRoutes(nextRoutes);
      setTraffic((previous) => withTrafficRates(previous, nextTraffic));
      setEvents(nextEvents);
      setSystem(nextSystem);
      setConfigVersion(nextRevisions.config_version);

      const optionalErrors: string[] = [];
      if (session?.role === 'administrator') {
        try {
          setChanges(await getChanges());
        } catch (err) {
          optionalErrors.push(err instanceof Error ? err.message : 'Очередь изменений недоступна');
        }
      } else {
        setChanges([]);
      }
      if (session?.role === 'administrator' || session?.role === 'diagnostician') {
        try {
          setSecurity(await getSecurity());
        } catch (err) {
          optionalErrors.push(err instanceof Error ? err.message : 'Аудит безопасности недоступен');
        }
      } else {
        setSecurity(null);
      }
      setApiError(optionalErrors.join('; '));
    } catch (err) {
      if (err instanceof APIError && err.status === 401) {
        setSession(null);
      }
      setApiError(err instanceof Error ? err.message : 'API недоступен');
    }
  }

  useEffect(() => {
    me()
      .then((next) => {
        setSession(next);
        setAuthChecked(true);
      })
      .catch((err) => {
        setAuthChecked(true);
        setSession(null);
        if (err instanceof APIError && err.code === 'setup_required') {
          setAuthError('Нужна первичная настройка администратора');
        }
      });
  }, []);

  useEffect(() => {
    if (!session) return;
    refresh();
    const timer = window.setInterval(refresh, 15000);
    let es: EventSource | undefined;
    try {
      es = new EventSource('/api/v1/events/stream');
      const pushEvent = (ev: Event) => {
        const item = JSON.parse((ev as MessageEvent).data) as EventItem;
        setEvents((old) => [item, ...old].slice(0, 80));
      };
      [
        'message',
        'system.start',
        'admin.login',
        'route.decision',
        'security.guard',
        'change.created',
        'change.validated',
        'change.awaiting_confirmation',
        'change.committed',
        'change.rolled_back'
      ].forEach((eventType) => es?.addEventListener(eventType, pushEvent));
    } catch {
      // dev mock mode
    }
    return () => {
      window.clearInterval(timer);
      es?.close();
    };
  }, [session?.user, session?.role]);

  async function handleLogin(username: string, password: string) {
    setAuthError('');
    try {
      const next = await login(username, password);
      setSession(next);
      setScreen('Обзор');
    } catch (err) {
      if (err instanceof APIError && err.status === 428) {
        setAuthError('Администратор ещё не создан. Используй setup token.');
      } else {
        setAuthError('Вход отклонён');
      }
    }
  }

  async function handleSetup(username: string, password: string, setupToken: string) {
    setAuthError('');
    try {
      await setupAdmin(username, password, setupToken);
      const next = await login(username, password);
      setSession(next);
      setScreen('Обзор');
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Настройка не удалась');
    }
  }

  async function handleLogout() {
    await logout().catch(() => undefined);
    setSession(null);
    setOverview(unavailableOverview);
    setTopology({ nodes: [], edges: [], status: 'unavailable', source: 'logged-out' });
    setDevices([]);
    setServices([]);
    setRoutes([]);
    setEvents([]);
    setChanges([]);
  }

  if (!authChecked) {
    return <BootScreen />;
  }

  if (!session) {
    return <AuthShell error={authError} onLogin={handleLogin} onSetup={handleSetup} />;
  }

  return (
    <div class="shell">
      <aside class="side">
        <div class="brand">
          <div class="mark">RP</div>
          <div>
            <strong>Router Policy</strong>
            <span>{session.user} · {session.role}</span>
          </div>
        </div>
        <nav>
          {screens.map((s) => (
            <button class={screen === s ? 'active' : ''} onClick={() => setScreen(s)} key={s}>
              <span class="nav-dot" />
              {s}
            </button>
          ))}
        </nav>
      </aside>
      <main>
        <SessionBar session={session} apiError={apiError} onLogout={handleLogout} />
        <TopBar overview={overview} />
        <Content screen={screen} session={session} configVersion={configVersion} overview={overview} topology={topology} devices={devices} services={services} routes={routes} traffic={traffic} events={events} changes={changes} security={security} system={system} refresh={refresh} />
      </main>
    </div>
  );
}

function BootScreen() {
  return (
    <main class="auth-page">
      <section class="auth-card">
        <div class="mark">RP</div>
        <h1>Router Policy</h1>
        <p>Проверка локальной сессии.</p>
      </section>
    </main>
  );
}

function AuthShell({ error, onLogin, onSetup }: { error: string; onLogin: (u: string, p: string) => Promise<void>; onSetup: (u: string, p: string, t: string) => Promise<void> }) {
  const [mode, setMode] = useState<'login' | 'setup'>('login');
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [setupToken, setSetupToken] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(ev: Event) {
    ev.preventDefault();
    setBusy(true);
    try {
      if (mode === 'login') {
        await onLogin(username, password);
      } else {
        await onSetup(username, password, setupToken);
      }
    } finally {
      setBusy(false);
    }
  }
  return (
    <main class="auth-page">
      <form class="auth-card" onSubmit={submit}>
        <div class="mark">RP</div>
        <h1>{mode === 'login' ? 'Вход' : 'Первичная настройка'}</h1>
        <label>
          <span>Пользователь</span>
          <input value={username} onInput={(e) => setUsername((e.target as HTMLInputElement).value)} autocomplete="username" />
        </label>
        <label>
          <span>Пароль</span>
          <input type="password" value={password} onInput={(e) => setPassword((e.target as HTMLInputElement).value)} autocomplete={mode === 'login' ? 'current-password' : 'new-password'} />
        </label>
        {mode === 'setup' && (
          <label>
            <span>Setup token</span>
            <input value={setupToken} onInput={(e) => setSetupToken((e.target as HTMLInputElement).value)} autocomplete="one-time-code" />
          </label>
        )}
        {error && <p class="auth-error">{error}</p>}
        <button class="primary" disabled={busy}>{busy ? 'Проверка...' : mode === 'login' ? 'Войти' : 'Создать администратора'}</button>
        <button type="button" onClick={() => setMode(mode === 'login' ? 'setup' : 'login')}>
          {mode === 'login' ? 'У меня setup token' : 'Вернуться ко входу'}
        </button>
      </form>
    </main>
  );
}

function SessionBar({ session, apiError, onLogout }: { session: SessionInfo; apiError: string; onLogout: () => void }) {
  return (
    <div class={`session-bar ${apiError ? 'warning' : ''}`}>
      <span>{apiError ? `API: ${apiError}` : `Сессия до ${new Date(session.expires_at).toLocaleTimeString()}`}</span>
      <button onClick={onLogout}>Выйти</button>
    </div>
  );
}

function TopBar({ overview }: { overview: any }) {
  const items = [
    ['Интернет', overview.internet],
    ['IPv4', overview.external_ipv4],
    ['IPv6', overview.ipv6],
    ['DNS', overview.dns],
    ['Zapret', overview.zapret],
    ['VLESS', overview.vless_working],
    ['Smart DNS', overview.smart_dns],
    ['CPU', overview.cpu],
    ['RAM', overview.memory],
    ['Temp', overview.temperature]
  ];
  return (
    <header class="topbar">
      {items.map(([k, v]) => (
        <div class="status-pill" key={k}>
          <span>{k}</span>
          <b>{String(v ?? 'недоступно')}</b>
        </div>
      ))}
    </header>
  );
}

function Content(props: any) {
  switch (props.screen) {
    case 'Вход':
      return <LoginScreen />;
    case 'Первичная настройка':
      return <SetupScreen />;
    case 'Обзор':
      return <OverviewScreen {...props} />;
    case 'Карта сети':
      return <NetworkMap topology={props.topology} expanded />;
    case 'Трафик':
      return <Traffic data={props.traffic} />;
    case 'Устройства':
      return <Devices devices={props.devices} />;
    case 'Карточка устройства':
      return <DeviceCard device={props.devices[0]} />;
    case 'Сервисы':
      return <Services services={props.services} />;
    case 'Группа сервиса':
      return <ServiceGroup service={props.services[0]} />;
    case 'Политики: таблица':
      return <Policies mode="table" />;
    case 'Политики: доска':
      return <Policies mode="board" />;
    case 'Очередь изменений':
      return <Changes changes={props.changes} refresh={props.refresh} role={props.session.role} configVersion={props.configVersion} />;
    case 'Маршруты':
      return <Routes routes={props.routes} />;
    case 'VLESS-серверы':
      return <Vless routes={props.routes} />;
    case 'Smart DNS':
      return <RouteType title="Smart DNS" type="smart_dns" routes={props.routes} />;
    case 'Zapret':
      return <RouteType title="Zapret" type="zapret" routes={props.routes} />;
    case 'Telegram':
      return <Telegram />;
    case 'Поток решений':
      return <DecisionFlow events={props.events} />;
    case 'Диагностика':
      return <Diagnostics system={props.system} />;
    case 'Безопасность':
      return <Security data={props.security} />;
    case 'Ревизии':
      return <Generic title="Ревизии" text="Текущая ревизия конфигурации, staged changes и история откатов." />;
    case 'Удалённые клиенты':
      return <Generic title="Удалённые клиенты" text="Профили удалённого доступа, лимиты, срок действия и политика маршрутизации." />;
    case 'Настройки':
      return <Settings />;
    case 'Обновление':
      return <Generic title="Обновление" text="Проверка версии, подпись выпуска, checksum, staged install и rollback." />;
    case 'Резервное копирование':
      return <Generic title="Резервное копирование и откат" text="Резервные копии конфигурации, секретов по явному выбору, nft/dnsmasq/fw4 snapshots." />;
    default:
      return <OverviewScreen {...props} />;
  }
}

function OverviewScreen({ overview, topology, services, events }: any) {
  return (
    <section class="dashboard">
      <div class="map-panel">
        <NetworkMap topology={topology} />
      </div>
      <div class="right-panel">
        <Card title="Критические сервисы">
          {services.slice(0, 5).map((s: any) => (
            <div class="row" key={s.id}>
              <RouteBadge type={s.category} />
              <b>{s.id}</b>
              <span>{s.probe_count} checks</span>
            </div>
          ))}
        </Card>
        <Card title="Предупреждения">
          <div class="row warn"><b>IPv6</b><span>{overview.ipv6}</span></div>
          <div class="row warn"><b>Zapret</b><span>{overview.zapret}</span></div>
          <div class="row"><b>Data plane</b><span>{overview.data_plane}</span></div>
        </Card>
        <Card title="Последние решения">
          {events.slice(0, 4).map((e: EventItem) => <EventRow event={e} key={e.id} />)}
        </Card>
      </div>
    </section>
  );
}

function NetworkMap({ topology }: { topology: any; expanded?: boolean }) {
  const nodes = topology.nodes ?? [];
  return (
    <div class="network">
      <div class="internet">Internet</div>
      <div class="router">Flint 2</div>
      <div class="groups">
        {nodes.filter((n: any) => n.type === 'group').map((n: any) => (
          <button class="node" key={n.id}>
            <span>{n.label}</span>
            <b>{n.clients} clients</b>
          </button>
        ))}
      </div>
      <div class="flow-line direct" />
      <div class="flow-line vless" />
    </div>
  );
}

function Devices({ devices }: { devices: any[] }) {
  return <Grid>{devices.map((d) => <DeviceCard device={d} key={d.id} />)}</Grid>;
}

function DeviceCard({ device }: { device: any }) {
  if (!device) return <Generic title="Карточка устройства" text="Нет устройства в выборке." />;
  return (
    <Card title={device.name}>
      <dl class="facts">
        <dt>Тип</dt><dd>{device.kind}</dd>
        <dt>IP</dt><dd class="mono">{device.ip}</dd>
        <dt>MAC</dt><dd class="mono">{device.mac ?? 'masked'}</dd>
        <dt>Политика</dt><dd>{device.policy}</dd>
      </dl>
      <div class="actions">
        {['Переименовать', 'Закрепить IP', 'Профиль', 'Лимит', 'Отключить интернет', 'Диагностика'].map((a) => <button>{a}</button>)}
      </div>
    </Card>
  );
}

function Services({ services }: { services: any[] }) {
  return <Grid>{services.map((s) => <ServiceGroup service={s} key={s.id} />)}</Grid>;
}

function ServiceGroup({ service }: { service: any }) {
  if (!service) return <Generic title="Группа сервиса" text="Сервис не выбран." />;
  return (
    <Card title={service.id}>
      <div class="row"><RouteBadge type={service.category} /><b>{service.category}</b><span>{service.probe_count} probes</span></div>
      <h4>Домены</h4>
      <div class="chips">{(service.domains ?? []).map((d: string) => <span class="chip mono">{d}</span>)}</div>
      <h4>Пути</h4>
      <div class="chips">{(service.allowed_paths ?? []).map((p: string) => <RouteBadge type={p} />)}</div>
    </Card>
  );
}

function Policies({ mode }: { mode: string }) {
  const items = ['emergency', 'BLOCKED', 'device+domain', 'device+service', 'domain', 'service', 'category', 'auto', 'default'];
  return <Card title={`Политики: ${mode}`}>{items.map((p, i) => <div class="row"><b>{i + 1}</b><span>{p}</span><small>формальный приоритет</small></div>)}</Card>;
}

function Changes({ changes, refresh, role, configVersion }: { changes: ChangeSet[]; refresh: () => void; role: SessionInfo['role']; configVersion: number }) {
  const [title, setTitle] = useState('');
  const [operationType, setOperationType] = useState<ChangeOp['type']>('set');
  const [path, setPath] = useState('');
  const [value, setValue] = useState('');
  const [error, setError] = useState('');

  if (role !== 'administrator') {
    return <Generic title="Очередь изменений" text="Просмотр и создание ChangeSet доступны только администратору." />;
  }

  async function create() {
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
    await changeAction(id, action);
    await refresh();
  }
  return (
    <Card title="Очередь изменений">
      <div class="change-editor">
        <label><span>Название</span><input value={title} onInput={(e) => setTitle((e.target as HTMLInputElement).value)} /></label>
        <label><span>Операция</span><select value={operationType} onChange={(e) => setOperationType((e.target as HTMLSelectElement).value as ChangeOp['type'])}><option value="set">set</option><option value="remove">remove</option></select></label>
        <label><span>Путь</span><input class="mono" placeholder="/services/example/category" value={path} onInput={(e) => setPath((e.target as HTMLInputElement).value)} /></label>
        {operationType === 'set' && <label><span>JSON-значение</span><textarea class="mono" placeholder={'"DIRECT_PREFERRED"'} value={value} onInput={(e) => setValue((e.target as HTMLTextAreaElement).value)} /></label>}
        <small>Базовая версия: {configVersion || 'загрузка...'}</small>
        {error && <p class="auth-error">{error}</p>}
        <button class="primary" disabled={!configVersion} onClick={create}>Создать ChangeSet</button>
      </div>
      {changes.map((c) => (
        <div class="change" key={c.id}>
          <b>{c.title}</b><span>{c.state}</span>
          <div class="actions">
            {['validate', 'apply', 'confirm', 'rollback'].map((a) => <button onClick={() => act(c.id, a)}>{a}</button>)}
          </div>
        </div>
      ))}
    </Card>
  );
}

function Routes({ routes }: { routes: any[] }) {
  return <Grid>{routes.map((r) => <Card title={r.tag}><RouteBadge type={r.type} /><pre>{JSON.stringify(r, null, 2)}</pre></Card>)}</Grid>;
}

type TrafficView = Omit<TrafficSnapshot, 'interfaces'> & { interfaces: Array<TrafficSnapshot['interfaces'][number] & { rx_bps?: number; tx_bps?: number }> };

function withTrafficRates(previous: TrafficView, current: TrafficSnapshot): TrafficView {
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

function Traffic({ data }: { data: TrafficView }) {
  return (
    <Card title="Трафик интерфейсов">
      <div class="row"><b>{data.status}</b><span>{data.source}</span><small>{data.collected_at ? new Date(data.collected_at).toLocaleTimeString() : data.reason ?? 'нет данных'}</small></div>
      {data.interfaces.map((item) => (
        <div class={`traffic-row ${(item.rx_errors || item.tx_errors) ? 'warn' : ''}`} key={item.name}>
          <b class="mono">{item.name}</b>
          <span>RX {formatBytes(item.rx_bytes)} · {formatRate(item.rx_bps)}</span>
          <span>TX {formatBytes(item.tx_bytes)} · {formatRate(item.tx_bps)}</span>
          <small>пакеты {item.rx_packets}/{item.tx_packets} · ошибки {item.rx_errors}/{item.tx_errors}</small>
        </div>
      ))}
      {data.interfaces.length === 0 && <p>{data.reason ?? 'Счётчики интерфейсов недоступны'}</p>}
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

function Vless({ routes }: { routes: any[] }) {
  const vless = routes.filter((r) => r.type === 'vless');
  return <Grid>{(vless.length ? vless : [{ tag: 'VPN subscription pending', type: 'vless', status: 'generated after subscription' }]).map((r) => <Card title={r.tag}><RouteBadge type="vless" /><span>{r.status ?? r.socks5 ?? 'pending'}</span></Card>)}</Grid>;
}

function RouteType({ title, type, routes }: { title: string; type: string; routes: any[] }) {
  return <Grid>{routes.filter((r) => r.type === type).map((r) => <Card title={r.tag}><RouteBadge type={type} /><pre>{JSON.stringify(r, null, 2)}</pre></Card>)}</Grid>;
}

function Telegram() {
  return <Generic title="Telegram" text="Цепочка: tg-ws-proxy -> VLESS -> другой VLESS -> DROP. Bot API проверяется отдельно." />;
}

function DecisionFlow({ events }: { events: EventItem[] }) {
  return <Card title="Поток решений">{events.map((e) => <EventRow event={e} key={e.id} />)}</Card>;
}

function Diagnostics({ system }: { system: any }) {
  return <Card title="Диагностика"><pre>{JSON.stringify(system ?? { status: 'requires adapter' }, null, 2)}</pre></Card>;
}

function Security({ data }: { data: any }) {
  return <Card title="Безопасность"><pre>{JSON.stringify(data ?? { status: 'audit unavailable in mock mode' }, null, 2)}</pre></Card>;
}

function Settings() {
  return <Card title="Настройки"><div class="row"><b>Приватность</b><span>IP и MAC скрываются по умолчанию</span></div><div class="row"><b>Анимации</b><span>можно отключить системной настройкой reduced motion</span></div></Card>;
}

function LoginScreen() {
  return <Card title="Вход"><p>Локальный администратор. Сессия защищается HttpOnly cookie и CSRF-токеном.</p><button class="primary">Войти локально</button></Card>;
}

function SetupScreen() {
  const steps = ['Администратор', 'Платформа', 'Сеть', 'VPN-подписка', 'VLESS', 'Smart DNS', 'Zapret', 'Telegram', 'IPv6', 'Политики', 'Приватность', 'Уведомления', 'Backup', 'Test apply', 'Confirm'];
  return <Card title="Первичная настройка">{steps.map((s, i) => <div class="row"><b>{i + 1}</b><span>{s}</span><small>{i < 3 ? 'ready' : 'requires input'}</small></div>)}</Card>;
}

function Generic({ title, text }: { title: string; text: string }) {
  return <Card title={title}><p>{text}</p></Card>;
}

function EventRow({ event }: { event: EventItem }) {
  return <div class={`event ${event.severity}`}><b>{new Date(event.time).toLocaleTimeString()}</b><span>{event.device_id ?? 'system'} · {event.domain ?? event.type} · {event.route ?? 'n/a'}</span><small>{event.reason_code}</small></div>;
}

function RouteBadge({ type }: { type: string }) {
  const normalized = String(type).toLowerCase().replace(/_/g, '-');
  return <span class={`badge ${normalized}`}><i />{type}</span>;
}

function Card({ title, children }: { title: string; children: any }) {
  return <section class="card"><h2>{title}</h2>{children}</section>;
}

function Grid({ children }: { children: any }) {
  return <section class="grid">{children}</section>;
}

render(<App />, document.getElementById('app')!);
