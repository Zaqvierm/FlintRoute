import { useEffect, useRef, useState } from 'preact/hooks';
import {
  APIError,
  getChanges,
  getBackups,
  getDevices,
  getDiagnostics,
  getDiscovery,
  getEvents,
  getHealth,
  getOverview,
  getOnboarding,
  getRevisions,
  getRoutes,
  getSecurity,
  getSecuritySummary,
  getServices,
  getSystem,
  getSettings,
  getLifecycle,
  getStorage,
  getTraffic,
  getTopology,
  login,
  logout,
  me,
  setupAdmin,
  updateOnboarding,
  type ChangeSet,
  type DiscoveryStatus,
  type EventItem,
  type OnboardingState,
  type RevisionSummary,
  type SessionInfo
} from '../api';
import {
  errorInfo,
  recoveryMutationAllowed,
  textValue
} from '../view-models';
import {
  AlertCenter,
  AuthShell,
  BootScreen,
  LoadingSkeleton,
  OperationCenterSummary,
  PrivacyBar,
  ScreenErrorBoundary,
  SessionBar,
  TopBar
} from './shell';
import {
  withTrafficRates,
  type TrafficView
} from '../features/system';
import { navigation, notFoundScreen, screenFromLocation } from './routes';
import { staleFallback, unavailableOverview } from './messages';
import { Content as ScreenContent } from './content';
import { useNavigation } from './useNavigation';

export { type ContentProps } from './content';

function App() {
  const { screen, screenRef, mobileMoreOpen, setMobileMoreOpen, selectScreen } = useNavigation();
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authError, setAuthError] = useState('');
  const [apiError, setApiError] = useState('');
  const [overview, setOverview] = useState<any>(unavailableOverview);
  const [onboarding, setOnboarding] = useState<OnboardingState | null>(null);
  const [sliceErrors, setSliceErrors] = useState<Array<{ name: string; message: string }>>([]);
  const [retryingSlice, setRetryingSlice] = useState('');
  const [topology, setTopology] = useState<any>({ nodes: [], edges: [], status: 'unavailable', source: 'api-unavailable' });
  const [devices, setDevices] = useState<any[]>([]);
  const [services, setServices] = useState<any[]>([]);
  const [routes, setRoutes] = useState<any[]>([]);
  const [discovery, setDiscovery] = useState<DiscoveryStatus | null>(null);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [changes, setChanges] = useState<ChangeSet[]>([]);
  const [security, setSecurity] = useState<any>(null);
  const [system, setSystem] = useState<any>(null);
  const [diagnostics, setDiagnostics] = useState<any>(null);
  const [lifecycle, setLifecycle] = useState<any>(null);
  const [storage, setStorage] = useState<any>(null);
  const [settings, setSettings] = useState<any>(null);
  const [backups, setBackups] = useState<any>(null);
  const [revisions, setRevisions] = useState<RevisionSummary | null>(null);
  const [securitySummary, setSecuritySummary] = useState<any>(null);
  const [configVersion, setConfigVersion] = useState(0);
  const [traffic, setTraffic] = useState<TrafficView>({ status: 'unavailable', source: 'api-unavailable', collected_at: '', interfaces: [] });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState('');
  const refreshInFlight = useRef<Promise<void> | null>(null);
  const refreshPrivacy = useRef<boolean | undefined>(undefined);
  const refreshScreen = useRef<string | undefined>(undefined);
  const refreshAbort = useRef<AbortController | null>(null);
  const sliceRetryAbort = useRef<AbortController | null>(null);
  const refreshGeneration = useRef(0);
  const [privacyHidden, setPrivacyHidden] = useState(() => {
    // Address visibility is a persistent UI preference.  The safe choice is
    // still available at any time, but do not silently change a user's
    // preference after a timer or a refresh.  Existing installs that have no
    // preference start in the visible mode so the network map is useful on
    // first launch; opting into hidden mode is explicit and persistent.
    try { return window.localStorage.getItem('flintroute-address-privacy') === 'hidden'; } catch { return false; }
  });
  async function refresh(hideAddresses = privacyHidden) {
    // One dashboard refresh is enough.  A slow router must not accumulate
    // overlapping command batches when the timer, SSE reconnect, or a user
    // click happens at the same time.
    const requestedScreen = screenRef.current;
    if (refreshInFlight.current && refreshPrivacy.current === hideAddresses && refreshScreen.current === requestedScreen) return refreshInFlight.current;
    refreshAbort.current?.abort();
    const controller = new AbortController();
    refreshAbort.current = controller;
    const signal = controller.signal;
    const generation = ++refreshGeneration.current;
    const operation = (async () => {
    setRefreshing(true);
    try {
      const activeScreen = requestedScreen;
      const needsTopology = ['Обзор', 'Карта сети', 'Устройства', 'Карточка устройства'].includes(activeScreen);
      const needsDevices = needsTopology;
      const needsServices = ['Обзор', 'Сервисы', 'Группа сервиса'].includes(activeScreen);
      const needsRoutes = ['Маршруты', 'VLESS-серверы', 'Zapret'].includes(activeScreen);
      const needsTraffic = ['Обзор', 'Трафик'].includes(activeScreen);
      const needsEvents = ['Обзор', 'Устройства', 'Карточка устройства', 'Поток решений', 'Telegram'].includes(activeScreen);
      const needsChanges = ['Обзор', 'Операции', 'Advanced'].includes(activeScreen);
      const needsDiscovery = ['Обзор', 'Discovery', 'Поток решений'].includes(activeScreen);
      const needsOnboarding = ['Обзор', 'Быстрая настройка'].includes(activeScreen);
      const needsRevisions = needsOnboarding || needsServices || needsRoutes || needsChanges || ['Smart DNS', 'External SOCKS', 'TG WS Proxy', 'Telegram', 'Ревизии и recovery'].includes(activeScreen);
      const needsSecurity = ['Обзор', 'Безопасность'].includes(activeScreen);
      const needsDiagnostics = activeScreen === 'Диагностика';
      const needsLifecycle = needsDiagnostics || activeScreen === 'Ревизии и recovery';
      const needsStorage = needsDiagnostics;
      const needsSettings = activeScreen === 'Настройки';
      const needsBackups = activeScreen === 'Ревизии и recovery' || activeScreen === 'Резервное копирование';
      const optionalErrors: Array<{ name: string; message: string }> = [];
      async function safe<T>(name: string, load: Promise<T>, fallback: T): Promise<T> {
        try {
          return await load;
        } catch (reason) {
          if (reason instanceof Error && reason.name === 'AbortError') throw reason;
          if (!(reason instanceof APIError && reason.status === 403)) optionalErrors.push({ name, message: errorInfo(reason).message });
          // Preserve useful data, but mark it stale.  Showing the last known
          // device/service/route list as a live green state is worse than an
          // explicit partial failure because it invites a false decision.
          return staleFallback(fallback);
        }
      }
      async function maybe<T>(needed: boolean, name: string, load: () => Promise<T>, fallback: T): Promise<T> {
        return needed ? safe(name, load(), fallback) : fallback;
      }
      const [nextOverview, nextTopology, nextDevices, nextServices, nextRoutes, nextTraffic, nextEvents, nextSystem, nextRevisions, nextDiscovery, nextOnboarding, nextHealth] = await Promise.all([
        safe('overview', getOverview(signal), staleFallback(overview)),
        maybe(needsTopology, 'topology', () => getTopology(hideAddresses, signal), hideAddresses ? { nodes: [], edges: [], status: 'unavailable', source: 'privacy-fallback' } : staleFallback(topology)),
        maybe(needsDevices, 'devices', () => getDevices(hideAddresses, signal), hideAddresses ? [] : devices),
        maybe(needsServices, 'services', () => getServices(signal), services),
        maybe(needsRoutes, 'routes', () => getRoutes(signal), routes),
        maybe(needsTraffic, 'traffic', () => getTraffic(signal), traffic),
        maybe(needsEvents, 'events', () => getEvents(500, hideAddresses, signal), hideAddresses ? [] : events),
        safe('system', getSystem(signal), staleFallback(system)),
        maybe(needsRevisions || activeScreen === notFoundScreen, 'revisions', () => getRevisions(signal), revisions),
        maybe(needsDiscovery, 'discovery', () => getDiscovery(signal), discovery),
        maybe(needsOnboarding || activeScreen === notFoundScreen, 'onboarding', () => getOnboarding(signal), onboarding),
        safe('health', getHealth(signal), { status: 'unavailable', recovery_status: 'unknown', recovery_reason: 'Статус восстановления недоступен' })
      ]);
      if (generation !== refreshGeneration.current) return;
      const enrichedOverview = nextOverview && typeof nextOverview === 'object'
        ? { ...(nextOverview as Record<string, unknown>), ...nextHealth }
        : nextOverview;
      setOverview(enrichedOverview);
      setTopology(nextTopology);
      setDevices(nextDevices);
      setServices(nextServices);
      setRoutes(nextRoutes);
      setTraffic((previous) => withTrafficRates(previous, nextTraffic));
      setEvents(nextEvents);
      setSystem(nextSystem);
      if (nextRevisions) {
        setRevisions(nextRevisions);
        setConfigVersion(nextRevisions.config_version);
      }
      setDiscovery(nextDiscovery);
      setOnboarding(nextOnboarding);
      if (nextRevisions && nextRevisions.config_version <= 1 && nextServices.length === 0 && nextOnboarding?.completed !== true) {
        const firstRunScreen = navigation[0].screens[0];
        const locationScreen = screenFromLocation();
        // Resume the wizard only from the landing screen (or an invalid URL).
        // An explicit deep-link to a component is a deliberate user action;
        // redirecting it on every refresh made Rules -> Zapret impossible to
        // use until onboarding was completed, and created a visible loop.
        // Recovery, diagnostics and read-only component screens must remain
        // reachable while setup is incomplete, so they are never trapped.
        const shouldResumeWizard = (screenRef.current === 'Обзор' || screenRef.current === notFoundScreen)
          && (locationScreen === null || ['Обзор', firstRunScreen, notFoundScreen].includes(locationScreen));
        const explicitComponentNavigation = locationScreen !== null
          && !['Обзор', firstRunScreen, notFoundScreen].includes(locationScreen);
        if (shouldResumeWizard && !explicitComponentNavigation && locationScreen !== firstRunScreen) selectScreen(firstRunScreen);
      }
      const optional = await Promise.allSettled([
        maybe(needsChanges, 'changes', () => getChanges(signal), changes),
        maybe(needsSecurity, 'security', () => getSecurity(signal), security),
        maybe(needsSecurity, 'security-summary', () => getSecuritySummary(signal), securitySummary),
        maybe(needsDiagnostics, 'diagnostics', () => getDiagnostics(signal), diagnostics),
        maybe(needsLifecycle, 'lifecycle', () => getLifecycle(signal), lifecycle),
        maybe(needsStorage, 'storage', () => getStorage(signal), storage),
        maybe(needsSettings, 'settings', () => getSettings(signal), settings),
        maybe(needsBackups, 'backups', () => getBackups(signal), backups)
      ]);
      const setters = [setChanges, setSecurity, setSecuritySummary, setDiagnostics, setLifecycle, setStorage, setSettings, setBackups];
      optional.forEach((result, index) => {
        if (result.status === 'fulfilled') setters[index](result.value as never);
        else if (!(result.reason instanceof APIError && result.reason.status === 403)) optionalErrors.push({ name: `optional-${index + 1}`, message: errorInfo(result.reason).message });
      });
      if (optional[0].status === 'rejected') setChanges([]);
      if (optional[1].status === 'rejected') setSecurity(null);
      setLastUpdated(new Date().toISOString());
      setLoading(false);
      setSliceErrors(optionalErrors);
      setApiError(optionalErrors.length ? 'Некоторые данные устарели или недоступны' : '');
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') return;
      if (generation !== refreshGeneration.current) return;
      if (err instanceof APIError && err.status === 401) {
        setSession(null);
      }
      setApiError(err instanceof Error ? err.message : 'API недоступен');
    } finally {
      if (refreshAbort.current === controller) refreshAbort.current = null;
      if (generation === refreshGeneration.current) {
        setRefreshing(false);
        setLoading(false);
      }
    }
    })();
    refreshInFlight.current = operation;
    refreshPrivacy.current = hideAddresses;
    refreshScreen.current = requestedScreen;
    try {
      await operation;
    } finally {
      if (refreshInFlight.current === operation) refreshInFlight.current = null;
      if (!refreshInFlight.current) {
        refreshPrivacy.current = undefined;
        refreshScreen.current = undefined;
      }
    }
  }

  async function retrySlice(name: string) {
    if (retryingSlice) return;
    sliceRetryAbort.current?.abort();
    const controller = new AbortController();
    sliceRetryAbort.current = controller;
    setRetryingSlice(name);
    try {
      switch (name) {
        case 'overview': setOverview(await getOverview(controller.signal)); break;
        case 'topology': setTopology(await getTopology(privacyHidden, controller.signal)); break;
        case 'devices': setDevices(await getDevices(privacyHidden, controller.signal)); break;
        case 'services': setServices(await getServices(controller.signal)); break;
        case 'routes': setRoutes(await getRoutes(controller.signal)); break;
        case 'traffic': {
          const next = await getTraffic(controller.signal);
          setTraffic((previous) => withTrafficRates(previous, next));
          break;
        }
        case 'events': setEvents(await getEvents(500, privacyHidden, controller.signal)); break;
        case 'system': setSystem(await getSystem(controller.signal)); break;
        case 'revisions': {
          const next = await getRevisions(controller.signal);
          setRevisions(next);
          setConfigVersion(next.config_version);
          break;
        }
        case 'discovery': setDiscovery(await getDiscovery(controller.signal)); break;
        case 'onboarding': setOnboarding(await getOnboarding(controller.signal)); break;
        case 'health': {
          const next = await getHealth(controller.signal);
          setOverview((previous: any) => ({ ...previous, ...next }));
          break;
        }
        case 'changes': setChanges(await getChanges(controller.signal)); break;
        case 'security': setSecurity(await getSecurity(controller.signal)); break;
        case 'security-summary': setSecuritySummary(await getSecuritySummary(controller.signal)); break;
        case 'diagnostics': setDiagnostics(await getDiagnostics(controller.signal)); break;
        case 'lifecycle': setLifecycle(await getLifecycle(controller.signal)); break;
        case 'storage': setStorage(await getStorage(controller.signal)); break;
        case 'settings': setSettings(await getSettings(controller.signal)); break;
        case 'backups': setBackups(await getBackups(controller.signal)); break;
        default: throw new Error('Для этого источника доступен только общий повтор');
      }
      setSliceErrors((current) => {
        const next = current.filter((item) => item.name !== name);
        // A successful source-only retry must also clear the aggregate
        // session warning once no stale slices remain.  Otherwise the source
        // is healthy again but the shell keeps reporting a false API outage.
        if (!next.length) setApiError('');
        return next;
      });
      setLastUpdated(new Date().toISOString());
    } catch (reason) {
      if (!(reason instanceof Error && reason.name === 'AbortError')) {
        const info = errorInfo(reason);
        setSliceErrors((current) => {
          const next = current.filter((item) => item.name !== name);
          setApiError('Некоторые данные устарели или недоступны');
          return [...next, { name, message: info.message }];
        });
      }
    } finally {
      if (sliceRetryAbort.current === controller) sliceRetryAbort.current = null;
      setRetryingSlice((current) => current === name ? '' : current);
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
    void refresh(privacyHidden);
    const timer = window.setInterval(() => {
      if (!document.hidden) void refresh(privacyHidden);
    }, 30000);
    let es: EventSource | undefined;
    let streamActive = true;
    try {
      es = new EventSource(`/api/v1/events/stream?privacy=${privacyHidden ? 'hidden' : 'visible'}`);
      const pushEvent = (ev: Event) => {
        // A privacy toggle closes the previous stream and opens a new one.
        // Guard the old callback as well: browsers may dispatch one queued
        // message during close, and a visible-mode event must never refill a
        // hidden-mode state slice.
        if (!streamActive) return;
        try {
          const item = JSON.parse((ev as MessageEvent).data) as EventItem;
          if (!item || typeof item !== 'object') return;
          setEvents((old) => [item, ...old].slice(0, 80));
        } catch {
          // A malformed event must not tear down the stream or poison the UI
          // state. The next heartbeat/reconnect remains useful evidence.
        }
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
      streamActive = false;
      window.clearInterval(timer);
      es?.close();
    };
  }, [session?.user, session?.role, privacyHidden]);

  useEffect(() => {
    if (session) void refresh(privacyHidden);
  }, [screen, session?.user, privacyHidden]);

  async function togglePrivacy() {
    const next = !privacyHidden;
    sliceRetryAbort.current?.abort();
    sliceRetryAbort.current = null;
    setRetryingSlice('');
    setPrivacyHidden(next);
    if (next) {
      // Do not leave a previously revealed entity alive while the hidden
      // response is in flight. The keyed content tree also closes drawers.
      setTopology({ nodes: [], edges: [], status: 'unavailable', source: 'privacy-transition' });
      setDevices([]);
      setEvents([]);
    }
    try { window.localStorage.setItem('flintroute-address-privacy', next ? 'hidden' : 'visible'); } catch { /* session state still works */ }
    await refresh(next);
  }

  async function handleLogin(username: string, password: string) {
    setAuthError('');
    try {
      const next = await login(username, password);
      setSession(next);
      selectScreen('Обзор');
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
      selectScreen('Обзор');
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Настройка не удалась');
    }
  }

  async function handleLogout() {
    // Invalidate any response that is still in flight before clearing the
    // store.  Without this generation bump a late dashboard response could
    // repopulate devices, events or diagnostics after the session was gone.
    refreshAbort.current?.abort();
    sliceRetryAbort.current?.abort();
    refreshAbort.current = null;
    sliceRetryAbort.current = null;
    refreshGeneration.current += 1;
    refreshInFlight.current = null;
    setRefreshing(false);
    await logout().catch(() => undefined);
    setSession(null);
    setOverview(unavailableOverview);
    setTopology({ nodes: [], edges: [], status: 'unavailable', source: 'logged-out' });
    setDevices([]);
    setServices([]);
    setRoutes([]);
    setEvents([]);
    setChanges([]);
    setOnboarding(null);
    setSystem(null);
    setDiagnostics(null);
    setLifecycle(null);
    setStorage(null);
    setSettings(null);
    setBackups(null);
    setRevisions(null);
    setSecurity(null);
    setSecuritySummary(null);
    setSliceErrors([]);
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
          <div class="mark">FR</div>
          <div>
            <strong>{textValue(system?.hostname, 'FlintRoute')}</strong>
            <span>{textValue(system?.model, 'OpenWrt router')}</span>
          </div>
        </div>
        <nav>
          {navigation.map((group) => <section class="nav-group" key={group.title}>
            <span class="nav-title">{group.title}</span>
            {group.screens.map((s) => (
              <button class={screen === s ? 'active' : ''} aria-current={screen === s ? 'page' : undefined} title={s} onClick={() => selectScreen(s)} key={s}>
                <span class="nav-dot" />{s}
              </button>
            ))}
          </section>)}
        </nav>
        <nav class="mobile-nav" aria-label="Основная навигация">
          {[
            ['Обзор', 'Обзор'],
            ['Карта сети', 'Сеть'],
            ['Сервисы', 'Правила'],
            ['Поток решений', 'Активность']
          ].map(([target, label]) => <button class={screen === target ? 'active' : ''} aria-current={screen === target ? 'page' : undefined} title={target} onClick={() => selectScreen(target)} key={target}><span class="nav-dot" />{label}</button>)}
          <button class={mobileMoreOpen ? 'active' : ''} aria-expanded={mobileMoreOpen} onClick={() => setMobileMoreOpen((open) => !open)}><span class="nav-dot" />Ещё</button>
        </nav>
        {mobileMoreOpen && <div class="mobile-more-backdrop" role="presentation" onClick={() => setMobileMoreOpen(false)}><section class="mobile-more" role="dialog" aria-modal="true" aria-label="Дополнительные разделы" onClick={(event) => event.stopPropagation()}><header><b>Дополнительные разделы</b><button class="icon-button" aria-label="Закрыть" onClick={() => setMobileMoreOpen(false)}>×</button></header>{navigation.flatMap((group) => group.screens).filter((item) => !['Обзор', 'Карта сети', 'Сервисы', 'Поток решений'].includes(item)).map((item) => <button class={screen === item ? 'active' : ''} aria-current={screen === item ? 'page' : undefined} onClick={() => selectScreen(item)} key={item}>{item}</button>)}</section></div>}
      </aside>
      <main>
        <SessionBar session={session} apiError={apiError} loading={refreshing} lastUpdated={lastUpdated} onRetry={() => refresh()} onLogout={handleLogout} />
        <PrivacyBar hidden={privacyHidden} onToggle={togglePrivacy} />
        <TopBar overview={overview} navigate={selectScreen} />
        <AlertCenter errors={sliceErrors} onRetry={(name) => { void retrySlice(name); }} onRetryAll={() => { void refresh(); }} retrying={retryingSlice} />
        <RecoveryMutationBanner overview={overview} navigate={selectScreen} onRetry={() => refresh()} />
        <OperationCenterSummary changes={changes} navigate={selectScreen} />
        {loading ? <LoadingSkeleton /> : <ScreenErrorBoundary key={`${screen}:${privacyHidden ? 'hidden' : 'visible'}`}><ScreenContent screen={screen} session={session} configVersion={configVersion} overview={overview} mutationLocked={!recoveryMutationAllowed(overview)} onboarding={onboarding} topology={topology} devices={devices} services={services} discovery={discovery} routes={routes} traffic={traffic} events={events} changes={changes} security={security} securitySummary={securitySummary} system={system} diagnostics={diagnostics} lifecycle={lifecycle} storage={storage} settings={settings} backups={backups} revisions={revisions} privacyHidden={privacyHidden} onTogglePrivacy={togglePrivacy} refresh={refresh} onboardingAction={async (step: string, action: 'skip' | 'accept' | 'automatic' | 'complete') => { const next = await updateOnboarding(step, action); setOnboarding(next); return next; }} navigate={selectScreen} /></ScreenErrorBoundary>}
      </main>
    </div>
  );
}

function RecoveryMutationBanner({ overview, navigate, onRetry }: { overview: any; navigate: (screen: string) => void; onRetry: () => void }) {
  if (overview?.recovery_status === undefined || recoveryMutationAllowed(overview)) return null;
  const status = textValue(overview.recovery_status, 'unknown');
  const reason = textValue(overview.recovery_reason, 'FlintRoute ещё не доказал безопасное состояние восстановления.');
  return <section class="warning-panel recovery-lock" role="alert">
    <div><b>Изменения временно заблокированы</b><p>{reason}</p><small>Интернет и просмотр данных остаются доступны. Новые правила и операции не запускаются, пока состояние роутера не подтверждено.</small></div>
    <div class="actions"><button onClick={onRetry}>Проверить снова</button><button onClick={() => navigate('Ревизии и recovery')}>Открыть восстановление</button><details><summary>Код</summary><span class="mono">{status} · {textValue(overview.recovery_reason_code, 'recovery_not_safe')}</span></details></div>
  </section>;
}

export { App };
