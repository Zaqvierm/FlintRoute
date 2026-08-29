import { Component, render, type ComponentChildren } from 'preact';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import QRCode from 'qrcode';
import {
  APIError,
  addManualVLESSServer,
  cancelZapretCalibration,
  componentAction,
  activateExternalSOCKS,
  activateZapretSetup,
  applyDiscoverySuggestion,
  changeAction,
  checkExternalSOCKS,
  checkZapretSetup,
  classifyService,
  configureDiscovery,
  configureSmartDNS,
  configureTelegram,
  configureTGWS,
  createChange,
  getChanges,
  getComponents,
  getBackups,
  getDevices,
  getDiagnostics,
  getDiscovery,
  getExternalSOCKS,
  getEvents,
  getHealth,
  getOverview,
  getOnboarding,
  getRevisions,
  getRoutes,
  getSecurity,
  getSecuritySummary,
  getSmartDNS,
  getServices,
  getSubscriptionHWID,
  getSubscriptionSecretStatus,
  getSystem,
  getSettings,
  getLifecycle,
  getManualVLESSServers,
  getVLESSPool,
  getStorage,
  getTelegram,
  getTGWS,
  getTraffic,
  getTopology,
  getZapret,
  getZapretCalibration,
  ignoreDiscoverySuggestion,
  login,
  logout,
  me,
  prepareSubscription,
  removeSubscriptionSource,
  saveSubscriptionSecrets,
  saveSubscriptionHWID,
  verifyService,
  runVLESSSpeedTest,
  setVLESSTariff,
  startZapretCalibration,
  setupAdmin,
  testTelegram,
  updateOnboarding,
  type ChangeSet,
  type ChangeOp,
  type ComponentAction,
  type ComponentKind,
  type ComponentStatus,
  type DiscoveryStatus,
  type EventItem,
  type ManualVLESSServer,
  type OnboardingState,
  type RevisionSummary,
  type SessionInfo,
  type SubscriptionHWIDSettings,
  type TrafficSnapshot,
  type ZapretCalibrationStatus
} from './api';
import {
  asArray,
  asRecord,
  errorInfo,
  formatDateTime,
  groupServices,
  humanStatus,
  isAdministrativeEvent,
  isDecisionEvent,
  onboardingRouterReady,
  onboardingProgress,
  parseResolverInput,
  recoveryMutationAllowed,
  serviceColumnFor,
  statusTone,
  stringArray,
  textValue,
  toDecisionCard,
  decisionVerificationPresentation,
  verificationPresentationLabel
} from './view-models';
import {
  AlertCenter,
  AuthShell,
  BootScreen,
  LoadingSkeleton,
  OperationCenterSummary,
  PrivacyBar,
  SessionBar,
  TopBar
} from './app/shell';
import {
  Card,
  DetailDrawer,
  DisabledActions,
  EmptyState,
  EntityCard,
  EventRow,
  EvidenceList,
  Generic,
  Grid,
  InfoGrid,
  PageHeader,
  RawDisclosure,
  RouteBadge,
  StatusBadge,
  StatusLine,
  useConfirmDialog,
  statusWithFreshness
} from './components/ui';
import { DeviceCard, Devices, NetworkMap, OverviewScreen } from './features/network';
import { Changes, Policies, Routes, ServiceGroup, Services } from './features/rules';
import './styles.css';

const navigation = [
  { title: 'Обзор', screens: ['Быстрая настройка', 'Обзор'] },
  { title: 'Сеть', screens: ['Карта сети', 'Устройства', 'Трафик'] },
  { title: 'Правила', screens: ['Сервисы', 'Маршруты', 'Компоненты', 'VLESS-серверы', 'Smart DNS', 'Zapret', 'TG WS Proxy', 'Discovery'] },
  { title: 'Активность', screens: ['Поток решений', 'Операции', 'Telegram', 'Ревизии и recovery'] },
  { title: 'Система', screens: ['Диагностика', 'Безопасность', 'Настройки', 'Резервное копирование', 'Advanced', 'External SOCKS'] }
];
const notFoundScreen = 'Страница не найдена';
const availableScreens = new Set([...navigation.flatMap((group) => group.screens), 'External SOCKS', notFoundScreen]);

class ScreenErrorBoundary extends Component<{ children: ComponentChildren }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  render() {
    if (this.state.failed) {
      return <section class="screen-error" role="alert" aria-live="assertive">
        <h1>Экран временно недоступен</h1>
        <p>FlintRoute не смог отрисовать этот раздел. Сеть и уже сохранённая конфигурация не изменялись.</p>
        <p class="mono">Код: ui_screen_render_failed</p>
        <button class="primary" onClick={() => this.setState({ failed: false })}>Повторить</button>
      </section>;
    }
    return this.props.children;
  }
}

function screenFromLocation(): string | null {
  if (typeof window === 'undefined') return null;
  const raw = new URLSearchParams(window.location.search).get('screen');
  if (raw === null) return null;
  return availableScreens.has(raw) ? raw : notFoundScreen;
}

function humanChangeBlock(reason?: string): string {
  const messages: Record<string, string> = {
    flow_offloading_incompatible: 'Аппаратное ускорение пакетов мешает выборочной маршрутизации. Разреши FlintRoute отключить flow offloading и повтори.',
    transparent_activation_unverified: 'Для этого правила нужен управляемый Xray. Сначала открой VLESS-серверы и явно включи managed Xray.',
    lan_interfaces_unverified: 'FlintRoute не смог надёжно определить LAN-интерфейсы. Сеть не изменена; открой диагностику.',
    wan_interface_unverified: 'FlintRoute не смог надёжно определить выход в интернет. Сеть не изменена; открой диагностику.'
  };
  return messages[reason ?? ''] ?? `Проверка на роутере не завершена${reason ? ` (${reason})` : ''}. Сеть не изменена. Открой «Диагностика», проверь состояние роутера и повтори применение.`;
}

function humanChangeFailure(change: ChangeSet): string {
  if (change.state === 'requires_device') return humanChangeBlock(change.artifact_block_reason);
  if (change.state === 'rolled_back') return 'Проверка нового правила не прошла. FlintRoute восстановил предыдущую рабочую конфигурацию; интернет не должен пострадать.';
  if (change.state === 'failed') return 'Не удалось применить правило. FlintRoute остановил изменение и сохранил прежнюю конфигурацию.';
  return `Правило не применено. Техническое состояние: ${change.state}. Открой подробности для диагностики.`;
}

function humanSmartDNSReason(reason?: string): string {
  const messages: Record<string, string> = {
    route_not_bound_to_verification_plan: 'DNS-сервер проверен, но пока не используется ни одним сервисом. Полный PathVerified будет выполнен внутри первой транзакции применения.',
    route_nft_counter_did_not_advance: 'DNS-сервер доступен, но FlintRoute пока не увидел трафик через новое правило.',
    smart_dns_socket_mark_or_policy_missing: 'DNS-сервер доступен, но правило маршрутизации не подтвердилось на роутере.',
    probe_adapter_revision_mismatch: 'Старая проверка относится к предыдущей конфигурации. Нужна свежая проверка пути.',
    dnsmasq_not_ready: 'dnsmasq не принял новую конфигурацию. FlintRoute восстановил предыдущую.'
  };
  return messages[reason ?? ''] ?? (reason ? `Проверка пути не пройдена: ${reason}.` : 'Конфигурация сохранена, но путь ещё не подтверждён.');
}

const unavailableOverview = {
  internet: 'unavailable',
  external_ipv4: 'unavailable',
  ipv6: 'unavailable',
  dns: 'unavailable',
  zapret: 'unavailable',
  vless_working: 0,
  smart_dns: 0,
  external_socks_configured: 0,
  cpu: 'unavailable',
  memory: 'unavailable',
  temperature: 'unavailable',
  data_plane: 'unavailable',
  source: 'api-unavailable',
  freshness: 'stale'
};

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

function App() {
  const [screen, setScreen] = useState(() => {
    try {
      const fromURL = screenFromLocation();
      if (fromURL) return fromURL;
      const stored = window.localStorage.getItem('flintroute-screen');
      return stored && availableScreens.has(stored) ? stored : 'Обзор';
    } catch {
      return 'Обзор';
    }
  });
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [mobileMoreOpen, setMobileMoreOpen] = useState(false);
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
  const screenRef = useRef(screen);

  useEffect(() => {
    screenRef.current = screen;
  }, [screen]);

  function selectScreen(next: string) {
    setScreen(next);
    setMobileMoreOpen(false);
    try {
      window.localStorage.setItem('flintroute-screen', next);
      const url = new URL(window.location.href);
      url.searchParams.set('screen', next);
      window.history.pushState({ screen: next }, '', url);
    } catch {
      // Storage may be disabled; navigation still works for this session.
    }
  }

  useEffect(() => {
    const onPopState = () => setScreen(screenFromLocation() ?? 'Обзор');
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

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
        {loading ? <LoadingSkeleton /> : <ScreenErrorBoundary key={`${screen}:${privacyHidden ? 'hidden' : 'visible'}`}><Content screen={screen} session={session} configVersion={configVersion} overview={overview} mutationLocked={!recoveryMutationAllowed(overview)} onboarding={onboarding} topology={topology} devices={devices} services={services} discovery={discovery} routes={routes} traffic={traffic} events={events} changes={changes} security={security} securitySummary={securitySummary} system={system} diagnostics={diagnostics} lifecycle={lifecycle} storage={storage} settings={settings} backups={backups} revisions={revisions} privacyHidden={privacyHidden} onTogglePrivacy={togglePrivacy} refresh={refresh} onboardingAction={async (step: string, action: 'skip' | 'accept' | 'automatic' | 'complete') => { const next = await updateOnboarding(step, action); setOnboarding(next); return next; }} navigate={selectScreen} /></ScreenErrorBoundary>}
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

function Content(props: any) {
  switch (props.screen) {
    case 'Вход':
      return <LoginScreen />;
    case 'Первичная настройка':
    case 'Быстрая настройка':
      return <SetupScreen {...props} />;
    case 'Обзор':
      return <OverviewScreen {...props} />;
    case 'Карта сети':
      return <NetworkMap topology={props.topology} devices={props.devices} system={props.system} expanded />;
    case 'Трафик':
      return <Traffic data={props.traffic} />;
    case 'Устройства':
      return <Devices devices={props.devices} events={props.events} />;
    case 'Карточка устройства':
      return <DeviceCard device={props.devices[0]} />;
    case 'Сервисы':
      return <Services services={props.services} configVersion={props.configVersion} role={props.session.role} mutationLocked={props.mutationLocked} refresh={props.refresh} navigate={props.navigate} />;
    case 'Discovery':
      return <Discovery data={props.discovery} configVersion={props.configVersion} role={props.session.role} mutationLocked={props.mutationLocked} refresh={props.refresh} />;
    case 'Группа сервиса':
      return <ServiceGroup service={props.services[0]} />;
    case 'Политики: таблица':
      return <Policies mode="table" />;
    case 'Политики: доска':
      return <Policies mode="board" />;
    case 'Advanced':
      return <Changes changes={props.changes} refresh={props.refresh} role={props.session.role} configVersion={props.configVersion} mutationLocked={props.mutationLocked} navigate={props.navigate} mode="developer" />;
    case 'Операции':
      return <Changes changes={props.changes} refresh={props.refresh} role={props.session.role} configVersion={props.configVersion} mutationLocked={props.mutationLocked} navigate={props.navigate} mode="operations" />;
    case 'Маршруты':
      return <Routes routes={props.routes} navigate={props.navigate} />;
    case 'Компоненты':
      return <Components role={props.session.role} mutationLocked={props.mutationLocked} navigate={props.navigate} />;
    case 'VLESS-серверы':
      return <Vless routes={props.routes} configVersion={props.configVersion} role={props.session.role} mutationLocked={props.mutationLocked} refresh={props.refresh} navigate={props.navigate} />;
    case 'Smart DNS':
      return <SmartDNS configVersion={props.configVersion} role={props.session.role} mutationLocked={props.mutationLocked} refresh={props.refresh} navigate={props.navigate} />;
    case 'Zapret':
      return <Zapret routes={props.routes} configVersion={props.configVersion} role={props.session.role} mutationLocked={props.mutationLocked} refresh={props.refresh} navigate={props.navigate} />;
    case 'External SOCKS':
      return <ExternalSOCKS configVersion={props.configVersion} role={props.session.role} mutationLocked={props.mutationLocked} refresh={props.refresh} navigate={props.navigate} />;
    case 'TG WS Proxy':
      return <TGWS role={props.session.role} mutationLocked={props.mutationLocked} navigate={props.navigate} />;
    case 'Telegram':
      return <Telegram role={props.session.role} mutationLocked={props.mutationLocked} events={props.events} />;
    case 'Поток решений':
      return <DecisionFlow events={props.events} discovery={props.discovery} />;
    case 'Диагностика':
      return <Diagnostics system={props.system} diagnostics={props.diagnostics} lifecycle={props.lifecycle} storage={props.storage} />;
    case 'Безопасность':
      return <Security data={props.security} summary={props.securitySummary} />;
    case 'Ревизии и recovery':
      return <Recovery revisions={props.revisions} backups={props.backups} lifecycle={props.lifecycle} />;
    case 'Удалённые клиенты':
      return <Generic title="Удалённые клиенты" text="Профили удалённого доступа, лимиты, срок действия и политика маршрутизации." />;
    case 'Настройки':
      return <Settings data={props.settings} privacyHidden={props.privacyHidden} onTogglePrivacy={props.onTogglePrivacy} mutationLocked={props.mutationLocked} role={props.session.role} />;
    case 'Обновление':
      return <Generic title="Обновление" text="Проверка версии, подпись выпуска, checksum, staged install и rollback." />;
    case 'Резервное копирование':
      return <Generic title="Резервное копирование и откат" text="Резервные копии конфигурации, секретов по явному выбору, nft/dnsmasq/fw4 snapshots." />;
    case notFoundScreen:
      return <Generic title="Страница не найдена" text="Такого раздела FlintRoute нет. Вернись в обзор или выбери раздел в меню." />;
    default:
      return <OverviewScreen {...props} />;
  }
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
    return 'Компонент установлен, но сейчас не используется. Настрой сервисы, чтобы подключить его к маршрутам.';
  }
  if (!status.health_ready) return status.health_reason || 'Компонент установлен, но health check не пройден.';
  if (status.kind === 'xray') return 'Готово. Следующий шаг — добавить VLESS-подписку или свой сервер.';
  if (status.kind === 'zapret') return 'Готово. Следующий шаг — запустить безопасную калибровку стратегии для текущей сети.';
  return 'Сервис установлен. Для PASS нужна фактическая проверка Telegram transport, а не один открытый TCP-порт.';
}

function Components({ role, mutationLocked, navigate }: { role: SessionInfo['role']; mutationLocked: boolean; navigate: (screen: string) => void }) {
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

function Discovery({ data, configVersion, role, mutationLocked, refresh }: { data: DiscoveryStatus | null; configVersion: number; role: SessionInfo['role']; mutationLocked: boolean; refresh: () => Promise<void> }) {
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

function Vless({
  routes,
  configVersion,
  role,
  mutationLocked,
  refresh,
  navigate
}: {
  routes: any[];
  configVersion: number;
  role: SessionInfo['role'];
  mutationLocked: boolean;
  refresh: () => Promise<void>;
  navigate: (screen: string) => void;
}) {
  const defaultHappPresetHWID = 'a330268d-7d9d-4343-8672-f6191f80a25c';
  const vless = routes.filter((r) => r.type === 'vless');
  const [urls, setURLs] = useState<string[]>(['']);
  const [present, setPresent] = useState<boolean | null>(null);
  const [configuredCount, setConfiguredCount] = useState(0);
  const [sourceStatuses, setSourceStatuses] = useState<Array<{ source_masked: string; source_type: string; crypto_version?: string }>>([]);
  const [hwid, setHWID] = useState<SubscriptionHWIDSettings | null>(null);
  const [hwidMode, setHWIDMode] = useState('generated');
  const [hwidSource, setHWIDSource] = useState('composite');
  const [hwidPreset, setHWIDPreset] = useState('');
  const [hwidCustomSeed, setHWIDCustomSeed] = useState('');
  const [hwidOpen, setHWIDOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [checkedServers, setCheckedServers] = useState<any[]>([]);
  const [managedAvailable, setManagedAvailable] = useState(false);
  const [selectedServer, setSelectedServer] = useState<any>(null);
  const [manualServers, setManualServers] = useState<ManualVLESSServer[]>([]);
  const [manualURI, setManualURI] = useState('');
  const [manualEditorOpen, setManualEditorOpen] = useState(false);
  const [pool, setPool] = useState<any>({ tariff_mbps: 300, sources: [], servers: [], provider_matches: [] });
  const [tariff, setTariff] = useState(300);
  const [xrayAvailable, setXrayAvailable] = useState(false);
  const confirmDialog = useConfirmDialog();

  function forceHappPreset(value: SubscriptionHWIDSettings): SubscriptionHWIDSettings {
    const preview = (value.preview ?? []).map((row) => ({ ...row, selected: row.source === 'preset' }));
    const presetRow = {
      source: 'preset',
      label: 'Preset / вручную заданный HWID',
      value: defaultHappPresetHWID,
      hwid: defaultHappPresetHWID,
      available: true,
      selected: true
    };
    const withoutPreset = preview.filter((row) => row.source !== 'preset');
    return { ...value, mode: 'preset', preset: defaultHappPresetHWID, current_hwid: defaultHappPresetHWID, preview: [presetRow, ...withoutPreset] };
  }

  function sourceRequiresHappHWID(value: string): boolean {
    const normalized = value.trim().toLowerCase();
    return normalized.startsWith('happ://') || /[?&]subkey=(?:happ(?:%3a|:)\/\/|happ\\:\/\/)/i.test(normalized);
  }

  useEffect(() => {
    const controller = new AbortController();
    const requests: Promise<any>[] = [getVLESSPool(controller.signal), getComponents(controller.signal)];
    if (role === 'administrator') requests.push(getSubscriptionSecretStatus(controller.signal), getManualVLESSServers(controller.signal), getSubscriptionHWID(controller.signal));
    Promise.allSettled(requests).then(([poolResult, componentsResult, subscription, manual, hwidResult]) => {
      if (controller.signal.aborted) return;
      if (poolResult.status === 'fulfilled') {
        setPool(poolResult.value);
        setTariff(poolResult.value.tariff_mbps || 300);
      }
      if (componentsResult.status === 'fulfilled') {
        const xrayComponent = componentsResult.value.find((item: ComponentStatus) => item.kind === 'xray');
        setXrayAvailable(Boolean(xrayComponent?.installed || xrayComponent?.health_ready || xrayComponent?.service_state === 'running'));
      }
      if (!subscription || !manual) return;
      if (subscription.status === 'fulfilled') {
        setPresent(subscription.value.present);
        setConfiguredCount(subscription.value.count ?? 0);
        setSourceStatuses(subscription.value.sources ?? []);
      } else {
        setPresent(null);
        setSourceStatuses([]);
      }
      if (manual.status === 'fulfilled') setManualServers(manual.value.servers);
      if (hwidResult?.status === 'fulfilled') {
        const hasHappSource = subscription?.status === 'fulfilled' && (subscription.value.sources ?? []).some((source: any) => source.source_type === 'happ' || source.crypto_version);
        // Happ subscriptions require the provider-compatible stable identity.
        // Do not let an older generated/custom setting silently win when a
        // Happ source is present; the save flow persists this exact preset
        // before it starts provider preparation.
        const visibleHWID = hasHappSource ? forceHappPreset(hwidResult.value) : hwidResult.value;
        setHWID(visibleHWID);
        setHWIDMode(visibleHWID.mode || 'generated');
        setHWIDSource(hwidResult.value.source || 'composite');
        setHWIDPreset(visibleHWID.preset || '');
        setHWIDCustomSeed(hwidResult.value.custom_seed || '');
      }
    }).catch(() => {
      // Promise.allSettled itself does not reject; keep this guard for a
      // provider that returns a thenable with unexpected behavior.
    });
    return () => controller.abort();
  }, [role]);

  useEffect(() => {
    if (!hwid) return;
    const happRequired = sourceStatuses.some((source) => source.source_type === 'happ' || Boolean(source.crypto_version)) || urls.some(sourceRequiresHappHWID);
    if (!happRequired || (hwid.mode === 'preset' && hwid.current_hwid === defaultHappPresetHWID)) return;
    const forced = forceHappPreset(hwid);
    setHWID(forced);
    setHWIDMode('preset');
    setHWIDPreset(defaultHappPresetHWID);
    setHWIDCustomSeed('');
  }, [sourceStatuses, urls, hwid]);

  async function saveTariff() {
    if (mutationLocked) { setMessage('Скорость тарифа нельзя изменить до подтверждения recovery state.'); return; }
    setBusy(true);
    try {
      await setVLESSTariff(tariff);
      const refreshed = await getVLESSPool();
      setPool(refreshed);
      setMessage(`Тариф ${tariff} Мбит/с сохранён. Он ограничивает вклад speedtest в score, но не режет сам трафик.`);
    } catch (error) {
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function saveHWIDSettings() {
    if (mutationLocked) { setMessage('HWID settings are temporarily locked by recovery fence.'); return; }
    setBusy(true);
    try {
      const happRequired = sourceStatuses.some((source) => source.source_type === 'happ' || Boolean(source.crypto_version)) || urls.some(sourceRequiresHappHWID);
      const settings = happRequired
        ? { mode: 'preset', source: hwidSource, preset: defaultHappPresetHWID, custom_seed: '' }
        : { mode: hwidMode, source: hwidSource, preset: hwidPreset, custom_seed: hwidCustomSeed };
      const result = await saveSubscriptionHWID(settings);
      setHWID(happRequired ? forceHappPreset(result) : result);
      if (happRequired) {
        setHWIDMode('preset');
        setHWIDPreset(defaultHappPresetHWID);
        setHWIDCustomSeed('');
      }
      setHWIDOpen(false);
      setMessage(`HWID сохранён: ${result.mode === 'preset' ? 'используется заданный UUID' : 'детерминированный источник'}.`);
    } catch (error) {
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function prepareCandidates(messagePrefix = 'Проверка завершена') {
    const result = await prepareSubscription(configVersion, false);
    if (!result.preparation.ready || result.preparation.secrets_printed) {
      throw new Error('Backend не подтвердил безопасный VLESS bundle.');
    }
    setCheckedServers(result.preparation.servers);
    const refreshed = await getVLESSPool();
    setPool(refreshed);
    setTariff(refreshed.tariff_mbps || 300);
    setManagedAvailable(result.activation.managed_available);
    setMessage(`${messagePrefix}: ${result.preparation.servers.length} серверов. Маршруты пока не включены — managed Xray подтверждается отдельно.`);
  }

  async function saveAndPrepare() {
    if (mutationLocked) { setMessage('Подписка временно заблокирована recovery fence. Просмотр серверов доступен.'); return; }
    const values = urls.map((value) => value.trim()).filter(Boolean);
    if (!values.length) {
      setMessage('Вставь хотя бы одну HTTPS-ссылку подписки.');
      return;
    }
    setBusy(true);
    setMessage('Сохраняю секрет и проверяю серверы. Это может занять несколько минут.');
    try {
      const saved = await saveSubscriptionSecrets(values);
      setURLs(['']);
      setPresent(true);
      setConfiguredCount(saved.count);
      setSourceStatuses(saved.sources ?? []);
      // Happ providers require an explicit stable identity. Never let a
      // first-run generated UUID or a stale provider-specific preset silently
      // reach this Happ provider. This source is bound to the administrator's
      // requested compatibility identity for the current product flow.
      if (values.some(sourceRequiresHappHWID)) {
        const preset = defaultHappPresetHWID;
        if (hwidMode !== 'preset' || hwidPreset.trim() !== preset) {
          const savedHWID = await saveSubscriptionHWID({ mode: 'preset', source: hwidSource, preset, custom_seed: '' });
          setHWID(savedHWID);
          setHWIDMode('preset');
          setHWIDPreset(preset);
        }
      }
      await prepareCandidates('Подписки сохранены и проверены');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Не удалось проверить подписку.');
    } finally {
      setBusy(false);
    }
  }

  async function removeStoredSubscription(index: number) {
    if (mutationLocked) { setMessage('Subscription changes are temporarily locked by recovery fence.'); return; }
    if (!(await confirmDialog.ask('Remove this subscription source? Existing active VLESS configuration is kept until a new verified bundle is activated.'))) return;
    setBusy(true);
    try {
      const result = await removeSubscriptionSource(index);
      setPresent(result.present);
      setConfiguredCount(result.count);
      setSourceStatuses(result.sources ?? []);
      setMessage(result.count ? 'Subscription source removed. Active VLESS configuration was not changed.' : 'All subscription sources removed. Active VLESS configuration was not changed.');
    } catch (error) {
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function addManualServer() {
    if (mutationLocked) { setMessage('Добавление сервера временно заблокировано recovery fence.'); return; }
    if (!manualURI.trim()) {
      setMessage('Вставь полный vless:// URI. UUID останется только в закрытом файле на роутере.');
      return;
    }
    setBusy(true);
    setMessage('Сохраняю ручной сервер и проверяю его реальный выход…');
    try {
      const inventory = await addManualVLESSServer(manualURI.trim());
      setManualServers(inventory.servers);
      setManualURI('');
      setManualEditorOpen(false);
      await prepareCandidates('Ручной сервер сохранён и проверен');
    } catch (error) {
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function refreshVLESSHealth() {
    setBusy(true);
    setMessage('Обновляю задержку и проверяю внешний путь. Недавний speedtest переиспользуется и трафик повторно не скачивается.');
    try {
      await prepareCandidates('Health обновлён');
    } catch (error) {
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function measureSelectedServer() {
    if (!selectedServer?.logical_id) {
      setMessage('Для этого сервера ещё нет logical ID. Сначала запусти проверку подписки.');
      return;
    }
    setBusy(true);
    setMessage('Измеряю скорость через конкретный VLESS server. Размер ограничен тарифом и пределом 16 MiB.');
    try {
      const result = await runVLESSSpeedTest(selectedServer.logical_id);
      const refreshed = await getVLESSPool();
      setPool(refreshed);
      setSelectedServer((current: any) => ({ ...current, ...result.server }));
      setMessage(`Скорость: ${result.measurement.measured_mbps.toFixed(0)} Мбит/с; использовано ${formatBytes(result.measurement.bytes_used)} за ${result.measurement.duration_ms} мс.`);
    } catch (error) {
      const info = errorInfo(error);
      setMessage(`${info.code}: ${info.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function activateManaged() {
    if (mutationLocked) { setMessage('Включение managed Xray временно заблокировано recovery fence.'); return; }
    setBusy(true);
    setMessage('Создаю черновик включения managed Xray…');
    try {
      const result = await prepareSubscription(configVersion, true);
      if (!result.change) throw new Error('Backend не создал транзакцию managed Xray.');
      setManagedAvailable(false);
      setMessage('Черновик managed Xray создан. Проверь diff и запусти применение отдельно в очереди изменений.');
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Managed Xray не включён; транзакция откатилась или ждёт устройство.');
    } finally {
      setBusy(false);
    }
  }

  const candidateServers = checkedServers.length ? checkedServers : pool.servers.length ? pool.servers : vless;
  const checksByTag = new Map(candidateServers.map((server: any) => [server.tag, server]));
  const subscriptionServers = candidateServers.filter((server: any) => !String(server.tag ?? '').startsWith('manual-'));
  const manualServerViews = manualServers.map((server) => ({ ...server, tag: server.id, ...asRecord(checksByTag.get(server.id)) }));

  function addSubscriptionRow() {
    if (urls.length < 5) setURLs((current) => [...current, '']);
  }

  function removeSubscriptionRow(index: number) {
    setURLs((current) => {
      const next = current.filter((_, currentIndex) => currentIndex !== index);
      return next.length ? next : [''];
    });
  }

  async function copyHWID() {
    if (!hwid?.current_hwid || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(hwid.current_hwid);
      setMessage('Deterministic subscription HWID copied.');
    } catch {
      setMessage('Clipboard is unavailable; the HWID remains visible in Settings.');
    }
  }

  function selectHWIDSource(source: string) {
    if (sourceStatuses.some((item) => item.source_type === 'happ' || Boolean(item.crypto_version)) || urls.some(sourceRequiresHappHWID)) {
      setHWIDMode('preset');
      setHWIDPreset(defaultHappPresetHWID);
      return;
    }
    setHWIDMode('generated');
    setHWIDSource(source);
  }

  const happSourceConfigured = sourceStatuses.some((source) => source.source_type === 'happ' || Boolean(source.crypto_version)) || urls.some(sourceRequiresHappHWID);

  return (
    <section>
      <PageHeader title="VLESS-серверы" text="Подписки и ручные серверы разделены. Ping — задержка проверки, а не скорость канала." />
      <Card title="Выбор сервера">
        {candidateServers.find((server: any) => server.selected) ? (() => { const active = candidateServers.find((server: any) => server.selected); return <div class="row"><b>{textValue(active.name ?? active.tag, 'VLESS server')}</b><span>{active.latency_ms ? `${active.latency_ms} мс` : 'latency неизвестна'} · {active.measured_mbps ? `${active.measured_mbps.toFixed(0)} Мбит/с` : 'speedtest не запускался'}</span><small>{active.path_verified ? 'PathVerified' : 'путь не подтверждён'} · score {Number(active.score ?? 0).toFixed(1)}</small></div>; })() : <p>Активного проверенного сервера пока нет.</p>}
        <div class="smart-dns-editor">
          <label><span>Скорость интернет-тарифа, Мбит/с</span><input type="number" min="1" max="100000" value={tariff} onInput={(event) => setTariff(Number((event.target as HTMLInputElement).value))} /></label>
          <div class="actions">{[100, 300, 500, 1000].map((value) => <button disabled={mutationLocked} class={tariff === value ? 'active' : ''} onClick={() => setTariff(value)} key={value}>{value}</button>)}<button class="primary" disabled={busy || mutationLocked || role !== 'administrator'} onClick={saveTariff}>Сохранить</button></div>
          <small>Для score используется min(измеренная скорость, тариф). Значение 850 Мбит/с при тарифе 300 даст эффективные 300.</small>
        </div>
      </Card>
      <Card title="VPN-подписки">
        <div class="row"><b>Источники</b><span>{present === true ? `${configuredCount} из 5` : present === false ? 'не заданы' : 'статус неизвестен'}</span></div>
        {role === 'administrator' ? (
          <div>
            <div class="subscription-source-list">
              {sourceStatuses.map((source, index) => <div class="subscription-source-status" key={`${source.source_masked}:${index}`}><b>#{index + 1}</b><span>{source.source_masked}</span><small>{source.source_type}{source.crypto_version ? ` / ${source.crypto_version}` : ''}</small><button type="button" class="icon-button" aria-label={`Remove stored source ${index + 1}`} onClick={() => void removeStoredSubscription(index)} disabled={busy || mutationLocked}>×</button></div>)}
              {urls.map((url, index) => (
                <label class="subscription-slot" key={index}>
                  <span>#{index + 1}</span>
                    <input
                     disabled={mutationLocked}
                    type="password"
                    value={url}
                    onInput={(event) => {
                      const next = [...urls];
                      next[index] = (event.target as HTMLInputElement).value;
                      setURLs(next);
                    }}
                    autocomplete="off"
                    placeholder="https://... or happ://crypt4/..."
                  />
                  <button type="button" class="icon-button" aria-label={`Remove source ${index + 1}`} onClick={() => removeSubscriptionRow(index)} disabled={busy || mutationLocked || urls.length === 1}>×</button>
                  <i>{busy ? 'checking' : 'new source'}</i>
                </label>
              ))}
            </div>
            <div class="actions"><button type="button" onClick={addSubscriptionRow} disabled={urls.length >= 5 || busy || mutationLocked}>+ Add subscription</button></div>
            <small>Original source is kept in the protected file. Happ payloads are resolved only for the provider request; the resolved credential is never returned.</small>
            <button class="primary" disabled={busy || mutationLocked || !configVersion} onClick={saveAndPrepare}>
              {busy ? 'Проверяю серверы…' : 'Сохранить и проверить'}
            </button>
            {managedAvailable && <button class="primary" disabled={busy || mutationLocked || !configVersion} onClick={activateManaged}>Явно включить managed Xray</button>}
            {managedAvailable && <small>Одна транзакция включит TPROXY, bypass mark и проверенные VLESS routes. Без успешной проверки она не будет подтверждена.</small>}
            <div class="hwid-settings hwid-compact">
              <div class="row"><span>Provider HWID</span><span>{hwidMode === 'preset' ? 'Preset UUID' : hwidMode === 'disabled' ? 'отключён' : 'детерминированный'}</span><button type="button" onClick={() => setHWIDOpen(true)} disabled={busy || role !== 'administrator'}>HWID</button></div>
              <small>Нужен только Happ-провайдеру. Источник и получающийся UUID — в компактном окне.</small>
            </div>
            {hwidOpen && <div class="modal-backdrop" role="presentation" onClick={() => setHWIDOpen(false)}><section class="confirm-dialog hwid-dialog" role="dialog" aria-modal="true" aria-labelledby="hwid-title" onClick={(event) => event.stopPropagation()}>
              <header class="modal-header"><h2 id="hwid-title">Источник HWID</h2><button type="button" class="icon-button" aria-label="Закрыть" onClick={() => setHWIDOpen(false)}>×</button></header>
              <p>Выбери стабильный источник. Один и тот же источник даёт один и тот же UUID после перезагрузки.</p>
              <div class="form-grid">
                <label><span>Режим</span><select value={happSourceConfigured ? 'preset' : hwidMode} onChange={(event) => setHWIDMode((event.target as HTMLSelectElement).value)} disabled={busy || mutationLocked || happSourceConfigured}><option value="generated">Сгенерированный</option><option value="preset">Preset / вручную</option><option value="disabled">Отключён</option></select></label>
                {hwidMode === 'preset' && <label><span>UUID</span><input type="text" value={hwidPreset} onInput={(event) => setHWIDPreset((event.target as HTMLInputElement).value)} autocomplete="off" placeholder="xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx" /></label>}
                {hwidMode === 'generated' && hwidSource === 'custom_seed' && <label><span>Custom seed</span><input type="text" value={hwidCustomSeed} onInput={(event) => setHWIDCustomSeed((event.target as HTMLInputElement).value)} autocomplete="off" placeholder="задайте стабильную строку" /></label>}
              </div>
              {happSourceConfigured && <small class="source-note">Для Happ-подписки используется обязательный совместимый preset: {defaultHappPresetHWID}.</small>}
              <div class="hwid-table-wrap"><table class="hwid-table"><thead><tr><th>Источник</th><th>Значение</th><th>Будет HWID</th><th></th></tr></thead><tbody>{(hwid?.preview ?? []).map((row) => { const selected = (hwidMode === 'preset' && row.source === 'preset') || (hwidMode === 'generated' && row.source === hwidSource); return <tr key={row.source} class={selected ? 'selected' : undefined}><td><b>{row.label}</b>{selected && <small>выбран</small>}</td><td class="mono">{row.value || row.reason || 'недоступно'}</td><td class="mono">{row.hwid || '—'}</td><td>{row.available && row.source !== 'preset' && <button type="button" onClick={() => selectHWIDSource(row.source)} disabled={busy || mutationLocked}>Выбрать</button>}{row.source === 'preset' && <button type="button" onClick={() => setHWIDMode('preset')} disabled={busy || mutationLocked}>Использовать</button>}</td></tr>; })}</tbody></table></div>
              <div class="row"><span>Текущий HWID</span><code>{hwidMode === 'disabled' ? 'отключён' : hwid?.current_hwid || 'недоступен'}</code><button type="button" onClick={() => void copyHWID()} disabled={!hwid?.current_hwid || hwidMode === 'disabled'}>Копировать</button></div>
              <div class="actions"><button type="button" onClick={() => setHWIDOpen(false)}>Отмена</button><button class="primary" disabled={busy || mutationLocked || role !== 'administrator'} onClick={() => void saveHWIDSettings()}>Сохранить выбор</button></div>
            </section></div>}
            {message && <div class="action-status"><p>{message}</p>{message.includes('черновик') && <button type="button" onClick={() => navigate('Операции')}>Открыть центр операций</button>}</div>}
          </div>
        ) : <p>Импорт подписки доступен администратору.</p>}
      </Card>
      <section class="server-section"><h2>Источники доступа</h2><div class="server-checks">
        {(pool.sources ?? []).map((source: any) => <EntityCard title={textValue(source.provider_name, source.name)} status={source.manual ? 'manual' : 'subscription'} onOpen={() => setSelectedServer({ source_record: source })} key={source.id}>
          <InfoGrid items={[["Источник", source.name], ["Original source", source.original_source_masked], ["Resolved source", source.resolved_source_masked], ["Type", source.source_type], ["Crypto", source.crypto_version], ["Resolution", source.resolution_status], ["Серверов", source.server_count], ["Срок", source.expiry_known ? formatDateTime(source.expires_at) : 'не предоставлен провайдером']]} />
        </EntityCard>)}
        {!pool.sources?.length && <EmptyState title="Источников пока нет" text="Добавь HTTPS-подписку или собственный VLESS URI." />}
      </div>{(pool.provider_matches ?? []).map((match: any) => <p class="reason" key={`${match.left_provider_id}:${match.right_provider_id}`}>Пулы похожи: совпало {match.matched_servers}/{match.compared_servers}. Объединение требует подтверждения и не выполняется молча.</p>)}</section>
       {xrayAvailable && <section class="server-section"><div class="section-title"><div><h2>VLESS servers</h2><p>Server status, measured latency and optional throughput are shown separately.</p></div><div class="actions"><button disabled={busy || !configVersion || (!present && manualServers.length === 0)} onClick={refreshVLESSHealth}>Refresh health</button><button disabled={mutationLocked} onClick={() => setManualEditorOpen((open) => !open)}>+ Add server</button></div></div>
      {manualEditorOpen && <div class="service-editor manual-vless-editor">
        <label><span>VLESS URI</span><input type="password" value={manualURI} onInput={(event) => setManualURI((event.target as HTMLInputElement).value)} autocomplete="off" placeholder="vless://UUID@server:443?security=reality&…" /></label>
        <small>URI и UUID не возвращаются через API и хранятся в закрытом файле. До явного managed activation сервер не меняет маршрутизацию.</small>
         <button class="primary" disabled={busy || mutationLocked || !configVersion} onClick={addManualServer}>{busy ? 'Проверяю…' : 'Сохранить и проверить'}</button>
      </div>}
      <div class="server-checks">
        {subscriptionServers.map((server: any) => (
          <EntityCard title={textValue(server.name ?? server.tag, 'VLESS server')} status={statusWithFreshness(server.status ?? server.health, server)} onOpen={() => setSelectedServer({ source: 'subscription', ...server })} key={server.tag}>
            <InfoGrid items={[["Hostname", server.hostname ?? server.address], ["Resolved IP", (server.resolved_ips ?? []).join(', ')], ["Страна", server.country || 'не определена'], ["Protocol / security", `vless / ${textValue(server.security, 'не указано')}`], ["Ping", server.latency_ms ? `${server.latency_ms} мс` : null], ["Скорость", server.measured_mbps ? `${server.measured_mbps.toFixed(0)} Мбит/с` : 'не измерена'], ["Источников", server.source_count ?? 1], ["Роль", server.selected ? 'selected' : server.standby ? 'standby' : server.quarantined ? 'quarantined' : null]]} />
            {server.reason && <p class="reason">{server.reason}</p>}
          </EntityCard>
        ))}
        {!subscriptionServers.length && <EmptyState title="Серверов из подписок пока нет" text="Добавь HTTPS-подписку и запусти проверку либо используй ручной VLESS ниже." />}
      </div></section>}
      {xrayAvailable && <section class="server-section"><h2>Добавленные вручную</h2><div class="server-checks">
        {manualServerViews.map((server: any) => <EntityCard title={textValue(server.name, 'Свой VPS')} status={statusWithFreshness(server.status ?? 'configured', server)} onOpen={() => setSelectedServer({ source: 'manual', ...server, uri_masked: `vless://••••@${server.address}:${server.port}` })} key={server.id}>
          <InfoGrid items={[["Адрес", `${server.address}:${server.port}`], ["Транспорт", server.network], ["Security", server.security], ["Ping", server.latency_ms ? `${server.latency_ms} мс` : 'ещё не измерен'], ["Состояние", server.status ?? 'configured']]} />
          {server.reason && <p class="reason">{humanStatus(server.reason)}</p>}
        </EntityCard>)}
        {!manualServerViews.length && <EmptyState title="Ручных серверов нет" text="Нажми «Добавить свой VPS», вставь vless:// URI и дождись проверки пути." />}
      </div></section>}
      <DetailDrawer title={textValue(selectedServer?.name ?? selectedServer?.tag ?? selectedServer?.source_record?.provider_name, 'VLESS server')} open={Boolean(selectedServer)} onClose={() => setSelectedServer(null)}><InfoGrid items={[["Источник", selectedServer?.source ?? selectedServer?.source_record?.name], ["Provider", selectedServer?.source_record?.provider_name], ["Hostname", selectedServer?.hostname ?? selectedServer?.address], ["Resolved IP", (selectedServer?.resolved_ips ?? []).join(', ')], ["URI", selectedServer?.uri_masked], ["Страна", selectedServer?.country], ["Источник страны", selectedServer?.country_source], ["Security", selectedServer?.security], ["Транспорт", selectedServer?.transport ?? selectedServer?.network], ["Ping", selectedServer?.latency_ms ? `${selectedServer.latency_ms} мс` : null], ["Средний ping", selectedServer?.average_latency_ms ? `${selectedServer.average_latency_ms} мс` : null], ["Jitter", selectedServer?.jitter_ms ? `${selectedServer.jitter_ms} мс` : null], ["Скорость raw", selectedServer?.measured_mbps ? `${selectedServer.measured_mbps} Мбит/с` : null], ["Эффективная скорость", selectedServer?.effective_mbps ? `${selectedServer.effective_mbps} Мбит/с` : null], ["Трафик speedtest", selectedServer?.speed_bytes ? formatBytes(selectedServer.speed_bytes) : null], ["Длительность speedtest", selectedServer?.speed_duration_ms ? `${selectedServer.speed_duration_ms} мс` : null], ["Score", selectedServer?.score], ["Health", selectedServer?.health ?? selectedServer?.status], ["PathVerified", selectedServer?.path_verified ? 'Да' : 'Нет'], ["Источники", (selectedServer?.source_ids ?? []).join(', ')], ["Expires", selectedServer?.source_record?.expiry_known ? formatDateTime(selectedServer?.source_record?.expires_at) : 'не предоставлен провайдером'], ["Quarantine", selectedServer?.quarantine_reason ?? selectedServer?.reason], ["Последняя проверка", formatDateTime(selectedServer?.last_checked_at)], ["Xray tag", selectedServer?.tag], ["SOCKS port", selectedServer?.socks_port ?? selectedServer?.socks5]]} /><p class="source-note">Ping идёт через candidate VLESS path. Полный speedtest запускается отдельно и не должен крутиться каждые 30 секунд.</p>{role === 'administrator' && selectedServer?.logical_id && <button class="primary" disabled={busy || !selectedServer.path_verified} onClick={measureSelectedServer}>Измерить скорость через этот сервер</button>}<RawDisclosure value={selectedServer} /></DetailDrawer>
    {confirmDialog.dialog}
    </section>
  );
}

function RouteType({ title, type, routes }: { title: string; type: string; routes: any[] }) {
  const [selected, setSelected] = useState<any>(null);
  return <section><h2>{title}</h2><Grid>{routes.filter((r) => r.type === type).map((r) => <EntityCard title={r.tag} status={statusWithFreshness(r.status, r)} onOpen={() => setSelected(r)}><RouteBadge type={type} /><p>{humanStatus(r.status)}</p></EntityCard>)}</Grid><DetailDrawer title={selected?.tag ?? title} open={Boolean(selected)} onClose={() => setSelected(null)}><DiagnosticDetails value={selected} /><RawDisclosure value={selected} /></DetailDrawer></section>;
}

function zapretProfileLabel(value: { profile_name?: string; profile_id?: string } | null | undefined, fallback = 'Стратегия') {
  // Names come from the pinned catalog. Falling back to the opaque ID is
  // deliberately honest; the UI must not invent a preset name for a profile
  // that the backend did not describe.
  return textValue(value?.profile_name, textValue(value?.profile_id, fallback));
}

function Zapret({ routes, configVersion, role, mutationLocked, refresh, navigate }: { routes: any[]; configVersion: number; role: SessionInfo['role']; mutationLocked: boolean; refresh: () => Promise<void>; navigate: (screen: string) => void }) {
  const [status, setStatus] = useState<any>(null);
  const [component, setComponent] = useState<ComponentStatus | null>(null);
  const [calibration, setCalibration] = useState<ZapretCalibrationStatus | null>(null);
  const [sourceURL, setSourceURL] = useState('');
  const [version, setVersion] = useState('');
  const [sha256, setSHA256] = useState('');
  const [testDomain, setTestDomain] = useState('example.com');
  const [report, setReport] = useState<any>(null);
  const [checked, setChecked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [showExhaustive, setShowExhaustive] = useState(false);
  async function load(signal?: AbortSignal) {
    const [zapretResult, componentsResult, calibrationResult] = await Promise.allSettled([getZapret(signal), getComponents(signal), getZapretCalibration(signal)]);
    if (signal?.aborted) return;
    const failures: string[] = [];
    if (zapretResult.status === 'fulfilled') setStatus(zapretResult.value);
    else { const info = errorInfo(zapretResult.reason); failures.push(`Zapret: ${info.code}: ${info.message}`); }
    if (componentsResult.status === 'fulfilled') {
      const managed = componentsResult.value.find((item) => item.kind === 'zapret') ?? null;
      setComponent(managed);
    } else { const info = errorInfo(componentsResult.reason); failures.push(`Компоненты: ${info.code}: ${info.message}`); }
    if (calibrationResult.status === 'fulfilled') setCalibration(calibrationResult.value);
    else { const info = errorInfo(calibrationResult.reason); failures.push(`Калибровка: ${info.code}: ${info.message}`); }
    if (failures.length) setMessage(failures.join(' · '));
    else setMessage('');
    const managed = componentsResult.status === 'fulfilled' ? componentsResult.value.find((item) => item.kind === 'zapret') ?? null : null;
    if (managed?.installed) {
      setSourceURL((value) => value || managed.pinned_asset_url || managed.source || '');
      setVersion((value) => value || managed.version || managed.latest_supported_version || '');
      setSHA256((value) => value || managed.binary_sha256 || managed.checksum || '');
    }
  }
  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal).catch((error) => {
      if (error instanceof Error && error.name === 'AbortError') return;
      setMessage(error instanceof Error ? error.message : 'Zapret API недоступен');
    });
    return () => controller.abort();
  }, []);
  useEffect(() => {
    if (calibration?.state !== 'running') return;
    const controller = new AbortController();
    let inFlight = false;
    const poll = () => {
      if (inFlight || controller.signal.aborted) return;
      inFlight = true;
      void getZapretCalibration(controller.signal)
        .then(setCalibration)
        .catch((error) => {
          if (error instanceof Error && error.name === 'AbortError') return;
          setMessage(error instanceof Error ? error.message : 'Не удалось обновить калибровку');
        })
        .finally(() => { inFlight = false; });
    };
    const timer = window.setInterval(poll,
      2000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [calibration?.state]);
  const input = { source_url: sourceURL.trim(), provider_version: version.trim(), binary_sha256: sha256.trim(), test_domain: testDomain.trim() };
  async function install() {
    if (mutationLocked) { setMessage('Установка Zapret заблокирована до подтверждения recovery state.'); return; }
    setBusy(true); setMessage('Определяю архитектуру, скачиваю закреплённый release и проверяю SHA-256…');
    try {
      const result = await componentAction('zapret', 'install');
      setMessage(result.changed ? 'Zapret установлен. Теперь можно запустить подбор стратегии.' : 'Zapret уже установлен и прошёл проверку.');
      await load();
    } catch (error) { const info = errorInfo(error); setMessage(`${info.code}: ${info.message}`); }
    finally { setBusy(false); }
  }
  async function startCalibration(mode: 'quick' | 'exhaustive') {
    if (mutationLocked) { setMessage('Калибровка Zapret заблокирована до подтверждения recovery state.'); return; }
    setBusy(true); setMessage(mode === 'quick'
      ? 'Запускаю быстрый curated-тест Zapret. Каждая стратегия должна доказать путь через nfqws/NFQUEUE; без такого доказательства PASS не будет.'
      : 'Запускаю полный подбор Zapret. Он может занять до 6 часов; найденный профиль не включается автоматически.');
    try {
      const result = await startZapretCalibration(testDomain.trim(), false, mode);
      setCalibration(result); setShowExhaustive(false); setMessage(mode === 'quick'
        ? 'Быстрый тест запущен. Если runtime не имеет curated evidence runner, FlintRoute остановит его без ложного PASS.'
        : 'Полный подбор запущен. Один worker сохраняет безопасное владение общими nft/NFQUEUE ресурсами.');
    } catch (error) { const info = errorInfo(error); setMessage(`${info.code}: ${info.message}`); }
    finally { setBusy(false); }
  }
  async function cancelCalibration() {
    if (mutationLocked) { setMessage('Управление калибровкой заблокировано до подтверждения recovery state.'); return; }
    setBusy(true);
    try { setCalibration(await cancelZapretCalibration()); setMessage('Остановка запрошена; test-run выполнит cleanup своих ресурсов.'); }
    catch (error) { const info = errorInfo(error); setMessage(`${info.code}: ${info.message}`); }
    finally { setBusy(false); }
  }
  async function check() {
    setBusy(true); setChecked(false); setMessage('Проверяю nfqws, архитектуру, NFQUEUE и dry-run…');
    try {
      const result = await checkZapretSetup(input, configVersion);
      setReport(result.report); setChecked(true); setMessage('Preflight пройден. Zapret ещё не включён.');
    } catch (error) { setReport(null); setMessage(error instanceof Error ? error.message : 'Zapret preflight провален.'); }
    finally { setBusy(false); }
  }
  async function activate() {
    setBusy(true); setMessage('Создаю черновик включения managed Zapret…');
    try {
      const result = await activateZapretSetup(input, configVersion);
      setChecked(false); setReport(result.report);
      setMessage(result.calibrated_profile_id
        ? `Создан черновик включения Zapret с профилем ${result.calibrated_profile_id}. Открой очередь, проверь diff и запусти применение отдельно.`
        : 'Создан черновик включения managed Zapret. Открой очередь, проверь diff и запусти применение отдельно.');
      await refresh();
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Zapret не включён; транзакция откатилась или ждёт устройство.'); }
    finally { setBusy(false); }
  }
  return <section class="grid">
    <Card title="Zapret">
      <div class="row"><b>{component?.installed ? `Установлен ${component.version ?? ''}` : 'Не установлен'}</b><span>{component?.service_state ?? 'service unavailable'}</span><small>{component?.health_ready ? 'Health check пройден' : component?.health_reason ?? 'Готов к установке'}</small></div>
      {status?.active_profile?.profile_id && <div class="zapret-active-profile"><div class="row"><b>Настроено</b><span>{zapretProfileLabel(status.active_profile)}</span><small>{status.active_profile.available === false ? 'Профиль не найден в закреплённом каталоге' : 'Сейчас используется'}</small></div>{status?.fallback_profile?.profile_id && <div class="row"><b>Fallback</b><span>{zapretProfileLabel(status.fallback_profile)}</span><small>{status.fallback_profile.available === false ? 'Профиль не найден в закреплённом каталоге' : 'Следующий разрешённый профиль'}</small></div>}</div>}
      {role === 'administrator' && !component?.installed && <button class="primary" disabled={busy || mutationLocked} onClick={install}>{busy ? 'Устанавливаю…' : 'Установить Zapret'}</button>}
      {component?.installed && role === 'administrator' && <div class="change-editor">
        <label><span>Домен для подбора стратегии</span><input class="mono" value={testDomain} onInput={(event) => { setTestDomain((event.target as HTMLInputElement).value); setChecked(false); }} /></label>
         {calibration?.state === 'running' ? <button disabled={busy || mutationLocked} onClick={cancelCalibration}>Остановить тест</button> : <div class="actions">
           <button class="primary" disabled={busy || mutationLocked || !testDomain.trim()} onClick={() => void startCalibration('quick')}>Быстрый тест Zapret</button>
           <button disabled={busy || mutationLocked || !testDomain.trim()} onClick={() => setShowExhaustive(true)}>Полный подбор стратегий</button>
        </div>}
        {showExhaustive && calibration?.state !== 'running' && <div class="warning-panel" role="alert">
          <b>Глубокий перебор — аварийно-длинная операция</b>
          <p>Будет проверено большое количество комбинаций upstream Zapret. Это может занять до 6 часов. Запускайте полный подбор только если быстрый тест не нашёл рабочую стратегию.</p>
           <div class="actions"><button class="primary" disabled={busy || mutationLocked} onClick={() => void startCalibration('exhaustive')}>Запустить полный подбор</button><button disabled={busy} onClick={() => setShowExhaustive(false)}>Отмена</button></div>
        </div>}
        <small>Параллельность: {textValue(calibration?.concurrency, '1')}. {textValue(calibration?.concurrency_reason, 'Общие nft/NFQUEUE ресурсы upstream требуют последовательного прогона.')}</small>
      </div>}
      {message && <div class="action-status"><p>{message}</p>{message.includes('черновик') && <button type="button" onClick={() => navigate('Операции')}>Открыть центр операций</button>}</div>}
    </Card>
    {calibration && calibration.state !== 'idle' && <Card title="Подбор стратегии">
      <div class="row"><b>{humanStatus(calibration.state)}</b><span>{calibration.mode === 'exhaustive' ? 'полный подбор' : 'быстрый тест'} · {textValue(calibration.scan_level, 'quick')}</span><small>{textValue(calibration.domain, 'домен не указан')} · {calibration.duration_ms ? `${Math.round(calibration.duration_ms / 1000)} сек` : 'идёт'}</small></div>
      {calibration.state === 'running' && <div class="row"><b>Проверено вариантов</b><span>{calibration.checks_completed ?? 0}{calibration.checks_total ? ` / ${calibration.checks_total}` : ''}</span><small>{calibration.mode === 'exhaustive' ? 'Upstream force scan; точное число зависит от версии и платформы.' : 'Curated-набор; каждая попытка должна вернуть path evidence и cleanup proof.'}</small></div>}
      {calibration.mode === 'quick' && calibration.state !== 'running' && <div class="row"><b>Доказательство пути</b><span>{calibration.path_verified ? 'Path verified' : 'Не подтверждено'}</span><small>{textValue(calibration.evidence_level, 'нет evidence')}</small></div>}
      {calibration.error && <p class="reason">{textValue(calibration.error_code, 'calibration_error')}: {textValue(calibration.error, 'Ошибка калибровки')}</p>}
      {(calibration.attempts ?? []).map((attempt, index) => <div class="row" key={`${attempt.profile_id}:${index}`}><b>{zapretProfileLabel(attempt, `Стратегия ${index + 1}`)}</b><span>{textValue(attempt.result, 'INFRA_ERROR')}</span><small>{textValue(attempt.target, 'target')} · {textValue(attempt.protocol, 'protocol')} · {attempt.path_verified ? 'path verified' : 'path не подтверждён'} · {attempt.cleanup_verified ? 'cleanup OK' : 'cleanup не подтверждён'}</small></div>)}
      <h4>Рабочие стратегии — появляются сразу</h4>
      {(calibration.working_strategies ?? []).length
        ? (calibration.working_strategies ?? []).map((strategy, index) => <div class="row" key={`${index}:${textValue(strategy, 'strategy')}`}><b>Рабочая #{index + 1}</b><span>{zapretProfileLabel({ profile_id: strategy })}</span></div>)
        : (calibration.candidates ?? []).length
          ? (calibration.candidates ?? []).map((candidate) => <div class="row" key={`verified:${candidate.profile_id}`}><b>Path verified</b><span>{zapretProfileLabel(candidate)}</span><small>Эта стратегия прошла проверку через собственную NFQUEUE и может быть включена отдельным черновиком.</small></div>)
          : <p>Пока ни одна стратегия не прошла проверку.</p>}
      {(calibration.candidates ?? []).map((candidate, index) => <div class="row" key={candidate.profile_id}><b>{zapretProfileLabel(candidate, `Кандидат ${index + 1}`)}</b><span>{candidate.provider} {candidate.provider_version}</span><small>{candidate.transports.join(' + ')} · {candidate.occurrences ?? 0} подтверждений</small></div>)}
      {calibration.recommended_profile_id && <p class="action-status">Рекомендован: <span>{zapretProfileLabel({ profile_id: calibration.recommended_profile_id })}</span> <span class="mono">({calibration.recommended_profile_id})</span>. Именно он будет привязан при явном включении ниже.</p>}
      <h4>Живой лог</h4>
      <pre>{(calibration.log_tail ?? []).join('\n') || 'blockcheck ещё не успел вывести данные'}</pre>
      {calibration.activation_required && <p>Профили записаны в проверенный каталог. Выбор не применяется молча: создай отдельный черновик, проверь diff и запусти транзакцию в центре операций.</p>}
    </Card>}
    {component?.installed && <Card title="Явное включение маршрута">
      <p>Установка бинарника и включение маршрута — разные операции. Apply проверит NFQUEUE, data path и подтвердится только через штатную транзакцию.</p>
       {role === 'administrator' && <div class="actions"><button disabled={busy || !configVersion} onClick={check}>{busy ? 'Проверяю…' : 'Проверить перед черновиком'}</button><button class="primary" disabled={busy || mutationLocked || !checked || !configVersion} onClick={activate}>Создать черновик Zapret</button></div>}
      <details><summary>Advanced · закреплённый источник</summary><div class="change-editor">
        <label><span>HTTPS source</span><input class="mono" value={sourceURL} onInput={(event) => { setSourceURL((event.target as HTMLInputElement).value); setChecked(false); }} /></label>
        <label><span>Версия</span><input class="mono" value={version} onInput={(event) => { setVersion((event.target as HTMLInputElement).value); setChecked(false); }} /></label>
        <label><span>SHA-256</span><input class="mono" value={sha256} onInput={(event) => { setSHA256((event.target as HTMLInputElement).value); setChecked(false); }} /></label>
      </div></details>
    </Card>}
    {report && <Card title="Результат preflight"><div class="row"><b>{report.dry_run ? 'dry-run OK' : 'dry-run FAIL'}</b><span>{report.architecture}</span><small>NFQUEUE: {report.kernel_support}</small></div><div class="row"><b>{report.provider_version}</b><span>{report.test_domain}</span><small>{report.source_pinned ? 'immutable source pinned' : 'source не закреплён'}</small></div></Card>}
    <RouteType title="Zapret route" type="zapret" routes={routes} />
  </section>;
}

function SmartDNS({
  configVersion,
  role,
  mutationLocked,
  refresh,
  navigate
}: {
  configVersion: number;
  role: SessionInfo['role'];
  mutationLocked: boolean;
  refresh: () => Promise<void>;
  navigate: (screen: string) => void;
}) {
  const [status, setStatus] = useState<any>(null);
  const [error, setError] = useState('');
  const [resolvers, setResolvers] = useState(['']);
  const [testDomain, setTestDomain] = useState('example.com');
  const [validations, setValidations] = useState<any[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    getSmartDNS(controller.signal)
      .then(setStatus)
      .catch((reason) => {
        if (reason instanceof Error && reason.name === 'AbortError') return;
        setError(reason instanceof Error ? reason.message : 'Smart DNS недоступен');
      });
    return () => controller.abort();
  }, []);
  async function save() {
    if (mutationLocked) { setMessage('Smart DNS нельзя изменить до подтверждения recovery state.'); return; }
    let values;
    try {
      values = resolvers.filter((value) => value.trim()).map(parseResolverInput);
    } catch (reason) {
      const info = errorInfo(reason);
      setMessage(`${info.code}: Проверь IP и необязательный порт.`);
      return;
    }
    if (!values.length) {
      setMessage('Укажи хотя бы один публичный IP резолвера и порт.');
      return;
    }
    if (!testDomain.trim()) {
      setMessage('Укажи домен для DNS и HTTP/TLS проверки.');
      return;
    }
    setBusy(true);
    setMessage('Создаю проверяемое изменение Smart DNS…');
    try {
      const result = await configureSmartDNS(values, testDomain.trim(), configVersion);
      setValidations(result.validations ?? []);
      setResolvers(['']);
      setMessage(`Smart DNS проверен. Создан черновик для ${result.endpoint_count} резолверов; открой очередь изменений для review и применения.`);
      setStatus(await getSmartDNS());
      await refresh();
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : 'Smart DNS не прошёл проверку. Предыдущая конфигурация сохранена.');
    } finally {
      setBusy(false);
    }
  }
  if (error) return <Generic title="Smart DNS" text={error} />;
  if (!status) return <Generic title="Smart DNS" text="Загружаю состояние…" />;
  return (
    <section class="grid">
      <Card title="Состояние Smart DNS">
        <div class="row"><b>{status.configured_count ?? 0}</b><span>DNS-серверов настроено</span><small>{status.ready ?? 0} готовы к выбору для GEO-сервисов</small></div>
        {status.configured && !status.ready && <p class="action-status">DNS-серверы сохранены, но маршрут пока не подтверждён. {humanSmartDNSReason(status.routes?.[0]?.health?.last_reason)}</p>}
        <h4>Проверка успеха</h4>
        <div class="chips">{(status.success_contract ?? []).map((item: string) => <span class="chip">{item}</span>)}</div>
        {role === 'administrator' && (
          <div class="smart-dns-editor">
            {resolvers.map((resolver, index) => <label key={index}><span>{index === 0 ? 'Основной резолвер' : 'Резервный резолвер'}</span><span class="inline-field"><input class="mono" value={resolver} placeholder={index ? '[2606:4700:4700::1111]:53' : '1.1.1.1'} onInput={(event) => {
              const next = [...resolvers]; next[index] = (event.target as HTMLInputElement).value; setResolvers(next);
            }} />{index > 0 && <button type="button" onClick={() => setResolvers((items) => items.filter((_, itemIndex) => itemIndex !== index))}>Убрать</button>}</span></label>)}
            {resolvers.length < 2 && <button type="button" onClick={() => setResolvers((items) => [...items, ''])}>Добавить резервный резолвер</button>}
            <small>Порт необязателен. По умолчанию используется 53. Поддерживаются IPv4, IPv4:порт, IPv6 и [IPv6]:порт.</small>
            <label><span>Домен для DNS + HTTP/TLS</span><input class="mono" value={testDomain} placeholder="example.com" onInput={(event) => setTestDomain((event.target as HTMLInputElement).value)} /></label>
            <button class="primary" disabled={busy || mutationLocked || !configVersion} onClick={save}>
              {busy ? 'Проверяю…' : 'Добавить и проверить endpoint'}
            </button>
            {mutationLocked && <p class="action-status">Настройка Smart DNS временно заблокирована recovery fence.</p>}
            {message && <div class={message.includes('применён') ? 'action-status ok' : 'action-status'}><p>{message}</p>{message.includes('черновик') && <button type="button" onClick={() => navigate('Операции')}>Открыть центр операций</button>}</div>}
          </div>
        )}
      </Card>
      {validations.map((validation: any) => <Card title={`Проверка ${validation.endpoint}`} key={validation.endpoint}>
        <div class="row"><b>{validation.udp?.safe ? 'UDP OK' : 'UDP FAIL'}</b><b>{validation.tcp?.safe ? 'TCP OK' : 'TCP FAIL'}</b><b>{validation.tls_ok ? 'TLS OK' : 'TLS FAIL'}</b><b>{validation.http_ok ? `HTTP ${validation.http_status}` : 'HTTP FAIL'}</b></div>
        <div class="chips">{(validation.addresses ?? []).map((address: string) => <span class="chip mono">{address}</span>)}</div>
        <small>Соединение: {validation.connected_ip || 'не установлено'} · Host/SNI: {validation.domain}</small>
      </Card>)}
      {(status.routes ?? []).map((route: any) => (
        <Card title={textValue(route.tag, 'Smart DNS route')} key={textValue(route.tag, 'smart-dns-route')}>
          <div class="row"><RouteBadge type="smart_dns" /><StatusBadge value={statusWithFreshness(route.status || 'не проверен', route)} /><span>{route.resolver_configured ? 'endpoint задан' : 'нужен endpoint'}</span></div>
          {route.last_validation && <div class="row"><b>{route.last_validation.result?.udp?.safe ? 'UDP OK' : 'UDP FAIL'}</b><b>{route.last_validation.result?.tcp?.safe ? 'TCP OK' : 'TCP FAIL'}</b><b>{route.last_validation.result?.tls_ok ? 'TLS OK' : 'TLS FAIL'}</b><b>{route.last_validation.result?.http_ok ? `HTTP ${route.last_validation.result.http_status}` : 'HTTP FAIL'}</b></div>}
          {route.status === 'validated_idle' && <p>DNS-сервер работает и готов к выбору. Сейчас он не используется ни одним сервисом.</p>}
          {route.status !== 'validated_idle' && route.health?.last_reason && <p>{humanSmartDNSReason(textValue(route.health.last_reason, 'Причина не указана'))}</p>}
          <small>{route.connect_to_resolved_ip ? 'HTTP/TLS проверяется по адресу из ответа DNS' : 'Маршрут выключен: resolver ещё не проверен'}</small>
          <small>Conditional DNS, не VPN.</small>
        </Card>
      ))}
      <Card title="Порядок fallback">
        <div class="row"><b>GEO</b><span>{(status.fallback_order?.geo ?? []).join(' → ')}</span></div>
        <div class="row"><b>TSPU</b><span>{(status.fallback_order?.tspu ?? []).join(' → ')}</span></div>
      </Card>
    </section>
  );
}

function ExternalSOCKS({ configVersion, role, mutationLocked, refresh, navigate }: { configVersion: number; role: SessionInfo['role']; mutationLocked: boolean; refresh: () => Promise<void>; navigate: (screen: string) => void }) {
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
    setBusy(true); setMessage('Создаю черновик внешнего SOCKS-маршрута…');
    try {
      const result = await activateExternalSOCKS(endpoint.trim(), domain.trim(), configVersion);
      if (!result.change) throw new Error('Backend не создал черновик внешнего SOCKS-маршрута.');
      setMessage('Черновик внешнего SOCKS-маршрута создан. Проверь diff и запусти применение отдельно в очереди изменений.');
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
        <button class="primary" disabled={busy || mutationLocked || !checked || !configVersion} onClick={activate}>Создать черновик маршрута</button>
        {message && <div class="action-status"><p>{message}</p>{message.includes('черновик') && <button type="button" onClick={() => navigate('Операции')}>Открыть центр операций</button>}</div>}
      </div>}
    </Card>
    {report && <Card title="Результат проверки"><div class="row"><b>{report.ready ? 'READY' : 'FAILED'}</b><span>SOCKS5: {report.socks5_handshake ? 'OK' : 'FAIL'}</span><small>TLS: {report.tls_verified ? 'OK' : 'FAIL'} · HTTP {report.http_status || '—'}</small></div></Card>}
  </section>;
}

function TGWS({ role, mutationLocked, navigate }: { role: SessionInfo['role']; mutationLocked: boolean; navigate: (screen: string) => void }) {
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

function Telegram({ role, mutationLocked, events: systemEvents }: { role: SessionInfo['role']; mutationLocked: boolean; events: EventItem[] }) {
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

function DecisionFlow({ events, discovery }: { events: EventItem[]; discovery: DiscoveryStatus | null }) {
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

function Diagnostics({ system, diagnostics, lifecycle, storage }: { system: any; diagnostics: any; lifecycle: any; storage: any }) {
  const sections = [
    { title: 'Платформа', value: system, summary: `${textValue(system?.hostname, 'Router')} · ${textValue(system?.model)}` },
    { title: 'Сеть и возможности', value: diagnostics, summary: humanStatus(diagnostics?.status) },
    { title: 'Lifecycle', value: lifecycle, summary: humanStatus(lifecycle?.status) },
    { title: 'Хранилище', value: storage, summary: humanStatus(storage?.status) }
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

function Security({ data, summary }: { data: any; summary: any }) {
  const [selected, setSelected] = useState<any>(null);
  const checks = asArray(data?.checks).map(asRecord);
  return <section><PageHeader title="Безопасность" text="Каждая проверка объясняет риск и действие. Код можно использовать для поиска в документации и логах." />
    <div class="security-summary"><StatusBadge value={data?.status ?? summary?.status} /><span>Секреты: {textValue(summary?.secrets, 'скрыты')}</span><span>Auth: {humanStatus(summary?.auth)}</span></div>
    <Grid>{checks.map((check) => <EntityCard title={textValue(check.name ?? check.id, 'Проверка')} status={check.status ?? check.severity} onOpen={() => setSelected(check)}><StatusLine label="Severity" value={check.severity} /><p>{textValue(check.message ?? check.explanation, 'Описание отсутствует')}</p><small class="mono">{textValue(check.code ?? check.id, 'security_check')}</small></EntityCard>)}</Grid>
    {!checks.length && <EmptyState title="Подробный аудит недоступен" text="Базовая защита API показана выше. Для полного аудита backend должен разрешить диагностический endpoint." />}
    <DetailDrawer title={textValue(selected?.name ?? selected?.id, 'Проверка безопасности')} open={Boolean(selected)} onClose={() => setSelected(null)}><InfoGrid items={[["Код", selected?.code ?? selected?.id], ["Severity", selected?.severity], ["Статус", selected?.status], ["Причина", selected?.message ?? selected?.explanation], ["Что делать", selected?.action ?? selected?.required_action]]} /><RawDisclosure value={selected} /></DetailDrawer>
  </section>;
}

function Recovery({ revisions, backups, lifecycle }: { revisions: RevisionSummary | null; backups: any; lifecycle: any }) {
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

function Settings({ data, privacyHidden, onTogglePrivacy, mutationLocked = false, role = 'viewer' }: { data?: any; privacyHidden?: boolean; onTogglePrivacy?: () => void; mutationLocked?: boolean; role?: SessionInfo['role'] }) {
  const hidden = Boolean(privacyHidden);
  return <section><PageHeader title="Настройки" text="Простые настройки FlintRoute. Системные операции по-прежнему проходят через безопасные сценарии и recovery fence." /><Grid><TariffSettingsCard mutationLocked={mutationLocked} role={role} /><EntityCard title="Приватность" status="configured"><p>{hidden ? 'Адреса устройств сейчас скрыты. FlintRoute не запрашивает raw IP и MAC, пока включён скрытый режим.' : 'Адреса устройств сейчас видны. Этот выбор сохраняется в браузере, пока вы не переключите режим обратно.'}</p>{onTogglePrivacy && <button type="button" onClick={onTogglePrivacy} aria-pressed={!hidden}>{hidden ? 'Показать адреса' : 'Скрыть адреса'}</button>}</EntityCard><EntityCard title="Хранение" status={data?.status}><StatusLine label="Events" value={data?.storage?.event_retention_days ? `${data.storage.event_retention_days} дней` : null} /><StatusLine label="Backups" value={data?.storage?.max_state_backups} /></EntityCard><EntityCard title="Обновление" status="not_implemented"><p>Автоматическое обновление из UI не реализовано.</p></EntityCard></Grid><RawDisclosure value={data} /></section>;
}

function LoginScreen() {
  return <Card title="Вход"><p>Локальный администратор. Сессия защищается HttpOnly cookie и CSRF-токеном.</p><button class="primary">Войти локально</button></Card>;
}

function SetupScreen({ overview, services, routes, discovery, onboarding, onboardingAction, navigate, mutationLocked = false }: any) {
  const [state, setState] = useState<any>({ loading: true, components: [], pool: null, smartDNS: null, tgws: null, zapret: null, error: '' });
  const [tariff, setTariff] = useState(300);
  const requestRef = useRef<AbortController | null>(null);
  const [actionBusy, setActionBusy] = useState('');
  const [actionError, setActionError] = useState('');

  async function load() {
    requestRef.current?.abort();
    const controller = new AbortController();
    requestRef.current = controller;
    setState((old: any) => ({ ...old, loading: true, error: '' }));
    const results = await Promise.allSettled([
      getComponents(controller.signal),
      getVLESSPool(controller.signal),
      getSmartDNS(controller.signal),
      getTGWS(controller.signal),
      getZapret(controller.signal)
    ]);
    if (controller.signal.aborted || requestRef.current !== controller) return;
    const value = (index: number, fallback: any) => results[index].status === 'fulfilled' ? (results[index] as PromiseFulfilledResult<any>).value : fallback;
    const failed = results.filter((item) => item.status === 'rejected');
    const pool = value(1, null);
    if (pool) setTariff(Number(pool.tariff_mbps) || 300);
    setState({
      loading: false,
      components: value(0, []),
      pool,
      smartDNS: value(2, null),
      tgws: value(3, null),
      zapret: value(4, null),
      error: failed.length ? 'Часть проверок недоступна. Повтори после восстановления соединения.' : ''
    });
  }

  useEffect(() => {
    // The setup screen owns its first-run data fetch.  Previously this effect
    // only installed the unmount cleanup, leaving a freshly opened wizard in
    // the permanent loading state until the user pressed Retry.
    void load();
    return () => {
      requestRef.current?.abort();
      requestRef.current = null;
    };
  }, []);

  const routerReady = onboardingRouterReady(onboarding, overview);
  const components = asArray(state.components).map(asRecord);
  const xray = components.find((item) => item.kind === 'xray');
  const zapretComponent = components.find((item) => item.kind === 'zapret');
  const tgwsComponent = components.find((item) => item.kind === 'tg_ws_proxy');
  const verifiedServers = asArray(state.pool?.servers).filter((raw) => Boolean(asRecord(raw).path_verified)).length;
  const smartReady = Number(state.smartDNS?.ready_resolvers ?? state.smartDNS?.ready ?? 0) > 0;
  const tgwsReady = Boolean(state.tgws?.client_path_verified);
  const zapretReady = Boolean(state.zapret?.ready ?? zapretComponent?.health_ready);
  const methodsStatus = textValue(onboarding?.steps?.methods?.status, 'pending');
  const sourcesStatus = textValue(onboarding?.steps?.sources?.status, 'pending');
  const servicesStatus = textValue(onboarding?.steps?.services?.status, 'pending');
  const progress = onboardingProgress({
    methodsStatus,
    sourcesStatus,
    servicesStatus,
    verifiedServers,
    smartReady,
    tgwsReady,
    zapretReady,
    canComplete: onboarding?.can_complete
  });
  const { methodsDone, sourcesDone, providerReady: providerChosen, serviceChoiceDone, setupReady } = progress;

  async function chooseDirect() {
    await onboardingAction('methods', 'skip');
    await onboardingAction('sources', 'skip');
  }
  async function chooseAutomatic() {
    await onboardingAction('services', 'automatic');
  }
  async function acceptSources() {
    await onboardingAction('sources', 'accept');
  }
  async function finish() {
    if (!setupReady) return;
    const result = await onboardingAction('complete', 'complete');
    if (result?.completed) navigate('Обзор');
  }
  async function runSetupAction(label: string, action: () => Promise<void>) {
    setActionBusy(label);
    setActionError('');
    try {
      await action();
    } catch (reason) {
      const info = errorInfo(reason);
      setActionError(`${info.code}: ${info.message}`);
    } finally {
      setActionBusy('');
    }
  }

  async function saveTariff() {
    if (mutationLocked) { setActionError('Изменение скорости временно заблокировано состоянием recovery.'); return; }
    if (!Number.isFinite(tariff) || tariff < 1 || tariff > 100000) { setActionError('Скорость должна быть от 1 до 100000 Мбит/с.'); return; }
    setActionBusy('tariff'); setActionError('');
    try { await setVLESSTariff(tariff); await load(); }
    catch (error) { const info = errorInfo(error); setActionError(`${info.code}: ${info.message}`); }
    finally { setActionBusy(''); }
  }

  return <section>
    <PageHeader title="Быстрая настройка" text="Пять шагов: проверить роутер, выбрать способы подключения, добавить источники, назначить сервисы и убедиться, что выбранные пути работают.">
      <button onClick={() => void load()} disabled={state.loading}>{state.loading ? 'Проверяю…' : 'Проверить снова'}</button>
      <button type="button" onClick={() => navigate('Компоненты')}>К компонентам без завершения</button>
    </PageHeader>
    {state.error && <div class="inline-error"><b>Не все проверки завершены</b><span>{state.error}</span><button onClick={() => void load()}>Повторить</button></div>}
    {actionError && <div class="inline-error" role="alert"><b>Шаг не сохранён</b><span>{actionError}</span><button onClick={() => setActionError('')}>Закрыть</button></div>}
    <div class="setup-progress">{[
      ['1', 'Роутер', routerReady],
       ['2', 'Маршруты', methodsDone],
       ['3', 'Источники', sourcesDone],
      ['4', 'Сервисы', serviceChoiceDone],
      ['5', 'Проверка', setupReady]
    ].map(([number, label, done]) => <div class={done ? 'done' : ''} key={String(number)}><b>{number}</b><span>{label}</span></div>)}</div>
    <Grid>
      <EntityCard title="1. Проверка роутера" status={routerReady ? 'ready' : 'unverified'} onOpen={() => navigate('Диагностика')}>
        <StatusLine label="Интернет" value={overview?.internet} /><StatusLine label="DNS" value={overview?.dns} />
        <p>{routerReady ? 'Базовая сеть работает. FlintRoute может переходить к настройке маршрутов.' : 'Базовая сеть не подтверждена. Открой диагностику и исправь проблему до применения правил.'}</p>
      </EntityCard>
      <EntityCard title="2. Способы подключения" status={methodsDone ? 'configured' : 'not_configured'} onOpen={() => navigate('Компоненты')}>
        <label><span>Скорость вашего тарифа, Мбит/с</span><input type="number" min="1" max="100000" value={tariff} onInput={(event) => setTariff(Number((event.target as HTMLInputElement).value))} /></label><div class="actions">{[100, 300, 500, 1000].map((value) => <button type="button" disabled={Boolean(actionBusy)} class={tariff === value ? 'active' : ''} onClick={() => setTariff(value)} key={value}>{value}</button>)}<button type="button" class="primary" disabled={actionBusy === 'tariff'} onClick={() => void saveTariff()}>{actionBusy === 'tariff' ? 'Сохраняю…' : 'Сохранить скорость'}</button></div>
        <StatusLine label="Zapret" value={zapretReady ? 'ready' : zapretComponent?.installed ? 'requires_config' : 'not_installed'} />
        <StatusLine label="Xray / VLESS" value={verifiedServers > 0 ? `${verifiedServers} verified` : xray?.installed ? 'requires_config' : 'not_installed'} />
        <StatusLine label="TG WS Proxy" value={tgwsReady ? 'verified' : tgwsComponent?.installed ? 'requires_config' : 'not_installed'} />
        {!providerChosen && <button disabled={Boolean(actionBusy)} onClick={() => void runSetupAction('methods', chooseDirect)}>Пока использовать только обычный интернет</button>}
      </EntityCard>
      <EntityCard title="3. Источники и проверка" status={sourcesDone ? 'ready' : 'not_configured'} onOpen={() => navigate(verifiedServers ? 'VLESS-серверы' : 'Компоненты')}>
        <StatusLine label="VLESS-серверы" value={verifiedServers ? `${verifiedServers} подтверждено` : 'не добавлены'} />
        <StatusLine label="Smart DNS" value={smartReady ? 'ready' : 'not_configured'} />
        <StatusLine label="Telegram proxy" value={tgwsReady ? 'verified' : 'not_configured'} />
        <p>Добавляй только нужные способы. FlintRoute не заставляет ставить всё подряд.</p>
        {providerChosen && !sourcesDone && <button disabled={Boolean(actionBusy)} onClick={() => void runSetupAction('sources', acceptSources)}>Подтвердить проверенные источники</button>}
      </EntityCard>
      <EntityCard title="4. Что нужно открыть" status={serviceChoiceDone ? 'configured' : 'not_configured'} onOpen={() => navigate('Сервисы')}>
        <p>{asArray(services).length ? `Настроено сервисов: ${asArray(services).length}.` : 'Можно закрепить Discord, ChatGPT, YouTube и другие сервисы за подходящими маршрутами.'}</p>
        {!serviceChoiceDone && <button disabled={Boolean(actionBusy)} onClick={() => void runSetupAction('services', chooseAutomatic)}>Пока выбирать автоматически</button>}
        <StatusLine label="Discovery" value={discovery?.mode ?? 'observe_only'} />
      </EntityCard>
      <EntityCard title="5. Финальная проверка" status={setupReady ? 'ready' : 'unverified'} onOpen={() => navigate('Маршруты')}>
        <StatusLine label="Обычный интернет" value={routerReady ? 'ready' : 'unverified'} />
        <StatusLine label="Выбранные маршруты" value={providerChosen ? 'configured' : 'not_configured'} />
        <StatusLine label="Правила сервисов" value={serviceChoiceDone ? 'configured' : 'not_configured'} />
        <button class="primary" disabled={!setupReady || Boolean(actionBusy)} onClick={() => void runSetupAction('complete', finish)}>Завершить настройку</button>
        {!setupReady && <p>Кнопка станет доступна, когда базовая сеть работает и выбран хотя бы Direct либо один проверенный управляемый путь.</p>}
      </EntityCard>
    </Grid>
    <details class="raw-disclosure"><summary>Что уже есть в системе</summary><InfoGrid items={[["Direct", routes?.find((r: any) => r.type === 'system_default')?.status ?? overview?.internet], ["Zapret", zapretReady ? 'ready' : 'not_configured'], ["VLESS", verifiedServers], ["Smart DNS", smartReady ? 'ready' : 'not_configured'], ["TG WS Proxy", tgwsReady ? 'verified' : 'not_configured']]} /></details>
  </section>;
}

render(<App />, document.getElementById('app')!);
