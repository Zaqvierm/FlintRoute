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
import { Vless } from './features/vless';
import { RouteType, SmartDNS, Zapret } from './features/route-integrations';
import {
  Components,
  DecisionFlow,
  Diagnostics,
  Discovery,
  ExternalSOCKS,
  LoginScreen,
  Recovery,
  Security,
  Settings,
  TGWS,
  Telegram,
  Traffic,
  withTrafficRates,
  type TrafficView
} from './features/system';
import { SetupScreen } from './features/setup';
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
render(<App />, document.getElementById('app')!);
