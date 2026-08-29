import { useEffect, useRef, useState } from 'preact/hooks';
import {
  APIError,
  getBackups,
  getChanges,
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
  getSettings,
  getSystem,
  getLifecycle,
  getStorage,
  getTraffic,
  getTopology,
  updateOnboarding,
  type ChangeSet,
  type DiscoveryStatus,
  type EventItem,
  type OnboardingState,
  type RevisionSummary,
  type SessionInfo
} from '../api';
import { errorInfo } from '../view-models';
import { withTrafficRates, type TrafficView } from '../features/system';
import { navigation, notFoundScreen, screenFromLocation } from './routes';
import { staleFallback, unavailableOverview } from './messages';

const emptyTopology = () => ({ nodes: [], edges: [], status: 'unavailable', source: 'api-unavailable' });

export type DashboardData = {
  overview: any;
  onboarding: OnboardingState | null;
  topology: any;
  devices: any[];
  services: any[];
  routes: any[];
  discovery: DiscoveryStatus | null;
  events: EventItem[];
  changes: ChangeSet[];
  security: any;
  securitySummary: any;
  system: any;
  diagnostics: any;
  lifecycle: any;
  storage: any;
  settings: any;
  backups: any;
  revisions: RevisionSummary | null;
  configVersion: number;
  traffic: TrafficView;
  loading: boolean;
  refreshing: boolean;
  lastUpdated: string;
  apiError: string;
  sliceErrors: Array<{ name: string; message: string }>;
  retryingSlice: string;
  refresh: (hideAddresses?: boolean) => Promise<void>;
  retrySlice: (name: string) => Promise<void>;
  clearPrivacySensitive: () => void;
  reset: () => void;
  updateOnboardingState: (step: string, action: 'skip' | 'accept' | 'automatic' | 'complete') => Promise<OnboardingState>;
};

type DashboardOptions = {
  screen: string;
  screenRef: { current: string };
  session: SessionInfo | null;
  privacyHidden: boolean;
  navigate: (screen: string) => void;
  onUnauthorized: () => void;
};

export function useDashboardData({ screen, screenRef, session, privacyHidden, navigate, onUnauthorized }: DashboardOptions): DashboardData {
  const [overview, setOverview] = useState<any>(unavailableOverview);
  const [onboarding, setOnboarding] = useState<OnboardingState | null>(null);
  const [sliceErrors, setSliceErrors] = useState<Array<{ name: string; message: string }>>([]);
  const [retryingSlice, setRetryingSlice] = useState('');
  const [topology, setTopology] = useState<any>(emptyTopology());
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
  const [apiError, setApiError] = useState('');
  const refreshInFlight = useRef<Promise<void> | null>(null);
  const refreshPrivacy = useRef<boolean | undefined>(undefined);
  const refreshScreen = useRef<string | undefined>(undefined);
  const refreshAbort = useRef<AbortController | null>(null);
  const sliceRetryAbort = useRef<AbortController | null>(null);
  const refreshGeneration = useRef(0);

  async function refresh(hideAddresses = privacyHidden) {
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
        const enrichedOverview = nextOverview && typeof nextOverview === 'object' ? { ...(nextOverview as Record<string, unknown>), ...nextHealth } : nextOverview;
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
          const shouldResumeWizard = (screenRef.current === 'Обзор' || screenRef.current === notFoundScreen) && (locationScreen === null || ['Обзор', firstRunScreen, notFoundScreen].includes(locationScreen));
          const explicitComponentNavigation = locationScreen !== null && !['Обзор', firstRunScreen, notFoundScreen].includes(locationScreen);
          if (shouldResumeWizard && !explicitComponentNavigation && locationScreen !== firstRunScreen) navigate(firstRunScreen);
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
        if (err instanceof APIError && err.status === 401) onUnauthorized();
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
        if (!streamActive) return;
        try {
          const item = JSON.parse((ev as MessageEvent).data) as EventItem;
          if (!item || typeof item !== 'object') return;
          setEvents((old) => [item, ...old].slice(0, 80));
        } catch {
          // Ignore malformed events; the stream remains usable.
        }
      };
      ['message', 'system.start', 'admin.login', 'route.decision', 'security.guard', 'change.created', 'change.validated', 'change.awaiting_confirmation', 'change.committed', 'change.rolled_back'].forEach((eventType) => es?.addEventListener(eventType, pushEvent));
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

  function clearPrivacySensitive() {
    sliceRetryAbort.current?.abort();
    sliceRetryAbort.current = null;
    setRetryingSlice('');
    setTopology({ nodes: [], edges: [], status: 'unavailable', source: 'privacy-transition' });
    setDevices([]);
    setEvents([]);
  }

  function reset() {
    refreshAbort.current?.abort();
    sliceRetryAbort.current?.abort();
    refreshAbort.current = null;
    sliceRetryAbort.current = null;
    refreshGeneration.current += 1;
    refreshInFlight.current = null;
    setRefreshing(false);
    setOverview(unavailableOverview);
    setTopology({ ...emptyTopology(), source: 'logged-out' });
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
    setDiscovery(null);
    setSliceErrors([]);
    setApiError('');
    setLastUpdated('');
    setConfigVersion(0);
    setTraffic({ status: 'unavailable', source: 'logged-out', collected_at: '', interfaces: [] });
  }

  async function updateOnboardingState(step: string, action: 'skip' | 'accept' | 'automatic' | 'complete') {
    const next = await updateOnboarding(step, action);
    setOnboarding(next);
    return next;
  }

  return { overview, onboarding, topology, devices, services, routes, discovery, events, changes, security, securitySummary, system, diagnostics, lifecycle, storage, settings, backups, revisions, configVersion, traffic, loading, refreshing, lastUpdated, apiError, sliceErrors, retryingSlice, refresh, retrySlice, clearPrivacySensitive, reset, updateOnboardingState };
}
