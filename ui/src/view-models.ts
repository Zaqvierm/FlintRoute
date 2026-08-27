import { APIError, type EventItem } from './api';

export type Tone = 'ok' | 'warn' | 'bad' | 'muted' | 'info';

/**
 * Maps backend classification values to an explicit UI bucket.
 * Unknown values must remain visible as unresolved; silently treating them as
 * Direct is a data-integrity bug because it can suggest a route that was
 * never selected or verified.
 */
export function serviceColumnFor(category: unknown): string {
  const normalized = textValue(category, '').trim().toUpperCase();
  switch (normalized) {
    case 'GEO_LOCKED':
    case 'TSPU_RESTRICTED':
    case 'TELEGRAM':
    case 'DIRECT_PREFERRED':
    case 'DIRECT_ONLY':
    case 'BLOCKED':
      return normalized;
    default:
      return 'UNRESOLVED';
  }
}

export type OnboardingProgress = {
  methodsDone: boolean;
  sourcesDone: boolean;
  serviceChoiceDone: boolean;
  providerReady: boolean;
  setupReady: boolean;
};

/**
 * Derive the five setup-step indicators from backend state only.  In
 * particular, a verified component must not mark the persisted "sources"
 * step complete, and a local browser preference can never make setupReady.
 */
export function onboardingProgress(input: {
  methodsStatus?: unknown;
  sourcesStatus?: unknown;
  servicesStatus?: unknown;
  verifiedServers?: number;
  smartReady?: boolean;
  tgwsReady?: boolean;
  zapretReady?: boolean;
  /** Legacy display input; it must never prove onboarding completion. */
  serviceCount?: number;
  canComplete?: boolean;
}): OnboardingProgress {
  const stepDone = (value: unknown) => ['accepted', 'skipped', 'automatic'].includes(textValue(value, 'pending').trim().toLowerCase());
  const methodsDone = stepDone(input.methodsStatus);
  const sourcesDone = stepDone(input.sourcesStatus);
  const serviceChoiceDone = stepDone(input.servicesStatus);
  const providerReady = (input.verifiedServers ?? 0) > 0 || Boolean(input.smartReady || input.tgwsReady || input.zapretReady) || methodsDone;
  return { methodsDone, sourcesDone, serviceChoiceDone, providerReady, setupReady: input.canComplete === true };
}

/**
 * The backend boolean is authoritative.  The fallback exists only while the
 * first response is loading or for older compatible providers; it accepts an
 * explicit healthy status instead of coercing objects to "[object Object]" or
 * treating simulation/unverified diagnostics as readiness proof.
 */
export function onboardingRouterReady(onboarding: unknown, overview: unknown): boolean {
  const state = asRecord(onboarding);
  if (typeof state.router_ready === 'boolean') return state.router_ready;
  const snapshot = asRecord(overview);
  return statusAllowed(snapshot.internet, ['route available', 'available', 'online', 'ok', 'ready']) &&
    statusAllowed(snapshot.dns, ['available', 'online', 'ok', 'ready']);
}

function statusAllowed(value: unknown, allowed: string[]): boolean {
  const normalized = textValue(value, '').trim().toLowerCase().replace(/[._-]+/g, ' ');
  return allowed.includes(normalized);
}

/**
 * UI-side mirror of the backend mutation fence.  Unknown, missing, starting,
 * failed and recovery-required states are deliberately unsafe.  A
 * not_required state is only safe when the backend supplied a bound baseline;
 * this prevents the UI from presenting a mutation button while recovery data
 * is merely absent or stale.
 */
export function recoveryMutationAllowed(input: unknown): boolean {
  if (!input || typeof input !== 'object') return false;
  const value = input as Record<string, unknown>;
  const nested = value.recovery && typeof value.recovery === 'object'
    ? value.recovery as Record<string, unknown>
    : value;
  const status = textValue(nested.status ?? value.recovery_status, '').trim().toLowerCase();
  if (status === 'ok') return true;
  if (status !== 'not_required') return false;
  const revision = textValue(nested.revision_id ?? value.active_revision, '').trim();
  const hash = textValue(nested.candidate_hash ?? value.candidate_hash, '').trim();
  return revision.length > 0 && hash.length > 0;
}

export type DecisionCard = {
  id: string;
  time: string;
  device: string;
  ip: string;
  domain: string;
  service: string;
  category: string;
  rule: string;
  strategy: string;
  route: string;
  fallback: boolean;
  fallbackPath: string[];
  verified: boolean;
  classificationState: string;
  probeState: string;
  policyState: string;
  status: string;
  classificationConfidence?: number;
  decisionConfidence?: number;
  durationMS?: number;
  probeLatencyMS?: number;
  routeLatencyMS?: number;
  routeLatencyAvailable: boolean;
  verificationDurationMS?: number;
  candidates: unknown[];
  timeline: unknown[];
  details: Record<string, unknown>;
  raw: EventItem;
};

export type VerificationPresentation = 'verified' | 'checking' | 'no_safe_route' | 'observed' | 'not_checked' | 'unverified';

const decisionTypes = new Set([
  'route.decision',
  'domain.decision',
  'path.verified',
  'route.fallback',
  'route.blocked',
  'route.dropped'
]);

export function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

export function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function stringArray(value: unknown): string[] {
  return asArray(value)
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean);
}

export function textValue(value: unknown, fallback = 'Недоступно'): string {
  if (value === null || value === undefined || value === '') return fallback;
  if (typeof value === 'boolean') return value ? 'Да' : 'Нет';
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : fallback;
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.length ? value.map((item) => textValue(item, '')).filter(Boolean).join(', ') : fallback;
  const record = asRecord(value);
  for (const key of ['status', 'state', 'value', 'label', 'name', 'reason']) {
    if (typeof record[key] === 'string' || typeof record[key] === 'number' || typeof record[key] === 'boolean') {
      return textValue(record[key], fallback);
    }
  }
  return fallback;
}

export function humanStatus(value: unknown): string {
  const raw = textValue(value, 'Недоступно');
  const normalized = raw.toLowerCase().replace(/[._-]+/g, ' ');
  const labels: Record<string, string> = {
    ok: 'Работает',
    running: 'Работает',
    ready: 'Готово',
    online: 'В сети',
    offline: 'Не в сети',
    healthy: 'Работает',
    available: 'Доступно',
    'route available': 'Интернет доступен',
    selected: 'Маршрут выбран',
    'no safe route': 'Ни один безопасный маршрут не прошёл проверку',
    verified: 'Путь подтверждён',
    configured: 'Настроено',
    'not configured': 'Не настроено',
    unavailable: 'Недоступно',
    disabled: 'Выключено',
    stale: 'Нет новых записей',
    unverified: 'Не подтверждено',
    degraded: 'Работает с ошибками',
    failed: 'Ошибка',
    error: 'Ошибка',
    stopped: 'Остановлено',
    foreign: 'Обнаружен вне FlintRoute',
    absent: 'Не установлен',
    'not installed': 'Не установлен',
    'requires device': 'Нужна проверка на роутере',
    lowerlayerdown: 'Кабель не подключён',
    simulation: 'Тестовые данные',
    'system default': 'Системный маршрут',
    'no managed policies': 'Нет управляемых правил',
    'dns resolved': 'DNS-имя разрешено',
    'direct selected': 'Выбран Direct',
    'zapret selected': 'Выбран Zapret',
    'smart dns selected': 'Выбран Smart DNS',
    'vless selected': 'Выбран VLESS',
    'fallback performed': 'Выполнен fallback',
    'path verified': 'Путь подтверждён',
    'tls ok': 'TLS OK',
    blocked: 'Заблокировано',
    dropped: 'Отброшено',
    'no verified route': 'Нет подтверждённого маршрута',
    rollback: 'Выполнен откат'
  };
  return labels[normalized] ?? raw.replace(/_/g, ' ');
}

export function statusTone(value: unknown): Tone {
  const raw = textValue(value, '').toLowerCase().replace(/[._-]+/g, ' ').trim();
  // Check negative/uncertain states before positive substrings.  Otherwise
  // `not_configured`, `unverified`, and `no_verified_route` all contain
  // `configured`/`verified` and were incorrectly painted green.
  if (!raw || /unavailable|not configured|not installed|absent|disabled|unsupported/.test(raw)) return 'muted';
  if (/fail|error|blocked|dropped|rollback|critical|offline|no safe route/.test(raw)) return 'bad';
  if (/warn|degrad|stale|unverified|pending|await|unknown|requires device|no verified route/.test(raw)) return 'warn';
  if (/ok|ready|running|online|verified|healthy|committed|configured|200/.test(raw)) return 'ok';
  return 'info';
}

function first(details: Record<string, unknown>, keys: string[], fallback = ''): string {
  for (const key of keys) {
    const value = details[key];
    if (typeof value === 'string' && value.trim()) return value;
    if (typeof value === 'number') return String(value);
  }
  return fallback;
}

function bool(details: Record<string, unknown>, keys: string[]): boolean {
  for (const key of keys) {
    const value = details[key];
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string' && /^(true|yes|ok|verified)$/i.test(value)) return true;
  }
  return false;
}

export function isDecisionEvent(event: EventItem): boolean {
  // Administrative lifecycle events may carry a domain/route in their
  // details, but they must remain in the engineering journal. Do this check
  // before the shape-based fallback below so a transaction event cannot leak
  // into the user-facing decision stream.
  if (/^(system|auth|change|admin|recovery|security)\./.test(event.type)) return false;
  if (decisionTypes.has(event.type)) return true;
  const details = asRecord(event.details);
  return Boolean(event.domain || details.domain) && Boolean(event.route || details.route || details.selected_route);
}

export function isAdministrativeEvent(event: EventItem): boolean {
  return !isDecisionEvent(event) || /^(system|auth|change|admin|recovery|security)\./.test(event.type);
}

export function toDecisionCard(event: EventItem): DecisionCard {
  const details = asRecord(event.details);
  const fallbackPath = asArray(details.fallback_path ?? details.fallback_sequence)
    .map((value) => textValue(value, ''))
    .filter(Boolean);
  const route = first(details, ['route_label'], event.route || first(details, ['route', 'selected_route', 'route_type'], 'Не выбран'));
  const status = first(details, ['final_status', 'http_status', 'status', 'result'], event.reason_code || event.type);
  const duration = Number(details.decision_duration_ms ?? details.duration_ms);
  const explicitRouteLatencyAvailable = typeof details.route_latency_available === 'boolean' || typeof details.route_latency_available === 'string';
  // `probe_latency_ms` was used by older payloads for the complete probe
  // duration. It is not safe to infer route latency from that field. Only an
  // explicit route_latency_ms (and, when present, its availability bit) is
  // allowed to reach scoring/presentation.
  const rawRouteLatency = details.route_latency_ms;
  const inferredRouteLatency = Number(rawRouteLatency);
  const hasMeasuredRouteLatency = Number.isFinite(inferredRouteLatency) && inferredRouteLatency > 0;
  const routeLatencyAvailable = hasMeasuredRouteLatency && (!explicitRouteLatencyAvailable || bool(details, ['route_latency_available']));
  const probeLatency = routeLatencyAvailable ? inferredRouteLatency : NaN;
  const verificationDuration = Number(details.verification_duration_ms ?? details.path_verification_duration_ms ?? duration);
  const classificationConfidence = Number(details.classification_confidence);
  const decisionConfidence = Number(details.decision_confidence ?? details.confidence);
  return {
    id: `${event.time}:${event.id}`,
    time: event.time,
    device: first(details, ['device_name', 'hostname'], event.device_id || 'Неизвестное устройство'),
    ip: first(details, ['device_ip', 'client_ip'], ''),
    domain: event.domain || first(details, ['domain', 'host'], 'Неизвестный домен'),
    service: event.service_id || first(details, ['service_name', 'service'], 'Не классифицирован'),
    category: first(details, ['classification', 'category'], 'unknown'),
    rule: first(details, ['rule', 'policy', 'policy_name'], 'Системное правило'),
    strategy: first(details, ['strategy', 'route_type'], route),
    route,
    fallback: bool(details, ['fallback', 'fallback_performed']) || fallbackPath.length > 1,
    fallbackPath,
    verified: bool(details, ['path_verified', 'verified', 'data_plane_verified']),
    classificationState: first(details, ['classification_state'], 'unresolved'),
    probeState: first(details, ['probe_state'], 'unverified'),
    policyState: first(details, ['policy_state'], 'observed'),
    status: humanStatus(status),
    classificationConfidence: Number.isFinite(classificationConfidence) ? classificationConfidence : undefined,
    decisionConfidence: Number.isFinite(decisionConfidence) ? decisionConfidence : undefined,
    durationMS: Number.isFinite(duration) ? duration : undefined,
    probeLatencyMS: Number.isFinite(probeLatency) ? probeLatency : undefined,
    routeLatencyMS: Number.isFinite(probeLatency) ? probeLatency : undefined,
    routeLatencyAvailable,
    verificationDurationMS: Number.isFinite(verificationDuration) ? verificationDuration : undefined,
    candidates: asArray(details.candidates),
    timeline: asArray(details.timeline ?? details.evidence_timeline),
    details,
    raw: event
  };
}

/**
 * A missing PathVerified bit is not, by itself, proof that every candidate
 * failed.  Keep the user-facing state aligned with the planner state machine:
 * VERIFYING is in progress, observe-only is passive, and NO_SAFE_ROUTE is
 * terminal only after the planner reports exhaustion.
 */
export function decisionVerificationPresentation(decision: Pick<DecisionCard, 'verified' | 'probeState' | 'policyState' | 'details'>): VerificationPresentation {
  const probeState = textValue(decision.probeState, '').toLowerCase().replace(/[._-]+/g, ' ');
  const verificationState = textValue(decision.details.verification_state, '').toLowerCase().replace(/[._-]+/g, ' ');
  if (['verifying', 'in progress', 'waiting for verification', 'waiting'].includes(probeState) || verificationState === 'in progress') return 'checking';
  // NO_SAFE_ROUTE is terminal only with an explicit planner terminal state.
  // A status string or a malformed probe_state alone is not exhaustion
  // evidence; keep it visibly in verification rather than lying to the user.
  if (verificationState === 'terminal no safe route') return 'no_safe_route';
  if (probeState === 'no safe route') return 'checking';
  if (probeState === 'not run observe only' || verificationState === 'not run observe only') return 'observed';
  if (probeState === 'not checked' || verificationState === 'not checked') return 'not_checked';
  if (decision.verified) return 'verified';
  return 'unverified';
}

export function verificationPresentationLabel(presentation: VerificationPresentation): string {
  switch (presentation) {
    case 'verified': return 'Путь подтверждён';
    case 'checking': return 'Проверяется…';
    case 'no_safe_route': return 'Безопасный маршрут не найден';
    case 'observed': return 'Наблюдение — проверка не запускалась';
    case 'not_checked': return 'Путь ещё не проверен';
    default: return 'Путь пока не подтверждён';
  }
}

export function groupServices(items: unknown[]): Array<Record<string, unknown>> {
  const grouped = new Map<string, Record<string, unknown>>();
  for (const raw of items) {
    const item = asRecord(raw);
    const id = textValue(item.id, 'unknown-service');
    const key = id.toLowerCase();
    const current = grouped.get(key) ?? { ...item, id, domains: [], sources: [], recent_decisions: [] };
    const domains = new Set<string>(asArray(current.domains).map((domain) => textValue(domain, '')).filter(Boolean));
    for (const domain of asArray(item.domains)) {
      const value = textValue(domain, '');
      if (value) domains.add(value);
    }
    const sources = new Set<string>(asArray(current.sources).map((source) => textValue(source, '')).filter(Boolean));
    const source = textValue(item.source, '');
    if (source) sources.add(source);
    const configured = source === 'configured' ? item : current;
    // A configured policy and an automatic observation can share one service
    // id. Keep policy fields from the configured item, but never discard the
    // observation's independent confidence/evidence fields while grouping.
    const evidence = source === 'configured' ? current : item;
    grouped.set(key, {
      ...current,
      ...configured,
      id,
      domains: [...domains].sort(),
      sources: [...sources].sort(),
      applied: current.applied === true || item.applied === true || source === 'configured',
      health: item.status ?? current.health ?? 'UNVERIFIED',
      latest_checked_at: item.checked_at ?? current.latest_checked_at,
      classification_confidence: evidence.classification_confidence ?? current.classification_confidence,
      classification_source: evidence.classification_source ?? current.classification_source,
      classification_evidence: evidence.classification_evidence ?? current.classification_evidence,
      decision_confidence: evidence.decision_confidence ?? current.decision_confidence
    });
  }
  return [...grouped.values()].sort((a, b) => textValue(a.id).localeCompare(textValue(b.id), 'ru'));
}

export function parseResolverInput(rawInput: string): { ip: string; port: number } {
  const raw = rawInput.trim();
  if (!raw) throw new Error('resolver_empty');
  if (raw.startsWith('[')) {
    const close = raw.indexOf(']');
    if (close < 2) throw new Error('resolver_invalid_ipv6');
    const ip = raw.slice(1, close);
    const suffix = raw.slice(close + 1);
    const port = suffix ? Number(suffix.replace(/^:/, '')) : 53;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('resolver_invalid_port');
    return { ip, port };
  }
  const colons = (raw.match(/:/g) ?? []).length;
  if (colons > 1) return { ip: raw, port: 53 };
  if (colons === 1) {
    const [ip, portRaw] = raw.split(':');
    const port = Number(portRaw);
    if (!ip || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('resolver_invalid_port');
    return { ip, port };
  }
  return { ip: raw, port: 53 };
}

export function errorInfo(error: unknown): { code: string; message: string } {
  if (error instanceof APIError) return { code: error.code, message: error.message };
  if (error instanceof Error) return { code: error.message.startsWith('resolver_') ? error.message : 'ui_error', message: error.message };
  return { code: 'unknown_error', message: 'Неизвестная ошибка' };
}

export function formatDateTime(value: unknown, fallback = 'Нет данных'): string {
  if (typeof value !== 'string' || !value) return fallback;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) || date.getUTCFullYear() < 2000 ? fallback : date.toLocaleString('ru-RU');
}
