import { APIError, type EventItem } from './api';

export type Tone = 'ok' | 'warn' | 'bad' | 'muted' | 'info';

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
    unverified: 'Не подтверждено',
    degraded: 'Работает с ошибками',
    failed: 'Ошибка',
    error: 'Ошибка',
    stopped: 'Остановлено',
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
  const raw = textValue(value, '').toLowerCase();
  if (/ok|ready|running|online|verified|healthy|committed|configured|200/.test(raw)) return 'ok';
  if (/fail|error|blocked|dropped|rollback|critical|offline/.test(raw)) return 'bad';
  if (/warn|degrad|stale|unverified|pending|await|unknown/.test(raw)) return 'warn';
  if (!raw || /unavailable|not.configured|disabled|unsupported/.test(raw)) return 'muted';
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
  if (decisionTypes.has(event.type)) return true;
  const details = asRecord(event.details);
  return Boolean(event.domain || details.domain) && Boolean(event.route || details.route || details.selected_route);
}

export function isAdministrativeEvent(event: EventItem): boolean {
  return !isDecisionEvent(event) || /^(system|change|admin|security)\./.test(event.type);
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
  const rawRouteLatency = details.route_latency_ms ?? details.probe_latency_ms;
  const inferredRouteLatency = Number(rawRouteLatency);
  const routeLatencyAvailable = explicitRouteLatencyAvailable
    ? bool(details, ['route_latency_available'])
    : Number.isFinite(inferredRouteLatency) && inferredRouteLatency > 0;
  const probeLatency = routeLatencyAvailable
    ? Number(rawRouteLatency ?? details.latency_ms)
    : NaN;
  const verificationDuration = Number(details.verification_duration_ms ?? details.path_verification_duration_ms ?? duration);
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
    grouped.set(key, {
      ...current,
      ...configured,
      id,
      domains: [...domains].sort(),
      sources: [...sources].sort(),
      applied: current.applied === true || item.applied === true || source === 'configured',
      health: item.status ?? current.health ?? 'UNVERIFIED',
      latest_checked_at: item.checked_at ?? current.latest_checked_at
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
