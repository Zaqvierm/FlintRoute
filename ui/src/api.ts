export type Envelope<T> = { request_id: string; data: T };
export type Overview = Record<string, unknown>;
export type SessionInfo = {
  user: string;
  role: 'administrator' | 'diagnostician' | 'viewer';
  csrf_token: string;
  expires_at: string;
  must_change_password: boolean;
};
export type EventItem = {
  id: number;
  time: string;
  type: string;
  severity: string;
  device_id?: string;
  service_id?: string;
  domain?: string;
  route?: string;
  reason_code: string;
  details: Record<string, unknown>;
};
export type ChangeSet = {
  id: string;
  state: string;
  title: string;
  description: string;
  base_version: number;
  version: number;
  revision_id?: string;
  transaction_id?: string;
  adapter_status?: string;
  operations: ChangeOp[];
  validation: Array<{ level: string; code: string; message: string }>;
  diff: Array<{ type: string; path: string; value?: unknown }>;
  data_plane_verified: boolean;
  created_at: string;
  updated_at: string;
  expires_at?: string;
  author: string;
};
export type ChangeOp = { type: 'set' | 'remove'; path: string; value?: unknown };
export type RevisionSummary = {
  source: string;
  status: string;
  active_revision: string;
  config_version: number;
  items: unknown[];
};
export type TrafficInterface = {
  name: string;
  rx_bytes: number;
  rx_packets: number;
  rx_errors: number;
  tx_bytes: number;
  tx_packets: number;
  tx_errors: number;
};
export type TrafficSnapshot = {
  status: string;
  source: string;
  collected_at: string;
  interfaces: TrafficInterface[];
  reason?: string;
};
export type SubscriptionSecretStatus = {
  configured: boolean;
  present: boolean;
  count: number;
  capacity: number;
  slots: Array<{ slot: number; configured: boolean }>;
  changed?: boolean;
};
export type SubscriptionPreparation = {
  change?: ChangeSet;
  preparation: {
    ready: boolean;
    selected_tag: string;
    servers: unknown[];
    routes: unknown[];
    checks: unknown[];
    secrets_printed: boolean;
  };
  activation: {
    current_mode: string;
    managed_available: boolean;
    explicit_confirmation_required: boolean;
    tproxy_mode: string;
    tproxy_port: number;
    bypass_mark: string;
  };
};

export type ZapretSetupRequest = {
  source_url: string;
  provider_version: string;
  binary_sha256: string;
  test_domain: string;
};
export type ZapretSetupReport = {
  ready: boolean;
  binary_present: boolean;
  binary_sha256: string;
  provider_version: string;
  architecture: string;
  nfqueue_available: boolean;
  kernel_support: string;
  dry_run: boolean;
  test_domain: string;
  source_pinned: boolean;
};

export type SmartDNSResolver = { ip: string; port: number };
export type SmartDNSValidation = {
  endpoint: string;
  domain: string;
  udp: { safe: boolean; addresses: string[] };
  tcp: { safe: boolean; addresses: string[] };
  addresses: string[];
  connected_ip: string;
  http_status: number;
  tls_ok: boolean;
  http_ok: boolean;
};
export type DiscoveryStatus = {
  mode: 'observe_only' | 'suggest' | 'auto_apply_verified' | 'locked';
  max_new_rules_per_hour: number;
  max_consecutive_rollbacks: number;
  consecutive_rollbacks: number;
  applied_last_hour: number;
  paused: boolean;
  paused_reason?: string;
  suggestions: Array<Record<string, unknown>>;
};
export type TelegramStatus = {
  state: 'not_configured' | 'configured' | 'verified' | 'degraded' | 'failed';
  enabled: boolean;
  token_configured: boolean;
  chat_configured: boolean;
  event_types: string[];
  queue_depth: number;
  queue_capacity: number;
  consecutive_failures: number;
  last_error_code?: string;
  last_verified_at?: string;
  last_delivery_at?: string;
  dropped: number;
};
export type TelegramOverview = {
  notifications: TelegramStatus;
  event_types: string[];
  transport: { type: 'external_socks'; managed_by: 'external'; core_routing_dependency: false };
};
export type ExternalSOCKSReport = {
  ready: boolean;
  endpoint: string;
  dependency: string;
  managed_by: 'external';
  tcp_reachable: boolean;
  socks5_handshake: boolean;
  remote_connect: boolean;
  tls_verified: boolean;
  http_status: number;
  test_domain: string;
};

export class APIError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

let csrf = '';

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has('content-type')) headers.set('content-type', 'application/json');
  if (csrf) headers.set('x-csrf-token', csrf);
  const res = await fetch(`/api/v1${path}`, { credentials: 'include', ...init, headers });
  if (!res.ok) {
    let code = 'http_error';
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      code = body.error?.code ?? code;
      message = body.error?.message ?? message;
    } catch {
      // keep HTTP fallback
    }
    throw new APIError(res.status, code, message);
  }
  const env = (await res.json()) as Envelope<T>;
  return env.data;
}

export async function me(): Promise<SessionInfo> {
  const session = await request<SessionInfo>('/auth/me');
  csrf = session.csrf_token;
  return session;
}

export async function login(username: string, password: string): Promise<SessionInfo> {
  const session = await request<SessionInfo>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
  });
  csrf = session.csrf_token;
  return session;
}

export async function setupAdmin(username: string, password: string, setupToken: string): Promise<void> {
  await request('/auth/setup', {
    method: 'POST',
    body: JSON.stringify({ username, password, setup_token: setupToken })
  });
}

export async function logout(): Promise<void> {
  await request('/auth/logout', { method: 'POST', body: '{}' });
  csrf = '';
}

export async function getOverview(): Promise<Overview> { return request<Overview>('/overview'); }
export async function getTopology(): Promise<any> { return request('/topology'); }
export async function getDevices(): Promise<any[]> { return request('/devices'); }
export async function getServices(): Promise<any[]> { return request('/services'); }
export async function classifyService(
  domain: string,
  category: string,
  baseVersion: number,
  allowedPaths?: string[]
): Promise<{ change: ChangeSet }> {
  return request('/services/classify', {
    method: 'POST',
    body: JSON.stringify({ domain, category, allowed_paths: allowedPaths, base_version: baseVersion })
  });
}
export async function getRoutes(): Promise<any[]> { return request('/routes'); }
export async function getSmartDNS(): Promise<any> { return request('/smart-dns'); }
export async function configureSmartDNS(resolvers: SmartDNSResolver[], testDomain: string, baseVersion: number): Promise<{ change: ChangeSet; endpoint_count: number; validations: SmartDNSValidation[] }> {
  return request('/smart-dns/configure', {
    method: 'POST',
    body: JSON.stringify({ resolvers, test_domain: testDomain, base_version: baseVersion })
  });
}
export async function getDiscovery(): Promise<DiscoveryStatus> { return request('/discovery'); }
export async function getTelegram(): Promise<TelegramOverview> { return request('/telegram'); }
export async function configureTelegram(botToken: string, chatID: string, enabled: boolean, eventTypes: string[]): Promise<TelegramStatus> {
  return request('/telegram/configure', { method: 'PUT', body: JSON.stringify({ bot_token: botToken, chat_id: chatID, enabled, event_types: eventTypes }) });
}
export async function testTelegram(): Promise<{ delivered: boolean; status: TelegramStatus }> {
  return request('/telegram/test', { method: 'POST', body: '{}' });
}
export async function getExternalSOCKS(): Promise<any> { return request('/external-socks'); }
export async function checkExternalSOCKS(endpoint: string, testDomain: string, baseVersion: number): Promise<{ report: ExternalSOCKSReport }> {
  return request('/external-socks/check', { method: 'POST', body: JSON.stringify({ endpoint, test_domain: testDomain, base_version: baseVersion }) });
}
export async function activateExternalSOCKS(endpoint: string, testDomain: string, baseVersion: number): Promise<{ report: ExternalSOCKSReport; change: ChangeSet }> {
  return request('/external-socks/activate', { method: 'POST', body: JSON.stringify({ endpoint, test_domain: testDomain, base_version: baseVersion }) });
}
export async function configureDiscovery(
  mode: DiscoveryStatus['mode'],
  maxNewRulesPerHour: number,
  maxConsecutiveRollbacks: number,
  baseVersion: number,
  resetFailures = false
): Promise<{ change: ChangeSet }> {
  return request('/discovery/configure', {
    method: 'POST',
    body: JSON.stringify({
      mode,
      max_new_rules_per_hour: maxNewRulesPerHour,
      max_consecutive_rollbacks: maxConsecutiveRollbacks,
      base_version: baseVersion,
      reset_failures: resetFailures
    })
  });
}
export async function getTraffic(): Promise<TrafficSnapshot> { return request('/traffic'); }
export async function getEvents(): Promise<EventItem[]> { return request('/events'); }
export async function getSecurity(): Promise<any> { return request('/security/audit'); }
export async function getSystem(): Promise<any> { return request('/system'); }
export async function getChanges(): Promise<ChangeSet[]> { return request('/changes'); }
export async function getRevisions(): Promise<RevisionSummary> { return request('/revisions'); }
export async function getSubscriptionSecretStatus(): Promise<SubscriptionSecretStatus> {
  return request('/xray/subscription/secret');
}
export async function saveSubscriptionSecrets(urls: string[]): Promise<SubscriptionSecretStatus> {
  return request('/xray/subscription/secret', { method: 'PUT', body: JSON.stringify({ urls }) });
}
export async function prepareSubscription(baseVersion: number, activateManaged = false): Promise<SubscriptionPreparation> {
  return request('/xray/subscription/prepare', { method: 'POST', body: JSON.stringify({ base_version: baseVersion, activate_managed: activateManaged }) });
}
export async function getZapret(): Promise<any> { return request('/zapret'); }
export async function checkZapretSetup(input: ZapretSetupRequest, baseVersion: number): Promise<{ report: ZapretSetupReport }> {
  return request('/zapret/setup/check', { method: 'POST', body: JSON.stringify({ ...input, base_version: baseVersion }) });
}
export async function activateZapretSetup(input: ZapretSetupRequest, baseVersion: number): Promise<{ report: ZapretSetupReport; change: ChangeSet }> {
  return request('/zapret/setup/activate', { method: 'POST', body: JSON.stringify({ ...input, base_version: baseVersion }) });
}
export async function createChange(title: string, baseVersion: number, operations: ChangeOp[]): Promise<ChangeSet> {
  if (!Number.isSafeInteger(baseVersion) || baseVersion < 1) throw new Error('Некорректная версия конфигурации');
  if (operations.length === 0) throw new Error('ChangeSet должен содержать хотя бы одну операцию');
  return request('/changes', { method: 'POST', body: JSON.stringify({ title, base_version: baseVersion, operations }) });
}
export async function changeAction(id: string, action: string): Promise<ChangeSet> {
  return request(`/changes/${id}/${action}`, { method: 'POST', body: '{}' });
}
