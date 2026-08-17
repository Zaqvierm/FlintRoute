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
  artifacts_ready?: boolean;
  artifact_block_reason?: string;
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
export type ManualVLESSServer = {
  id: string;
  name: string;
  address: string;
  port: number;
  protocol: string;
  security: string;
  network: string;
};
export type ManualVLESSInventory = {
  servers: ManualVLESSServer[];
  count: number;
  capacity: number;
  changed?: boolean;
};

export type ComponentKind = 'xray' | 'zapret' | 'tg_ws_proxy';
export type ComponentAction = 'install' | 'check' | 'check_updates' | 'update' | 'restart' | 'rollback' | 'uninstall';
export type ComponentStatus = {
  kind: ComponentKind;
  installed: boolean;
  version?: string;
  latest_supported_version: string;
  latest_upstream_version?: string;
  update_available: boolean;
  update_blocked_reason?: string;
  architecture?: string;
  source: string;
  checksum?: string;
  service_state: string;
  health_state: string;
  health_ready: boolean;
  health_reason?: string;
  last_successful_check?: string;
  last_checked_at?: string;
  rollback_version?: string;
  next_actions?: string[];
  preflight?: Record<string, unknown>;
};
export type ComponentResult = {
  status: ComponentStatus;
  action: ComponentAction;
  changed: boolean;
  rollback_performed: boolean;
  stages: string[];
};
export type VLESSPoolSnapshot = {
  generated_at?: string;
  tariff_mbps: number;
  sources: Array<{ id: string; name: string; provider_id: string; provider_name: string; added_at?: string; expires_at?: string; expiry_known: boolean; server_count: number; manual?: boolean }>;
  provider_matches?: Array<{ left_provider_id: string; right_provider_id: string; matched_servers: number; compared_servers: number; overlap: number; recommendation: string }>;
  servers: any[];
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

export type ZapretCalibrationCandidate = {
  profile_id: string;
  provider: string;
  provider_version: string;
  transports: string[];
  ports: number[];
  strategy_digest: string;
  tests?: string[];
  occurrences?: number;
};

export type ZapretCalibrationStatus = {
  id?: string;
  state: 'idle' | 'running' | 'completed' | 'failed' | 'cancelled' | 'unavailable';
  stage: string;
  domain?: string;
  concurrency: number;
  concurrency_reason: string;
  candidate_count: number;
  checks_completed?: number;
  checks_total?: number;
  candidates?: ZapretCalibrationCandidate[];
  started_at?: string;
  finished_at?: string;
  duration_ms?: number;
  error_code?: string;
  error?: string;
  activation_required: boolean;
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
  observation_source: {
    status: 'receiving' | 'listening' | 'waiting' | 'unavailable';
    reason?: string;
    bytes?: number;
    last_updated?: string;
  };
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
export type TGWSStatus = {
  installed: boolean;
  configured: boolean;
  enabled: boolean;
  running: boolean;
  local_listener: boolean;
  upstream_reachable: boolean;
  client_path_verified: boolean;
  port?: number;
  fake_tls: boolean;
  state: string;
  reason?: string;
  checked_at: string;
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
export async function getDevices(revealAddresses = false): Promise<any[]> {
  return request(`/devices?privacy=${revealAddresses ? 'revealed' : 'private'}`);
}
export async function getServices(): Promise<any[]> { return request('/services'); }
export async function classifyService(
  domain: string,
  category: string,
  baseVersion: number,
  allowedPaths?: string[],
  allowDisableFlowOffloading = false
): Promise<{ change: ChangeSet }> {
  return request('/services/classify', {
    method: 'POST',
    body: JSON.stringify({
      domain,
      category,
      allowed_paths: allowedPaths,
      base_version: baseVersion,
      allow_disable_flow_offloading: allowDisableFlowOffloading
    })
  });
}
export async function getRoutes(): Promise<any[]> { return request('/routes'); }
export async function getComponents(): Promise<ComponentStatus[]> {
  const result = await request<{ components: ComponentStatus[] }>('/components');
  return result.components;
}
export async function getComponent(kind: ComponentKind, upstream = false): Promise<ComponentStatus> {
  return request(`/components/${kind}${upstream ? '?upstream=1' : ''}`);
}
export async function componentAction(kind: ComponentKind, action: ComponentAction, confirmDisruption = false, preserveConfig = true): Promise<ComponentResult> {
  return request('/components/action', { method: 'POST', body: JSON.stringify({ kind, action, confirm_disruption: confirmDisruption, preserve_config: preserveConfig }) });
}
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
export async function getTGWS(): Promise<TGWSStatus> { return request('/tgws'); }
export async function configureTGWS(port: number, fakeTLSDomain: string): Promise<{ status: TGWSStatus; connect_link: string; one_time: boolean }> {
  return request('/tgws/configure', { method: 'POST', body: JSON.stringify({ port, fake_tls_domain: fakeTLSDomain }) });
}
export async function configureDiscovery(
  mode: DiscoveryStatus['mode'],
  maxNewRulesPerHour: number,
  maxConsecutiveRollbacks: number,
  baseVersion: number,
  resetFailures = false
): Promise<{ applied: boolean; dataplane_changed: boolean; config_version: number; mode: DiscoveryStatus['mode'] }> {
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
export async function getEvents(limit = 500): Promise<EventItem[]> { return request(`/events?limit=${limit}`); }
export async function getSecurity(): Promise<any> { return request('/security/audit'); }
export async function getSecuritySummary(): Promise<any> { return request('/security'); }
export async function getDiagnostics(): Promise<any> { return request('/diagnostics'); }
export async function getLifecycle(): Promise<any> { return request('/lifecycle'); }
export async function getStorage(): Promise<any> { return request('/storage'); }
export async function getSettings(): Promise<any> { return request('/settings'); }
export async function getBackups(): Promise<any> { return request('/backups'); }
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
export async function getManualVLESSServers(): Promise<ManualVLESSInventory> {
  return request('/xray/manual-servers');
}
export async function addManualVLESSServer(uri: string): Promise<ManualVLESSInventory> {
  return request('/xray/manual-servers', { method: 'POST', body: JSON.stringify({ uri }) });
}
export async function deleteManualVLESSServer(id: string): Promise<ManualVLESSInventory> {
  return request('/xray/manual-servers', { method: 'DELETE', body: JSON.stringify({ id }) });
}
export async function getVLESSPool(): Promise<VLESSPoolSnapshot> { return request('/xray/pool'); }
export async function setVLESSTariff(tariffMbps: number): Promise<{ tariff_mbps: number }> {
  return request('/xray/pool/settings', { method: 'PUT', body: JSON.stringify({ tariff_mbps: tariffMbps }) });
}
export async function runVLESSSpeedTest(logicalID: string): Promise<{ server: any; measurement: { measured_mbps: number; bytes_used: number; duration_ms: number; tested_at: string } }> {
  return request('/xray/pool/speedtest', { method: 'POST', body: JSON.stringify({ logical_id: logicalID }) });
}
export async function getZapret(): Promise<any> { return request('/zapret'); }
export async function getZapretCalibration(): Promise<ZapretCalibrationStatus> { return request('/zapret/calibration'); }
export async function startZapretCalibration(domain: string, allowManagedRestart = true): Promise<ZapretCalibrationStatus> {
  return request('/zapret/calibration', { method: 'POST', body: JSON.stringify({ domain, allow_managed_restart: allowManagedRestart }) });
}
export async function cancelZapretCalibration(): Promise<ZapretCalibrationStatus> {
  return request('/zapret/calibration', { method: 'DELETE' });
}
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
