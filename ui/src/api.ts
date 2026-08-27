export type Envelope<T> = { request_id: string; data: T };
export type Overview = Record<string, unknown>;
export type OnboardingState = {
  version: number;
  steps: Record<string, { status: string; updated_at?: string }>;
  completed: boolean;
  can_complete: boolean;
  router_ready: boolean;
  source: 'backend' | string;
  updated_at?: string;
  completion_note?: string;
};
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
  noop?: boolean;
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
  sources?: Array<{ source_masked: string; source_type: string; crypto_version?: string }>;
  changed?: boolean;
};
export type SubscriptionHWIDSettings = {
  mode: 'generated' | 'preset' | 'disabled' | string;
  source: 'composite' | 'device' | 'os' | 'software' | 'machine' | 'network' | 'mac' | 'machine_id' | 'router_serial' | 'hostname' | 'device_model' | 'ssid' | 'custom_seed' | string;
  current_hwid: string;
  preset_configured: boolean;
  preset?: string;
  custom_seed?: string;
  preview?: Array<{
    source: string;
    label: string;
    value?: string;
    hwid?: string;
    available: boolean;
    selected: boolean;
    reason?: string;
  }>;
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
  detected: boolean;
  managed: boolean;
  ownership: 'flintroute' | 'foreign' | 'absent' | string;
  version?: string;
  latest_supported_version: string;
  latest_upstream_version?: string;
  update_available: boolean;
  update_blocked_reason?: string;
  architecture?: string;
  source: string;
  pinned_asset_url?: string;
  checksum?: string;
  binary_sha256?: string;
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
  sources: Array<{ id: string; name: string; provider_id: string; provider_name: string; added_at?: string; expires_at?: string; expiry_known: boolean; server_count: number; manual?: boolean; original_source_masked?: string; resolved_source_masked?: string; source_type?: string; crypto_version?: string; resolution_status?: string }>;
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
  profile_name?: string;
  provider: string;
  provider_version: string;
  transports: string[];
  ports: number[];
  strategy_digest: string;
  tests?: string[];
  occurrences?: number;
};

export type ZapretCalibrationAttempt = {
  profile_id: string;
  profile_name?: string;
  target: string;
  protocol: string;
  result: 'PASS' | 'FAIL' | 'TIMEOUT' | 'INFRA_ERROR' | string;
  path_verified: boolean;
  cleanup_verified: boolean;
  route_evidence?: string;
  nfqueue_packets?: number;
  nfqueue_counter_delta?: number;
  latency_ms?: number;
  verification_duration_ms?: number;
  classification_state?: string;
  classification_reason?: string;
  http_status?: number;
  error_code?: string;
  error?: string;
};

export type ZapretCalibrationStatus = {
  id?: string;
  state: 'idle' | 'running' | 'completed' | 'failed' | 'cancelled' | 'unavailable';
  stage: string;
  domain?: string;
  mode?: 'quick' | 'exhaustive';
  scan_level?: 'quick' | 'standard' | 'force' | string;
  concurrency: number;
  concurrency_reason: string;
  candidate_count: number;
  checks_completed?: number;
  checks_total?: number;
  candidates?: ZapretCalibrationCandidate[];
  attempts?: ZapretCalibrationAttempt[];
  evidence_level?: 'none' | 'curl_only' | 'path_verified' | string;
  path_verified?: boolean;
  recommended_profile_id?: string;
  log_tail?: string[];
  working_strategies?: string[];
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
  observations?: Array<{ domain: string; query_type?: string; client?: string; observed_at?: string }>;
  applied_count?: number;
  failed_count?: number;
  queue_depth?: number;
  queue_capacity?: number;
  active_probe_jobs?: number;
  observation_source: {
    status: 'disabled' | 'receiving' | 'stale' | 'listening' | 'waiting' | 'unavailable';
    enabled?: boolean;
    source?: string;
    reason?: string;
    bytes?: number;
    last_updated?: string;
    cursor?: number;
    lag_bytes?: number;
    emitted?: number;
    dropped?: number;
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

export type HealthSnapshot = {
  status: string;
  provider?: string;
  simulation?: boolean;
  recovery_status?: string;
  recovery_reason_code?: string;
  recovery_reason?: string;
  active_revision?: string;
  time?: string;
};

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

export async function getHealth(signal?: AbortSignal): Promise<HealthSnapshot> {
  return request<HealthSnapshot>('/health', { signal });
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

export async function getOverview(signal?: AbortSignal): Promise<Overview> { return request<Overview>('/overview', { signal }); }
export async function getOnboarding(signal?: AbortSignal): Promise<OnboardingState> { return request<OnboardingState>('/onboarding', { signal }); }
export async function updateOnboarding(step: string, action: 'skip' | 'accept' | 'automatic' | 'complete'): Promise<OnboardingState> {
  return request<OnboardingState>('/onboarding', { method: 'POST', body: JSON.stringify({ step, action }) });
}
export async function getTopology(hideAddresses = false, signal?: AbortSignal): Promise<any> { return request(`/topology?privacy=${hideAddresses ? 'hidden' : 'visible'}`, { signal }); }
export async function getDevices(hideAddresses = false, signal?: AbortSignal): Promise<any[]> {
  return request(`/devices?privacy=${hideAddresses ? 'hidden' : 'visible'}`, { signal });
}
export async function getServices(signal?: AbortSignal): Promise<any[]> { return request('/services', { signal }); }
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
export type ServiceVerification = {
  service_id: string;
  domain: string;
  status: string;
  verification_state: string;
  classification_state?: string;
  classification_reason?: string;
  reason?: string;
  error_code?: string;
  error?: string;
  checked_at?: string;
  verification_duration_ms?: number;
  selected_route_tag?: string;
  selected_route_type?: string;
  path_verified: boolean;
  route_latency_ms?: number;
  route_latency_available?: boolean;
  end_to_end_latency_ms?: number;
  end_to_end_latency_available?: boolean;
  selection_score?: number;
  evidence_persisted: number;
  candidates: unknown[];
};
export async function verifyService(serviceID: string, domain?: string): Promise<ServiceVerification> {
  return request('/services/verify', {
    method: 'POST',
    body: JSON.stringify({ service_id: serviceID, domain })
  });
}
export async function getRoutes(signal?: AbortSignal): Promise<any[]> { return request('/routes', { signal }); }
export async function getComponents(signal?: AbortSignal): Promise<ComponentStatus[]> {
  const result = await request<{ components: ComponentStatus[] }>('/components', { signal });
  return result.components;
}
export async function getComponent(kind: ComponentKind, upstream = false): Promise<ComponentStatus> {
  return request(`/components/${kind}${upstream ? '?upstream=1' : ''}`);
}
export async function componentAction(kind: ComponentKind, action: ComponentAction, confirmDisruption = false, preserveConfig = true): Promise<ComponentResult> {
  return request('/components/action', { method: 'POST', body: JSON.stringify({ kind, action, confirm_disruption: confirmDisruption, preserve_config: preserveConfig }) });
}
export async function getSmartDNS(signal?: AbortSignal): Promise<any> { return request('/smart-dns', { signal }); }
export async function configureSmartDNS(resolvers: SmartDNSResolver[], testDomain: string, baseVersion: number): Promise<{ change: ChangeSet; endpoint_count: number; validations: SmartDNSValidation[] }> {
  return request('/smart-dns/configure', {
    method: 'POST',
    body: JSON.stringify({ resolvers, test_domain: testDomain, base_version: baseVersion })
  });
}
export async function getDiscovery(signal?: AbortSignal): Promise<DiscoveryStatus> { return request('/discovery', { signal }); }
export async function applyDiscoverySuggestion(domain: string, route?: string): Promise<{ applied: boolean; domain: string; route: string; route_type: string; post_apply_proof: boolean; post_apply_proof_kind?: string }> {
  return request(`/discovery/suggestions/${encodeURIComponent(domain)}/apply`, { method: 'POST', body: JSON.stringify(route ? { route } : {}) });
}
export async function ignoreDiscoverySuggestion(domain: string): Promise<{ applied: boolean; ignored: boolean; domain: string }> {
  return request(`/discovery/suggestions/${encodeURIComponent(domain)}/ignore`, { method: 'POST', body: '{}' });
}
export async function getTelegram(signal?: AbortSignal): Promise<TelegramOverview> { return request('/telegram', { signal }); }
export async function configureTelegram(botToken: string, chatID: string, enabled: boolean, eventTypes: string[]): Promise<TelegramStatus> {
  return request('/telegram/configure', { method: 'PUT', body: JSON.stringify({ bot_token: botToken, chat_id: chatID, enabled, event_types: eventTypes }) });
}
export async function testTelegram(): Promise<{ delivered: boolean; status: TelegramStatus }> {
  return request('/telegram/test', { method: 'POST', body: '{}' });
}
export async function getExternalSOCKS(signal?: AbortSignal): Promise<any> { return request('/external-socks', { signal }); }
export async function checkExternalSOCKS(endpoint: string, testDomain: string, baseVersion: number): Promise<{ report: ExternalSOCKSReport }> {
  return request('/external-socks/check', { method: 'POST', body: JSON.stringify({ endpoint, test_domain: testDomain, base_version: baseVersion }) });
}
export async function activateExternalSOCKS(endpoint: string, testDomain: string, baseVersion: number): Promise<{ report: ExternalSOCKSReport; change: ChangeSet }> {
  return request('/external-socks/activate', { method: 'POST', body: JSON.stringify({ endpoint, test_domain: testDomain, base_version: baseVersion }) });
}
export async function getTGWS(signal?: AbortSignal): Promise<TGWSStatus> { return request('/tgws', { signal }); }
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
export async function getTraffic(signal?: AbortSignal): Promise<TrafficSnapshot> { return request('/traffic', { signal }); }
export async function getEvents(limit = 500, hideAddresses = true, signal?: AbortSignal): Promise<EventItem[]> { return request(`/events?limit=${limit}&privacy=${hideAddresses ? 'hidden' : 'visible'}`, { signal }); }
export async function getSecurity(signal?: AbortSignal): Promise<any> { return request('/security/audit', { signal }); }
export async function getSecuritySummary(signal?: AbortSignal): Promise<any> { return request('/security', { signal }); }
export async function getDiagnostics(signal?: AbortSignal): Promise<any> { return request('/diagnostics', { signal }); }
export async function getLifecycle(signal?: AbortSignal): Promise<any> { return request('/lifecycle', { signal }); }
export async function getStorage(signal?: AbortSignal): Promise<any> { return request('/storage', { signal }); }
export async function getSettings(signal?: AbortSignal): Promise<any> { return request('/settings', { signal }); }
export async function getBackups(signal?: AbortSignal): Promise<any> { return request('/backups', { signal }); }
export async function getSystem(signal?: AbortSignal): Promise<any> { return request('/system', { signal }); }
export async function getChanges(signal?: AbortSignal): Promise<ChangeSet[]> { return request('/changes', { signal }); }
export async function getRevisions(signal?: AbortSignal): Promise<RevisionSummary> { return request('/revisions', { signal }); }
export async function getSubscriptionSecretStatus(signal?: AbortSignal): Promise<SubscriptionSecretStatus> {
  return request('/xray/subscription/secret', { signal });
}
export async function saveSubscriptionSecrets(urls: string[]): Promise<SubscriptionSecretStatus> {
  return request('/xray/subscription/secret', { method: 'PUT', body: JSON.stringify({ urls }) });
}
export async function removeSubscriptionSource(index: number): Promise<SubscriptionSecretStatus> {
  return request('/xray/subscription/secret', { method: 'DELETE', body: JSON.stringify({ index }) });
}
export async function getSubscriptionHWID(signal?: AbortSignal): Promise<SubscriptionHWIDSettings> {
  return request('/xray/subscription/hwid', { signal });
}
export async function saveSubscriptionHWID(settings: { mode: string; source: string; preset?: string; custom_seed?: string }): Promise<SubscriptionHWIDSettings> {
  return request('/xray/subscription/hwid', { method: 'PUT', body: JSON.stringify(settings) });
}
export async function prepareSubscription(baseVersion: number, activateManaged = false): Promise<SubscriptionPreparation> {
  return request('/xray/subscription/prepare', { method: 'POST', body: JSON.stringify({ base_version: baseVersion, activate_managed: activateManaged }) });
}
export async function getManualVLESSServers(signal?: AbortSignal): Promise<ManualVLESSInventory> {
  return request('/xray/manual-servers', { signal });
}
export async function addManualVLESSServer(uri: string): Promise<ManualVLESSInventory> {
  return request('/xray/manual-servers', { method: 'POST', body: JSON.stringify({ uri }) });
}
export async function deleteManualVLESSServer(id: string): Promise<ManualVLESSInventory> {
  return request('/xray/manual-servers', { method: 'DELETE', body: JSON.stringify({ id }) });
}
export async function getVLESSPool(signal?: AbortSignal): Promise<VLESSPoolSnapshot> { return request('/xray/pool', { signal }); }
export async function setVLESSTariff(tariffMbps: number): Promise<{ tariff_mbps: number }> {
  return request('/xray/pool/settings', { method: 'PUT', body: JSON.stringify({ tariff_mbps: tariffMbps }) });
}
export async function runVLESSSpeedTest(logicalID: string): Promise<{ server: any; measurement: { measured_mbps: number; bytes_used: number; duration_ms: number; tested_at: string } }> {
  return request('/xray/pool/speedtest', { method: 'POST', body: JSON.stringify({ logical_id: logicalID }) });
}
export async function getZapret(signal?: AbortSignal): Promise<any> { return request('/zapret', { signal }); }
export async function getZapretCalibration(signal?: AbortSignal): Promise<ZapretCalibrationStatus> { return request('/zapret/calibration', { signal }); }
export async function startZapretCalibration(domain: string, allowManagedRestart = false, mode: 'quick' | 'exhaustive' = 'quick'): Promise<ZapretCalibrationStatus> {
  return request('/zapret/calibration', { method: 'POST', body: JSON.stringify({ domain, mode, allow_managed_restart: allowManagedRestart }) });
}
export async function cancelZapretCalibration(): Promise<ZapretCalibrationStatus> {
  return request('/zapret/calibration', { method: 'DELETE' });
}
export async function checkZapretSetup(input: ZapretSetupRequest, baseVersion: number): Promise<{ report: ZapretSetupReport }> {
  return request('/zapret/setup/check', { method: 'POST', body: JSON.stringify({ ...input, base_version: baseVersion }) });
}
export async function activateZapretSetup(input: ZapretSetupRequest, baseVersion: number): Promise<{ report: ZapretSetupReport; change: ChangeSet; calibrated_profile_id?: string }> {
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
