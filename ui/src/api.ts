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
export async function getRoutes(): Promise<any[]> { return request('/routes'); }
export async function getTraffic(): Promise<TrafficSnapshot> { return request('/traffic'); }
export async function getEvents(): Promise<EventItem[]> { return request('/events'); }
export async function getSecurity(): Promise<any> { return request('/security/audit'); }
export async function getSystem(): Promise<any> { return request('/system'); }
export async function getChanges(): Promise<ChangeSet[]> { return request('/changes'); }
export async function getRevisions(): Promise<RevisionSummary> { return request('/revisions'); }
export async function createChange(title: string, baseVersion: number, operations: ChangeOp[]): Promise<ChangeSet> {
  if (!Number.isSafeInteger(baseVersion) || baseVersion < 1) throw new Error('Некорректная версия конфигурации');
  if (operations.length === 0) throw new Error('ChangeSet должен содержать хотя бы одну операцию');
  return request('/changes', { method: 'POST', body: JSON.stringify({ title, base_version: baseVersion, operations }) });
}
export async function changeAction(id: string, action: string): Promise<ChangeSet> {
  return request(`/changes/${id}/${action}`, { method: 'POST', body: '{}' });
}
