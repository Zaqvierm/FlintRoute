import { test, expect, type Page, type Route } from '@playwright/test';

const rawIP = '192.0.2.44';
const rawMAC = '02:00:00:00:00:44';

function envelope(data: unknown, status = 200) {
  return { status, contentType: 'application/json', body: JSON.stringify({ data }) };
}

export async function mockAPI(page: Page, options: { securityFailure?: boolean; recoveryStatus?: string; bootstrapRequired?: boolean; decisionState?: 'verifying' | 'no_safe_route'; changeState?: 'requires_device'; objectStatuses?: boolean; onboardingFailure?: boolean } = {}) {
  const onboarding = {
    completed: false,
    can_complete: false,
    router_ready: true,
    steps: {
      methods: { status: 'pending' },
      sources: { status: 'pending' },
      services: { status: 'pending' },
      verification: { status: 'pending' }
    }
  };
  const onboardingSnapshot = () => ({
    ...onboarding,
    can_complete: Object.values(onboarding.steps).slice(0, 3).every((step) => step.status !== 'pending')
  });
  await page.route('**/api/v1/**', async (route: Route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace('/api/v1', '');
    if (path === '/auth/me') return route.fulfill(envelope({ user: 'admin', role: 'administrator', csrf_token: 'test-csrf' }));
    if (path === '/health') return route.fulfill(envelope({ status: 'ready', recovery_status: options.recoveryStatus ?? 'ok', recovery_reason: options.recoveryStatus && options.recoveryStatus !== 'ok' ? 'Восстановление ещё не подтверждено.' : '', checked_at: new Date().toISOString() }));
    if (path === '/overview') return route.fulfill(envelope({ internet: options.objectStatuses ? { status: 'route_available' } : 'route_available', data_plane: options.objectStatuses ? { state: 'ready' } : 'ready', dns: options.objectStatuses ? { status: 'ready' } : 'ready', current_route: options.objectStatuses ? { tag: 'Direct' } : 'Direct', critical_errors: [], freshness: 'live' }));
    if (path === '/topology') {
      const hidden = url.searchParams.get('privacy') === 'hidden';
      return route.fulfill(envelope({ status: 'ready', source: 'fixture', collected_at: new Date().toISOString(), freshness: 'live', nodes: [{ type: 'internet', status: 'online' }, { type: 'router', hostname: 'fixture-router', model: 'fixture-model' }], edges: [], raw_ip: hidden ? undefined : rawIP, raw_mac: hidden ? undefined : rawMAC }));
    }
    if (path === '/devices') {
      const hidden = url.searchParams.get('privacy') === 'hidden';
      return route.fulfill(envelope(hidden ? [{ id: 'phone', name: 'Phone', connected: true, kind: 'wifi', ip_display: 'IP скрыт', mac_display: 'MAC скрыт' }] : [{ id: 'phone', name: 'Phone', connected: true, kind: 'wifi', ip: rawIP, mac: rawMAC }]));
    }
    if (path === '/services') return route.fulfill(envelope(options.bootstrapRequired ? [] : [{ id: 'Discord', name: 'Discord', category: 'TELEGRAM', domains: ['discord.com'], route: 'VLESS', applied: true, source: 'configured', health: 'ready' }]));
    if (path === '/routes') return route.fulfill(envelope([{ type: 'system_default', tag: 'Direct', status: options.objectStatuses ? { status: 'ready' } : 'ready' }]));
    if (path === '/events') {
      if (!options.decisionState) return route.fulfill(envelope([]));
      const terminal = options.decisionState === 'no_safe_route';
      return route.fulfill(envelope([{
        id: 1,
        time: new Date().toISOString(),
        type: 'route.decision',
        severity: 'info',
        device_id: 'phone',
        domain: 'example.com',
        route: 'Direct',
        details: {
          device_name: 'Phone', device_ip: rawIP, service_name: 'Unknown', category: 'UNKNOWN',
          path_verified: false,
          probe_state: terminal ? 'no_safe_route' : 'verifying',
          verification_state: terminal ? 'terminal_no_safe_route' : 'in_progress',
          policy_state: 'observed',
          status: terminal ? 'NO_SAFE_ROUTE' : 'VERIFYING',
          decision_duration_ms: terminal ? 4200 : 120
        }
      }]));
    }
    if (path === '/traffic') return route.fulfill(envelope({ status: options.objectStatuses ? { state: 'ready' } : 'ready', source: options.objectStatuses ? { name: 'fixture' } : 'fixture', collected_at: new Date().toISOString(), interfaces: [] }));
    if (path === '/onboarding') {
      if (options.onboardingFailure && route.request().method() === 'POST') return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { code: 'fixture_onboarding_down', message: 'onboarding unavailable' } }) });
      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON() as { step?: string; action?: string };
        if (body.step === 'complete' && onboardingSnapshot().can_complete && body.action === 'complete') {
          onboarding.completed = true;
          onboarding.steps.verification = { status: 'verified' };
        } else if (body.step && body.step in onboarding.steps && body.step !== 'verification') {
          onboarding.steps[body.step as 'methods' | 'sources' | 'services'] = { status: body.action === 'skip' ? 'skipped' : 'accepted' };
        }
      }
      return route.fulfill(envelope(onboardingSnapshot()));
    }
    if (path === '/revisions') return route.fulfill(envelope({ active_revision: 'fixture', config_version: options.bootstrapRequired ? 1 : 2, items: [] }));
    if (path === '/discovery') return route.fulfill(envelope({ mode: options.objectStatuses ? { value: 'observe_only' } : 'observe_only', observation_source: { status: options.objectStatuses ? { state: 'waiting' } : 'waiting' }, suggestions: [] }));
    if (path === '/components') return route.fulfill(envelope({ components: [] }));
    if (path === '/xray/pool') return route.fulfill(envelope({ tariff_mbps: 300, sources: [], servers: [] }));
    if (path === '/smart-dns') return route.fulfill(envelope({ configured_count: 0, ready: 0, routes: [] }));
    if (path === '/tgws') return route.fulfill(envelope({ status: 'not_configured' }));
    if (path === '/zapret') return route.fulfill(envelope({ ready: false }));
    if (path === '/changes') {
      if (options.changeState) {
        return route.fulfill(envelope([{
          id: 'fixture-change', state: options.changeState, title: 'Rule fixture', description: 'fixture',
          base_version: 1, version: 1, operations: [{ type: 'set', path: '/services/discord/route', value: 'VLESS' }],
          validation: [], diff: [], data_plane_verified: false,
          created_at: new Date().toISOString(), updated_at: new Date().toISOString(), author: 'fixture',
          artifact_block_reason: 'fixture_unknown'
        }]));
      }
      return route.fulfill(envelope([]));
    }
    if (path === '/security' && options.securityFailure) return route.fulfill(envelope({ error: { code: 'fixture_security_down', message: 'security fixture unavailable' } }, 503));
    if (path === '/security') return route.fulfill(envelope({ status: 'ready', checks: [] }));
    if (path === '/security/summary') return route.fulfill(envelope({ status: 'ready', secrets: 'hidden', auth: 'ready' }));
    if (path === '/diagnostics') return route.fulfill(envelope({ status: 'ready', collected_at: new Date().toISOString() }));
    if (path === '/lifecycle') return route.fulfill(envelope({ status: 'ready', recovery: { status: 'not_required' } }));
    if (path === '/storage') return route.fulfill(envelope({ status: 'ready' }));
    if (path === '/settings') return route.fulfill(envelope({ status: 'ready' }));
    if (path === '/backups') return route.fulfill(envelope({ status: 'ready', items: [] }));
    return route.fulfill(envelope({}));
  });
}

test.describe('FlintRoute UI v2', () => {
  test('explains requires-device and offers a diagnostics next step', async ({ page }) => {
    await mockAPI(page, { changeState: 'requires_device' });
    await page.goto('/?screen=%D0%9E%D0%BF%D0%B5%D1%80%D0%B0%D1%86%D0%B8%D0%B8');
    await expect(page.getByText(/\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u043d\u0430 \u0440\u043e\u0443\u0442\u0435\u0440\u0435 \u043d\u0435 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0430/)).toBeVisible();
    await page.getByRole('button', { name: /\u041e\u0442\u043a\u0440\u044b\u0442\u044c \u0434\u0438\u0430\u0433\u043d\u043e\u0441\u0442\u0438\u043a\u0443/ }).click();
    await expect(page).toHaveURL(/screen=.*%D0%94%D0%B8%D0%B0%D0%B3%D0%BD%D0%BE%D1%81%D1%82%D0%B8%D0%BA%D0%B0/);
  });

  test('keeps the shell usable and navigable on a phone', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await mockAPI(page);
    await page.goto('/?screen=Обзор');
    await expect(page.locator('.mobile-brand')).toBeVisible();
    const mobileNav = page.locator('.mobile-nav');
    await expect(mobileNav).toBeVisible();
    await expect(mobileNav.locator('button').nth(1)).toBeVisible();
    await mobileNav.locator('button').nth(1).click();
    await expect(page).toHaveURL(/screen=%D0%9A%D0%B0%D1%80%D1%82%D0%B0/);
    await page.goBack();
    await expect(page).toHaveURL(/screen=%D0%9E%D0%B1%D0%B7%D0%BE%D1%80/);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  });

  test('purges revealed address data when privacy is switched back to hidden', async ({ page }) => {
    await mockAPI(page);
    await page.goto('/?screen=Устройства');
    await page.getByText('Показать адреса').click();
    await expect(page.getByText(rawIP)).toBeVisible();
    await page.getByText('Скрыть адреса').click();
    await expect(page.getByText('Адреса скрыты')).toBeVisible();
    await expect(page.locator('body')).not.toContainText(rawIP);
    await expect(page.locator('body')).not.toContainText(rawMAC);
  });

  test('does not present unfinished device actions as clickable controls', async ({ page }) => {
    await mockAPI(page);
    await page.goto(`/?screen=${encodeURIComponent('\u0423\u0441\u0442\u0440\u043e\u0439\u0441\u0442\u0432\u0430')}`);
    await page.locator('.entity-card').first().getByRole('button', { name: /\u041e\u0442\u043a\u0440\u044b\u0442\u044c/ }).click();
    await expect(page.getByText(/\u0423\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u0438\u0435 \u0443\u0441\u0442\u0440\u043e\u0439\u0441\u0442\u0432\u043e\u043c \u043f\u043e\u043a\u0430 \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u043d\u043e/)).toBeVisible();
    await expect(page.getByRole('button', { name: /\u041f\u0435\u0440\u0435\u0438\u043c\u0435\u043d\u043e\u0432\u0430\u0442\u044c/ })).toHaveCount(0);
    await expect(page.locator('button[title="Not implemented"]')).toHaveCount(0);
  });

  test('isolates a failed security slice from the overview', async ({ page }) => {
    await mockAPI(page, { securityFailure: true });
    await page.goto('/?screen=Обзор');
    await expect(page.locator('.topbar').getByText('Интернет доступен')).toBeVisible();
    await expect(page.getByText('Часть данных недоступна')).toBeVisible();
  });

  test('marks a previously loaded service list stale when its refresh fails', async ({ page }) => {
    await mockAPI(page);
    await page.goto('/?screen=Сервисы');
    await expect(page.locator('.service-table tbody tr')).toHaveCount(1);
    await page.route('**/api/v1/services', async (route) => route.fulfill(envelope({ error: { code: 'fixture_services_down', message: 'services unavailable' } }, 503)));
    await page.getByRole('button', { name: 'Обзор', exact: true }).first().click();
    await page.getByRole('button', { name: 'Сервисы', exact: true }).first().click();
    await expect(page.locator('.status-badge.warn').filter({ hasText: 'устарели' })).toBeVisible();
  });

  test('retries only the failed source from the alert center', async ({ page }) => {
    await mockAPI(page);
    let serviceCalls = 0;
    await page.route('**/api/v1/services', async (route) => {
      serviceCalls += 1;
      if (serviceCalls === 1) {
        await route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { code: 'fixture_services_down', message: 'services unavailable' } }) });
        return;
      }
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ data: [{ id: 'Discord', name: 'Discord', category: 'TELEGRAM', domains: ['discord.com'], route: 'VLESS' }] }) });
    });
    await page.goto(`/?screen=${encodeURIComponent('\u041e\u0431\u0437\u043e\u0440')}`);
    await expect(page.getByText(/\u0427\u0430\u0441\u0442\u044c \u0434\u0430\u043d\u043d\u044b\u0445 \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u043d\u0430/)).toBeVisible();
    await page.locator('.alert-center details').first().locator('summary').click();
    await page.getByRole('button', { name: /\u041f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u044c \u044d\u0442\u043e\u0442 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a/ }).click();
    await expect.poll(() => serviceCalls).toBe(2);
    await expect(page.getByText(/\u0427\u0430\u0441\u0442\u044c \u0434\u0430\u043d\u043d\u044b\u0445 \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u043d\u0430/)).toHaveCount(0);
    await expect(page.locator('.session-bar.warning')).toHaveCount(0);
  });

  test('never renders object statuses as [object Object]', async ({ page }) => {
    await mockAPI(page, { objectStatuses: true });
    await page.goto('/?screen=Discovery');
    await expect(page.getByRole('heading', { name: /discovery/i }).first()).toBeVisible();
    await expect(page.locator('body')).not.toContainText('[object Object]');
  });

  test('fails closed when recovery is not proven safe', async ({ page }) => {
    await mockAPI(page, { recoveryStatus: 'starting' });
    await page.goto('/?screen=Сервисы');
    await expect(page.getByText('Изменения временно заблокированы')).toBeVisible();
    await expect(page.getByRole('button', { name: '+ Новое правило' })).toBeDisabled();
  });

  test('opens backend-required fast start instead of trusting local storage', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('flintroute-first-run-opened', '1'));
    await mockAPI(page, { bootstrapRequired: true });
    await page.goto('/?screen=Обзор');
    await expect.poll(() => new URL(page.url()).searchParams.get('screen')).toBe('Быстрая настройка');
    await expect(page.getByRole('heading', { name: 'Быстрая настройка' })).toBeVisible();
  });

  test('keeps recovery reachable while first-run setup is incomplete', async ({ page }) => {
    await mockAPI(page, { bootstrapRequired: true, recoveryStatus: 'starting' });
    await page.goto(`/?screen=${encodeURIComponent('Ревизии и recovery')}`);
    await expect(page.getByRole('heading', { name: 'Ревизии и recovery' })).toBeVisible();
    await expect(page.getByText('Изменения временно заблокированы')).toBeVisible();
  });

  test('loads setup provider state when the wizard first opens', async ({ page }) => {
    const setupRequests: string[] = [];
    page.on('request', (request) => {
      const path = new URL(request.url()).pathname.replace('/api/v1', '');
      if (['/components', '/xray/pool', '/smart-dns', '/tgws', '/zapret'].includes(path)) setupRequests.push(path);
    });
    await mockAPI(page, { bootstrapRequired: true });
    await page.goto(`/?screen=${encodeURIComponent('Быстрая настройка')}`);
    await expect(page.getByRole('heading', { name: 'Быстрая настройка' })).toBeVisible();
    await expect.poll(() => setupRequests.length).toBeGreaterThan(0);
    expect(new Set(setupRequests)).toEqual(new Set(['/components', '/xray/pool', '/smart-dns', '/tgws', '/zapret']));
  });

  test('explains a failed onboarding write instead of leaving an unhandled promise', async ({ page }) => {
    await mockAPI(page, { bootstrapRequired: true, onboardingFailure: true });
    await page.goto('/?screen=Быстрая настройка');
    await page.getByRole('button', { name: 'Пока использовать только обычный интернет' }).click();
    const alert = page.getByRole('alert').filter({ hasText: 'Шаг не сохранён' });
    await expect(alert).toContainText('Шаг не сохранён');
    await expect(alert).toContainText('fixture_onboarding_down');
  });

  test('completes the backend-driven fast start flow', async ({ page }) => {
    await mockAPI(page, { bootstrapRequired: true });
    await page.goto('/?screen=Обзор');
    await expect(page.getByRole('heading', { name: 'Быстрая настройка' })).toBeVisible();
    await page.getByRole('button', { name: 'Пока использовать только обычный интернет' }).click();
    await expect(page.getByRole('button', { name: 'Пока выбирать автоматически' })).toBeVisible();
    await page.getByRole('button', { name: 'Пока выбирать автоматически' }).click();
    const finish = page.getByRole('button', { name: 'Завершить настройку' });
    await expect(finish).toBeEnabled();
    await finish.click();
    await expect(page).toHaveURL(/screen=%D0%9E%D0%B1%D0%B7%D0%BE%D1%80/);
  });

  test('loads screen-specific data instead of polling the whole dashboard', async ({ page }) => {
    const apiPaths: string[] = [];
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (url.pathname.startsWith('/api/v1/')) apiPaths.push(url.pathname.replace('/api/v1', ''));
    });
    await mockAPI(page);
    await page.goto('/?screen=Сервисы');
    await expect(page.getByText('Правила сервисов', { exact: true })).toBeVisible();
    expect(apiPaths.filter((path) => ['/topology', '/devices', '/routes', '/traffic', '/events', '/discovery', '/diagnostics', '/backups'].includes(path))).toHaveLength(0);
    expect(apiPaths.filter((path) => path === '/services')).toHaveLength(1);
    expect(apiPaths.length).toBeLessThanOrEqual(8);
  });

  test('aborts an in-flight screen refresh when navigation changes', async ({ page }) => {
    let servicesSeen = false;
    let servicesAborted = false;
    await mockAPI(page);
    await page.route('**/api/v1/services', async (route) => {
      servicesSeen = true;
      try {
        await new Promise((resolve) => setTimeout(resolve, 2_000));
        await route.fulfill(envelope([{ id: 'Discord', name: 'Discord', category: 'TELEGRAM', domains: ['discord.com'], route: 'VLESS' }]));
      } catch {
        servicesAborted = true;
      }
    });
    page.on('requestfailed', (request) => {
      if (new URL(request.url()).pathname === '/api/v1/services') servicesAborted = true;
    });
    await page.goto('/?screen=Сервисы');
    await expect.poll(() => servicesSeen).toBe(true);
    await page.getByRole('button', { name: 'Обзор', exact: true }).first().click();
    await expect.poll(() => servicesAborted, { timeout: 5_000 }).toBe(true);
  });

  test('keeps verifying decisions separate from terminal no-safe-route failures', async ({ page }) => {
    await mockAPI(page, { decisionState: 'verifying' });
    await page.goto('/?screen=Поток решений');
    await expect(page.getByText('Проверяется…')).toBeVisible();
    await expect(page.getByText('Безопасный маршрут не найден')).toHaveCount(0);
  });

  test('shows no-safe-route only after a terminal exhausted decision', async ({ page }) => {
    await mockAPI(page, { decisionState: 'no_safe_route' });
    await page.goto('/?screen=Поток решений');
    await expect(page.getByText('Безопасный маршрут не найден')).toBeVisible();
  });
});
