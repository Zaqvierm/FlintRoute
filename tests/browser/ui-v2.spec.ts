import { test, expect, type Page, type Route } from '@playwright/test';

const rawIP = '192.0.2.44';
const rawMAC = '02:00:00:00:00:44';

function envelope(data: unknown, status = 200) {
  return { status, contentType: 'application/json', body: JSON.stringify({ data }) };
}

export async function mockAPI(page: Page, options: { securityFailure?: boolean; recoveryStatus?: string; bootstrapRequired?: boolean } = {}) {
  await page.route('**/api/v1/**', async (route: Route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace('/api/v1', '');
    if (path === '/auth/me') return route.fulfill(envelope({ user: 'admin', role: 'administrator', csrf_token: 'test-csrf' }));
    if (path === '/health') return route.fulfill(envelope({ status: 'ready', recovery_status: options.recoveryStatus ?? 'ok', recovery_reason: options.recoveryStatus && options.recoveryStatus !== 'ok' ? 'Восстановление ещё не подтверждено.' : '', checked_at: new Date().toISOString() }));
    if (path === '/overview') return route.fulfill(envelope({ internet: 'route_available', data_plane: 'ready', dns: 'ready', current_route: 'Direct', critical_errors: [], freshness: 'live' }));
    if (path === '/topology') {
      const hidden = url.searchParams.get('privacy') === 'hidden';
      return route.fulfill(envelope({ status: 'ready', source: 'fixture', collected_at: new Date().toISOString(), freshness: 'live', nodes: [{ type: 'internet', status: 'online' }, { type: 'router', hostname: 'fixture-router', model: 'fixture-model' }], edges: [], raw_ip: hidden ? undefined : rawIP, raw_mac: hidden ? undefined : rawMAC }));
    }
    if (path === '/devices') {
      const hidden = url.searchParams.get('privacy') === 'hidden';
      return route.fulfill(envelope(hidden ? [{ id: 'phone', name: 'Phone', connected: true, kind: 'wifi', ip_display: 'IP скрыт', mac_display: 'MAC скрыт' }] : [{ id: 'phone', name: 'Phone', connected: true, kind: 'wifi', ip: rawIP, mac: rawMAC }]));
    }
    if (path === '/services') return route.fulfill(envelope(options.bootstrapRequired ? [] : [{ id: 'Discord', name: 'Discord', category: 'TELEGRAM', domains: ['discord.com'], route: 'VLESS' }]));
    if (path === '/routes') return route.fulfill(envelope([{ type: 'system_default', tag: 'Direct', status: 'ready' }]));
    if (path === '/events') return route.fulfill(envelope([]));
    if (path === '/traffic') return route.fulfill(envelope({ status: 'ready', source: 'fixture', collected_at: new Date().toISOString(), interfaces: [] }));
    if (path === '/onboarding') return route.fulfill(envelope({ completed: false, can_complete: false, steps: { methods: { status: 'pending' }, sources: { status: 'pending' }, services: { status: 'pending' } } }));
    if (path === '/revisions') return route.fulfill(envelope({ active_revision: 'fixture', config_version: options.bootstrapRequired ? 1 : 2, items: [] }));
    if (path === '/discovery') return route.fulfill(envelope({ mode: 'observe_only', observation_source: { status: 'waiting' }, suggestions: [] }));
    if (path === '/components') return route.fulfill(envelope({ components: [] }));
    if (path === '/xray/pool') return route.fulfill(envelope({ tariff_mbps: 300, sources: [], servers: [] }));
    if (path === '/smart-dns') return route.fulfill(envelope({ configured_count: 0, ready: 0, routes: [] }));
    if (path === '/tgws') return route.fulfill(envelope({ status: 'not_configured' }));
    if (path === '/zapret') return route.fulfill(envelope({ ready: false }));
    if (path === '/changes') return route.fulfill(envelope([]));
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

  test('isolates a failed security slice from the overview', async ({ page }) => {
    await mockAPI(page, { securityFailure: true });
    await page.goto('/?screen=Обзор');
    await expect(page.locator('.topbar').getByText('Интернет доступен')).toBeVisible();
    await expect(page.getByText('Часть данных недоступна')).toBeVisible();
  });

  test('fails closed when recovery is not proven safe', async ({ page }) => {
    await mockAPI(page, { recoveryStatus: 'starting' });
    await page.goto('/?screen=Сервисы');
    await expect(page.getByText('Изменения временно заблокированы')).toBeVisible();
    await expect(page.getByRole('button', { name: '+ Новое правило' })).toBeDisabled();
  });

  test('opens backend-required fast start instead of trusting local storage', async ({ page }) => {
    await mockAPI(page, { bootstrapRequired: true });
    await page.goto('/?screen=Обзор');
    await expect.poll(() => new URL(page.url()).searchParams.get('screen')).toBe('Быстрая настройка');
    await expect(page.getByRole('heading', { name: 'Быстрая настройка' })).toBeVisible();
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
});
