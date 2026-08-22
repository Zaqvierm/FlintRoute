import { describe, expect, it } from 'vitest';
import { decisionVerificationPresentation, formatDateTime, groupServices, humanStatus, isAdministrativeEvent, isDecisionEvent, onboardingProgress, onboardingRouterReady, parseResolverInput, recoveryMutationAllowed, serviceColumnFor, stringArray, textValue, toDecisionCard, verificationPresentationLabel } from './view-models';
import type { EventItem } from './api';

describe('safe display values', () => {
  it('never renders object coercion text', () => {
    expect(textValue({ status: 'READY' })).toBe('READY');
    expect(textValue({ nested: true })).toBe('Недоступно');
    expect(textValue({ nested: true })).not.toContain('[object Object]');
  });

  it('uses human readable health labels', () => {
    expect(humanStatus('NO_MANAGED_POLICIES')).toBe('Нет управляемых правил');
    expect(humanStatus('path.verified')).toBe('Путь подтверждён');
    expect(humanStatus('ROUTE_AVAILABLE')).toBe('Интернет доступен');
    expect(humanStatus('not_installed')).toBe('Не установлен');
    expect(humanStatus('NO_SAFE_ROUTE')).toBe('Ни один безопасный маршрут не прошёл проверку');
  });

  it('does not render zero-value timestamps as year one', () => {
    expect(formatDateTime('0001-01-01T00:00:00Z')).toBe('Нет данных');
  });

  it('normalizes nullable API string lists before rendering controls', () => {
    expect(stringArray(null)).toEqual([]);
    expect(stringArray([' apply.ok ', null, 4, ''])).toEqual(['apply.ok']);
  });
});

describe('Smart DNS endpoint input', () => {
  it.each([
    ['1.1.1.1', { ip: '1.1.1.1', port: 53 }],
    ['1.1.1.1:5353', { ip: '1.1.1.1', port: 5353 }],
    ['2606:4700:4700::1111', { ip: '2606:4700:4700::1111', port: 53 }],
    ['[2606:4700:4700::1111]:5353', { ip: '2606:4700:4700::1111', port: 5353 }]
  ])('parses %s', (input, expected) => {
    expect(parseResolverInput(input)).toEqual(expected);
  });

  it('rejects invalid ports', () => {
    expect(() => parseResolverInput('1.1.1.1:0')).toThrow('resolver_invalid_port');
    expect(() => parseResolverInput('[2606:4700::1111]:99999')).toThrow('resolver_invalid_port');
  });
});

describe('service view model', () => {
  it.each([
    ['GEO_LOCKED', 'GEO_LOCKED'],
    ['TSPU_RESTRICTED', 'TSPU_RESTRICTED'],
    ['TELEGRAM', 'TELEGRAM'],
    ['DIRECT_PREFERRED', 'DIRECT_PREFERRED'],
    ['DIRECT_ONLY', 'DIRECT_ONLY'],
    ['BLOCKED', 'BLOCKED'],
    ['future_category', 'UNRESOLVED'],
    ['', 'UNRESOLVED']
  ])('maps category %s explicitly', (category, expected) => {
    expect(serviceColumnFor(category)).toBe(expected);
  });

  it('groups configured and discovered domains into one service', () => {
    const grouped = groupServices([
      { id: 'Discord', category: 'TSPU_RESTRICTED', domains: ['discord.com', 'discord.gg'], source: 'configured' },
      { id: 'Discord', category: 'TSPU_RESTRICTED', domains: ['discord.media'], source: 'automatic', status: 'VERIFIED' }
    ]);
    expect(grouped).toHaveLength(1);
    expect(grouped[0].domains).toEqual(['discord.com', 'discord.gg', 'discord.media']);
    expect(grouped[0].sources).toEqual(['automatic', 'configured']);
    expect(grouped[0].applied).toBe(true);
  });

  it('keeps a discovery-only item explicitly unapplied', () => {
    const [observed] = groupServices([
      { id: 'UNKNOWN:example.com', category: 'DIRECT_PREFERRED', domains: ['example.com'], source: 'automatic', applied: false, status: 'SELECTED', confidence: 0.8 }
    ]);
    expect(observed.applied).toBe(false);
    expect(observed.sources).toEqual(['automatic']);
  });
});

describe('onboarding truthfulness', () => {
  it('does not mark sources complete merely because a route is verified', () => {
    const progress = onboardingProgress({ verifiedServers: 2, methodsStatus: 'pending', sourcesStatus: 'pending', servicesStatus: 'pending' });
    expect(progress.providerReady).toBe(true);
    expect(progress.methodsDone).toBe(false);
    expect(progress.sourcesDone).toBe(false);
    expect(progress.serviceChoiceDone).toBe(false);
    expect(progress.setupReady).toBe(false);
  });

  it('uses persisted backend statuses for skipped direct and automatic choices', () => {
    const progress = onboardingProgress({ methodsStatus: 'skipped', sourcesStatus: 'skipped', servicesStatus: 'automatic', canComplete: true });
    expect(progress.methodsDone).toBe(true);
    expect(progress.sourcesDone).toBe(true);
    expect(progress.serviceChoiceDone).toBe(true);
    expect(progress.setupReady).toBe(true);
  });

  it('does not treat an unknown persisted step status as complete', () => {
    const progress = onboardingProgress({ methodsStatus: 'corrupted', sourcesStatus: 'verified', servicesStatus: 'pending' });
    expect(progress.methodsDone).toBe(false);
    expect(progress.sourcesDone).toBe(false);
    expect(progress.serviceChoiceDone).toBe(false);
    expect(progress.setupReady).toBe(false);
  });

  it('does not infer the services step from an existing service list', () => {
    const progress = onboardingProgress({ serviceCount: 12, methodsStatus: 'skipped', sourcesStatus: 'skipped', servicesStatus: 'pending' });
    expect(progress.serviceChoiceDone).toBe(false);
  });

  it('uses the backend router gate and never treats simulation as ready', () => {
    expect(onboardingRouterReady({ router_ready: false }, { internet: 'ROUTE_AVAILABLE', dns: 'AVAILABLE' })).toBe(false);
    expect(onboardingRouterReady({ router_ready: true }, { internet: 'simulation', dns: 'simulation' })).toBe(true);
    expect(onboardingRouterReady({}, { internet: 'simulation', dns: 'simulation' })).toBe(false);
    expect(onboardingRouterReady({}, { internet: { status: 'ROUTE_AVAILABLE' }, dns: { state: 'AVAILABLE' } })).toBe(true);
  });
});

describe('recovery mutation fence', () => {
  it.each(['starting', 'error', 'recovery_required', '', 'unknown'])('blocks unsafe status %s', (status) => {
    expect(recoveryMutationAllowed({ recovery_status: status })).toBe(false);
  });

  it('allows only proven safe statuses', () => {
    expect(recoveryMutationAllowed({ recovery_status: 'ok' })).toBe(true);
    expect(recoveryMutationAllowed({ recovery: { status: 'not_required', revision_id: 'rev-1', candidate_hash: 'sha256:a' } })).toBe(true);
    expect(recoveryMutationAllowed({ recovery_status: 'not_required', active_revision: 'rev-1' })).toBe(false);
  });
});

describe('decision cards', () => {
  const event: EventItem = {
    id: 7,
    time: '2026-08-02T12:00:00Z',
    type: 'route.decision',
    severity: 'info',
    device_id: 'phone',
    service_id: 'YouTube',
    domain: 'youtube.com',
    route: 'zapret-primary',
    reason_code: 'path_verified',
    details: {
      device_name: 'Phone', device_ip: '192.0.*.*', category: 'TSPU_RESTRICTED', strategy: 'Zapret',
      fallback_path: ['zapret', 'vless', 'direct'], path_verified: true, http_status: 'HTTP 200 OK', decision_duration_ms: 43,
      classification_state: 'classified', probe_state: 'verified_candidate', policy_state: 'suggested'
    }
  };

  it('separates routing decisions from the administrative journal', () => {
    expect(isDecisionEvent(event)).toBe(true);
    expect(isAdministrativeEvent(event)).toBe(false);
    expect(isAdministrativeEvent({ ...event, type: 'system.change.prepared', domain: undefined, route: undefined, details: {} })).toBe(true);
  });

  it('creates a user-facing card with detailed evidence kept behind open', () => {
    const card = toDecisionCard({ ...event, details: { ...event.details, route_label: 'Direct (системный маршрут)' } });
    expect(card.device).toBe('Phone');
    expect(card.service).toBe('YouTube');
    expect(card.verified).toBe(true);
    expect(card.fallback).toBe(true);
    expect(card.durationMS).toBe(43);
    expect(card.classificationState).toBe('classified');
    expect(card.probeState).toBe('verified_candidate');
    expect(card.policyState).toBe('suggested');
    expect(card.route).toBe('Direct (системный маршрут)');
  });

  it('does not pass route latency off as total decision duration', () => {
    const card = toDecisionCard({ ...event, details: { route_latency_ms: 75, route_latency_available: true, path_verified: true } });
    expect(card.durationMS).toBeUndefined();
    expect(card.probeLatencyMS).toBe(75);
  });

  it('does not turn unavailable route latency into a zero millisecond measurement', () => {
    const card = toDecisionCard({ ...event, details: { route_latency_ms: 0, route_latency_available: false, verification_duration_ms: 3910 } });
    expect(card.routeLatencyAvailable).toBe(false);
    expect(card.routeLatencyMS).toBeUndefined();
    expect(card.verificationDurationMS).toBe(3910);
  });

  it('shows resolved observation classification instead of internal UNKNOWN id', () => {
    const card = toDecisionCard({
      ...event,
      service_id: undefined,
      details: { service: 'UNKNOWN:chess.com', service_name: 'chess.com', category: 'DIRECT_PREFERRED', classification: 'direct' }
    });
    expect(card.service).toBe('chess.com');
    expect(card.category).toBe('direct');
  });

  it('does not call an in-progress probe a terminal no-safe-route failure', () => {
    const card = toDecisionCard({
      ...event,
      details: { ...event.details, path_verified: false, probe_state: 'verifying', verification_state: 'in_progress', status: 'VERIFYING' }
    });
    expect(decisionVerificationPresentation(card)).toBe('checking');
    expect(verificationPresentationLabel(decisionVerificationPresentation(card))).toBe('Проверяется…');
  });

  it('keeps observe-only passive and reserves no-safe-route for terminal exhaustion', () => {
    const observed = toDecisionCard({
      ...event,
      details: { ...event.details, path_verified: false, probe_state: 'not_run_observe_only', policy_state: 'observed' }
    });
    expect(decisionVerificationPresentation(observed)).toBe('observed');

    const exhausted = toDecisionCard({
      ...event,
      details: { ...event.details, path_verified: false, probe_state: 'no_safe_route', verification_state: 'terminal_no_safe_route', status: 'NO_SAFE_ROUTE' }
    });
    expect(decisionVerificationPresentation(exhausted)).toBe('no_safe_route');
    expect(verificationPresentationLabel(decisionVerificationPresentation(exhausted))).toBe('Безопасный маршрут не найден');
  });
});
