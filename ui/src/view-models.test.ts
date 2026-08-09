import { describe, expect, it } from 'vitest';
import { groupServices, humanStatus, isAdministrativeEvent, isDecisionEvent, parseResolverInput, stringArray, textValue, toDecisionCard } from './view-models';
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
  it('groups configured and discovered domains into one service', () => {
    const grouped = groupServices([
      { id: 'Discord', category: 'TSPU_RESTRICTED', domains: ['discord.com', 'discord.gg'], source: 'configured' },
      { id: 'Discord', category: 'TSPU_RESTRICTED', domains: ['discord.media'], source: 'automatic', status: 'VERIFIED' }
    ]);
    expect(grouped).toHaveLength(1);
    expect(grouped[0].domains).toEqual(['discord.com', 'discord.gg', 'discord.media']);
    expect(grouped[0].sources).toEqual(['automatic', 'configured']);
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
      fallback_path: ['zapret', 'vless', 'direct'], path_verified: true, http_status: 'HTTP 200 OK', decision_duration_ms: 43
    }
  };

  it('separates routing decisions from the administrative journal', () => {
    expect(isDecisionEvent(event)).toBe(true);
    expect(isAdministrativeEvent(event)).toBe(false);
    expect(isAdministrativeEvent({ ...event, type: 'system.change.prepared', domain: undefined, route: undefined, details: {} })).toBe(true);
  });

  it('creates a user-facing card with detailed evidence kept behind open', () => {
    const card = toDecisionCard(event);
    expect(card.device).toBe('Phone');
    expect(card.service).toBe('YouTube');
    expect(card.verified).toBe(true);
    expect(card.fallback).toBe(true);
    expect(card.durationMS).toBe(43);
  });
});
