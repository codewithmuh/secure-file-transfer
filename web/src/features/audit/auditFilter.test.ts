import { describe, expect, it } from 'vitest';
import {
  detailRows,
  EMPTY_FILTER,
  exportFileName,
  filterBody,
  filterProblems,
  isIpAddress,
  KNOWN_ACTIONS,
  localToIso,
  MAX_ACTIONS,
  toggleAction,
} from './auditFilter';

const id = '0190c0de-0000-7000-8000-000000000010';

describe('the audit filter (#216)', () => {
  it('sends no filter when nothing is filled in', () => {
    expect(filterBody(EMPTY_FILTER)).toBeUndefined();
    expect(filterProblems(EMPTY_FILTER)).toEqual([]);
  });

  it('sends only the fields filled in, trimmed, in the contract\'s names (UC-4)', () => {
    const body = filterBody({
      ...EMPTY_FILTER,
      email: ' tanaka@example.co.jp ',
      actions: ['download.granted', 'download.granted'],
      targetType: 'transfer',
      targetId: id.toUpperCase(),
      sourceIp: '198.51.100.5',
      actorType: 'recipient',
    });
    expect(body).toEqual({
      email: 'tanaka@example.co.jp',
      actions: ['download.granted'],
      target_type: 'transfer',
      target_id: id,
      source_ip: '198.51.100.5',
      actor_type: 'recipient',
    });
  });

  it('turns local date and time into RFC 3339 and needs the end after the start', () => {
    expect(localToIso('2026-11-08T09:30')).toBe(new Date('2026-11-08T09:30').toISOString());
    expect(localToIso('8 Nov')).toBeNull();
    const form = { ...EMPTY_FILTER, from: '2026-11-08T10:00', to: '2026-11-08T09:00' };
    expect(filterProblems(form)).toEqual(['to']);
    expect(filterBody({ ...form, to: '2026-11-09T00:00' })).toEqual({
      occurred_after: new Date('2026-11-08T10:00').toISOString(),
      occurred_before: new Date('2026-11-09T00:00').toISOString(),
    });
  });

  it('checks IDs, the address, the IP, the target type and at most 20 actions', () => {
    const many = Array.from({ length: MAX_ACTIONS + 1 }, (_, i) => `x.a${i}`);
    expect(
      filterProblems({
        ...EMPTY_FILTER,
        actorId: 'nope',
        email: 'not-an-address',
        sourceIp: '300.1.1.1',
        targetType: 'Transfer!',
        targetId: '123',
        actions: many,
      }),
    ).toEqual(['actorId', 'email', 'actions', 'targetType', 'targetId', 'sourceIp']);
  });

  it('accepts IPv4 and IPv6 addresses only', () => {
    for (const ip of ['192.0.2.1', '2001:db8::1', '::1', 'fe80::1:2']) expect(isIpAddress(ip), ip).toBe(true);
    for (const ip of ['192.0.2', '1.2.3.256', 'example.com', '2001:db8::g', ':::']) expect(isIpAddress(ip), ip).toBe(false);
  });

  it('toggles actions, and offers only dotted action codes', () => {
    expect(toggleAction(['a.b'], 'c.d')).toEqual(['a.b', 'c.d']);
    expect(toggleAction(['a.b', 'c.d'], 'a.b')).toEqual(['c.d']);
    for (const action of Object.values(KNOWN_ACTIONS).flat()) expect(action).toMatch(/^[a-z_]+\.[a-z_]+$/);
  });
});

describe('the export\'s file name (#216)', () => {
  const now = new Date('2026-11-08T12:00:00Z');

  it('reads filename and filename* from Content-Disposition', () => {
    expect(exportFileName('attachment; filename="audit-2026-11-08.csv"', 'csv', now)).toBe('audit-2026-11-08.csv');
    expect(exportFileName('attachment; filename=audit.json', 'json', now)).toBe('audit.json');
    expect(exportFileName(`attachment; filename="a.csv"; filename*=UTF-8''%E7%9B%A3%E6%9F%BB.csv`, 'csv', now)).toBe('監査.csv');
  });

  it('falls back to a dated name, and never keeps a path', () => {
    expect(exportFileName(null, 'csv', now)).toBe('audit-events-2026-11-08.csv');
    expect(exportFileName('attachment', 'json', now)).toBe('audit-events-2026-11-08.json');
    expect(exportFileName('attachment; filename="../../etc/passwd"', 'csv', now)).toBe('passwd');
    expect(exportFileName('attachment; filename=".."', 'csv', now)).toBe('audit-events-2026-11-08.csv');
  });
});

describe('an event\'s details (#216)', () => {
  it('lists details sorted by key, nested values as JSON', () => {
    expect(detailRows({ b: 2, a: 'x', c: { d: [1] }, e: null })).toEqual([
      ['a', 'x'],
      ['b', '2'],
      ['c', '{"d":[1]}'],
      ['e', 'null'],
    ]);
  });
});
