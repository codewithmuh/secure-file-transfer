import { describe, expect, it } from 'vitest';
import type { ApiKey } from '@/api';
import {
  activeKeysOf,
  createBody,
  DEFAULT_KEY_DAYS,
  EMPTY_KEY_FORM,
  keyFormProblems,
  keyStatus,
  mayClose,
  secretStep,
  toggleScope,
  type SecretStep,
} from './apiKeys';

const owner = '0190c0de-0000-7000-8000-000000000001';
const other = '0190c0de-0000-7000-8000-000000000002';
const now = new Date('2026-11-08T00:00:00Z');

const key = (id: string, createdBy: string, extra: Partial<ApiKey> = {}): ApiKey => ({
  id,
  name: `key ${id}`,
  key_prefix: 'sft_dev_abcdefgh',
  scopes: ['transfers:read'],
  created_by: createdBy,
  created_at: '2026-10-01T00:00:00Z',
  expires_at: '2027-01-01T00:00:00Z',
  last_used_at: null,
  revoked_at: null,
  ...extra,
});

describe('the create dialog (#215)', () => {
  it('needs a name of 1 to 100 characters and a scope', () => {
    expect(keyFormProblems(EMPTY_KEY_FORM)).toEqual(['name', 'scopes']);
    expect(keyFormProblems({ ...EMPTY_KEY_FORM, name: '  ', scopes: ['audit:read'] })).toEqual(['name']);
    expect(keyFormProblems({ ...EMPTY_KEY_FORM, name: 'x'.repeat(101), scopes: ['audit:read'] })).toEqual(['name']);
    expect(keyFormProblems({ name: 'CI', scopes: ['audit:read'], days: 366 })).toEqual(['days']);
    expect(keyFormProblems({ name: 'CI', scopes: ['audit:read'], days: 365 })).toEqual([]);
  });

  it('leaves the 90-day default to the service, and sends any other expiry from now', () => {
    expect(createBody({ name: ' CI ', scopes: ['audit:read'], days: DEFAULT_KEY_DAYS }, now)).toEqual({
      name: 'CI',
      scopes: ['audit:read'],
    });
    expect(createBody({ name: 'CI', scopes: ['audit:read'], days: 30 }, now).expires_at).toBe('2026-12-08T00:00:00.000Z');
  });

  it('sends scopes in the contract\'s order, whatever order they were ticked in', () => {
    let scopes = toggleScope([], 'audit:read');
    scopes = toggleScope(scopes, 'transfers:write');
    expect(createBody({ name: 'CI', scopes, days: 90 }).scopes).toEqual(['transfers:write', 'audit:read']);
    expect(toggleScope(scopes, 'audit:read')).toEqual(['transfers:write']);
  });

  it('shows the secret once and closes only once the admin says they stored it', () => {
    let state: SecretStep = { step: 'form' };
    expect(mayClose(state)).toBe(true);
    // A stray "stored" before a key exists changes nothing.
    expect(secretStep(state, { type: 'stored', value: true })).toEqual(state);
    const secret = ['sft', 'dev', 'not-a-real-key'].join('_');
    state = secretStep(state, { type: 'created', key: key('1', owner), secret });
    expect(state).toMatchObject({ step: 'created', secret, stored: false });
    expect(mayClose(state)).toBe(false);
    state = secretStep(state, { type: 'stored', value: true });
    expect(mayClose(state)).toBe(true);
    state = secretStep(state, { type: 'reset' });
    expect(state).toEqual({ step: 'form' });
    expect(JSON.stringify(state)).not.toContain(secret);
  });
});

describe('key status and ownership (authn-authz 5.2)', () => {
  it('is revoked, expired or active', () => {
    expect(keyStatus(key('1', owner), now)).toBe('active');
    expect(keyStatus(key('1', owner, { expires_at: '2026-11-07T00:00:00Z' }), now)).toBe('expired');
    expect(keyStatus(key('1', owner, { revoked_at: '2026-11-01T00:00:00Z', expires_at: '2026-11-07T00:00:00Z' }), now)).toBe(
      'revoked',
    );
  });

  it('lists only the keys the user owns that still work', () => {
    const keys = [
      key('1', owner),
      key('2', other),
      key('3', owner, { revoked_at: '2026-11-01T00:00:00Z' }),
      key('4', owner, { expires_at: '2026-11-01T00:00:00Z' }),
    ];
    expect(activeKeysOf(keys, owner, now).map((k) => k.id)).toEqual(['1']);
    expect(activeKeysOf(keys, '0190c0de-0000-7000-8000-000000000009', now)).toEqual([]);
  });
});
