import { afterEach, describe, expect, it, vi } from 'vitest';
import { setUpApi } from '@/test/apiHarness';
import {
  emailDomain,
  isStepUpMessage,
  STEP_UP_COMPLETE_PATH,
  STEP_UP_MESSAGE,
  stepUpOutcome,
  stepUpSignIn,
  stepUpSignInUrl,
} from './stepUp';

afterEach(() => {
  vi.unstubAllGlobals();
});

const own = 'https://app.example';

describe('stepUpSignIn (#232): sign in again the same way in as the session', () => {
  it('goes to the identity provider, with the address\'s domain only, for an SSO session', () => {
    expect(stepUpSignIn({ authMethod: 'sso', email: 'Aiko@Example.CO.JP' })).toEqual({ method: 'sso', domain: 'example.co.jp' });
  });

  it.each(['passkey', 'password_totp', 'local'] as const)('signs in locally for a %s session', (authMethod) => {
    expect(stepUpSignIn({ authMethod, email: 'aiko@example.co.jp' })).toEqual({ method: 'local' });
  });

  it('falls back to local when an SSO session has no usable domain, or there is no member', () => {
    expect(stepUpSignIn({ authMethod: 'sso', email: 'not-an-address' })).toEqual({ method: 'local' });
    expect(stepUpSignIn(null)).toEqual({ method: 'local' });
  });

  it('builds the sign-in start URL that comes back to the popup\'s page', async () => {
    await setUpApi(() => ({ status: 404 }));
    const url = new URL(stepUpSignInUrl({ authMethod: 'sso', email: 'aiko@example.co.jp' }, STEP_UP_COMPLETE_PATH), own);
    expect(url.pathname).toBe('/v1/auth/sign-in');
    expect(url.searchParams.get('method')).toBe('sso');
    expect(url.searchParams.get('sso_domain')).toBe('example.co.jp');
    expect(url.searchParams.get('return_to')).toBe(STEP_UP_COMPLETE_PATH);
    expect(url.search).not.toContain('aiko');
  });

  it('comes back to the page for a full-page sign-in when the popup is blocked', async () => {
    await setUpApi(() => ({ status: 404 }));
    const url = new URL(stepUpSignInUrl({ authMethod: 'passkey', email: 'aiko@example.co.jp' }, '/approvals/abc'), own);
    expect(url.searchParams.get('method')).toBe('local');
    expect(url.searchParams.get('sso_domain')).toBeNull();
    expect(url.searchParams.get('return_to')).toBe('/approvals/abc');
  });
});

describe('emailDomain', () => {
  it.each([
    ['aiko@example.co.jp', 'example.co.jp'],
    ['a@b@sub.example.com', 'sub.example.com'],
    ['@example.com', null],
    ['aiko@localhost', null],
    ['aiko@exa mple.com', null],
    ['', null],
  ])('%s gives %s', (email, domain) => {
    expect(emailDomain(email)).toBe(domain);
  });
});

describe('isStepUpMessage: only this app\'s own "done", nothing else', () => {
  it('accepts the popup\'s message from the same origin', () => {
    expect(isStepUpMessage({ origin: own, data: STEP_UP_MESSAGE }, own)).toBe(true);
  });

  it.each<[string, { origin: string; data: unknown }]>([
    ['another origin', { origin: 'https://evil.example', data: STEP_UP_MESSAGE }],
    ['the API origin', { origin: 'https://api.example', data: STEP_UP_MESSAGE }],
    ['another type', { origin: own, data: { type: 'sft:something-else' } }],
    ['a bare string', { origin: own, data: 'sft:step-up-complete' }],
    ['no data', { origin: own, data: null }],
  ])('ignores a message from %s', (_, event) => {
    expect(isStepUpMessage(event, own)).toBe(false);
  });
});

describe('stepUpOutcome: retry only for the same member', () => {
  it('retries when the same member signed in again', () => {
    expect(stepUpOutcome({ id: 'u1' }, { id: 'u1' })).toBe('retry');
  });

  it('never retries as someone else', () => {
    expect(stepUpOutcome({ id: 'u1' }, { id: 'u2' })).toBe('other_member');
    expect(stepUpOutcome(null, { id: 'u2' })).toBe('other_member');
  });

  it('fails when the new session couldn\'t be loaded', () => {
    expect(stepUpOutcome({ id: 'u1' }, null)).toBe('failed');
  });
});
