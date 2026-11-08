import { afterEach, describe, expect, it, vi } from 'vitest';
import { renderToString } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import '@/lib/i18n';
import { resources } from '@/lib/i18n';
import { setUpApi } from '@/test/apiHarness';
import { SignInPage } from './SignInPage';
import { returnPathOf } from './returnPath';

const en = resources.en.translation.auth;

function render(path = '/sign-in') {
  return renderToString(
    <MemoryRouter initialEntries={[path]}>
      <SignInPage />
    </MemoryRouter>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('SignInPage: the SSO button follows config.ssoSignIn (#195)', () => {
  it('offers only the password sign-in, as the primary action, while SSO is off', async () => {
    await setUpApi(() => ({ status: 404 }), '/sign-in', { ssoSignIn: false });
    const html = render();
    expect(html).not.toContain(en.continueWithSso);
    expect(html).toContain(en.signInWithPassword);
    expect(html).toContain('btn-primary');
    expect(html).not.toContain('type="email"');
  });

  it('offers SSO first, then the password sign-in, once SSO is on (M6)', async () => {
    await setUpApi(() => ({ status: 404 }), '/sign-in', { ssoSignIn: true });
    const html = render();
    expect(html).toContain(en.continueWithSso);
    expect(html).toContain('type="email"');
    expect(html.indexOf(en.continueWithSso)).toBeLessThan(html.indexOf(en.signInWithPassword));
  });

  it('says a failed sign-in failed, naming no reason', async () => {
    await setUpApi(() => ({ status: 404 }));
    expect(render('/sign-in?error=sign_in_failed')).toContain(en.signInFailed);
    expect(render('/sign-in')).not.toContain(en.signInFailed);
  });
});

describe('returnPathOf: the deep link ProtectedRoute came from', () => {
  it('reads the path and query of the location in the router state', () => {
    expect(returnPathOf({ from: { pathname: '/transfers/abc', search: '?x=1', hash: '' } })).toBe('/transfers/abc?x=1');
    expect(returnPathOf({ from: { pathname: '/admin/users' } })).toBe('/admin/users');
  });

  it('is null for any other state', () => {
    for (const state of [null, undefined, 'x', {}, { from: null }, { from: { pathname: 3 } }]) {
      expect(returnPathOf(state)).toBeNull();
    }
  });
});
