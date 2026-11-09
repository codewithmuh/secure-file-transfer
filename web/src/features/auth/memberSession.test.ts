import { afterEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import { csrfToken, currentMember, header, member, problem, setUpApi } from '@/test/apiHarness';
import {
  finishSignIn,
  isLogoutUrl,
  refreshMemberSession,
  restoreMemberSession,
  signInUrl,
  signOutMember,
  SIGN_IN_FAILED_PATH,
} from './memberSession';

const token = csrfToken('member');

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('restoreMemberSession: a refresh keeps the member signed in (#73 defect 1)', () => {
  it('restores the member and their CSRF token from GET /me on a fresh page load', async () => {
    const api = await setUpApi((config) =>
      config.url === '/me' ? { status: 200, data: currentMember(token, 'admin') } : { status: 404 },
    );
    expect(useAuthStore.getState().memberStatus).toBe('unknown');

    await expect(restoreMemberSession()).resolves.toBe(true);

    const state = useAuthStore.getState();
    expect(state.memberStatus).toBe('authenticated');
    expect(state.user).toEqual({ ...member, role: 'admin' });
    expect(state.memberCsrfToken).toBe(token);
    expect(api.sent.map((c) => `${c.method} ${c.url}`)).toEqual(['get /me']);
  });

  it('shows the check as in progress until GET /me answers, and shares one request', async () => {
    const api = await setUpApi(() => ({ status: 200, data: currentMember(token) }));

    const first = restoreMemberSession();
    const second = restoreMemberSession();
    expect(useAuthStore.getState().memberStatus).toBe('checking');
    await Promise.all([first, second]);

    expect(api.sent).toHaveLength(1);
    expect(useAuthStore.getState().memberStatus).toBe('authenticated');
  });

  it('marks the tab signed out on 401 without a full-page redirect, so the router keeps the deep link', async () => {
    const api = await setUpApi(() => problem(401, 'authentication_required'), '/transfers/abc');

    await expect(restoreMemberSession()).resolves.toBe(false);

    expect(useAuthStore.getState().memberStatus).toBe('anonymous');
    expect(api.location.assign).not.toHaveBeenCalled();
  });

  it('fails closed when GET /me answers something that is not a CurrentMember', async () => {
    await setUpApi(() => ({ status: 200, data: { user: { id: 'x' }, csrf_token: 'not-a-token' } }));

    await expect(restoreMemberSession()).resolves.toBe(false);

    expect(useAuthStore.getState().memberStatus).toBe('anonymous');
    expect(useAuthStore.getState().memberCsrfToken).toBeNull();
  });

  it('never writes the session or the CSRF token to browser storage', async () => {
    const storage = { setItem: vi.fn(), getItem: vi.fn(), removeItem: vi.fn(), clear: vi.fn() };
    vi.stubGlobal('localStorage', storage);
    vi.stubGlobal('sessionStorage', storage);
    await setUpApi(() => ({ status: 200, data: currentMember(token) }));

    await restoreMemberSession();

    expect(storage.setItem).not.toHaveBeenCalled();
  });
});

describe('refreshMemberSession: the new session after a step-up sign-in in a popup (#232)', () => {
  it('loads the new CSRF token without the page going back to "checking", so its form stays mounted', async () => {
    const newer = csrfToken('newer');
    await setUpApi(() => ({ status: 200, data: currentMember(newer, 'admin') }));
    useAuthStore.getState().setAuth({ ...member, role: 'admin' }, token);
    const statuses: string[] = [];
    const stop = useAuthStore.subscribe((state) => statuses.push(state.memberStatus));

    const refreshed = await refreshMemberSession();
    stop();

    expect(refreshed).toEqual({ ...member, role: 'admin' });
    expect(useAuthStore.getState().memberCsrfToken).toBe(newer);
    expect(statuses).not.toContain('checking');
  });

  it('keeps how the session signed in, for the next step-up', async () => {
    const body = currentMember(token);
    body.session.auth_method = 'sso';
    await setUpApi(() => ({ status: 200, data: body }));

    await expect(refreshMemberSession()).resolves.toMatchObject({ authMethod: 'sso' });
  });

  it('resolves null and leaves the store as it was when the API can\'t answer', async () => {
    await setUpApi(() => problem(503, 'service_unavailable'));
    useAuthStore.getState().setAuth(member, token);

    await expect(refreshMemberSession()).resolves.toBeNull();
    expect(useAuthStore.getState().memberStatus).toBe('authenticated');
  });
});

describe('finishSignIn: the /auth/callback page', () => {
  it('loads the new session, then goes to the checked return path', async () => {
    await setUpApi(() => ({ status: 200, data: currentMember(token) }));

    await expect(finishSignIn(new URLSearchParams('return_path=/transfers/new'))).resolves.toBe('/transfers/new');
    expect(useAuthStore.getState().memberStatus).toBe('authenticated');
  });

  it('sends a crafted return path to the dashboard instead (#73 defect 4)', async () => {
    await setUpApi(() => ({ status: 200, data: currentMember(token) }));

    await expect(finishSignIn(new URLSearchParams('return_path=%2F%2Fevil.example'))).resolves.toBe('/');
  });

  it('goes to the sign-in error page when sign-in failed or no session came back', async () => {
    const api = await setUpApi(() => problem(401, 'authentication_required'));

    await expect(finishSignIn(new URLSearchParams('error=sign_in_failed'))).resolves.toBe(SIGN_IN_FAILED_PATH);
    expect(api.sent).toHaveLength(0);
    await expect(finishSignIn(new URLSearchParams('return_path=/transfers'))).resolves.toBe(SIGN_IN_FAILED_PATH);
  });
});

describe('signOutMember: with the session restored on load, sign-out must end it at the API', () => {
  it('posts signOut with the member CSRF token, clears the store and goes to the logout URL', async () => {
    const logoutUrl = 'https://auth.example.com/logout?client_id=abc';
    const api = await setUpApi(() => ({ status: 200, data: { logout_url: logoutUrl } }), '/transfers');
    useAuthStore.getState().setAuth(member, token);

    await signOutMember();

    expect(api.sent[0]?.url).toBe('/auth/sign-out');
    expect(api.sent[0]?.data).toBe(JSON.stringify({ all_sessions: false })); // only this session (SignOutRequest)
    expect(header(api.sent[0], 'X-CSRF-Token')).toBe(token);
    expect(useAuthStore.getState().memberStatus).toBe('anonymous');
    expect(api.location.assign).toHaveBeenCalledWith(logoutUrl);
  });

  it('treats 401 session_expired as already signed out', async () => {
    const api = await setUpApi(() => problem(401, 'session_expired'));
    useAuthStore.getState().setAuth(member, token);

    await signOutMember();

    expect(useAuthStore.getState().memberStatus).toBe('anonymous');
    expect(api.location.assign).toHaveBeenCalledWith('/sign-in');
  });

  it('keeps the member signed in and reports the error when the API could not end the session', async () => {
    const api = await setUpApi(() => problem(503, 'service_unavailable'));
    useAuthStore.getState().setAuth(member, token);

    await expect(signOutMember()).rejects.toBeTruthy();

    expect(useAuthStore.getState().memberStatus).toBe('authenticated');
    expect(api.location.assign).not.toHaveBeenCalled();
  });

  it.each([
    'javascript:alert(1)',
    'http://auth.example.com/logout',
    'https://evil.example/logout',
    'https://auth.example.com.evil.example/logout',
    'data:text/html,hi',
    'not a url',
  ])(
    'ignores a logout URL that is not on the sign-in origin: %s',
    async (logoutUrl) => {
      const api = await setUpApi(() => ({ status: 200, data: { logout_url: logoutUrl } }));
      useAuthStore.getState().setAuth(member, token);

      await signOutMember();

      expect(api.location.assign).toHaveBeenCalledWith('/sign-in');
    },
  );
});

describe('signOutMember in the local stack: Keycloak is the sign-in origin (#195)', () => {
  it('follows the http logout URL of the configured sign-in origin', async () => {
    const logoutUrl = 'http://localhost:8180/realms/sft/protocol/openid-connect/logout';
    const api = await setUpApi(() => ({ status: 200, data: { logout_url: logoutUrl } }), '/', {
      apiOrigin: 'http://localhost:8000/v1',
      signInOrigin: 'http://localhost:8180',
    });
    useAuthStore.getState().setAuth(member, token);

    await signOutMember();

    expect(api.location.assign).toHaveBeenCalledWith(logoutUrl);
  });

  it('refuses another port, scheme or host than the sign-in origin', async () => {
    await setUpApi(() => ({ status: 404 }), '/', { signInOrigin: 'http://localhost:8180' });
    expect(isLogoutUrl('http://localhost:8180/realms/sft/protocol/openid-connect/logout')).toBe(true);
    expect(isLogoutUrl('http://localhost:8181/logout')).toBe(false);
    expect(isLogoutUrl('https://localhost:8180/logout')).toBe(false);
    expect(isLogoutUrl('http://127.0.0.1:8180/logout')).toBe(false);
    expect(isLogoutUrl('javascript://localhost:8180/%0aalert(1)')).toBe(false);
  });
});

describe('signInUrl: startSignIn on the API origin, with return_to (#195)', () => {
  it('uses the config\'s apiOrigin and the contract\'s return_to, checked', async () => {
    await setUpApi(() => ({ status: 404 }), '/', { apiOrigin: 'http://localhost:8000/v1' });
    expect(signInUrl('local', '/transfers/0190c0de-0000-7000-8000-000000000001')).toBe(
      'http://localhost:8000/v1/auth/sign-in?method=local&return_to=%2Ftransfers%2F0190c0de-0000-7000-8000-000000000001',
    );
    // A crafted path goes to the dashboard instead; the API checks it again.
    expect(signInUrl('local', '//evil.example')).toBe('http://localhost:8000/v1/auth/sign-in?method=local&return_to=%2F');
    expect(signInUrl('local', null)).toContain('return_to=%2F');
  });

  it('stays relative behind the dev server\'s proxy, and sends only the domain for SSO', async () => {
    await setUpApi(() => ({ status: 404 }));
    expect(signInUrl('sso', '/admin/users', 'example.co.jp')).toBe(
      '/v1/auth/sign-in?method=sso&sso_domain=example.co.jp&return_to=%2Fadmin%2Fusers',
    );
    expect(signInUrl('local', '/')).not.toContain('return_path');
  });
});
