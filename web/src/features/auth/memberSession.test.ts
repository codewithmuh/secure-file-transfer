import { afterEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import { csrfToken, currentMember, header, member, problem, setUpApi } from '@/test/apiHarness';
import { finishSignIn, restoreMemberSession, signOutMember, SIGN_IN_FAILED_PATH } from './memberSession';

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

  it('ignores a logout URL that is not https', async () => {
    const api = await setUpApi(() => ({ status: 200, data: { logout_url: 'javascript:alert(1)' } }));
    useAuthStore.getState().setAuth(member, token);

    await signOutMember();

    expect(api.location.assign).toHaveBeenCalledWith('/sign-in');
  });
});
