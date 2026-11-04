import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiClient } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { csrfToken, header, member, problem, setUpApi } from '@/test/apiHarness';

const memberToken = csrfToken('member');
const linkToken = csrfToken('link');
const linkSessionId = '0190c0de-0000-7000-8000-0000000000bb';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('apiClient credentials: member and link sessions stay apart (#73 defect 2)', () => {
  it('sends the member CSRF token on member writes while a link session is open', async () => {
    const api = await setUpApi(() => ({ status: 201, data: {} }));
    useAuthStore.getState().setAuth(member, memberToken);
    useAuthStore.getState().setLinkSession(linkSessionId, linkToken);

    await apiClient.post('/transfers', {});

    expect(header(api.sent[0], 'X-CSRF-Token')).toBe(memberToken);
    expect(header(api.sent[0], 'X-Link-Session')).toBeUndefined();
  });

  it('sends the member CSRF token again after the link session is cleared', async () => {
    const api = await setUpApi(() => ({ status: 201, data: {} }));
    useAuthStore.getState().setAuth(member, memberToken);
    useAuthStore.getState().setLinkSession(linkSessionId, linkToken);
    useAuthStore.getState().clearLinkSession();

    await apiClient.delete('/api-keys/abc');

    expect(header(api.sent[0], 'X-CSRF-Token')).toBe(memberToken);
  });

  it('sends the link session ID and its own CSRF token only on /session routes', async () => {
    const api = await setUpApi(() => ({ status: 200, data: {} }));
    useAuthStore.getState().setAuth(member, memberToken);
    useAuthStore.getState().setLinkSession(linkSessionId, linkToken);

    await apiClient.get('/session');
    await apiClient.post('/session/files', {});

    expect(header(api.sent[0], 'X-Link-Session')).toBe(linkSessionId);
    expect(header(api.sent[0], 'X-CSRF-Token')).toBeUndefined();
    expect(header(api.sent[1], 'X-Link-Session')).toBe(linkSessionId);
    expect(header(api.sent[1], 'X-CSRF-Token')).toBe(linkToken);
  });

  it('sends no session credentials to public routes or other origins', async () => {
    const api = await setUpApi(() => ({ status: 200, data: {} }));
    useAuthStore.getState().setAuth(member, memberToken);
    useAuthStore.getState().setLinkSession(linkSessionId, linkToken);

    await apiClient.post('/links/resolve', { token: 'x' });
    await apiClient.put('https://uploads.example/part-1', 'bytes');

    for (const config of api.sent) {
      expect(header(config, 'X-CSRF-Token')).toBeUndefined();
      expect(header(config, 'X-Link-Session')).toBeUndefined();
    }
  });
});

describe('apiClient 401 handling: who gets sent where (#73 defect 3)', () => {
  it('sends a recipient whose link session lapsed back to verification, not to member sign-in', async () => {
    const api = await setUpApi(
      (config) => (config.url === '/session' ? problem(401, 'authentication_required') : { status: 201, data: {} }),
      '/t',
    );
    useAuthStore.getState().setAuth(member, memberToken);
    useAuthStore.getState().setLinkSession(linkSessionId, linkToken);

    await expect(apiClient.get('/session')).rejects.toMatchObject({ response: { status: 401 } });

    // The page stays on the link; nothing navigates to the member sign-in page.
    expect(api.location.href).toBe('https://app.example/t');
    expect(api.location.assign).not.toHaveBeenCalled();
    // The member, signed in elsewhere in this browser, keeps their session and CSRF token.
    await apiClient.post('/transfers', {});
    expect(header(api.sent[1], 'X-CSRF-Token')).toBe(memberToken);

    const state = useAuthStore.getState();
    expect(state.memberStatus).toBe('authenticated');
    expect(state.linkSession).toBeNull();
    expect(state.linkSessionLapsed).toBe(true);
  });

  it('treats session_expired on a /session route the same way', async () => {
    const api = await setUpApi(() => problem(401, 'session_expired'), '/u');
    useAuthStore.getState().setLinkSession(linkSessionId, linkToken);

    await expect(apiClient.post('/session/files', {})).rejects.toBeTruthy();

    expect(api.location.href).toBe('https://app.example/u');
    expect(api.location.assign).not.toHaveBeenCalled();
    expect(useAuthStore.getState().linkSessionLapsed).toBe(true);
  });

  it('keeps a newer link session when a stale request for an older one fails', async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered: () => void = () => undefined;
    const inFlight = new Promise<void>((resolve) => {
      entered = resolve;
    });
    await setUpApi(() => problem(401, 'session_expired'), '/t');
    const answer = apiClient.defaults.adapter as (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>;
    apiClient.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
      entered();
      await gate;
      return answer(config);
    };
    useAuthStore.getState().setLinkSession('old-session', linkToken);

    const stale = apiClient.get('/session');
    await inFlight;
    useAuthStore.getState().setLinkSession('new-session', csrfToken('newer'));
    release();
    await expect(stale).rejects.toBeTruthy();

    expect(useAuthStore.getState().linkSession?.id).toBe('new-session');
  });

  it('signs a member out and sends them to /sign-in on a member 401, leaving any link session alone', async () => {
    const api = await setUpApi(() => problem(401, 'authentication_required'), '/transfers');
    useAuthStore.getState().setAuth(member, memberToken);
    useAuthStore.getState().setLinkSession(linkSessionId, linkToken);

    await expect(apiClient.get('/transfers')).rejects.toBeTruthy();

    const state = useAuthStore.getState();
    expect(state.memberStatus).toBe('anonymous');
    expect(state.memberCsrfToken).toBeNull();
    expect(state.linkSession?.id).toBe(linkSessionId);
    expect(api.location.assign).toHaveBeenCalledWith('/sign-in');
  });

  it('does not sign a member out when the API asks for step-up', async () => {
    const api = await setUpApi(() => problem(401, 'reauthentication_required'), '/admin/users');
    useAuthStore.getState().setAuth(member, memberToken);

    await expect(apiClient.post('/users', {})).rejects.toBeTruthy();

    expect(useAuthStore.getState().memberStatus).toBe('authenticated');
    expect(api.location.assign).not.toHaveBeenCalled();
  });
});
