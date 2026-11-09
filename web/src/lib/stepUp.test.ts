import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiClient } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { csrfToken, header, member, problem, setUpApi } from '@/test/apiHarness';
import { needsStepUp, setStepUpHandler, type FailedRequest } from './stepUp';

const oldToken = csrfToken('old');
const newToken = csrfToken('new');

let unmount: (() => void) | null = null;

/** Mounts a step-up handler that signs in again (a new CSRF token) and answers `ok`, counting its calls. */
function mountHandler(ok = true) {
  const handler = vi.fn(async () => {
    if (ok) useAuthStore.getState().setAuth(member, newToken);
    return ok;
  });
  unmount = setStepUpHandler(handler);
  return handler;
}

afterEach(() => {
  unmount?.();
  unmount = null;
  vi.unstubAllGlobals();
});

describe('needsStepUp (#232): only a member request answering 401 reauthentication_required, once', () => {
  const base: FailedRequest = { status: 401, code: 'reauthentication_required', scope: 'member' };

  it('asks for a step-up for a member request the API wants a recent sign-in for', () => {
    expect(needsStepUp(base)).toBe(true);
  });

  it.each<[string, Partial<FailedRequest>]>([
    ['another 401 code', { code: 'session_expired' }],
    ['a 403 passkey_required', { status: 403, code: 'passkey_required' }],
    ['a link-session request', { scope: 'link' }],
    ['a public request', { scope: 'public' }],
    ['the retry itself', { stepUpRetried: true }],
    ['a request that opted out', { skipStepUp: true }],
  ])('never for %s', (_, change) => {
    expect(needsStepUp({ ...base, ...change })).toBe(false);
  });
});

describe('the step-up interceptor: re-authenticate, then retry once', () => {
  it('sends the same request again, once, with the new session\'s CSRF token', async () => {
    let calls = 0;
    const api = await setUpApi(() => {
      calls += 1;
      return calls === 1 ? problem(401, 'reauthentication_required') : { status: 201, data: { id: 'u1' } };
    }, '/admin/users');
    useAuthStore.getState().setAuth(member, oldToken);
    const handler = mountHandler();

    const response = await apiClient.post('/users', { email: 'tanaka@example.co.jp', role: 'member' });

    expect(response.data).toEqual({ id: 'u1' });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(api.sent).toHaveLength(2);
    expect(header(api.sent[0], 'X-CSRF-Token')).toBe(oldToken);
    expect(header(api.sent[1], 'X-CSRF-Token')).toBe(newToken);
    expect(api.sent[1]?.url).toBe('/users');
    expect(api.sent[1]?.method).toBe('post');
    // The body goes again as it was, not encoded twice.
    expect(JSON.parse(api.sent[1]?.data as string)).toEqual({ email: 'tanaka@example.co.jp', role: 'member' });
  });

  it('keeps headers such as Idempotency-Key on the retry', async () => {
    let calls = 0;
    const api = await setUpApi(() => {
      calls += 1;
      return calls === 1 ? problem(401, 'reauthentication_required') : { status: 201, data: {} };
    });
    useAuthStore.getState().setAuth(member, oldToken);
    mountHandler();

    await apiClient.post('/dlp/rules', {}, { headers: { 'Idempotency-Key': 'key-1' } });

    expect(header(api.sent[1], 'Idempotency-Key')).toBe('key-1');
  });

  it('never retries twice: a second reauthentication_required goes to the page', async () => {
    const api = await setUpApi(() => problem(401, 'reauthentication_required'));
    useAuthStore.getState().setAuth(member, oldToken);
    const handler = mountHandler();

    await expect(apiClient.post('/users', {})).rejects.toMatchObject({ response: { status: 401 } });

    expect(handler).toHaveBeenCalledTimes(1);
    expect(api.sent).toHaveLength(2);
  });

  it('sends nothing again when the member cancels', async () => {
    const api = await setUpApi(() => problem(401, 'reauthentication_required'));
    useAuthStore.getState().setAuth(member, oldToken);
    const handler = mountHandler(false);

    await expect(apiClient.patch('/tenant/policy', {})).rejects.toMatchObject({ response: { status: 401 } });

    expect(handler).toHaveBeenCalledTimes(1);
    expect(api.sent).toHaveLength(1);
  });

  it('passes the error on when no dialog is mounted', async () => {
    const api = await setUpApi(() => problem(401, 'reauthentication_required'));
    useAuthStore.getState().setAuth(member, oldToken);

    await expect(apiClient.post('/api-keys', {})).rejects.toMatchObject({ response: { status: 401 } });

    expect(api.sent).toHaveLength(1);
    expect(useAuthStore.getState().memberStatus).toBe('authenticated');
  });

  it('asks once for requests that fail together, and retries each', async () => {
    const seen = new Map<string, number>();
    const api = await setUpApi((config) => {
      const count = (seen.get(config.url ?? '') ?? 0) + 1;
      seen.set(config.url ?? '', count);
      return count === 1 ? problem(401, 'reauthentication_required') : { status: 200, data: {} };
    });
    useAuthStore.getState().setAuth(member, oldToken);
    const handler = mountHandler();

    await Promise.all([apiClient.post('/users', {}), apiClient.patch('/tenant/sso', {})]);

    expect(handler).toHaveBeenCalledTimes(1);
    expect(api.sent).toHaveLength(4);
  });

  it('never steps up a link-session request', async () => {
    const api = await setUpApi(() => problem(401, 'reauthentication_required'));
    const handler = mountHandler();

    await expect(apiClient.post('/session/downloads', {})).rejects.toBeTruthy();

    expect(handler).not.toHaveBeenCalled();
    expect(api.sent).toHaveLength(1);
  });

  it('reads the problem of a blob request (the audit export) and retries it', async () => {
    let calls = 0;
    const body = { type: 'about:blank', title: 'x', status: 401, code: 'reauthentication_required' };
    const api = await setUpApi(() => {
      calls += 1;
      return calls === 1
        ? { status: 401, data: new Blob([JSON.stringify(body)], { type: 'application/problem+json' }) }
        : { status: 200, data: new Blob(['a,b']) };
    });
    useAuthStore.getState().setAuth(member, oldToken);
    const handler = mountHandler();

    const response = await apiClient.post('/audit/exports', { format: 'csv' }, { responseType: 'blob' });

    expect(handler).toHaveBeenCalledTimes(1);
    expect(response.status).toBe(200);
    expect(api.sent).toHaveLength(2);
  });

  it('leaves other errors alone', async () => {
    const api = await setUpApi(() => problem(403, 'passkey_required'));
    useAuthStore.getState().setAuth(member, oldToken);
    const handler = mountHandler();

    await expect(apiClient.post('/users', {})).rejects.toMatchObject({ response: { status: 403 } });

    expect(handler).not.toHaveBeenCalled();
    expect(api.sent).toHaveLength(1);
  });
});
