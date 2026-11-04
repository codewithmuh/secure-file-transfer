import { afterEach, describe, expect, expectTypeOf, it, vi } from 'vitest';
import { apiClient } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { csrfToken, header, member, setUpApi } from '@/test/apiHarness';
import { api, fillPath, type PathsWith, type Schema } from './client';

const memberToken = csrfToken('member');
const linkToken = csrfToken('link');
const linkSessionId = '0190c0de-0000-7000-8000-0000000000bb';
const transferId = '0190c0de-0000-7000-8000-000000000010';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('api: requests built from the contract', () => {
  it('fills path parameters, percent-encoded', async () => {
    const harness = await setUpApi(() => ({ status: 200, data: {} }));

    await api.get('/transfers/{transfer_id}', { path: { transfer_id: transferId } });
    await api.get('/users/{user_id}', { path: { user_id: 'a b/c' } });

    expect(harness.sent.map((c) => c.url)).toEqual([`/transfers/${transferId}`, '/users/a%20b%2Fc']);
  });

  it('refuses a missing, empty or dot-segment path parameter before sending anything', async () => {
    const harness = await setUpApi(() => ({ status: 200, data: {} }));

    for (const bad of ['', '.', '..']) {
      expect(() => api.get('/transfers/{transfer_id}', { path: { transfer_id: bad } })).toThrow(
        /transfer_id/,
      );
    }
    expect(() => fillPath('/files/{file_id}', {})).toThrow(/file_id/);
    expect(harness.sent).toHaveLength(0);
  });

  it('sends array query parameters repeated, as the contract\'s form style says', async () => {
    const harness = await setUpApi(() => ({ status: 200, data: { items: [], next_cursor: null } }));

    await api.get('/transfers', { query: { state: ['sent', 'held'], limit: 20 } });

    expect(apiClient.getUri(harness.sent[0])).toBe('/v1/transfers?state=sent&state=held&limit=20');
  });

  it('sends the JSON body and the contract\'s header parameters', async () => {
    const harness = await setUpApi(() => ({ status: 201, data: {} }));
    useAuthStore.getState().setAuth(member, memberToken);

    await api.post('/transfers', {
      body: { recipients: [{ email: 'aiko@example.co.jp' }] },
      headers: { 'Idempotency-Key': 'f3c1d1a0-0000-4000-8000-000000000001' },
    });

    expect(harness.sent[0]?.data).toBe(JSON.stringify({ recipients: [{ email: 'aiko@example.co.jp' }] }));
    expect(header(harness.sent[0], 'Idempotency-Key')).toBe('f3c1d1a0-0000-4000-8000-000000000001');
  });

  it('keeps the interceptors: member CSRF on member writes, link session headers on /session routes', async () => {
    const harness = await setUpApi(() => ({ status: 200, data: {} }));
    useAuthStore.getState().setAuth(member, memberToken);
    useAuthStore.getState().setLinkSession(linkSessionId, linkToken);

    await api.post('/transfers/{transfer_id}/revoke', { path: { transfer_id: transferId } });
    await api.get('/session');
    await api.delete('/session');

    expect(header(harness.sent[0], 'X-CSRF-Token')).toBe(memberToken);
    expect(header(harness.sent[0], 'X-Link-Session')).toBeUndefined();
    expect(header(harness.sent[1], 'X-Link-Session')).toBe(linkSessionId);
    expect(header(harness.sent[1], 'X-CSRF-Token')).toBeUndefined();
    expect(header(harness.sent[2], 'X-Link-Session')).toBe(linkSessionId);
    expect(header(harness.sent[2], 'X-CSRF-Token')).toBe(linkToken);
  });

  it('keeps the 401 handling: a member 401 signs out and goes to /sign-in', async () => {
    const harness = await setUpApi(
      () => ({ status: 401, data: { type: 'about:blank', title: 'x', status: 401, code: 'session_expired' } }),
      '/transfers',
    );
    useAuthStore.getState().setAuth(member, memberToken);

    await expect(api.get('/transfers')).rejects.toMatchObject({ response: { status: 401 } });

    expect(useAuthStore.getState().memberStatus).toBe('anonymous');
    expect(harness.location.assign).toHaveBeenCalledWith('/sign-in');
  });
});

describe('api: types checked against the contract', () => {
  // These run under `tsc` (npm run typecheck). A `@ts-expect-error` that stops erroring fails the type check.
  it('types response bodies from the contract', () => {
    expectTypeOf<Awaited<ReturnType<typeof api.get<'/me'>>>['data']>().toEqualTypeOf<Schema<'CurrentMember'>>();
    expectTypeOf<Awaited<ReturnType<typeof api.get<'/transfers'>>>['data']>().toEqualTypeOf<Schema<'TransferPage'>>();
    expectTypeOf<Awaited<ReturnType<typeof api.delete<'/session'>>>['data']>().toEqualTypeOf<undefined>();
  });

  it('accepts only contract paths and methods, without the operator API', () => {
    expectTypeOf<'/transfers'>().toMatchTypeOf<PathsWith<'post'>>();
    expectTypeOf<'/me'>().not.toMatchTypeOf<PathsWith<'post'>>();
    expectTypeOf<'/operator/tenants'>().not.toMatchTypeOf<PathsWith<'post'>>();
  });

  it('rejects calls the contract does not allow', () => {
    const typeErrors = () => {
      // @ts-expect-error: no such path
      void api.get('/transfer');
      // @ts-expect-error: the path parameter is required
      void api.get('/transfers/{transfer_id}');
      // @ts-expect-error: the request body is required
      void api.post('/transfers', {});
      // @ts-expect-error: not a TransferState
      void api.get('/transfers', { query: { state: ['active'] } });
      // @ts-expect-error: SignOutRequest has no such property
      void api.post('/auth/sign-out', { body: { everywhere: true } });
    };
    expect(typeErrors).toBeTypeOf('function');
  });
});
