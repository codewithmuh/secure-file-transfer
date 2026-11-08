import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';
import { Revocation, REVOKE_RETRY_MAX_MS, revokeRetryDelay } from './revocation';

const transferA = '0190c0de-0000-7000-8000-00000000000a';
const transferB = '0190c0de-0000-7000-8000-00000000000b';

const unavailable = () =>
  new AxiosError('failed', 'ERR_BAD_RESPONSE', undefined, null, {
    status: 503,
    statusText: '503',
    data: { type: 'about:blank', title: 'service_unavailable', status: 503, code: 'service_unavailable' },
    headers: {},
    config: { headers: new AxiosHeaders() },
  });

/** A revoke call that answers from `replies` in order (`503` or `200`), then `200`. */
function answering(...replies: (503 | 200)[]) {
  return vi.fn(async (_transferId: string) => {
    if (replies.shift() === 503) throw unavailable();
    return {};
  });
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('Revocation: an unconfirmed revocation keeps retrying in the background (#199 review)', () => {
  it('waits 15 s, 30 s, 60 s, then every 2 minutes', () => {
    expect([0, 1, 2, 3, 4, 10].map(revokeRetryDelay)).toEqual([15_000, 30_000, 60_000, 120_000, 120_000, 120_000]);
    expect(REVOKE_RETRY_MAX_MS).toBe(120_000);
  });

  it('retries after each 503, with a growing wait, until a 200 confirms it; then stops', async () => {
    const call = answering(503, 503, 503, 200);
    const settled = vi.fn();
    const revocation = new Revocation(transferA, call, settled);

    expect(await revocation.revoke()).toBe('unconfirmed');
    await vi.advanceTimersByTimeAsync(14_999);
    expect(call).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(call).toHaveBeenCalledTimes(2); // the second 503 arms the next retry: the bug was that nothing did
    expect(revocation.getState().status).toBe('unconfirmed');

    await vi.advanceTimersByTimeAsync(29_999);
    expect(call).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(call).toHaveBeenCalledTimes(3);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(call).toHaveBeenCalledTimes(4);
    expect(revocation.getState()).toEqual({ status: 'revoked', busy: false, error: null });
    expect(settled).toHaveBeenCalledTimes(4);

    await vi.advanceTimersByTimeAsync(10 * REVOKE_RETRY_MAX_MS);
    expect(call).toHaveBeenCalledTimes(4);
  });

  it('re-arms after a manual retry that gets 503, in place of the pending one', async () => {
    const call = answering(503, 503, 200);
    const revocation = new Revocation(transferA, call, () => {});

    await revocation.revoke();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(await revocation.revoke()).toBe('unconfirmed'); // "Confirm now", before the background retry
    expect(call).toHaveBeenCalledTimes(2);

    // The pending 15 s retry was replaced by the next wait, 30 s from the manual one: no double call.
    await vi.advanceTimersByTimeAsync(29_999);
    expect(call).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(call).toHaveBeenCalledTimes(3);
    expect(revocation.getState().status).toBe('revoked');
  });

  it('notifies its subscribers on every change, busy included', async () => {
    const revocation = new Revocation(transferA, answering(200), () => {});
    const seen: string[] = [];
    revocation.subscribe(() => seen.push(`${revocation.getState().status}${revocation.getState().busy ? ':busy' : ''}`));
    await revocation.revoke();
    expect(seen).toEqual(['idle:busy', 'revoked']);
  });
});

describe('Revocation: bound to the transfer it was made for (#199 review)', () => {
  it('every call, background retries included, revokes that transfer', async () => {
    const call = answering(503, 200);
    const revocation = new Revocation(transferA, call, () => {});
    await revocation.revoke();
    await vi.advanceTimersByTimeAsync(15_000);
    expect(call.mock.calls).toEqual([[transferA], [transferA]]);
  });

  it('a pending retry stops with its view, so showing another transfer revokes nothing', async () => {
    const callA = answering(503);
    const shownA = new Revocation(transferA, callA, () => {});
    await shownA.revoke();
    shownA.stop(); // the detail page now shows transfer B: its keyed view unmounts A's

    const callB = answering();
    const shownB = new Revocation(transferB, callB, () => {});
    shownB.start();
    await vi.advanceTimersByTimeAsync(10 * REVOKE_RETRY_MAX_MS);
    expect(callA).toHaveBeenCalledTimes(1);
    expect(callB).not.toHaveBeenCalled();
    expect(shownB.getState().status).toBe('idle');
  });

  it('starts again (React StrictMode mounts twice) and carries on retrying', async () => {
    const call = answering(503, 200);
    const revocation = new Revocation(transferA, call, () => {});
    await revocation.revoke();
    revocation.stop();
    revocation.start();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(call).toHaveBeenCalledTimes(2);
    expect(revocation.getState().status).toBe('revoked');
  });
});
