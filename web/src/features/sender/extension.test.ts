import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Transfer } from '@/api';
import { csrfToken, header, setUpApi } from '@/test/apiHarness';
import { useAuthStore } from '@/stores/authStore';
import { extendTransferExpiry } from '@/hooks/transfers';
import { EXTENDABLE_STATES, extensionChoices, extensionLimit } from './extension';

const DAY = 86_400_000;
const SUBMITTED = Date.parse('2026-11-01T10:00:00Z');
const NOW = Date.parse('2026-11-05T00:00:00Z');

const sent = (expiresInDays: number, state: Transfer['state'] = 'sent') => ({
  state,
  submitted_at: new Date(SUBMITTED).toISOString(),
  expires_at: new Date(SUBMITTED + expiresInDays * DAY).toISOString(),
});

const times = (choices: ReturnType<typeof extensionChoices>) => choices.map((choice) => Date.parse(choice.expiresAt));

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the extend expiry range (#214, FR-9)', () => {
  it('reaches at most 30 days after submitted_at, whatever the policy says above that', () => {
    expect(extensionLimit(sent(7), 'P30D')).toBe(SUBMITTED + 30 * DAY);
    expect(extensionLimit(sent(7), undefined)).toBe(SUBMITTED + 30 * DAY);
  });

  it('reaches at most the tenant\'s max_expiry after submitted_at when that is shorter', () => {
    expect(extensionLimit(sent(7), 'P14D')).toBe(SUBMITTED + 14 * DAY);
    expect(extensionLimit(sent(7), 'PT36H')).toBe(SUBMITTED + 36 * 3_600_000);
  });

  it('offers steps after the current expiry that stay before the limit, then the latest allowed', () => {
    const choices = extensionChoices(sent(7), 'P30D', NOW);
    expect(choices.map((choice) => (choice.kind === 'step' ? choice.step : 'latest'))).toEqual([
      'P1D',
      'P3D',
      'P7D',
      'P14D',
      'latest',
    ]);
    expect(times(choices)).toEqual([8, 10, 14, 21, 30].map((days) => SUBMITTED + days * DAY));
    // Never earlier than the current expiry, and never past the limit.
    for (const time of times(choices)) {
      expect(time).toBeGreaterThan(SUBMITTED + 7 * DAY);
      expect(time).toBeLessThanOrEqual(SUBMITTED + 30 * DAY);
    }
  });

  it('drops the steps that would pass a shorter policy cap', () => {
    const choices = extensionChoices(sent(7), 'P10D', NOW);
    expect(times(choices)).toEqual([8, 10].map((days) => SUBMITTED + days * DAY));
    expect(choices[choices.length - 1]?.kind).toBe('latest');
  });

  it('offers nothing once the transfer is at its limit, or the policy now caps below its expiry', () => {
    expect(extensionChoices(sent(30), 'P30D', NOW)).toEqual([]);
    expect(extensionChoices(sent(7), 'P3D', NOW)).toEqual([]);
  });

  it('offers nothing for a draft, an ended transfer or one whose expiry has passed', () => {
    expect(extensionChoices({ state: 'draft', submitted_at: null, expires_at: null }, 'P30D', NOW)).toEqual([]);
    for (const state of ['revoked', 'expired', 'cancelled'] as const) expect(extensionChoices(sent(7, state), 'P30D', NOW)).toEqual([]);
    expect(extensionChoices(sent(3), 'P30D', SUBMITTED + 4 * DAY)).toEqual([]);
  });

  it('takes the states the contract names: submitted and not ended', () => {
    expect([...EXTENDABLE_STATES].sort()).toEqual(['awaiting_confirmation', 'held', 'pending_approval', 'sent', 'submitted']);
  });

  it('extendTransferExpiry posts the new time with its Idempotency-Key and the member\'s CSRF token', async () => {
    const transferId = '0190c0de-0000-7000-8000-000000000010';
    const { sent: requests } = await setUpApi(() => ({ status: 200, data: { id: transferId } }));
    useAuthStore.setState({ memberCsrfToken: csrfToken('member') });
    await extendTransferExpiry(transferId, { expires_at: '2026-11-20T10:00:00.000Z' }, 'key-1');
    expect(requests[0]?.url).toBe(`/transfers/${transferId}/extend`);
    expect(header(requests[0], 'Idempotency-Key')).toBe('key-1');
    expect(header(requests[0], 'X-CSRF-Token')).toBe(csrfToken('member'));
    expect(JSON.parse(String(requests[0]?.data))).toEqual({ expires_at: '2026-11-20T10:00:00.000Z' });
  });
});
