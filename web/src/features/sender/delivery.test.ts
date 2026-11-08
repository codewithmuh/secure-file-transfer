import { afterEach, describe, expect, it, vi } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';
import type { TransferState } from '@/api';
import { resources } from '@/lib/i18n';
import { csrfToken, problem, setUpApi, type FakeReply } from '@/test/apiHarness';
import { useAuthStore } from '@/stores/authStore';
import { revokeTransfer, unlockRecipient } from '@/hooks/transfers';
import { RECIPIENT_POLL_INTERVAL_MS, POLL_INTERVAL_MS, shouldPollRecipients } from './polling';
import { nextRevocation } from './revocation';
import {
  accessStateVariant,
  deliveryStateVariant,
  EXPLAINED_DELIVERY_STATES,
  REVOCABLE_STATES,
  TRANSFER_STATES,
  type AccessState,
  type DeliveryState,
} from './states';

/** Every value of the contract's enums: a `Record` over them fails the type check when the contract adds one. */
const DELIVERY_STATES = Object.keys(deliveryStateVariant) as DeliveryState[];
const ACCESS_STATES = Object.keys(accessStateVariant) as AccessState[];

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('delivery and access states (#199, FR-7)', () => {
  it('names every DeliveryState and AccessState of the contract', () => {
    expect(DELIVERY_STATES.sort()).toEqual(['bounced', 'pending', 'queued', 'sent', 'suppressed']);
    expect(ACCESS_STATES.sort()).toEqual(['invited', 'locked', 'verified']);
  });

  it('has a label for each state, and an explanation for bounced and suppressed only, in both languages', () => {
    for (const language of ['en', 'ja'] as const) {
      const text = resources[language].translation;
      for (const state of DELIVERY_STATES) {
        expect(text.deliveryState[state], `${language}: deliveryState.${state}`).toBeTruthy();
        const explained = (text.deliveryExplain as Record<string, string | undefined>)[state];
        expect(Boolean(explained), `${language}: deliveryExplain.${state}`).toBe(EXPLAINED_DELIVERY_STATES.includes(state));
      }
      for (const state of ACCESS_STATES) expect(text.accessState[state], `${language}: accessState.${state}`).toBeTruthy();
    }
  });

  it('shows a lockout and a bounce as danger, an email on its way as info, never only by colour', () => {
    expect(accessStateVariant.locked).toBe('danger');
    expect(accessStateVariant.verified).toBe('success');
    expect(deliveryStateVariant.bounced).toBe('danger');
    expect(deliveryStateVariant.suppressed).toBe('warning');
    expect(deliveryStateVariant.queued).toBe('info');
  });
});

describe('shouldPollRecipients', () => {
  it('polls only while the transfer is sent, slower than the scans', () => {
    const polled = TRANSFER_STATES.filter((state) => shouldPollRecipients(state));
    expect(polled).toEqual(['sent']);
    for (const state of ['revoked', 'expired', 'cancelled'] as TransferState[]) expect(shouldPollRecipients(state)).toBe(false);
    expect(shouldPollRecipients(undefined)).toBe(false);
    expect(RECIPIENT_POLL_INTERVAL_MS).toBeGreaterThan(POLL_INTERVAL_MS);
  });
});

describe('revocation (#199, FR-20)', () => {
  const failed = (status: number, code: string) =>
    new AxiosError('failed', 'ERR_BAD_RESPONSE', undefined, null, {
      status,
      statusText: String(status),
      data: { type: 'about:blank', title: code, status, code },
      headers: {},
      config: { headers: new AxiosHeaders() },
    });

  it('is offered for submitted, held and sent, and the M5 states the contract names; never after the end', () => {
    for (const state of ['submitted', 'held', 'sent'] as TransferState[]) expect(REVOCABLE_STATES).toContain(state);
    for (const state of ['draft', 'revoked', 'expired', 'cancelled'] as TransferState[]) {
      expect(REVOCABLE_STATES).not.toContain(state);
    }
  });

  it('a 200 shows revoked', () => {
    expect(nextRevocation('idle', null)).toBe('revoked');
  });

  it('a 503 keeps the revoked banner and offers a retry: the revocation stands, unconfirmed', () => {
    expect(nextRevocation('idle', failed(503, 'service_unavailable'))).toBe('unconfirmed');
    // A retry that fails again, however, never turns it into a failure: it took effect already.
    expect(nextRevocation('unconfirmed', failed(503, 'service_unavailable'))).toBe('unconfirmed');
    expect(nextRevocation('unconfirmed', failed(429, 'rate_limited'))).toBe('unconfirmed');
    expect(nextRevocation('unconfirmed', null)).toBe('revoked');
  });

  it('any other first failure is a failure, shown in the dialog', () => {
    expect(nextRevocation('idle', failed(409, 'transfer_expired'))).toBe('failed');
    expect(nextRevocation('failed', failed(409, 'invalid_state'))).toBe('failed');
  });

  it('revokeTransfer posts with the member\'s CSRF token and no body', async () => {
    const replies: FakeReply[] = [{ status: 503, data: { code: 'service_unavailable', status: 503, title: '', type: 'about:blank' } }];
    const { sent } = await setUpApi(() => replies.shift() ?? { status: 200, data: {} });
    useAuthStore.setState({ memberCsrfToken: csrfToken('member') });
    await expect(revokeTransfer('0190c0de-0000-7000-8000-000000000010')).rejects.toThrow();
    await revokeTransfer('0190c0de-0000-7000-8000-000000000010');
    expect(sent.map((config) => config.url)).toEqual([
      '/transfers/0190c0de-0000-7000-8000-000000000010/revoke',
      '/transfers/0190c0de-0000-7000-8000-000000000010/revoke',
    ]);
    expect(AxiosHeaders.from(sent[0]?.headers).get('X-CSRF-Token')).toBe(csrfToken('member'));
  });
});

describe('unlockRecipient: a 503 unlocked too, with its audit record pending (#199 review)', () => {
  const transferId = '0190c0de-0000-7000-8000-000000000010';
  const recipientId = '0190c0de-0000-7000-8000-000000000020';

  it('a 200 is unlocked', async () => {
    const { sent } = await setUpApi(() => ({ status: 200, data: {} }));
    expect(await unlockRecipient(transferId, recipientId)).toBe('unlocked');
    expect(sent[0]?.url).toBe(`/transfers/${transferId}/recipients/${recipientId}/unlock`);
  });

  it('a 503 is unlocked, unconfirmed: the contract says the unlock took effect at once', async () => {
    await setUpApi(() => problem(503, 'service_unavailable'));
    expect(await unlockRecipient(transferId, recipientId)).toBe('unconfirmed');
  });

  it('any other error is still an error, shown in the dialog', async () => {
    await setUpApi(() => problem(403, 'passkey_required'));
    await expect(unlockRecipient(transferId, recipientId)).rejects.toThrow();
  });

  it('has the "audit record pending" text in both languages', () => {
    for (const language of ['en', 'ja'] as const) {
      const text = resources[language].translation.delivery;
      expect(text.unlockedUnconfirmed, `${language}: delivery.unlockedUnconfirmed`).toContain('{{email}}');
      expect(text.unlockedUnconfirmed).not.toBe(text.unlocked);
    }
  });
});
