import { describe, expect, it, vi } from 'vitest';
import { renderToString } from 'react-dom/server';
import '@/lib/i18n';
import { resources } from '@/lib/i18n';
import type { Transfer } from '@/api';
import { TransferEndBanner } from './RevokeTransfer';
import type { RevocationStatus } from './revocation';

const en = resources.en.translation.delivery;

const transfer = (state: Transfer['state'], revokedAt: string | null = null) =>
  ({ id: 't', state, revoked_at: revokedAt }) as Transfer;

const revocation = (status: RevocationStatus) => ({ status, busy: false, error: null, revoke: vi.fn(), reset: vi.fn() });

const banner = (state: Transfer['state'], status: RevocationStatus, revokedAt: string | null = null) =>
  renderToString(<TransferEndBanner transfer={transfer(state, revokedAt)} revocation={revocation(status)} date={(v) => v} />);

describe('TransferEndBanner (#199)', () => {
  it('after a 503 says the transfer is revoked, and offers "Confirm now", even once the transfer shows revoked', () => {
    for (const state of ['sent', 'revoked'] as const) {
      const html = banner(state, 'unconfirmed');
      expect(html).toContain(en.revokeUnconfirmed.replace(/'/g, '&#x27;'));
      expect(html).toContain(en.revokeRetry);
    }
  });

  it('says revoked, with its time, once confirmed', () => {
    const html = banner('revoked', 'idle', '2026-11-08T05:00:00Z');
    expect(html).toContain(en.revoked);
    expect(html).toContain('Revoked 2026-11-08T05:00:00Z.');
    expect(html).not.toContain(en.revokeRetry);
  });

  it('says an expired transfer is read-only', () => {
    expect(banner('expired', 'idle')).toContain(en.expiredReadOnly);
  });

  it('says nothing while the transfer is shared', () => {
    expect(banner('sent', 'idle')).toBe('');
  });
});
