import { describe, expect, it, vi } from 'vitest';
import { renderToString } from 'react-dom/server';
import '@/lib/i18n';
import { resources } from '@/lib/i18n';
import type { UploadRequest } from '@/api';
import { RequestEndBanner } from './UploadRequestDetailPage';
import type { RevocationStatus } from './revocation';

const en = resources.en.translation;

const banner = (state: UploadRequest['state'], status: RevocationStatus, revokedAt: string | null = null) =>
  renderToString(
    <RequestEndBanner
      request={{ state, revoked_at: revokedAt }}
      revocation={{ status, busy: false, revoke: vi.fn() }}
      date={(value) => value}
    />,
  );

const escaped = (text: string) => text.replace(/'/g, '&#x27;');

describe('RequestEndBanner (#212, FR-20)', () => {
  it('after a 503 says the request is revoked and offers "Confirm now", even once it shows revoked', () => {
    for (const state of ['open', 'revoked'] as const) {
      const html = banner(state, 'unconfirmed');
      expect(html).toContain(escaped(en.requests.revokeUnconfirmed));
      expect(html).toContain(en.delivery.revokeRetry);
    }
  });

  it('says revoked, with its time, once confirmed', () => {
    const html = banner('revoked', 'idle', '2026-11-08T05:00:00Z');
    expect(html).toContain(en.requests.revoked);
    expect(html).toContain('Revoked 2026-11-08T05:00:00Z.');
    expect(html).not.toContain(en.delivery.revokeRetry);
  });

  it('says an expired request takes no more uploads, and that received files stay', () => {
    expect(banner('expired', 'idle')).toContain(en.requests.expiredReadOnly);
  });

  it('says nothing while the request is open', () => {
    expect(banner('open', 'idle')).toBe('');
  });
});
