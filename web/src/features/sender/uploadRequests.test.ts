import { afterEach, describe, expect, it, vi } from 'vitest';
import type { UploadRequestState } from '@/api';
import { resources } from '@/lib/i18n';
import { csrfToken, header, problem, setUpApi } from '@/test/apiHarness';
import { useAuthStore } from '@/stores/authStore';
import {
  createReceivedFileDownload,
  createUploadRequest,
  revokeUploadRequest,
  unlockUploader,
} from '@/hooks/uploadRequests';
import { POLL_INTERVAL_MS } from './polling';
import {
  EXPIRY_MARGIN_MS,
  expiresAtFor,
  receivedFileActions,
  receivedFilesPollInterval,
  REQUEST_POLL_INTERVAL_MS,
  requestBody,
  RequestAttempt,
  requestPollInterval,
  UPLOAD_REQUEST_STATES,
  uploadRequestStateVariant,
  type RequestForm,
} from './uploadRequests';

const NOW = Date.parse('2026-11-08T00:00:00Z');
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const requestId = '0190c0de-0000-7000-8000-0000000000b1';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('upload request states (#212)', () => {
  it('names every UploadRequestState of the contract, with a label in both languages', () => {
    expect((Object.keys(uploadRequestStateVariant) as UploadRequestState[]).sort()).toEqual(['expired', 'open', 'revoked']);
    expect([...UPLOAD_REQUEST_STATES].sort()).toEqual(['expired', 'open', 'revoked']);
    for (const language of ['en', 'ja'] as const) {
      for (const state of UPLOAD_REQUEST_STATES) {
        expect(resources[language].translation.uploadRequestState[state], `${language}: ${state}`).toBeTruthy();
      }
    }
    expect(uploadRequestStateVariant.revoked).toBe('danger');
  });

  it('polls a request only while it is open', () => {
    expect(requestPollInterval({ state: 'open' })).toBe(REQUEST_POLL_INTERVAL_MS);
    expect(requestPollInterval({ state: 'revoked' })).toBe(false);
    expect(requestPollInterval({ state: 'expired' })).toBe(false);
    expect(requestPollInterval(undefined)).toBe(false);
  });

  it('polls received files fast while one is scanned, slowly while open, never once ended and still', () => {
    expect(receivedFilesPollInterval([{ state: 'scanning' }], 'revoked')).toBe(POLL_INTERVAL_MS);
    expect(receivedFilesPollInterval([{ state: 'completing' }], 'open')).toBe(POLL_INTERVAL_MS);
    expect(receivedFilesPollInterval([{ state: 'clean' }], 'open')).toBe(REQUEST_POLL_INTERVAL_MS);
    expect(receivedFilesPollInterval([{ state: 'clean' }], 'expired')).toBe(false);
    expect(receivedFilesPollInterval(undefined, undefined)).toBe(false);
  });
});

describe('received files: who may download and delete (#213, UC-3, FR-13)', () => {
  it('lets the owner download a shareable file, and delete one whose scan is over', () => {
    expect(receivedFileActions({ state: 'clean', shareable: true }, true)).toEqual({ download: true, remove: true });
    expect(receivedFileActions({ state: 'unscannable', shareable: true }, true)).toEqual({ download: true, remove: true });
    expect(receivedFileActions({ state: 'infected', shareable: false }, true)).toEqual({ download: false, remove: true });
    expect(receivedFileActions({ state: 'scanning', shareable: false }, true)).toEqual({ download: false, remove: false });
    expect(receivedFileActions({ state: 'uploading', shareable: false }, true)).toEqual({ download: false, remove: false });
    expect(receivedFileActions({ state: 'deleted', shareable: false }, true)).toEqual({ download: false, remove: false });
  });

  it('gives an admin looking at another member\'s request the metadata only', () => {
    expect(receivedFileActions({ state: 'clean', shareable: true }, false)).toEqual({ download: false, remove: false });
  });
});

describe('the create form\'s expires_at (#212, FR-3)', () => {
  it('is now plus the chosen duration and a small margin, so the shortest choice is still an hour away on arrival', () => {
    expect(Date.parse(expiresAtFor('PT1H', 'P30D', NOW))).toBe(NOW + HOUR + EXPIRY_MARGIN_MS);
    expect(Date.parse(expiresAtFor('P7D', 'P30D', NOW))).toBe(NOW + 7 * DAY + EXPIRY_MARGIN_MS);
  });

  it('never passes the tenant\'s max_expiry, nor 30 days', () => {
    expect(Date.parse(expiresAtFor('P7D', 'P7D', NOW))).toBe(NOW + 7 * DAY);
    expect(Date.parse(expiresAtFor('P30D', undefined, NOW))).toBe(NOW + 30 * DAY);
    expect(Date.parse(expiresAtFor('P30D', 'P90D', NOW))).toBe(NOW + 30 * DAY);
  });

  it('builds the body: trimmed address, locale, the time, and the message only when there is one', () => {
    const form: RequestForm = { email: '  supplier@example.com ', locale: 'ja', expiresIn: 'P3D', message: '  ' };
    expect(requestBody(form, 'P30D', NOW)).toEqual({
      uploader_email: 'supplier@example.com',
      locale: 'ja',
      expires_at: new Date(NOW + 3 * DAY + EXPIRY_MARGIN_MS).toISOString(),
    });
    expect(requestBody({ ...form, message: 'The signed contract' }, 'P30D', NOW).message).toBe('The signed contract');
  });

  it('a retry of the same form sends the same body, so its Idempotency-Key replays; a change or done starts anew', () => {
    const attempt = new RequestAttempt();
    const form: RequestForm = { email: 'supplier@example.com', locale: 'en', expiresIn: 'P7D', message: '' };
    const first = attempt.bodyFor(form, 'P30D', NOW);
    expect(attempt.bodyFor(form, 'P30D', NOW + 60_000)).toBe(first);
    const changed = attempt.bodyFor({ ...form, expiresIn: 'P3D' }, 'P30D', NOW + 60_000);
    expect(changed).not.toBe(first);
    attempt.done();
    expect(attempt.bodyFor({ ...form, expiresIn: 'P3D' }, 'P30D', NOW + 120_000).expires_at).not.toBe(changed.expires_at);
  });
});

describe('the upload request calls (#212, #213)', () => {
  it('createUploadRequest sends the body with its Idempotency-Key and the member\'s CSRF token', async () => {
    const { sent } = await setUpApi(() => ({ status: 201, data: { id: requestId } }));
    useAuthStore.setState({ memberCsrfToken: csrfToken('member') });
    const body = { uploader_email: 'supplier@example.com', locale: 'en' as const, expires_at: '2026-11-15T00:00:00Z' };
    await createUploadRequest(body, 'key-1');
    expect(sent[0]?.url).toBe('/upload-requests');
    expect(header(sent[0], 'Idempotency-Key')).toBe('key-1');
    expect(header(sent[0], 'X-CSRF-Token')).toBe(csrfToken('member'));
    expect(JSON.parse(String(sent[0]?.data))).toEqual(body);
  });

  it('revokeUploadRequest throws a 503, which the revocation shows as done and retries', async () => {
    const { sent } = await setUpApi(() => problem(503, 'service_unavailable'));
    await expect(revokeUploadRequest(requestId)).rejects.toThrow();
    expect(sent[0]?.url).toBe(`/upload-requests/${requestId}/revoke`);
  });

  it('unlockUploader: a 200 is unlocked, a 503 unlocked with its record pending, anything else an error', async () => {
    const { sent } = await setUpApi(() => ({ status: 200, data: {} }));
    expect(await unlockUploader(requestId)).toBe('unlocked');
    expect(sent[0]?.url).toBe(`/upload-requests/${requestId}/unlock`);
    await setUpApi(() => problem(503, 'service_unavailable'));
    expect(await unlockUploader(requestId)).toBe('unconfirmed');
    await setUpApi(() => problem(409, 'upload_request_revoked'));
    await expect(unlockUploader(requestId)).rejects.toThrow();
  });

  it('createReceivedFileDownload asks for a new grant on the file', async () => {
    const fileId = '0190c0de-0000-7000-8000-0000000000f1';
    const { sent } = await setUpApi(() => ({ status: 200, data: { grant_id: 'g' } }));
    await createReceivedFileDownload(fileId);
    expect(sent[0]?.url).toBe(`/files/${fileId}/downloads`);
    expect(sent[0]?.method).toBe('post');
  });

  it('has its own text for a revoked or expired request, in both languages', () => {
    for (const language of ['en', 'ja'] as const) {
      const problems = resources[language].translation.problems;
      expect(problems.upload_request_revoked).toBeTruthy();
      expect(problems.upload_request_expired).toBeTruthy();
    }
  });
});
