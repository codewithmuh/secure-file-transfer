import { AxiosError, AxiosHeaders, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { describe, expect, it } from 'vitest';
import { IdempotencyKeys, mayHaveHappened } from './idempotency';

function answered(status: number): AxiosError {
  const config = { headers: new AxiosHeaders() } as InternalAxiosRequestConfig;
  const response: AxiosResponse = { status, statusText: '', data: {}, headers: {}, config };
  return new AxiosError(`status ${status}`, 'ERR_BAD_RESPONSE', config, null, response);
}

describe('IdempotencyKeys: one key per attempt, so a retry replays (#196)', () => {
  it('keeps the key of an attempt until it is done', () => {
    const keys = new IdempotencyKeys();
    const first = keys.keyFor('createTransfer');
    expect(keys.keyFor('createTransfer')).toBe(first); // the retry
    expect(first).toMatch(/^[0-9a-f-]{36}$/);
    expect(keys.keyFor('addTransferFile:a')).not.toBe(first);
    keys.done('createTransfer');
    expect(keys.keyFor('createTransfer')).not.toBe(first); // a new attempt
    const other = keys.keyFor('addTransferFile:a');
    keys.reset();
    expect(keys.keyFor('addTransferFile:a')).not.toBe(other);
  });

  it('gives an edited body a new key, and an unchanged retry the same one (#196 review)', () => {
    const keys = new IdempotencyKeys();
    const body = { recipients: [{ email: 'a@example.com', locale: 'en' }], expires_in: 'P7D' };
    const first = keys.keyForBody('createTransfer', body);
    expect(keys.keyForBody('createTransfer', { ...body })).toBe(first);
    const edited = keys.keyForBody('createTransfer', { ...body, expires_in: 'P3D' });
    expect(edited).not.toBe(first);
    // Back to the first body: still a new attempt, never the key the API saw with another body.
    expect(keys.keyForBody('createTransfer', body)).not.toBe(edited);
    expect(keys.keyForBody('createTransfer', body)).not.toBe(first);
  });
});

describe('mayHaveHappened: which failures keep the key (#197 review)', () => {
  it('keeps it when the call may have been done: no answer, a timeout, 429 or a server error', () => {
    expect(mayHaveHappened(new AxiosError('Network Error', 'ERR_NETWORK'))).toBe(true);
    expect(mayHaveHappened(new Error('anything'))).toBe(true);
    for (const status of [408, 429, 500, 502, 503]) expect(mayHaveHappened(answered(status)), String(status)).toBe(true);
  });

  it('drops it on a definite refusal the user must change their input for', () => {
    for (const status of [400, 403, 409, 413, 422]) expect(mayHaveHappened(answered(status)), String(status)).toBe(false);
  });
});
