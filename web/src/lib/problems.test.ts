import { AxiosError, AxiosHeaders, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import i18n from 'i18next';
import { describe, expect, it } from 'vitest';
import { resources } from './i18n';
import { failureOf, fieldErrors, HANDLED_PROBLEMS, problemMessage, STATUS_TEXTS } from './problems';

function apiError(status: number, data: unknown, headers: Record<string, string> = {}): AxiosError {
  const config = { headers: new AxiosHeaders() } as InternalAxiosRequestConfig;
  const response: AxiosResponse = { status, statusText: '', data, headers: new AxiosHeaders(headers), config };
  return new AxiosError(`status ${status}`, 'ERR_BAD_REQUEST', config, null, response);
}

const problem = (status: number, code: string, extra: object = {}) => ({
  type: `https://secure-file-transfer.example/problems/${code}`,
  title: code,
  status,
  code,
  ...extra,
});

const tIn = (language: 'en' | 'ja') => i18n.getFixedT(language);

describe('problemMessage (#196)', () => {
  it('gives every handled code its own text in English and in Japanese', () => {
    for (const language of ['en', 'ja'] as const) {
      const texts = resources[language].translation.problems as Record<string, string>;
      for (const code of HANDLED_PROBLEMS) {
        expect(texts[code], `${language} problems.${code}`).toBeTruthy();
        const text = problemMessage(failureOf(apiError(400, problem(400, code))), tIn(language));
        expect(text).toBe(texts[code]);
      }
      for (const status of STATUS_TEXTS) expect(texts[`status${status}`], `${language} status${status}`).toBeTruthy();
    }
  });

  it('falls back on the status for a code it does not handle, as the contract says', () => {
    const t = tIn('en');
    // The link pages explain `link_revoked` themselves; the shared messages fall back on its status.
    expect(problemMessage(failureOf(apiError(410, problem(410, 'link_revoked'))), t)).toBe(
      resources.en.translation.problems.status410,
    );
    expect(problemMessage(failureOf(apiError(418, problem(418, 'brand_new_code'))), t)).toBe(
      resources.en.translation.problems.unknown,
    );
    expect(problemMessage(failureOf(apiError(502, 'Bad gateway')), t)).toBe(resources.en.translation.problems.unknown);
    expect(problemMessage(failureOf(new Error('offline')), t)).toBe(resources.en.translation.problems.network);
  });

  it('shows the Retry-After of a 429 or 503 as a wait, in seconds or from an HTTP date', () => {
    const t = tIn('en');
    const limited = failureOf(apiError(429, problem(429, 'rate_limited'), { 'Retry-After': '30' }));
    expect(limited.retryAfter).toBe(30);
    expect(problemMessage(limited, t)).toBe(`${resources.en.translation.problems.rate_limited} Try again in 30 seconds.`);
    const now = Date.parse('2026-11-08T00:00:00Z');
    const dated = failureOf(apiError(503, problem(503, 'service_unavailable'), { 'Retry-After': 'Sun, 08 Nov 2026 00:00:05 GMT' }), now);
    expect(dated.retryAfter).toBe(5);
    expect(problemMessage(failureOf(apiError(503, problem(503, 'service_unavailable'), { 'Retry-After': '1' })), tIn('ja'))).toContain('1秒後');
    // Only 429 and 503 carry a wait.
    expect(failureOf(apiError(409, problem(409, 'invalid_state'), { 'Retry-After': '30' })).retryAfter).toBeNull();
  });

  it('maps 422 field errors by their JSON Pointer', () => {
    const failure = failureOf(
      apiError(
        422,
        problem(422, 'validation_failed', {
          errors: [
            { detail: 'Not an address.', pointer: '#/recipients/3/email' },
            { detail: 'Too long.', pointer: '#/expires_in' },
            { detail: 'Bad cursor.', parameter: 'cursor' },
          ],
        }),
      ),
    );
    expect(fieldErrors(failure)).toEqual({ 'recipients/3/email': 'Not an address.', expires_in: 'Too long.' });
  });

  it('has en and ja text for last_admin and user_exists (#197)', () => {
    for (const language of ['en', 'ja'] as const) {
      const texts = resources[language].translation.problems;
      expect(texts.last_admin).toBeTruthy();
      expect(texts.user_exists).toBeTruthy();
    }
    expect(resources.ja.translation.problems.last_admin).not.toBe(resources.en.translation.problems.last_admin);
  });
});
