import { describe, expect, it } from 'vitest';
import { DEFAULT_RETURN_PATH, safeReturnPath } from './returnPath';

describe('safeReturnPath: only same-app paths under allowed routes (#73 defect 4)', () => {
  it.each([
    '/',
    '/transfers',
    '/transfers/',
    '/transfers/new',
    '/transfers/0190c0de-0000-7000-8000-000000000001',
    '/transfers?status=sent&cursor=abc',
    '/upload-requests',
    '/upload-requests/new',
    '/admin/users',
    '/admin/audit',
  ])('accepts %s', (path) => {
    expect(safeReturnPath(path)).toBe(path);
  });

  it.each([
    null,
    undefined,
    '',
    'transfers',
    'https://evil.example/transfers',
    'HTTPS://evil.example',
    'javascript:alert(1)',
    'data:text/html,hi',
    '//evil.example',
    '//evil.example/transfers',
    '///evil.example',
    '/\\evil.example',
    '\\\\evil.example',
    '/transfers\\..\\sign-in',
    '/%2F%2Fevil.example',
    '/%2fevil.example',
    '/transfers%2F..%2F..%2Fsign-in',
    '/%5Cevil.example',
    '/transfers/../sign-in',
    '/transfers/./new',
    '/transfers//new',
    '/sign-in',
    '/sign-in?error=sign_in_failed',
    '/auth/callback?return_path=//evil.example',
    '/t',
    '/u',
    '/transfersx',
    '/administrator',
    '/transfers#token',
    '/transfers@evil.example',
    ' /transfers',
    '/transfers ',
    '/\t/evil.example',
    '/transfers\n',
    `/transfers/${'a'.repeat(520)}`,
    // Under an allowed prefix, but with characters the path may not contain.
    '/transfers/%2F%2Fevil.example',
    '/transfers/%2e%2e/sign-in',
    '/transfers/\\evil.example',
    '/transfers/a#token',
    '/transfers/a b',
    '/transfers/a\u0000',
    '/admin/users@evil.example',
    '/transfers/https://evil.example',
  ])('refuses %j and falls back to the dashboard', (path) => {
    expect(safeReturnPath(path)).toBe(DEFAULT_RETURN_PATH);
  });

  it('refuses values that only become dangerous once URLSearchParams decodes them', () => {
    for (const query of ['return_path=%2F%2Fevil.example', 'return_path=%2F%5Cevil.example', 'return_path=https%3A%2F%2Fevil.example']) {
      expect(safeReturnPath(new URLSearchParams(query).get('return_path'))).toBe(DEFAULT_RETURN_PATH);
    }
  });

  it('refuses double-encoded values', () => {
    expect(safeReturnPath(new URLSearchParams('return_path=%252F%252Fevil.example').get('return_path'))).toBe('/');
  });
});
