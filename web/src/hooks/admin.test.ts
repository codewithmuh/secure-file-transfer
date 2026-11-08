import { afterEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import { csrfToken, header, member, problem, setUpApi } from '@/test/apiHarness';
import { clearEmailSuppression, exportAuditEvents, revokeApiKey } from './admin';
import { problemCode } from '@/lib/problems';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the admin calls (#215, #216, #217)', () => {
  it('clears a suppression with the address in the body, never the URL', async () => {
    const api = await setUpApi(() => ({ status: 204 }));
    useAuthStore.getState().setAuth(member, csrfToken('member'));
    await clearEmailSuppression('tanaka@example.co.jp');
    expect(api.sent[0]?.url).toBe('/email-suppressions/clear');
    expect(api.sent[0]?.params).toBeUndefined();
    expect(JSON.parse(String(api.sent[0]?.data))).toEqual({ email: 'tanaka@example.co.jp' });
    expect(header(api.sent[0], 'X-CSRF-Token')).toBe(csrfToken('member'));
  });

  it('exports with the filter in the body, and reads a refusal\'s problem back from its blob', async () => {
    const refusal = problem(422, 'export_too_large');
    const api = await setUpApi(() => ({ status: 422, data: new Blob([JSON.stringify(refusal.data)]) }));
    const filter = { email: 'tanaka@example.co.jp', source_ip: '198.51.100.5' };
    const failure = await exportAuditEvents(filter, 'csv').catch((error: unknown) => error);
    expect(problemCode(failure)).toBe('export_too_large');
    expect(api.sent[0]?.url).toBe('/audit/exports');
    expect(api.sent[0]?.params).toBeUndefined();
    expect(JSON.parse(String(api.sent[0]?.data))).toEqual({ filter, format: 'csv' });
  });

  it('names an export by its Content-Disposition, or by date', async () => {
    await setUpApi(() => ({ status: 200, data: new Blob(['"id"\r\n']) }));
    const file = await exportAuditEvents(undefined, 'json');
    expect(file.fileName).toMatch(/^audit-events-\d{4}-\d{2}-\d{2}\.json$/);
  });

  it('says a revocation whose record isn\'t confirmed (503) is unconfirmed, not failed', async () => {
    await setUpApi(() => problem(503, 'service_unavailable'));
    expect(await revokeApiKey('0190c0de-0000-7000-8000-000000000001')).toBe('unconfirmed');
    await setUpApi(() => ({ status: 200, data: {} }));
    expect(await revokeApiKey('0190c0de-0000-7000-8000-000000000001')).toBe('revoked');
    await setUpApi(() => problem(404, 'not_found'));
    await expect(revokeApiKey('0190c0de-0000-7000-8000-000000000001')).rejects.toBeTruthy();
  });
});
