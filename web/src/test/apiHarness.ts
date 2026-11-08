/**
 * Test helpers: load the runtime config, answer `apiClient` requests without a network, and stand in for
 * `window.location`, so the API client and the auth store can be tested in Node without a DOM.
 */
import { AxiosError, AxiosHeaders, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { vi } from 'vitest';
import { apiClient } from '@/lib/api';
import { loadConfig, resetConfig, type AppConfig } from '@/lib/config';
import { useAuthStore } from '@/stores/authStore';

export interface FakeReply {
  status: number;
  data?: unknown;
}

export type FakeHandler = (config: InternalAxiosRequestConfig) => FakeReply;

export interface Harness {
  /** Every request the client sent, after the request interceptor ran. */
  sent: InternalAxiosRequestConfig[];
  location: { pathname: string; href: string; assign: ReturnType<typeof vi.fn> };
}

/** A CSRF token in the contract's shape (`CsrfToken`). */
export function csrfToken(seed: string): string {
  return `k1.${seed.padEnd(43, 'A').slice(0, 43)}`;
}

export function problem(status: number, code: string): FakeReply {
  return { status, data: { type: `https://secure-file-transfer.example/problems/${code}`, title: code, status, code } };
}

/** The runtime config the tests load, as `public/config.json` has it but with an https sign-in origin. */
export const testConfig: AppConfig = {
  apiOrigin: '/v1',
  uploadOrigin: 'https://files.example',
  signInOrigin: 'https://auth.example.com',
  ssoSignIn: false,
};

export async function setUpApi(
  handler: FakeHandler,
  pathname = '/',
  config: Partial<AppConfig> = {},
): Promise<Harness> {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify({ ...testConfig, ...config }), { status: 200 })),
  );
  resetConfig();
  await loadConfig();

  const href = `https://app.example${pathname}`;
  const location = { pathname, href, assign: vi.fn() };
  vi.stubGlobal('window', { location });

  useAuthStore.setState(useAuthStore.getInitialState(), true);

  const sent: InternalAxiosRequestConfig[] = [];
  apiClient.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    sent.push(config);
    const reply = handler(config);
    const response: AxiosResponse = {
      status: reply.status,
      statusText: String(reply.status),
      data: reply.data,
      headers: {},
      config,
    };
    if (reply.status >= 400) {
      throw new AxiosError(`Request failed with status code ${reply.status}`, 'ERR_BAD_REQUEST', config, null, response);
    }
    return response;
  };

  return { sent, location };
}

export function header(config: InternalAxiosRequestConfig | undefined, name: string): unknown {
  return config ? AxiosHeaders.from(config.headers).get(name) : undefined;
}

export const member = {
  id: '0190c0de-0000-7000-8000-000000000001',
  email: 'aiko@example.co.jp',
  name: 'aiko@example.co.jp',
  role: 'member' as const,
  tenantId: '0190c0de-0000-7000-8000-0000000000aa',
  tenantName: 'Example KK',
};

/** A `GET /me` body in the contract's `CurrentMember` shape. */
export function currentMember(token: string, effectiveRole: 'admin' | 'member' = 'member') {
  return {
    user: {
      id: member.id,
      email: member.email,
      role: effectiveRole,
      status: 'active',
      sso_fallback: false,
      dlp_approver: false,
      created_at: '2026-10-01T00:00:00Z',
    },
    tenant: { id: member.tenantId, name: member.tenantName, status: 'active', created_at: '2026-01-01T00:00:00Z' },
    session: {
      auth_method: 'passkey',
      auth_time: '2026-11-04T00:00:00Z',
      effective_role: effectiveRole,
      expires_at: '2026-11-04T12:00:00Z',
    },
    csrf_token: token,
  };
}
