import axios from 'axios';
import { getConfig } from './config';
import { useAuthStore } from '@/stores/authStore';

declare module 'axios' {
  interface AxiosRequestConfig {
    /** On a member 401, clear member auth but don't leave the page: the caller handles it (the session probe). */
    skipAuthRedirect?: boolean;
  }
}

/**
 * Which credential a request carries (authn-authz 1, "one credential per request"):
 * - `link`: `/session` routes, which read only the link session named in `X-Link-Session`.
 * - `public`: sign-in and link verification routes, which take no session; and any absolute URL, so the
 *   app's CSRF token or link session ID never goes to another origin.
 * - `member`: every other route, with the member session.
 */
export type RequestScope = 'member' | 'link' | 'public';

const PUBLIC_ROUTES = ['/auth/sign-in', '/auth/callback', '/auth/invitations', '/links'];
const UNSAFE_METHODS = new Set(['post', 'put', 'patch', 'delete']);

function underRoute(path: string, route: string): boolean {
  return path === route || path.startsWith(`${route}/`);
}

export function requestScope(url: string | undefined): RequestScope {
  const raw = url ?? '';
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.startsWith('//')) return 'public';
  const pathOnly = raw.split(/[?#]/, 1)[0] ?? '';
  const path = pathOnly.startsWith('/') ? pathOnly : `/${pathOnly}`;
  if (underRoute(path, '/session')) return 'link';
  if (PUBLIC_ROUTES.some((route) => underRoute(path, route))) return 'public';
  return 'member';
}

function problemCode(data: unknown): string | undefined {
  if (typeof data === 'object' && data !== null && 'code' in data) {
    const { code } = data as { code: unknown };
    return typeof code === 'string' ? code : undefined;
  }
  return undefined;
}

export const apiClient = axios.create({
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use((config) => {
  config.baseURL = getConfig().apiOrigin;

  const scope = requestScope(config.url);
  const unsafe = UNSAFE_METHODS.has((config.method ?? 'get').toLowerCase());
  const { memberCsrfToken, linkSession } = useAuthStore.getState();

  if (scope === 'member' && unsafe && memberCsrfToken) {
    config.headers['X-CSRF-Token'] = memberCsrfToken;
  }

  if (scope === 'link' && linkSession) {
    // A request that names its session (resuming another link's session) keeps it; the held session's CSRF token
    // goes only with the held session.
    const named = config.headers.get('X-Link-Session');
    if (named === undefined || named === null) config.headers.set('X-Link-Session', linkSession.id);
    if (unsafe && (named ?? linkSession.id) === linkSession.id) config.headers.set('X-CSRF-Token', linkSession.csrfToken);
  }

  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      const code = problemCode(error.response.data);
      if (code === 'authentication_required' || code === 'session_expired') {
        const scope = requestScope(error.config?.url);
        const auth = useAuthStore.getState();
        if (scope === 'link') {
          // The recipient or uploader goes back to the verification step for their link; member auth is untouched.
          const sentId = error.config?.headers?.['X-Link-Session'];
          auth.expireLinkSession(typeof sentId === 'string' ? sentId : undefined);
        } else if (scope === 'member') {
          auth.clearAuth();
          if (!error.config?.skipAuthRedirect) window.location.assign('/sign-in');
        }
      }
    }
    return Promise.reject(error);
  },
);
