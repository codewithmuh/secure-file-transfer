/** Where a member lands after sign-in when the return path is missing or refused: the dashboard. */
export const DEFAULT_RETURN_PATH = '/';

/**
 * Route prefixes a member may be sent back to after sign-in: the protected routes in `app/router.tsx`. The sign-in
 * pages and the public link pages (`/t`, `/u`) are left out on purpose.
 */
export const RETURN_PATH_PREFIXES = ['/transfers', '/upload-requests', '/admin'] as const;

/** The contract's limit for the return path (`ReturnTo`, maxLength 512). */
const MAX_LENGTH = 512;

/**
 * A path, then an optional query, from a small set of characters. That leaves out `%` (no encoded tricks: the
 * value has already been decoded once by `URLSearchParams`), `\`, `#`, `@`, `:`, whitespace and control characters.
 */
const SAFE_SHAPE = /^\/[A-Za-z0-9\-._~/]*(\?[A-Za-z0-9\-._~=&]*)?$/;

/**
 * Returns `raw` when it is a same-app relative path under an allowed route prefix, otherwise the dashboard. The API
 * checks the return path too (authn-authz 2.4, "no open redirect"); this is the web app's own check.
 */
export function safeReturnPath(raw: string | null | undefined): string {
  if (!raw || raw.length > MAX_LENGTH || !SAFE_SHAPE.test(raw)) return DEFAULT_RETURN_PATH;

  const path = raw.split('?', 1)[0] ?? '';
  const segments = path.split('/').slice(1);
  // `//host` (protocol-relative), empty segments and dot segments are refused, so nothing is normalised away.
  if (path.startsWith('//') || segments.some((s, i) => s === '.' || s === '..' || (s === '' && i < segments.length - 1))) {
    return DEFAULT_RETURN_PATH;
  }

  if (path === '/') return raw;
  const allowed = RETURN_PATH_PREFIXES.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
  return allowed ? raw : DEFAULT_RETURN_PATH;
}

/** The path a protected route sent the member here from (`ProtectedRoute`), so sign-in can return to it. */
export function returnPathOf(state: unknown): string | null {
  if (typeof state !== 'object' || state === null || !('from' in state)) return null;
  const from = (state as { from: unknown }).from;
  if (typeof from !== 'object' || from === null) return null;
  const { pathname, search } = from as { pathname?: unknown; search?: unknown };
  if (typeof pathname !== 'string') return null;
  return `${pathname}${typeof search === 'string' ? search : ''}`;
}
