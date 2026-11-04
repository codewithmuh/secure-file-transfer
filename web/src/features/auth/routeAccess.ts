import type { Member, MemberStatus } from '@/stores/authStore';

/** What a protected route shows: a loading state, the sign-in page, the dashboard (wrong role) or the page. */
export type RouteAccess = 'wait' | 'sign-in' | 'forbidden' | 'allow';

export function routeAccess(
  status: MemberStatus,
  role: Member['role'] | undefined,
  requiredRole?: Member['role'],
): RouteAccess {
  // Until `GET /me` answers, the app can't know whether the session cookie is still valid.
  if (status === 'unknown' || status === 'checking') return 'wait';
  if (status !== 'authenticated') return 'sign-in';
  if (requiredRole === 'admin' && role !== 'admin') return 'forbidden';
  return 'allow';
}
