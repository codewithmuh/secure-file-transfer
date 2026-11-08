import axios from 'axios';
import { z } from 'zod';
import { api, type CurrentMember, type Schema } from '@/api';
import { apiUrl, getConfig } from '@/lib/config';
import { useAuthStore, type Member } from '@/stores/authStore';
import { safeReturnPath } from './returnPath';

/** The fields of `CurrentMember` the web app reads, with the contract's types. */
interface MemberFields {
  user: Pick<CurrentMember['user'], 'id' | 'email' | 'dlp_approver'>;
  tenant: Pick<CurrentMember['tenant'], 'id' | 'name'>;
  session: Pick<CurrentMember['session'], 'effective_role' | 'auth_method'>;
  csrf_token: CurrentMember['csrf_token'];
}

/**
 * Checks `GET /me` at run time, so a malformed answer signs the member out (fail closed). The annotation makes the
 * type check fail if what this accepts stops fitting the generated contract types.
 */
const currentMemberSchema: z.ZodType<MemberFields> = z.object({
  user: z.object({ id: z.string().min(1), email: z.string().min(1), dlp_approver: z.boolean() }),
  tenant: z.object({ id: z.string().min(1), name: z.string() }),
  session: z.object({
    effective_role: z.enum(['admin', 'member']),
    auth_method: z.enum(['passkey', 'password_totp', 'local', 'sso']),
  }),
  csrf_token: z.string().regex(/^[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]{43}$/),
});

const signOutResultSchema: z.ZodType<Schema<'SignOutResult'>> = z.object({ logout_url: z.url({ protocol: /^https?$/ }) });

/**
 * Whether the browser may follow the API's logout URL: only to the user pool's own sign-in origin, `signInOrigin` in
 * the config (authn-authz 3.5): managed login over https in AWS, Keycloak on http://localhost:8180 in the local stack.
 * A `javascript:` URL, another scheme or another origin is refused, so the API's answer can't send the member anywhere
 * else.
 */
export function isLogoutUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
  return parsed.origin === new URL(getConfig().signInOrigin).origin;
}

/**
 * Where the sign-in page sends the browser: `startSignIn` on the API's origin, with the checked path to come back to
 * (`return_to`), so a deep link lands where it pointed after the user pool. `sso` sends only the address's domain.
 */
export function signInUrl(method: 'local' | 'sso', returnTo: string | null | undefined, ssoDomain?: string): string {
  const params = new URLSearchParams({ method });
  if (method === 'sso' && ssoDomain) params.set('sso_domain', ssoDomain);
  params.set('return_to', safeReturnPath(returnTo));
  return apiUrl(`/auth/sign-in?${params.toString()}`);
}

export const SIGN_IN_FAILED_PATH = '/sign-in?error=sign_in_failed';

let pending: Promise<boolean> | null = null;

/** `GET /me`, checked, into the store: the member and the CSRF token of the session the cookie holds now. */
async function loadMember(): Promise<Member> {
  const response = await api.get('/me', { skipAuthRedirect: true });
  const me = currentMemberSchema.parse(response.data);
  const member: Member = {
    id: me.user.id,
    email: me.user.email,
    name: me.user.email,
    role: me.session.effective_role,
    dlpApprover: me.user.dlp_approver,
    authMethod: me.session.auth_method,
    tenantId: me.tenant.id,
    tenantName: me.tenant.name,
  };
  useAuthStore.getState().setAuth(member, me.csrf_token);
  return member;
}

/**
 * Asks the API who is signed in (`GET /me`) and puts the member and their CSRF token in the store. The session is an
 * HttpOnly cookie, so this is how a page load or a deep link finds out it is still signed in; no token is ever kept
 * in browser storage. Resolves `true` when signed in. Any failure leaves the member signed out (fail closed).
 * Concurrent calls share one request.
 */
export function restoreMemberSession(): Promise<boolean> {
  if (pending) return pending;
  useAuthStore.getState().beginMemberCheck();
  pending = loadMember()
    .then(() => true)
    .catch(() => {
      useAuthStore.getState().clearAuth();
      return false;
    })
    .finally(() => {
      pending = null;
    });
  return pending;
}

/**
 * Loads the session again after a step-up sign-in in another window (#232): that sign-in made a new session and revoked
 * this one, so the CSRF token in memory is stale. Unlike `restoreMemberSession`, the member's status never goes back
 * to `checking`, so the protected page stays mounted with its form as it was. Resolves the member, or `null` when the
 * session can't be loaded. A `401` signs the member out as on any request (without leaving the page); any other
 * failure leaves the store as it was.
 */
export async function refreshMemberSession(): Promise<Member | null> {
  try {
    return await loadMember();
  } catch {
    return null;
  }
}

/** The `/auth/callback` page: load the new session, then go to a checked return path. Returns where to go. */
export async function finishSignIn(params: URLSearchParams): Promise<string> {
  if (params.get('error')) return SIGN_IN_FAILED_PATH;
  const signedIn = await restoreMemberSession();
  return signedIn ? safeReturnPath(params.get('return_path')) : SIGN_IN_FAILED_PATH;
}

/**
 * Signs out (`signOut`): the API revokes the session and clears the cookie, then the browser goes to the user pool's
 * logout URL so managed login's own cookie is cleared too (authn-authz 3.5). A `401` means the session had already
 * ended, which counts as signed out. Any other failure is thrown and the member stays signed in, so nobody walks away
 * from a session they think has ended.
 */
export async function signOutMember(): Promise<void> {
  let destination = '/sign-in';
  try {
    const response = await api.post('/auth/sign-out', { body: { all_sessions: false }, skipAuthRedirect: true });
    const result = signOutResultSchema.safeParse(response.data);
    if (result.success && isLogoutUrl(result.data.logout_url)) destination = result.data.logout_url;
  } catch (error) {
    if (!(axios.isAxiosError(error) && error.response?.status === 401)) throw error;
  }
  useAuthStore.getState().clearAuth();
  window.location.assign(destination);
}
