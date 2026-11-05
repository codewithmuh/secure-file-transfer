import axios from 'axios';
import { z } from 'zod';
import { api, type CurrentMember, type Schema } from '@/api';
import { useAuthStore } from '@/stores/authStore';
import { safeReturnPath } from './returnPath';

/** The fields of `CurrentMember` the web app reads, with the contract's types. */
interface MemberFields {
  user: Pick<CurrentMember['user'], 'id' | 'email'>;
  tenant: Pick<CurrentMember['tenant'], 'id' | 'name'>;
  session: Pick<CurrentMember['session'], 'effective_role'>;
  csrf_token: CurrentMember['csrf_token'];
}

/**
 * Checks `GET /me` at run time, so a malformed answer signs the member out (fail closed). The annotation makes the
 * type check fail if what this accepts stops fitting the generated contract types.
 */
const currentMemberSchema: z.ZodType<MemberFields> = z.object({
  user: z.object({ id: z.string().min(1), email: z.string().min(1) }),
  tenant: z.object({ id: z.string().min(1), name: z.string() }),
  session: z.object({ effective_role: z.enum(['admin', 'member']) }),
  csrf_token: z.string().regex(/^[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]{43}$/),
});

/** Only an https logout URL is followed (authn-authz 3.5); anything else, such as `javascript:`, fails the check. */
const signOutResultSchema: z.ZodType<Schema<'SignOutResult'>> = z.object({ logout_url: z.url({ protocol: /^https$/ }) });

export const SIGN_IN_FAILED_PATH = '/sign-in?error=sign_in_failed';

let pending: Promise<boolean> | null = null;

/**
 * Asks the API who is signed in (`GET /me`) and puts the member and their CSRF token in the store. The session is an
 * HttpOnly cookie, so this is how a page load or a deep link finds out it is still signed in; no token is ever kept
 * in browser storage. Resolves `true` when signed in. Any failure leaves the member signed out (fail closed).
 * Concurrent calls share one request.
 */
export function restoreMemberSession(): Promise<boolean> {
  if (pending) return pending;
  useAuthStore.getState().beginMemberCheck();
  pending = api
    .get('/me', { skipAuthRedirect: true })
    .then((response) => {
      const me = currentMemberSchema.parse(response.data);
      useAuthStore.getState().setAuth(
        {
          id: me.user.id,
          email: me.user.email,
          name: me.user.email,
          role: me.session.effective_role,
          tenantId: me.tenant.id,
          tenantName: me.tenant.name,
        },
        me.csrf_token,
      );
      return true;
    })
    .catch(() => {
      useAuthStore.getState().clearAuth();
      return false;
    })
    .finally(() => {
      pending = null;
    });
  return pending;
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
    if (result.success) destination = result.data.logout_url;
  } catch (error) {
    if (!(axios.isAxiosError(error) && error.response?.status === 401)) throw error;
  }
  useAuthStore.getState().clearAuth();
  window.location.assign(destination);
}
