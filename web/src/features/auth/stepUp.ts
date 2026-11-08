import type { Member } from '@/stores/authStore';
import { signInUrl } from './memberSession';

/**
 * The pure parts of the step-up sign-in (#232; FR-35, authn-authz 3.3): which way to sign in again, where the popup
 * lands, and the one message it may send back. The dialog (`StepUpDialog`) and the popup's page
 * (`StepUpCompletePage`) use these.
 */

/** Where the step-up sign-in in the popup comes back to: the page that tells the opener and closes. */
export const STEP_UP_COMPLETE_PATH = '/auth/step-up-complete';

/** The message type the popup posts to its opener when the sign-in is done. It carries nothing else. */
export const STEP_UP_MESSAGE_TYPE = 'sft:step-up-complete';

export interface StepUpMessage {
  type: typeof STEP_UP_MESSAGE_TYPE;
}

export const STEP_UP_MESSAGE: StepUpMessage = { type: STEP_UP_MESSAGE_TYPE };

/** The way in for a step-up: the same as the session's, so an SSO member goes back to their identity provider. */
export interface StepUpSignIn {
  method: 'local' | 'sso';
  /** For `sso`: the domain of the member's address, the only part of it the sign-in start receives. */
  domain?: string;
}

/** The domain of an email address, lower case; `null` when there is none. */
export function emailDomain(email: string): string | null {
  const at = email.lastIndexOf('@');
  if (at < 1) return null;
  const domain = email.slice(at + 1).trim().toLowerCase();
  return domain.includes('.') && !/[\s/@?#\\]/.test(domain) ? domain : null;
}

/**
 * `sso`, with the domain of the member's address, when this session signed in through the tenant's identity provider
 * (`session.auth_method = sso`); `local` otherwise, and for an SSO session whose address has no usable domain (the
 * API would refuse `method=sso` without one).
 */
export function stepUpSignIn(member: Pick<Member, 'authMethod' | 'email'> | null | undefined): StepUpSignIn {
  if (member?.authMethod === 'sso') {
    const domain = emailDomain(member.email);
    if (domain) return { method: 'sso', domain };
  }
  return { method: 'local' };
}

/** The sign-in start URL for a step-up, coming back to `returnTo`. */
export function stepUpSignInUrl(member: Pick<Member, 'authMethod' | 'email'> | null | undefined, returnTo: string): string {
  const { method, domain } = stepUpSignIn(member);
  return signInUrl(method, returnTo, domain);
}

/**
 * Whether a `message` event is the popup's "done": from this app's own origin and of the one known type. Anything else,
 * from any other window or origin, is ignored.
 */
export function isStepUpMessage(event: Pick<MessageEvent, 'origin' | 'data'>, ownOrigin: string): boolean {
  if (event.origin !== ownOrigin) return false;
  const data: unknown = event.data;
  return typeof data === 'object' && data !== null && (data as { type?: unknown }).type === STEP_UP_MESSAGE_TYPE;
}

/**
 * What the opener does once the new session is loaded: send the request again only when the same member signed in.
 * A sign-in as someone else must never send the first member's change under the new identity.
 */
export function stepUpOutcome(before: Pick<Member, 'id'> | null, after: Pick<Member, 'id'> | null): 'retry' | 'failed' | 'other_member' {
  if (!after) return 'failed';
  if (!before || before.id !== after.id) return 'other_member';
  return 'retry';
}
