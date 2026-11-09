import { create } from 'zustand';

/** The signed-in member, from `GET /me` (`getCurrentMember`). */
export interface Member {
  id: string;
  email: string;
  /** The contract's `User` has no display name, so this is the email address for now. */
  name: string;
  /** `session.effective_role`: a local admin without a passkey sign-in acts as `member` (authn-authz 3.3). */
  role: 'admin' | 'member';
  /** `user.dlp_approver`: the member may approve other members' transfers (FR-43). */
  dlpApprover: boolean;
  /** `session.auth_method`: how this session signed in, so a step-up signs in the same way again (#232). */
  authMethod: 'passkey' | 'password_totp' | 'local' | 'sso';
  tenantId: string;
  tenantName: string;
}

/**
 * Whether this tab knows if the browser holds a member session. The session itself is an HttpOnly cookie the web
 * app can't read (authn-authz 3.1), so the status stays `unknown` until the first `GET /me` answers.
 */
export type MemberStatus = 'unknown' | 'checking' | 'authenticated' | 'anonymous';

/** Which public link page a link token was opened on: `/t` (recipient) or `/u` (uploader). */
export type LinkMode = 'recipient' | 'uploader';

/** A recipient's or uploader's link session (authn-authz 4.3). The ID is not a credential. */
export interface LinkSession {
  id: string;
  csrfToken: string;
}

export interface AuthState {
  // Member session. Only member routes use these.
  memberStatus: MemberStatus;
  user: Member | null;
  memberCsrfToken: string | null;

  // Link session. Only `/session` routes use these, and nothing here ever touches the member's fields.
  /** The link token from the URL fragment, kept in memory only so the page can verify again after a lapse. */
  linkToken: { mode: LinkMode; value: string } | null;
  linkSession: LinkSession | null;
  /** The API ended the link session (401): the page goes back to its verification step. */
  linkSessionLapsed: boolean;

  beginMemberCheck: () => void;
  setAuth: (user: Member, csrfToken: string) => void;
  clearAuth: () => void;

  setLinkToken: (mode: LinkMode, value: string) => void;
  setLinkSession: (sessionId: string, csrfToken: string) => void;
  clearLinkSession: () => void;
  /** Ends the link session after a 401, if it is still the one the failed request named. */
  expireLinkSession: (sessionId?: string) => void;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  memberStatus: 'unknown',
  user: null,
  memberCsrfToken: null,

  linkToken: null,
  linkSession: null,
  linkSessionLapsed: false,

  beginMemberCheck: () => set({ memberStatus: 'checking' }),
  setAuth: (user, csrfToken) => set({ memberStatus: 'authenticated', user, memberCsrfToken: csrfToken }),
  clearAuth: () => set({ memberStatus: 'anonymous', user: null, memberCsrfToken: null }),

  setLinkToken: (mode, value) => set({ linkToken: { mode, value } }),
  setLinkSession: (sessionId, csrfToken) =>
    set({ linkSession: { id: sessionId, csrfToken }, linkSessionLapsed: false }),
  clearLinkSession: () => set({ linkSession: null, linkSessionLapsed: false }),
  expireLinkSession: (sessionId) => {
    const current = get().linkSession;
    if (!current || (sessionId !== undefined && sessionId !== current.id)) return;
    set({ linkSession: null, linkSessionLapsed: true });
  },
}));
