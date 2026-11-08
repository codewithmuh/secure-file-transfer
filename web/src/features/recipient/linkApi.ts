/**
 * The recipient's side of the API (#198): resolve the emailed link, ask for a code, verify it, then read the link
 * session and download its files (FR-6, FR-14, FR-15, FR-18). Pages call these, never `api` directly for links.
 *
 * - The link token comes from the URL fragment (`linkToken.ts`), stays in memory and goes only in request bodies.
 * - The link session's ID and CSRF token come from `createLinkSession` or `getLinkSession`, are checked with Zod (fail
 *   closed: a malformed answer leaves the page unverified) and go to the store, never to browser storage.
 * - A download's grant ID is kept per link session and file in `sessionStorage` until the download is handed to the
 *   browser, so a click after an interrupted start (even after the page is opened again) resumes the same grant,
 *   uncounted (`resume_grant_id`, `downloadFile`). It is not a credential: the content needs the `__Host-sft_link`
 *   cookie of the session that made it.
 */
import type { TFunction } from 'i18next';
import { AxiosError, AxiosHeaders } from 'axios';
import { z } from 'zod';
import { api, type Schema } from '@/api';
import { apiClient } from '@/lib/api';
import { getConfig } from '@/lib/config';
import i18n, { LANGUAGES, type Language } from '@/lib/i18n';
import { errorMessage, failureOf, problemCode } from '@/lib/problems';
import { useAuthStore } from '@/stores/authStore';

export type LinkResolution = Schema<'LinkResolution'>;
export type LinkSession = Schema<'LinkSession'>;
export type SessionFile = Schema<'SessionFile'>;
export type DownloadAccess = Schema<'DownloadAccess'>;
export type VerificationCodeRequested = Schema<'VerificationCodeRequested'>;

const id = z.string().regex(/^[0-9a-fA-F-]{32,36}$/);
const timestamp = z.string().min(1);
const locale = z.enum(['en', 'ja']);
const kind = z.enum(['transfer', 'upload_request']);

const resolutionSchema: z.ZodType<LinkResolution> = z.object({
  kind,
  access_state: z.enum(['verification_required', 'verified', 'locked']),
  link_session_id: id.optional(),
  locale,
});

/** The fields of `LinkSession` the pages read, checked against the generated contract types by the annotation. */
type LinkSessionFields = Pick<LinkSession, 'id' | 'csrf_token' | 'kind' | 'email' | 'locale' | 'expires_at'> & {
  transfer?: Schema<'LinkSessionTransfer'>;
};

const linkSessionSchema: z.ZodType<LinkSessionFields> = z.object({
  id,
  csrf_token: z.string().regex(/^[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]{43}$/),
  kind,
  email: z.string().min(1),
  locale,
  expires_at: timestamp,
  transfer: z
    .object({
      tenant_name: z.string(),
      sender_email: z.string().min(1),
      message: z.string().nullable(),
      expires_at: timestamp,
      download_limit: z.number().int().nullable(),
    })
    .optional(),
});

export type VerifiedSession = LinkSessionFields;

/** Thrown when the API's answer doesn't have the contract's shape: the page stays unverified. */
export class MalformedAnswer extends Error {
  constructor(what: string) {
    super(`The API's ${what} answer is malformed`);
    this.name = 'MalformedAnswer';
  }
}

function checked<T>(schema: z.ZodType<T>, data: unknown, what: string): T {
  const result = schema.safeParse(data);
  if (!result.success) throw new MalformedAnswer(what);
  return result.data;
}

/**
 * The page's language follows the link's `locale` (FR-33), whatever the browser prefers; `<html lang>` follows it
 * (i18n.ts). A locale the app doesn't have leaves the language as it is.
 */
export function applyLinkLocale(value: string): void {
  if ((LANGUAGES as readonly string[]).includes(value) && i18n.language !== value) {
    void i18n.changeLanguage(value as Language);
  }
}

/** `resolveLink`: what kind of link it is and whether this browser is verified for it. Reveals nothing else. */
export async function resolveLink(token: string): Promise<LinkResolution> {
  const response = await api.post('/links/resolve', { body: { token } });
  return checked(resolutionSchema, response.data, 'resolveLink');
}

/** One code every 30 seconds per link (`requestVerificationCode`, abuse-and-rate-limits 2.2 A). */
export const RESEND_WAIT_SECONDS = 30;

/** `requestVerificationCode`: a code to the address the link was sent to. */
export async function requestCode(token: string): Promise<VerificationCodeRequested> {
  return (await api.post('/links/codes', { body: { token } })).data;
}

/** Puts a checked session in the store. Only its ID and CSRF token are kept, in memory. */
function keep(session: LinkSessionFields): VerifiedSession {
  useAuthStore.getState().setLinkSession(session.id, session.csrf_token);
  return session;
}

/** `createLinkSession`: verifies the code. A malformed answer throws `MalformedAnswer` and stores nothing. */
export async function verifyCode(token: string, code: string): Promise<VerifiedSession> {
  const response = await api.post('/links/sessions', { body: { token, code } });
  return keep(checked(linkSessionSchema, response.data, 'createLinkSession'));
}

/**
 * Carries on in a session this browser already holds (`resolveLink` said `verified`): `getLinkSession` with that ID,
 * which also returns its CSRF token. Nothing is stored unless the answer is well formed and names the same session.
 * Like `createLinkSession`'s answer, it carries the sender, message and expiry the download page shows (FR-14).
 */
export async function resumeLinkSession(sessionId: string): Promise<VerifiedSession> {
  // This header names the session, and the request interceptor keeps it even while the store holds another link's.
  const response = await apiClient.get('/session', { headers: { 'X-Link-Session': sessionId } });
  const session = checked(linkSessionSchema, response.data, 'getLinkSession');
  if (session.id !== sessionId) throw new MalformedAnswer('getLinkSession');
  return keep(session);
}

/** `listSessionFiles`: the shareable files with their counts and warnings. */
export async function listSessionFiles(signal?: AbortSignal): Promise<SessionFile[]> {
  return (await api.get('/session/files', { signal })).data.items;
}

/** `endLinkSession`, then the store forgets the session and this tab its grants. */
export async function endLinkSession(): Promise<void> {
  const session = useAuthStore.getState().linkSession;
  try {
    await api.delete('/session');
  } finally {
    if (session) forgetGrants(session.id);
    useAuthStore.getState().clearLinkSession();
  }
}

// ---- download grants ----

const GRANT_PREFIX = 'sft.grant.';

function grantKey(sessionId: string, fileId: string): string {
  return `${GRANT_PREFIX}${sessionId}.${fileId}`;
}

/** `sessionStorage`, or nothing when the browser refuses it (a private window may): resuming is then not offered. */
function storage(): Storage | null {
  try {
    return globalThis.sessionStorage ?? null;
  } catch {
    return null;
  }
}

export function storedGrant(sessionId: string, fileId: string): string | null {
  try {
    return storage()?.getItem(grantKey(sessionId, fileId)) ?? null;
  } catch {
    return null;
  }
}

function storeGrant(sessionId: string, fileId: string, grantId: string | null): void {
  try {
    const store = storage();
    if (!store) return;
    if (grantId === null) store.removeItem(grantKey(sessionId, fileId));
    else store.setItem(grantKey(sessionId, fileId), grantId);
  } catch {
    // Storage full or refused: the next click counts a new download, as without resuming.
  }
}

function forgetGrants(sessionId: string): void {
  try {
    const store = storage();
    if (!store) return;
    const prefix = `${GRANT_PREFIX}${sessionId}.`;
    const keys = Array.from({ length: store.length }, (_, index) => store.key(index)).filter(
      (key): key is string => key?.startsWith(prefix) ?? false,
    );
    for (const key of keys) store.removeItem(key);
  } catch {
    // Nothing to forget.
  }
}

/**
 * `createSessionDownload`. With a grant this tab kept for the file, it sends `resume_grant_id` and gets the same grant
 * back, uncounted (FR-6). A kept grant the API no longer knows for this session (`404`) is dropped and a new download
 * asked for; one that is used up (`403 download_grant_exhausted`) is dropped and the error passed on, so the page
 * explains it and the next click counts a new download.
 */
export async function createDownload(fileId: string): Promise<DownloadAccess> {
  const session = useAuthStore.getState().linkSession;
  if (!session) throw new Error('No link session');
  const kept = storedGrant(session.id, fileId);
  const ask = (resume: string | null) =>
    api.post('/session/files/{file_id}/downloads', {
      path: { file_id: fileId },
      body: resume ? { resume_grant_id: resume } : {},
    });
  let access: DownloadAccess;
  try {
    access = (await ask(kept)).data;
  } catch (error) {
    const code = problemCode(error);
    if (kept && (code === 'download_grant_exhausted' || code === 'not_found')) storeGrant(session.id, fileId, null);
    if (!kept || code !== 'not_found') throw error;
    access = (await ask(null)).data;
  }
  storeGrant(session.id, fileId, access.grant_id);
  return access;
}

/**
 * Checks, from inside the app, that the content request will succeed, before the browser navigates to it: a failure
 * (`410 link_revoked`, `403 download_grant_exhausted`, `401`) is thrown as the API's problem and shown on the page,
 * instead of the browser replacing the app with the API's JSON. `HEAD` isn't offered and the API's CORS doesn't allow
 * `Range`, so it is a plain `GET`, cancelled as soon as the status and headers arrive; it costs one of the grant's 20
 * requests and the few bytes sent before the cancel reached the API. Like the navigation, it sends no
 * `X-Link-Session`: only the `__Host-sft_link` cookie (`credentials: 'include'`).
 */
export async function checkContent(href: string): Promise<void> {
  const abort = new AbortController();
  let response: Response;
  try {
    response = await fetch(href, { credentials: 'include', cache: 'no-store', redirect: 'error', signal: abort.signal });
  } catch (cause) {
    // No response: the page explains it as a network failure (`failureOf`), as for any call the network stopped.
    throw Object.assign(new AxiosError('The download could not start', AxiosError.ERR_NETWORK), { cause });
  }
  if (response.ok) {
    abort.abort();
    return;
  }
  let data: unknown = null;
  try {
    data = await response.json();
  } catch {
    // Not a problem document: the status alone says what happened.
  }
  const headers = new AxiosHeaders();
  response.headers.forEach((value, name) => headers.set(name, value));
  throw new AxiosError(`Request failed with status code ${response.status}`, AxiosError.ERR_BAD_REQUEST, undefined, null, {
    status: response.status,
    statusText: response.statusText,
    data,
    headers,
    config: { headers },
  });
}

/**
 * Starts the browser's own download of `href` by navigating a hidden link (`getSessionDownloadContent`): the response
 * is an attachment, so the page stays, and the download manager saves the file and resumes it with `Range` and
 * `If-Range`. A navigation sends no `X-Link-Session`, as the contract says; the `__Host-sft_link` cookie goes with it.
 */
export function startDownload(href: string, doc: Document = document): void {
  const link = doc.createElement('a');
  link.href = href;
  link.rel = 'noopener';
  link.hidden = true;
  doc.body.appendChild(link);
  try {
    link.click();
  } finally {
    link.remove();
  }
}

/**
 * Whether "Download" is off for a file: its counted downloads are used up, and this tab keeps no grant of an
 * interrupted start to resume uncounted (`downloadFile` forgets a grant once the browser has its download).
 */
export function downloadsUsedUp(file: Pick<SessionFile, 'download_limit' | 'downloads_used'>, kept: string | null): boolean {
  const limit = file.download_limit ?? null;
  return limit !== null && (file.downloads_used ?? 0) >= limit && kept === null;
}

/** The content request's problems after which a kept grant can't resume: the next click counts a new download. */
const GRANT_ENDED = new Set(['download_grant_exhausted', 'not_found']);

/**
 * One click on "Download" (FR-6): a grant (`createDownload`, which resumes a kept one uncounted), the in-app check
 * (`checkContent`), then the browser's download. A grant is kept in `sessionStorage` only until its download is handed
 * to the browser: from then on the download manager resumes it itself, by `Range` under the same grant, and the page
 * can't see whether it finished, so a later click counts a new download rather than taking a further copy uncounted.
 * A grant whose check failed for a while (`503`, `429`, the network, or the page closing in between) stays kept, so
 * the next click resumes it uncounted; one that can't resume is dropped. A `401` ends the link session in the store,
 * as for any `/session` call, so the page goes back to the code step.
 */
export async function downloadFile(fileId: string, doc: Document = document): Promise<DownloadAccess> {
  const session = useAuthStore.getState().linkSession;
  if (!session) throw new Error('No link session');
  const access = await createDownload(fileId);
  try {
    await checkContent(contentUrl(access.url));
  } catch (error) {
    const failure = failureOf(error);
    const code = failure.problem?.code;
    if (code && GRANT_ENDED.has(code)) storeGrant(session.id, fileId, null);
    if (failure.status === 401) useAuthStore.getState().expireLinkSession(session.id);
    throw error;
  }
  startDownload(contentUrl(access.url), doc);
  storeGrant(session.id, fileId, null);
  return access;
}

// ---- what a failed link call means ----

/** The link states with a page of their own (#198): not found, revoked, expired, locked. */
export type LinkGone = 'not_found' | 'revoked' | 'expired' | 'locked';

const GONE: Partial<Record<string, LinkGone>> = {
  link_not_found: 'not_found',
  link_revoked: 'revoked',
  link_expired: 'expired',
  recipient_locked: 'locked',
};

/** The link state a failed call reveals, or null when the page should explain the error where it happened. */
export function goneOf(error: unknown): LinkGone | null {
  const code = problemCode(error);
  return (code && GONE[code]) ?? null;
}

/** The problems the recipient's steps explain in their own words (`recipient.problems.<code>` in i18n.ts). */
export const RECIPIENT_PROBLEMS = [
  'code_invalid',
  'code_expired',
  'code_attempts_exhausted',
  'recipient_undeliverable',
  'rate_limited',
  'download_limit_reached',
  'download_grant_exhausted',
  'file_not_shareable',
  'service_unavailable',
] as const satisfies readonly Schema<'ProblemCode'>[];

/**
 * The text for a failed link call: the recipient's own text for the codes above (`code_invalid` with the attempts
 * the code still allows), else the member pages' text for the code or status, then any `Retry-After` wait.
 */
export function linkProblemText(error: unknown, t: TFunction): string {
  if (error instanceof MalformedAnswer) return t('recipient.malformed');
  const failure = failureOf(error);
  const code = failure.problem?.code;
  if (!code || !(RECIPIENT_PROBLEMS as readonly string[]).includes(code)) return errorMessage(error, t);
  const text = t(`recipient.problems.${code}`, { count: failure.problem?.attempts_remaining ?? 0 });
  return failure.retryAfter === null ? text : `${text} ${t('problems.retryAfter', { count: failure.retryAfter })}`;
}

/**
 * Where the browser fetches a grant's bytes. The contract gives a path starting `/v1/`, which belongs to the API's
 * scheme and host (`config.apiOrigin`, which already ends in `/v1`), never to the web app's origin: locally the API is
 * on :8000 and the app on :3000, and in AWS they are separate origins too. Behind the dev server's proxy (`apiOrigin:
 * /v1`) the API is on the page's origin. An absolute URL is accepted only on the API's origin.
 */
export function contentUrl(url: string, apiOrigin = getConfig().apiOrigin, pageOrigin = globalThis.location?.origin): string {
  const apiBase = new URL(apiOrigin, pageOrigin);
  if (url.startsWith('/v1/')) return new URL(url, apiBase.origin).href;
  const absolute = new URL(url, apiBase.href);
  if (absolute.origin !== apiBase.origin || !absolute.pathname.startsWith('/v1/')) {
    throw new Error('A download URL that is not on the API');
  }
  return absolute.href;
}
