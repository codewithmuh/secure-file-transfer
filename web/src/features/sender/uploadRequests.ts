import type { FileState, Schema, UploadRequest, UploadRequestState } from '@/api';
import { durationSeconds, MAX_EXPIRY } from '@/lib/durations';
import { POLL_INTERVAL_MS } from './polling';
import type { BadgeVariant } from './states';

/**
 * The member's side of upload requests (#212, #213; UC-2, FR-10 to FR-13, FR-20): how the pages show a request and
 * its received files, when they poll, and the body `createUploadRequest` gets. Kept apart from React so it can be
 * tested on its own.
 */

export type UploadRequestCreate = Schema<'UploadRequestCreate'>;
export type Locale = Schema<'Locale'>;
type ApiFile = Schema<'File'>;

export const UPLOAD_REQUEST_STATES: readonly UploadRequestState[] = ['open', 'revoked', 'expired'];

/** A badge colour per state; the label is always text too (`uploadRequestState.<state>`, WCAG 1.4.1). */
export const uploadRequestStateVariant: Record<UploadRequestState, BadgeVariant> = {
  open: 'success',
  revoked: 'danger',
  expired: 'default',
};

/** How often an open request is read again: its link email, the uploader's verification and what arrived. */
export const REQUEST_POLL_INTERVAL_MS = 10_000;

/** File states the service moves on by itself: a completion and a scan. */
const SERVER_MOVES: readonly FileState[] = ['completing', 'scanning'];

/** `getUploadRequest` is polled while the request is open: the uploader may verify, lock or upload at any time. */
export function requestPollInterval(request: Pick<UploadRequest, 'state'> | undefined): number | false {
  return request?.state === 'open' ? REQUEST_POLL_INTERVAL_MS : false;
}

/**
 * `listUploadRequestFiles` is polled fast while a file completes or is scanned, slower while the request is open (the
 * uploader may add files), and not at all once it has ended and nothing moves.
 */
export function receivedFilesPollInterval(
  files: readonly Pick<ApiFile, 'state'>[] | undefined,
  state: UploadRequestState | undefined,
): number | false {
  if (files?.some((file) => SERVER_MOVES.includes(file.state))) return POLL_INTERVAL_MS;
  return state === 'open' ? REQUEST_POLL_INTERVAL_MS : false;
}

/** File states in which the member may delete a received file early (FR-13): the upload and the scan are over. */
export const DELETABLE_RECEIVED_STATES: readonly FileState[] = ['clean', 'infected', 'unscannable', 'scan_failed', 'rejected'];

/**
 * Only the member who created the request may download or delete its files; a tenant admin sees the metadata only
 * (`403 permission_denied` otherwise, UC-3). A download needs a shareable file (FR-16).
 */
export function receivedFileActions(file: Pick<ApiFile, 'state' | 'shareable'>, isOwner: boolean) {
  return {
    download: isOwner && file.shareable && file.state !== 'deleted',
    remove: isOwner && DELETABLE_RECEIVED_STATES.includes(file.state),
  };
}

/** Whether the request can still be revoked, and its uploader unlocked: it is open. */
export function isOpen(request: Pick<UploadRequest, 'state'>): boolean {
  return request.state === 'open';
}

// ---- the create form (#212) ----

/**
 * A request is open from creation, so the contract takes a time (`expires_at`), not a duration: between 1 hour and 30
 * days from now, within the tenant's `max_expiry` (FR-3). The form offers durations, as the create-transfer form does,
 * and turns the chosen one into a time when it is sent. This margin is added so that the shortest choice is still an
 * hour from the API's "now" when the request arrives; the result never passes the cap.
 */
export const EXPIRY_MARGIN_MS = 120_000;

export interface RequestForm {
  email: string;
  locale: Locale;
  /** An ISO 8601 duration from `expiryOptions`. */
  expiresIn: string;
  message: string;
}

/** The longest a request may stay open: the tenant's `max_expiry`, never over 30 days. */
export function expiryCapSeconds(maxExpiry: string | undefined): number {
  const thirty = durationSeconds(MAX_EXPIRY) as number;
  const cap = maxExpiry === undefined ? null : durationSeconds(maxExpiry);
  return cap === null ? thirty : Math.min(cap, thirty);
}

/** The `expires_at` for a duration chosen at `now` (ms): now plus the duration and the margin, at most now plus the cap. */
export function expiresAtFor(expiresIn: string, maxExpiry: string | undefined, now: number): string {
  const seconds = durationSeconds(expiresIn) ?? (durationSeconds('P7D') as number);
  const capMs = expiryCapSeconds(maxExpiry) * 1000;
  return new Date(now + Math.min(seconds * 1000 + EXPIRY_MARGIN_MS, capMs)).toISOString();
}

/** The `createUploadRequest` body for the form, sent at `now`. An empty message is left out. */
export function requestBody(form: RequestForm, maxExpiry: string | undefined, now: number): UploadRequestCreate {
  return {
    uploader_email: form.email.trim(),
    locale: form.locale,
    expires_at: expiresAtFor(form.expiresIn, maxExpiry, now),
    ...(form.message.trim() ? { message: form.message } : {}),
  };
}

/**
 * The body of the current attempt at creating a request. The body holds a time computed when it was first sent, so a
 * retry of the same form must send that body again, byte for byte: the `Idempotency-Key` (`IdempotencyKeys.keyForBody`)
 * then stays the same and the API replays its first answer instead of creating a second request. A changed form is a
 * new attempt, with a new time and so a new key; `done` starts a new attempt after a success or a definite refusal.
 */
export class RequestAttempt {
  private current: { form: string; body: UploadRequestCreate } | null = null;

  bodyFor(form: RequestForm, maxExpiry: string | undefined, now: number): UploadRequestCreate {
    const fingerprint = JSON.stringify([form.email.trim(), form.locale, form.expiresIn, form.message, maxExpiry ?? null]);
    if (this.current?.form === fingerprint) return this.current.body;
    const body = requestBody(form, maxExpiry, now);
    this.current = { form: fingerprint, body };
    return body;
  }

  done(): void {
    this.current = null;
  }
}
