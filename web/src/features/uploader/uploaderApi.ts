/**
 * The uploader's side of an upload request (#212, #213; FR-11, FR-12, FR-14, FR-15), after verifying on `/u`. Pages
 * call these, never `api` directly.
 *
 * - **Calls.** Every call is a `/session` route, so the API client's interceptor sends the link session's ID in
 *   `X-Link-Session` and, on an unsafe call, its CSRF token (authn-authz 1), as for the recipient's pages.
 * - **Uploads.** The M3 upload engine (`FileUpload`, `features/sender/upload.ts`) runs unchanged over the session's
 *   operations (`sessionUploadApi`): `listSessionUploadedParts` first, so a resumed upload sends only missing parts,
 *   then part URLs from `requestSessionUploadPartUrls`, the `PUT`s to storage, and `completeSessionUpload`.
 * - **Taking a file back** (#229). While the request is open, the uploader may remove a file they declared or
 *   uploaded (`deleteSessionUploadFile`), unless it was blocked: it stops counting toward the limits and the company
 *   never gets it. The engine is still given no `deleteFile`: the page removes a file, never an upload by itself.
 * - **What the uploader sees.** Each file's state from `listSessionFiles`, as a few plain words: a blocked file says
 *   only "blocked by the company's policy" or "couldn't be scanned", never a finding or a scan detail (FR-12). An
 *   unscannable file the company's policy accepts (`warning: unscannable`) reads as accepted, not as a failure (#229).
 *   A file the API marks `blocked` (malware, a failed scan, or the company's data policy, FR-51) reads "not accepted",
 *   with no reason: the company sees why (#221).
 */
import type { TFunction } from 'i18next';
import { api, type FileState, type Schema } from '@/api';
import type { UploadApi } from '@/features/sender/upload';
import { linkProblemText } from '@/features/recipient/linkApi';
import { failureOf } from '@/lib/problems';
import type { BadgeVariant } from '@/features/sender/states';

export type SessionFile = Schema<'SessionFile'>;
export type FileCreate = Schema<'FileCreate'>;
export type LinkSessionUploadRequest = Schema<'LinkSessionUploadRequest'>;

/** The engine's calls for one of the uploader's files. */
export const sessionUploadApi: UploadApi<SessionFile> = {
  async listUploadedParts(fileId) {
    return (await api.get('/session/files/{file_id}/parts', { path: { file_id: fileId } })).data;
  },
  async requestPartUrls(fileId, partNumbers) {
    return (
      await api.post('/session/files/{file_id}/parts', { path: { file_id: fileId }, body: { part_numbers: partNumbers } })
    ).data.parts;
  },
  async completeUpload(fileId) {
    return (await api.post('/session/files/{file_id}/complete', { path: { file_id: fileId } })).data;
  },
};

/** `addSessionUploadFile`: declares the file and returns it with its upload plan; replayed by its `Idempotency-Key`. */
export async function addSessionUploadFile(body: FileCreate, idempotencyKey: string): Promise<SessionFile> {
  return (await api.post('/session/files', { body, headers: { 'Idempotency-Key': idempotencyKey } })).data;
}

/** `deleteSessionUploadFile`: takes a file back while the request is open; a retry of a removed file is fine (`204`). */
export async function deleteSessionUploadFile(fileId: string): Promise<void> {
  await api.delete('/session/files/{file_id}', { path: { file_id: fileId } });
}

/** `listSessionFiles` for an uploader: the files they sent to this request, each with its state. */
export async function listUploadedFiles(signal?: AbortSignal): Promise<SessionFile[]> {
  return (await api.get('/session/files', { signal })).data.items;
}

// ---- what the uploader sees of each file ----

/**
 * A file's state in the uploader's words (FR-12). Infected is "blocked by the company's policy"; unscannable and a
 * failed scan are "couldn't be scanned", unless the company's policy accepted the unscannable file (`warning`), which
 * is "accepted" (#229). No finding and no scan detail is ever shown on this side.
 */
export type UploaderFileStatus =
  | 'uploading'
  | 'checking'
  | 'received'
  | 'accepted'
  | 'blocked'
  | 'unscannable'
  | 'rejected'
  | 'removed'
  | 'notAccepted';

const STATUS: Record<FileState, UploaderFileStatus> = {
  uploading: 'uploading',
  completing: 'uploading',
  scanning: 'checking',
  clean: 'received',
  infected: 'blocked',
  unscannable: 'unscannable',
  scan_failed: 'unscannable',
  rejected: 'rejected',
  deleted: 'removed',
};

export function uploaderFileStatus(state: FileState, warning?: SessionFile['warning'], blocked?: boolean): UploaderFileStatus {
  if (blocked && state !== 'deleted') return 'notAccepted';
  if (state === 'unscannable' && warning === 'unscannable') return 'accepted';
  return STATUS[state];
}

/** The statuses whose file the uploader may take back (#229): every file but a blocked or deleted one. */
const REMOVABLE: ReadonlySet<UploaderFileStatus> = new Set(['uploading', 'checking', 'received', 'accepted', 'rejected']);

/**
 * Whether the uploader may remove the file: not blocked and not deleted, as the API allows. A blocked file stays for
 * the company to review (`409 invalid_state`), whatever blocked it.
 */
export function uploaderMayRemove(file: Pick<SessionFile, 'state' | 'warning' | 'blocked'>): boolean {
  return REMOVABLE.has(uploaderFileStatus(file.state, file.warning, file.blocked));
}

export const uploaderStatusVariant: Record<UploaderFileStatus, BadgeVariant> = {
  uploading: 'info',
  checking: 'info',
  received: 'success',
  accepted: 'success',
  blocked: 'danger',
  unscannable: 'warning',
  rejected: 'danger',
  removed: 'default',
  notAccepted: 'danger',
};

/** The file list is read again fast while the service moves a file (a completion, a scan) or this tab uploads one. */
export const UPLOADS_POLL_MS = 3000;
/** Otherwise slowly, so a revocation or an expiry shows within this time (`410`, the gate's own page). */
export const IDLE_POLL_MS = 15_000;

export function uploadsPollInterval(files: readonly Pick<SessionFile, 'state'>[] | undefined, uploadingHere: boolean): number {
  if (uploadingHere) return UPLOADS_POLL_MS;
  return files?.some((file) => file.state === 'completing' || file.state === 'scanning') ? UPLOADS_POLL_MS : IDLE_POLL_MS;
}

// ---- the request's limits (FR-11), checked before anything is sent ----

export interface UploadLimits {
  maxFiles: number;
  maxFileSize: number;
  maxTotalSize: number;
}

export function limitsOf(request: Pick<LinkSessionUploadRequest, 'max_files' | 'max_file_size' | 'max_total_size'>): UploadLimits {
  return { maxFiles: request.max_files, maxFileSize: request.max_file_size, maxTotalSize: request.max_total_size };
}

/** The files that count against the limits: everything declared but a rejected or removed file. */
export function countedFiles<T extends Pick<SessionFile, 'state'>>(files: readonly T[]): T[] {
  return files.filter((file) => file.state !== 'rejected' && file.state !== 'deleted');
}

export type UploaderFileProblem = 'empty' | 'too_large' | 'total_too_large' | 'too_many';

/** Why a file of `size` can't join files whose sizes are `existing`, under the request's limits, or `null`. */
export function uploaderFileProblem(size: number, existing: readonly number[], limits: UploadLimits): UploaderFileProblem | null {
  if (size <= 0) return 'empty';
  if (size > limits.maxFileSize) return 'too_large';
  if (existing.length >= limits.maxFiles) return 'too_many';
  if (existing.reduce((sum, n) => sum + n, 0) + size > limits.maxTotalSize) return 'total_too_large';
  return null;
}

/** A server file still `uploading` that a picked file continues: the same name and size (as the draft page matches). */
export function resumableMatch<T extends Pick<SessionFile, 'id' | 'display_name' | 'size' | 'state'>>(
  picked: Pick<File, 'name' | 'size'>,
  files: readonly T[],
  taken: ReadonlySet<string>,
): T | null {
  return (
    files.find(
      (file) => file.state === 'uploading' && !taken.has(file.id) && file.display_name === picked.name && file.size === picked.size,
    ) ?? null
  );
}

/** The problems the uploader's page words for an uploader (`uploader.problems.<code>`). */
const UPLOADER_PROBLEMS = ['file_too_large', 'total_too_large', 'too_many_files', 'storage_quota_exceeded'] as const;

/** The text for a failed upload call: the uploader's own words for the limits, else the link pages' text. */
export function uploaderProblemText(error: unknown, t: TFunction): string {
  const code = failureOf(error).problem?.code;
  if (code && (UPLOADER_PROBLEMS as readonly string[]).includes(code)) return t(`uploader.problems.${code}`);
  return linkProblemText(error, t);
}
