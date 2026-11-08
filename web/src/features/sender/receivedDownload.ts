/**
 * The member's download of a received file (#213, #229; FR-6, FR-12): a grant (`createReceivedFileDownload`), the
 * in-app check of its content URL (`checkContent`), then the browser's own download by navigation (`startDownload`),
 * as the recipient's page does (`downloadFile` in `linkApi.ts`).
 *
 * **Resuming.** The grant's ID is kept in this tab's `sessionStorage`, per file, from the grant until the browser has
 * the download, and the next click sends it as `resume_grant_id`, so a start the network, a `503`, a `429` or a reload
 * interrupted gets the same grant back, with what is left of its 24 hours, bytes and requests (abuse 5.4). Once the
 * browser has the download, its download manager resumes it with `Range` under the same grant, so the kept ID is
 * dropped. A kept grant the API no longer knows for this member session (`404`: another session, or one that ended)
 * is dropped and a new grant asked for; one that is used up (`403 download_grant_exhausted`) is dropped and the error
 * passed on, so the page explains it and the next click asks for a new grant. The ID is not a credential: the content
 * needs the member session cookie that made the grant.
 */
import { createReceivedFileDownload, type DownloadAccess } from '@/hooks/uploadRequests';
import { checkContent, contentUrl, startDownload } from '@/features/recipient/linkApi';
import { problemCode } from '@/lib/problems';

const PREFIX = 'sft.received-grant.';

/** `sessionStorage`, or nothing when the browser refuses it (a private window may): resuming is then not offered. */
function storage(): Storage | null {
  try {
    return globalThis.sessionStorage ?? null;
  } catch {
    return null;
  }
}

/** The grant this tab kept for the file, if an earlier start didn't reach the browser's download manager. */
export function storedReceivedGrant(fileId: string): string | null {
  try {
    return storage()?.getItem(`${PREFIX}${fileId}`) ?? null;
  } catch {
    return null;
  }
}

function keep(fileId: string, grantId: string | null): void {
  try {
    const store = storage();
    if (!store) return;
    if (grantId === null) store.removeItem(`${PREFIX}${fileId}`);
    else store.setItem(`${PREFIX}${fileId}`, grantId);
  } catch {
    // Storage full or refused: the next click asks for a new grant, as without resuming.
  }
}

/** The problems after which a kept grant can't come back: the next click asks for a new one. */
const ENDED = new Set(['download_grant_exhausted', 'not_found']);

/** A grant for the file: the kept one again (`resume_grant_id`) if it still has time, bytes and requests left. */
export async function createReceivedDownload(fileId: string): Promise<DownloadAccess> {
  const kept = storedReceivedGrant(fileId);
  let access: DownloadAccess;
  try {
    access = await createReceivedFileDownload(fileId, kept);
  } catch (error) {
    const code = problemCode(error);
    if (kept && code && ENDED.has(code)) keep(fileId, null);
    if (!kept || code !== 'not_found') throw error;
    access = await createReceivedFileDownload(fileId, null);
  }
  keep(fileId, access.grant_id);
  return access;
}

/**
 * One click on "Download": the grant, the check, then the browser's download. The kept grant is dropped once the
 * browser has the download, or when the check says it can't resume; a check that failed for a while (`503`, `429`,
 * the network) keeps it, so the next click resumes it.
 */
export async function downloadReceivedFile(fileId: string, doc: Document = document): Promise<DownloadAccess> {
  const access = await createReceivedDownload(fileId);
  const href = contentUrl(access.url);
  try {
    // As on the recipient's page: a refused grant is explained here, not by the browser showing the API's JSON.
    await checkContent(href);
  } catch (error) {
    const code = problemCode(error);
    if (code && ENDED.has(code)) keep(fileId, null);
    throw error;
  }
  startDownload(href, doc);
  keep(fileId, null);
  return access;
}
