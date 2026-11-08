import { create } from 'zustand';
import type { FileState, Transfer, TransferState } from '@/api';

/** How often the detail page asks for the transfer while something is still moving (#196). */
export const POLL_INTERVAL_MS = 3000;

/** File states the service moves on by itself: a completion and a scan. */
const SERVER_MOVES: readonly FileState[] = ['completing', 'scanning'];

/**
 * The files this tab is uploading right now (`FileUpload` runs for them). A file `uploading` with no upload running
 * in this tab doesn't move until someone picks it again, so it is no reason to poll.
 */
export const useActiveUploads = create<{ ids: ReadonlySet<string>; start: (id: string) => void; stop: (id: string) => void }>(
  (set) => ({
    ids: new Set<string>(),
    start: (id) => set((state) => ({ ids: new Set(state.ids).add(id) })),
    stop: (id) =>
      set((state) => {
        const ids = new Set(state.ids);
        ids.delete(id);
        return { ids };
      }),
  }),
);

/**
 * Whether the detail page keeps polling `getTransfer` (#196 review): while the service can change the transfer on its
 * own (it is `submitted`, or a file is completing or being scanned), or while this tab uploads one of its files.
 * Otherwise nothing changes without the member, so polling stops: a stalled draft doesn't poll forever. A file's scan
 * and its inspection are recorded together (sft.service.scans), so `clean` already carries its inspection.
 */
export function shouldPoll(
  transfer: Pick<Transfer, 'state' | 'files'> | undefined,
  uploading: ReadonlySet<string> = new Set(),
): boolean {
  if (!transfer) return false;
  if (transfer.state === 'submitted') return true;
  return transfer.files.some(
    (file) => SERVER_MOVES.includes(file.state) || (file.state === 'uploading' && uploading.has(file.id)),
  );
}

/**
 * How often the detail page asks for a transfer that waits for an approver (#220): an approval, a rejection or the
 * request's expiry moves it at a person's pace.
 */
export const APPROVAL_POLL_INTERVAL_MS = 15_000;

/**
 * How often `getTransfer` is asked again: every few seconds while the service moves the transfer (`shouldPoll`), every
 * 15 seconds while it is `pending_approval`, else not at all. `awaiting_confirmation` and `held` wait for the sender,
 * so they aren't polled; a change made in another tab shows when this one has the focus again.
 */
export function pollInterval(
  transfer: Pick<Transfer, 'state' | 'files'> | undefined,
  uploading: ReadonlySet<string> = new Set(),
): number | false {
  if (shouldPoll(transfer, uploading)) return POLL_INTERVAL_MS;
  if (transfer?.state === 'pending_approval') return APPROVAL_POLL_INTERVAL_MS;
  return false;
}

/**
 * How often the detail page asks for the recipients' delivery while the transfer is `sent` (#199): slower than the
 * scans, since emails, verifications and downloads move at a person's pace.
 */
export const RECIPIENT_POLL_INTERVAL_MS = 10_000;

/** Whether `listTransferRecipients` is polled: only while the transfer is `sent`, so links are out and in use. */
export function shouldPollRecipients(state: TransferState | undefined): boolean {
  return state === 'sent';
}
