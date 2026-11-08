/**
 * The TanStack Query hooks over the typed `api` client (#196): the member's transfers, their files and the tenant's
 * policy. Pages read through these, never through `api` directly, so caching, polling and invalidation live in one
 * place. Mutations invalidate what they change.
 */
import { useInfiniteQuery, useQuery, type QueryClient } from '@tanstack/react-query';
import { api, type Schema, type Transfer, type TransferState } from '@/api';
import { pollInterval, RECIPIENT_POLL_INTERVAL_MS, shouldPollRecipients, useActiveUploads } from '@/features/sender/polling';
import type { ApiFile, PartUrl, UploadApi, UploadedParts } from '@/features/sender/upload';
import { failureOf } from '@/lib/problems';

export const queryKeys = {
  transfers: ['transfers'] as const,
  transferList: (state: TransferState | null, scope: ListScope = 'own') => ['transfers', 'list', state ?? 'all', scope] as const,
  recentTransfers: ['transfers', 'recent'] as const,
  transfer: (id: string) => ['transfers', 'detail', id] as const,
  recipients: (id: string) => ['transfers', 'detail', id, 'recipients'] as const,
  inspection: (fileId: string) => ['files', fileId, 'inspection'] as const,
  uploadRequests: ['upload-requests'] as const,
  uploadRequestList: (state: string | null, scope: ListScope = 'own') => ['upload-requests', 'list', state ?? 'all', scope] as const,
  recentUploadRequests: ['upload-requests', 'recent'] as const,
  uploadRequest: (id: string) => ['upload-requests', 'detail', id] as const,
  uploadRequestFiles: (id: string) => ['upload-requests', 'detail', id, 'files'] as const,
  tenantPolicy: ['tenant-policy'] as const,
  users: ['users'] as const,
  userList: (role: string | null, status: string | null) => ['users', 'list', role ?? 'all', status ?? 'all'] as const,
};

/** `own` (the default) or, for an admin, `tenant`: every member's items (FR-20, UC-3; #217). */
export type ListScope = 'own' | 'tenant';

/**
 * A page of transfers, newest first, with "load more" through the cursor (`listTransfers`): the member's own, or with
 * `scope=tenant` every transfer of the tenant (an admin only; a member gets `403`).
 */
export function useTransferList(state: TransferState | null, limit = 25, scope: ListScope = 'own') {
  return useInfiniteQuery({
    queryKey: queryKeys.transferList(state, scope),
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam, signal }) =>
      (
        await api.get('/transfers', {
          query: {
            limit,
            ...(scope === 'tenant' ? { scope } : {}),
            ...(state ? { state: [state] } : {}),
            ...(pageParam ? { cursor: pageParam } : {}),
          },
          signal,
        })
      ).data,
    getNextPageParam: (page) => page.next_cursor ?? null,
  });
}

/** The five newest, for the dashboard. */
export function useRecentTransfers() {
  return useQuery({
    queryKey: queryKeys.recentTransfers,
    queryFn: async ({ signal }) => (await api.get('/transfers', { query: { limit: 5 }, signal })).data.items,
  });
}

/** One transfer, polled every few seconds while it or a file is still moving (`shouldPoll`): on the service, or in
 * this tab's uploads; and every 15 seconds while it waits for an approver (`pollInterval`). */
export function useTransfer(id: string) {
  return useQuery({
    queryKey: queryKeys.transfer(id),
    queryFn: async ({ signal }) => (await api.get('/transfers/{transfer_id}', { path: { transfer_id: id }, signal })).data,
    refetchInterval: (query) => pollInterval(query.state.data, useActiveUploads.getState().ids),
    staleTime: 0,
  });
}

/**
 * Each recipient's delivery, verification and downloads (`listTransferRecipients`, #199), polled every 10 seconds
 * while the transfer is `sent` (`shouldPollRecipients`).
 */
export function useTransferRecipients(id: string, state: TransferState | undefined) {
  return useQuery({
    queryKey: queryKeys.recipients(id),
    queryFn: async ({ signal }) =>
      (await api.get('/transfers/{transfer_id}/recipients', { path: { transfer_id: id }, signal })).data.items,
    enabled: state !== undefined,
    refetchInterval: shouldPollRecipients(state) ? RECIPIENT_POLL_INTERVAL_MS : false,
    staleTime: 0,
  });
}

/**
 * A file's findings, fetched only when the member asks: every response with details is audited, so this is never
 * part of the poll, and is kept once fetched.
 */
export function useFileInspection(fileId: string, enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.inspection(fileId),
    queryFn: async ({ signal }) =>
      (await api.get('/files/{file_id}/inspection', { path: { file_id: fileId }, signal })).data,
    enabled,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    retry: false,
  });
}

/** The tenant's policy: every member reads it, for the expiry cap and the default locale. */
export function useTenantPolicy() {
  return useQuery({
    queryKey: queryKeys.tenantPolicy,
    queryFn: async ({ signal }) => (await api.get('/tenant/policy', { signal })).data,
    staleTime: 60_000,
  });
}

export type TransferCreate = Schema<'TransferCreate'>;
export type FileCreate = Schema<'FileCreate'>;

/** `createTransfer`, replayed by its `Idempotency-Key` on a retry. */
export async function createTransfer(body: TransferCreate, idempotencyKey: string): Promise<Transfer> {
  return (await api.post('/transfers', { body, headers: { 'Idempotency-Key': idempotencyKey } })).data;
}

/** `addTransferFile`: the file and its upload plan. */
export async function addTransferFile(transferId: string, body: FileCreate, idempotencyKey: string): Promise<ApiFile> {
  return (
    await api.post('/transfers/{transfer_id}/files', {
      path: { transfer_id: transferId },
      body,
      headers: { 'Idempotency-Key': idempotencyKey },
    })
  ).data;
}

export async function sendTransfer(transferId: string): Promise<Transfer> {
  return (await api.post('/transfers/{transfer_id}/send', { path: { transfer_id: transferId } })).data;
}

export async function cancelTransfer(transferId: string): Promise<Transfer> {
  return (await api.post('/transfers/{transfer_id}/cancel', { path: { transfer_id: transferId } })).data;
}

/** `revokeTransfer`. A `503` means the revocation stands but isn't confirmed yet (`revocation.ts`). */
export async function revokeTransfer(transferId: string): Promise<Transfer> {
  return (await api.post('/transfers/{transfer_id}/revoke', { path: { transfer_id: transferId } })).data;
}

export type ExpiryExtension = Schema<'ExpiryExtension'>;

/**
 * `extendTransferExpiry` (#214, FR-9): moves `expires_at` later, with an `Idempotency-Key` kept for the attempt. The
 * current time again returns the transfer unchanged, so a retry is safe either way.
 */
export async function extendTransferExpiry(
  transferId: string,
  body: ExpiryExtension,
  idempotencyKey: string,
): Promise<Transfer> {
  return (
    await api.post('/transfers/{transfer_id}/extend', {
      path: { transfer_id: transferId },
      body,
      headers: { 'Idempotency-Key': idempotencyKey },
    })
  ).data;
}

export type RecipientStatus = Schema<'RecipientStatus'>;

/**
 * How an unlock ended: `unlocked`, or `unconfirmed` when the API answered `503`. The contract says the unlock takes
 * effect at once and the `503` means only that its audit record isn't in both regions' archive yet, so the page shows
 * it as done, with the record pending.
 */
export type UnlockOutcome = 'unlocked' | 'unconfirmed';

/**
 * `unlockRecipient`: the failed attempts start again from zero and a new link is emailed; the old one stops working.
 * Any error but `503` is thrown.
 */
export async function unlockRecipient(transferId: string, recipientId: string): Promise<UnlockOutcome> {
  try {
    await api.post('/transfers/{transfer_id}/recipients/{recipient_id}/unlock', {
      path: { transfer_id: transferId, recipient_id: recipientId },
    });
    return 'unlocked';
  } catch (error) {
    if (failureOf(error).status === 503) return 'unconfirmed';
    throw error;
  }
}

/** The upload engine's calls for one file (`FileUpload`); a member can delete the file too. */
export const uploadApi: Required<UploadApi> = {
  async listUploadedParts(fileId): Promise<UploadedParts> {
    return (await api.get('/files/{file_id}/parts', { path: { file_id: fileId } })).data;
  },
  async requestPartUrls(fileId, partNumbers): Promise<PartUrl[]> {
    return (
      await api.post('/files/{file_id}/parts', { path: { file_id: fileId }, body: { part_numbers: partNumbers } })
    ).data.parts;
  },
  async completeUpload(fileId): Promise<ApiFile> {
    return (await api.post('/files/{file_id}/complete', { path: { file_id: fileId } })).data;
  },
  async deleteFile(fileId): Promise<void> {
    await api.delete('/files/{file_id}', { path: { file_id: fileId } });
  },
};

/** After a change to transfers: every list and the detail refetch. */
export function invalidateTransfers(client: QueryClient): Promise<void> {
  return client.invalidateQueries({ queryKey: queryKeys.transfers });
}
