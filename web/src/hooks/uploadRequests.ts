/**
 * The TanStack Query hooks and calls for the member's upload requests (#212, #213), over the typed `api` client, as
 * `transfers.ts` does for transfers. Mutations invalidate what they change.
 */
import { useInfiniteQuery, useQuery, type QueryClient } from '@tanstack/react-query';
import { api, type Schema, type UploadRequest, type UploadRequestState } from '@/api';
import { receivedFilesPollInterval, requestPollInterval, type UploadRequestCreate } from '@/features/sender/uploadRequests';
import { failureOf } from '@/lib/problems';
import { queryKeys, type ListScope, type UnlockOutcome } from './transfers';

export type DownloadAccess = Schema<'DownloadAccess'>;

/**
 * A page of upload requests, newest first, with "load more" through the cursor (`listUploadRequests`): the member's own,
 * or every request of the tenant for an admin (`scope=tenant`, #217).
 */
export function useUploadRequestList(state: UploadRequestState | null, limit = 25, scope: ListScope = 'own') {
  return useInfiniteQuery({
    queryKey: queryKeys.uploadRequestList(state, scope),
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam, signal }) =>
      (
        await api.get('/upload-requests', {
          query: { scope, limit, ...(state ? { state: [state] } : {}), ...(pageParam ? { cursor: pageParam } : {}) },
          signal,
        })
      ).data,
    getNextPageParam: (page) => page.next_cursor ?? null,
  });
}

/** The five newest, for the dashboard. */
export function useRecentUploadRequests() {
  return useQuery({
    queryKey: queryKeys.recentUploadRequests,
    queryFn: async ({ signal }) => (await api.get('/upload-requests', { query: { scope: 'own', limit: 5 }, signal })).data.items,
  });
}

/** One request, polled while it is open (`requestPollInterval`). */
export function useUploadRequest(id: string) {
  return useQuery({
    queryKey: queryKeys.uploadRequest(id),
    queryFn: async ({ signal }) =>
      (await api.get('/upload-requests/{upload_request_id}', { path: { upload_request_id: id }, signal })).data,
    refetchInterval: (query) => requestPollInterval(query.state.data),
    staleTime: 0,
  });
}

/** The files received through a request (`listUploadRequestFiles`), polled while one moves or the request is open. */
export function useReceivedFiles(id: string, state: UploadRequestState | undefined) {
  return useQuery({
    queryKey: queryKeys.uploadRequestFiles(id),
    queryFn: async ({ signal }) =>
      (await api.get('/upload-requests/{upload_request_id}/files', { path: { upload_request_id: id }, signal })).data.items,
    enabled: state !== undefined,
    refetchInterval: (query) => receivedFilesPollInterval(query.state.data, state),
    staleTime: 0,
  });
}

/** `createUploadRequest`, replayed by its `Idempotency-Key` on a retry. */
export async function createUploadRequest(body: UploadRequestCreate, idempotencyKey: string): Promise<UploadRequest> {
  return (await api.post('/upload-requests', { body, headers: { 'Idempotency-Key': idempotencyKey } })).data;
}

/** `revokeUploadRequest`. A `503` means the revocation stands but isn't confirmed yet (`revocation.ts`). */
export async function revokeUploadRequest(id: string): Promise<UploadRequest> {
  return (await api.post('/upload-requests/{upload_request_id}/revoke', { path: { upload_request_id: id } })).data;
}

/**
 * `unlockUploader`: a new link is emailed and the old one stops working. As for `unlockRecipient`, a `503` means the
 * unlock took effect and only its audit record is pending. Any other error is thrown.
 */
export async function unlockUploader(id: string): Promise<UnlockOutcome> {
  try {
    await api.post('/upload-requests/{upload_request_id}/unlock', { path: { upload_request_id: id } });
    return 'unlocked';
  } catch (error) {
    if (failureOf(error).status === 503) return 'unconfirmed';
    throw error;
  }
}

/**
 * `createReceivedFileDownload`: a grant for one received file, whose `url` the browser then fetches. With
 * `resumeGrantId`, the grant kept from an interrupted start comes back (#229, `receivedDownload.ts`).
 */
export async function createReceivedFileDownload(fileId: string, resumeGrantId?: string | null): Promise<DownloadAccess> {
  const body = resumeGrantId ? { resume_grant_id: resumeGrantId } : {};
  return (await api.post('/files/{file_id}/downloads', { path: { file_id: fileId }, body })).data;
}

/** `deleteFile` on a received file: deleted before its retention ends (FR-13). */
export async function deleteReceivedFile(fileId: string): Promise<void> {
  await api.delete('/files/{file_id}', { path: { file_id: fileId } });
}

/** After a change to upload requests: every list, the detail and its files refetch. */
export function invalidateUploadRequests(client: QueryClient): Promise<void> {
  return client.invalidateQueries({ queryKey: queryKeys.uploadRequests });
}
