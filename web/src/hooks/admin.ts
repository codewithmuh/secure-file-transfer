/**
 * The admin's M5 hooks and calls over the typed `api` client: API keys (#215), audit search and export (#216), and
 * clearing an email suppression (#217). Pages read through these, never through `api` directly.
 */
import axios from 'axios';
import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { api, type ApiKey, type Schema } from '@/api';
import { apiClient } from '@/lib/api';
import { failureOf } from '@/lib/problems';
import { exportFileName, type AuditFilter, type ExportFormat } from '@/features/audit/auditFilter';

export type ApiKeyCreate = Schema<'ApiKeyCreate'>;
export type ApiKeyCreated = Schema<'ApiKeyCreated'>;
export type AuditEventPage = Schema<'AuditEventPage'>;

export const adminKeys = {
  apiKeys: ['api-keys'] as const,
  apiKeyList: ['api-keys', 'list'] as const,
  allApiKeys: ['api-keys', 'all'] as const,
  /** The filter is part of the key, in memory only: it never reaches a URL (T-47). */
  audit: (filter: AuditFilter | undefined, cursor: string | null, limit: number) =>
    ['audit', 'search', filter ?? null, cursor, limit] as const,
};

/** The tenant's keys, newest first, with "load more" through the cursor (`listApiKeys`). */
export function useApiKeyList(limit = 50) {
  return useInfiniteQuery({
    queryKey: adminKeys.apiKeyList,
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam, signal }) =>
      (await api.get('/api-keys', { query: { limit, ...(pageParam ? { cursor: pageParam } : {}) }, signal })).data,
    getNextPageParam: (page) => page.next_cursor ?? null,
  });
}

/** The most pages `useAllApiKeys` reads: 25 active keys at most, plus the revoked and expired ones still listed. */
const MAX_KEY_PAGES = 10;

/**
 * Every key of the tenant, for the users page's deactivate and demote dialogs, which list the keys the user owns
 * before the admin confirms (authn-authz 5.2). Fetched only while such a dialog is open.
 */
export function useAllApiKeys(enabled: boolean) {
  return useQuery({
    queryKey: adminKeys.allApiKeys,
    enabled,
    staleTime: 0,
    queryFn: async ({ signal }) => {
      const keys: ApiKey[] = [];
      let cursor: string | null = null;
      for (let page = 0; page < MAX_KEY_PAGES; page += 1) {
        const query: { limit: number; cursor?: string } = { limit: 100, ...(cursor ? { cursor } : {}) };
        const data: Schema<'ApiKeyPage'> = (await api.get('/api-keys', { query, signal })).data;
        keys.push(...data.items);
        cursor = data.next_cursor ?? null;
        if (!cursor) break;
      }
      return keys;
    },
  });
}

/** `createApiKey`: no `Idempotency-Key`, since the secret is never stored and a retry couldn't return it. */
export async function createApiKey(body: ApiKeyCreate): Promise<ApiKeyCreated> {
  return (await api.post('/api-keys', { body })).data;
}

/**
 * `revokeApiKey`. The revocation takes effect at once; a `503` means only that its record isn't in both regions'
 * archive yet, so the page says the key is revoked and a retry is safe.
 */
export async function revokeApiKey(id: string): Promise<'revoked' | 'unconfirmed'> {
  try {
    await api.post('/api-keys/{api_key_id}/revoke', { path: { api_key_id: id } });
    return 'revoked';
  } catch (error) {
    if (failureOf(error).status === 503) return 'unconfirmed';
    throw error;
  }
}

/** One page of `searchAuditEvents`. `filter` is `null` until the admin searches. */
export function useAuditSearch(filter: AuditFilter | undefined, cursor: string | null, limit: number, enabled: boolean) {
  return useQuery({
    queryKey: adminKeys.audit(filter, cursor, limit),
    enabled,
    placeholderData: keepPreviousData,
    staleTime: 30_000,
    retry: false,
    queryFn: async ({ signal }) =>
      (
        await api.post('/audit/events/search', {
          body: { ...(filter ? { filter } : {}), ...(cursor ? { cursor } : {}), limit },
          signal,
        })
      ).data,
  });
}

/** An export, ready to save: the file's content and the name `Content-Disposition` gave it. */
export interface AuditExport {
  blob: Blob;
  fileName: string;
}

/**
 * `exportAuditEvents`, streamed into a blob. Through the one `apiClient`, so the member's CSRF token goes with it.
 * An error's body arrives as a blob too; it is read back into the problem document, so the page shows its code.
 */
export async function exportAuditEvents(filter: AuditFilter | undefined, format: ExportFormat): Promise<AuditExport> {
  try {
    const response = await apiClient.post<Blob>('/audit/exports', { ...(filter ? { filter } : {}), format }, {
      responseType: 'blob',
      headers: { Accept: format === 'csv' ? 'text/csv' : 'application/json' },
    });
    const header = response.headers['content-disposition'] as string | undefined;
    return { blob: response.data, fileName: exportFileName(header, format) };
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.data instanceof Blob) {
      try {
        error.response.data = JSON.parse(await error.response.data.text());
      } catch {
        // Not JSON: the page shows the status's text.
      }
    }
    throw error;
  }
}

/** Saves an export through a temporary object URL and a download link. */
export function saveExport({ blob, fileName }: AuditExport): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  link.rel = 'noopener';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** `clearEmailSuppression`: always `204`, whether or not the address was suppressed, so it reveals nothing. */
export async function clearEmailSuppression(email: string): Promise<void> {
  await api.post('/email-suppressions/clear', { body: { email } });
}

/** The most pages `useUserEmails` reads, 100 users each. */
const MAX_USER_PAGES = 20;

/**
 * Every user's address by ID, for the owner column of the tenant-wide lists (#217) and the API keys page's "created
 * by". Only an admin may list users, so it is fetched only when `enabled`.
 */
export function useUserEmails(enabled: boolean) {
  return useQuery({
    queryKey: ['users', 'emails'] as const,
    enabled,
    staleTime: 60_000,
    queryFn: async ({ signal }) => {
      const emails = new Map<string, string>();
      let cursor: string | null = null;
      for (let page = 0; page < MAX_USER_PAGES; page += 1) {
        const query: { limit: number; cursor?: string } = { limit: 100, ...(cursor ? { cursor } : {}) };
        const data: Schema<'UserPage'> = (await api.get('/users', { query, signal })).data;
        for (const user of data.items) emails.set(user.id, user.email);
        cursor = data.next_cursor ?? null;
        if (!cursor) break;
      }
      return emails;
    },
  });
}
