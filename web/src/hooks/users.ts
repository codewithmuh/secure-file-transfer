/** The admin's hooks and calls over the typed `api` client (#197): members, roles and the tenant policy. */
import { useInfiniteQuery } from '@tanstack/react-query';
import { api, type Schema, type User } from '@/api';
import { queryKeys } from './transfers';

export type Role = Schema<'Role'>;
export type UserStatus = Schema<'UserStatus'>;
export type TenantPolicy = Schema<'TenantPolicy'>;
export type TenantPolicyUpdate = Schema<'TenantPolicyUpdate'>;

/** The tenant's users, with the role and status filters, and "load more" through the cursor (`listUsers`). */
export function useUserList(role: Role | null, status: UserStatus | null, limit = 50) {
  return useInfiniteQuery({
    queryKey: queryKeys.userList(role, status),
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam, signal }) =>
      (
        await api.get('/users', {
          query: { limit, ...(role ? { role } : {}), ...(status ? { status } : {}), ...(pageParam ? { cursor: pageParam } : {}) },
          signal,
        })
      ).data,
    getNextPageParam: (page) => page.next_cursor ?? null,
  });
}

export async function inviteUser(email: string, role: Role, idempotencyKey: string): Promise<User> {
  return (await api.post('/users', { body: { email, role }, headers: { 'Idempotency-Key': idempotencyKey } })).data;
}

export async function updateUser(userId: string, body: Schema<'UserUpdate'>): Promise<User> {
  return (await api.patch('/users/{user_id}', { path: { user_id: userId }, body })).data;
}

export async function deactivateUser(userId: string): Promise<User> {
  return (await api.post('/users/{user_id}/deactivate', { path: { user_id: userId } })).data;
}

export async function signOutUser(userId: string): Promise<User> {
  return (await api.post('/users/{user_id}/sign-out', { path: { user_id: userId } })).data;
}

export async function resetUserSignIn(userId: string): Promise<User> {
  return (await api.post('/users/{user_id}/reset-sign-in', { path: { user_id: userId } })).data;
}

export async function updateTenantPolicy(body: TenantPolicyUpdate): Promise<TenantPolicy> {
  return (await api.patch('/tenant/policy', { body })).data;
}
