/**
 * The tenant's single sign-on settings (#231; FR-26, authn-authz 2.5) over the typed `api` client: read them, change
 * them, and claim, verify and give up an email domain. Every write is a step-up operation; `apiClient` handles its
 * `401 reauthentication_required` by asking the admin to confirm it's them and sending the call again (#232).
 */
import { useQuery } from '@tanstack/react-query';
import { api, type SsoDomain, type TenantSsoSettings, type TenantSsoSettingsUpdate } from '@/api';

export const ssoKeys = {
  settings: ['tenant-sso'] as const,
};

/** `getTenantSso`. */
export function useTenantSso() {
  return useQuery({
    queryKey: ssoKeys.settings,
    retry: false,
    queryFn: async ({ signal }) => (await api.get('/tenant/sso', { signal })).data,
  });
}

/** `updateTenantSso`: only the fields sent change. Returns the settings after the change. */
export async function updateTenantSso(body: TenantSsoSettingsUpdate): Promise<TenantSsoSettings> {
  return (await api.patch('/tenant/sso', { body })).data;
}

/** `claimSsoDomain`: the claim with its TXT record; a domain this tenant already claimed returns that claim. */
export async function claimSsoDomain(domain: string): Promise<SsoDomain> {
  return (await api.post('/tenant/sso/domains', { body: { domain } })).data;
}

/** `verifySsoDomain`: the domain, proven, or `422 validation_failed` (no record yet) / `409 invalid_state` (taken). */
export async function verifySsoDomain(id: string): Promise<SsoDomain> {
  return (await api.post('/tenant/sso/domains/{sso_domain_id}/verify', { path: { sso_domain_id: id } })).data;
}

/** `deleteSsoDomain`. */
export async function deleteSsoDomain(id: string): Promise<void> {
  await api.delete('/tenant/sso/domains/{sso_domain_id}', { path: { sso_domain_id: id } });
}

/** The settings with one domain added or replaced (by ID), for the query cache after a claim or a verify. */
export function withDomain(settings: TenantSsoSettings, domain: SsoDomain): TenantSsoSettings {
  const found = settings.domains.some((entry) => entry.id === domain.id);
  return {
    ...settings,
    domains: found ? settings.domains.map((entry) => (entry.id === domain.id ? domain : entry)) : [...settings.domains, domain],
  };
}

/** The settings without one domain, after a delete. */
export function withoutDomain(settings: TenantSsoSettings, id: string): TenantSsoSettings {
  return { ...settings, domains: settings.domains.filter((entry) => entry.id !== id) };
}
