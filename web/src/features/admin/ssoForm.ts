import type { Schema, SsoDomain, SsoGroupRole, TenantSsoSettings, TenantSsoSettingsUpdate } from '@/api';
import { normalizeDomain } from './domains';

/**
 * The single sign-on page's rules (#231; FR-26, authn-authz 2.5), checked before anything is sent so an admin sees a
 * mistake by its input. The service decides in the end, with the contract's limits: 20 domains, 50 group mappings,
 * each group once and at most 256 characters, and `sso_required` only with an active connection and a confirmation
 * that the identity provider enforces MFA.
 */

/** The contract's `maxItems` for `TenantSsoSettings.domains`. */
export const MAX_SSO_DOMAINS = 20;
/** The contract's `maxItems` for `group_roles`. */
export const MAX_GROUP_ROLES = 50;
/** The contract's `maxLength` for `SsoGroupRole.group`. */
export const MAX_GROUP_LENGTH = 256;

type Role = Schema<'Role'>;

export type ClaimProblem = 'invalid' | 'duplicate' | 'tooMany';

/**
 * The domain to claim, as the service stores it (lower case, ASCII form), or why it can't be claimed. A domain this
 * tenant already holds is refused here, although the API would return the existing claim, so the admin sees it in the
 * list instead.
 */
export function claimDomain(
  held: readonly Pick<SsoDomain, 'domain'>[],
  input: string,
): { domain: string } | { problem: ClaimProblem } {
  const domain = normalizeDomain(input);
  if (domain === null) return { problem: 'invalid' };
  if (held.some((entry) => entry.domain === domain)) return { problem: 'duplicate' };
  if (held.length >= MAX_SSO_DOMAINS) return { problem: 'tooMany' };
  return { domain };
}

/**
 * Where a domain is: `pending` until its TXT record is checked, `verified` once proven, `linked` once an operator also
 * linked it to the connection, so "Continue with SSO" for an address on it goes to the identity provider.
 */
/**
 * Why `verifySsoDomain` failed, when it has an explanation of its own: `422 validation_failed` is a TXT record that
 * isn't there yet and `409 invalid_state` a domain another organization proved first (the contract's existing codes).
 */
export type VerifyProblem = 'unverified' | 'taken';

export function verifyProblem(code: string | null): VerifyProblem | null {
  if (code === 'validation_failed') return 'unverified';
  if (code === 'invalid_state') return 'taken';
  return null;
}

export type DomainState = 'pending' | 'verified' | 'linked';

export function domainState(domain: Pick<SsoDomain, 'status' | 'idp_connection_id'>): DomainState {
  if (domain.status !== 'verified') return 'pending';
  return domain.idp_connection_id ? 'linked' : 'verified';
}

export type GroupProblem = 'empty' | 'tooLong' | 'duplicate' | 'tooMany';

/**
 * A group name as it is sent: without surrounding spaces, which are almost always a slip of the paste. Otherwise as
 * typed, since the identity provider's names are compared exactly.
 */
export function cleanGroup(input: string): string {
  return input.trim();
}

/** Why a group name can't be used in `list`, or `null`. `list` is the mappings without this one. */
export function groupProblem(list: readonly SsoGroupRole[], group: string): GroupProblem | null {
  if (group === '') return 'empty';
  if ([...group].length > MAX_GROUP_LENGTH) return 'tooLong';
  if (list.some((entry) => entry.group === group)) return 'duplicate';
  if (list.length >= MAX_GROUP_ROLES) return 'tooMany';
  return null;
}

/** Adds a mapping, or says why it can't. */
export function addGroupRole(
  list: readonly SsoGroupRole[],
  input: string,
  role: Role,
): { list: SsoGroupRole[] } | { problem: GroupProblem } {
  const group = cleanGroup(input);
  const problem = groupProblem(list, group);
  return problem ? { problem } : { list: [...list, { group, role }] };
}

export function removeGroupRole(list: readonly SsoGroupRole[], group: string): SsoGroupRole[] {
  return list.filter((entry) => entry.group !== group);
}

export function setGroupRole(list: readonly SsoGroupRole[], group: string, role: Role): SsoGroupRole[] {
  return list.map((entry) => (entry.group === group ? { group, role } : entry));
}

/** Whether a whole list may be sent: at most 50 mappings, each group once, none empty or too long. */
export function groupRolesValid(list: readonly SsoGroupRole[]): boolean {
  if (list.length > MAX_GROUP_ROLES) return false;
  const seen = new Set<string>();
  for (const { group } of list) {
    if (group === '' || [...group].length > MAX_GROUP_LENGTH || seen.has(group)) return false;
    seen.add(group);
  }
  return true;
}

/** Whether two lists map the same groups to the same roles. The order means nothing: admin wins either way. */
export function sameGroupRoles(a: readonly SsoGroupRole[], b: readonly SsoGroupRole[]): boolean {
  if (a.length !== b.length) return false;
  const roles = new Map(a.map((entry) => [entry.group, entry.role]));
  return b.every((entry) => roles.get(entry.group) === entry.role);
}

/** The part of the settings the form edits. */
export interface SsoForm {
  sso_required: boolean;
  jit_provisioning: boolean;
  group_roles: SsoGroupRole[];
}

export function formOf(settings: TenantSsoSettings): SsoForm {
  return {
    sso_required: settings.sso_required,
    jit_provisioning: settings.jit_provisioning,
    group_roles: settings.group_roles.map(({ group, role }) => ({ group, role })),
  };
}

/**
 * What saving sends: only the fields that changed, `group_roles` whole (it replaces the list). `{}` when nothing
 * changed; `null` when the list can't be sent.
 */
export function changedSsoFields(settings: TenantSsoSettings, form: SsoForm): TenantSsoSettingsUpdate | null {
  if (!groupRolesValid(form.group_roles)) return null;
  const body: TenantSsoSettingsUpdate = {};
  if (form.sso_required !== settings.sso_required) body.sso_required = form.sso_required;
  if (form.jit_provisioning !== settings.jit_provisioning) body.jit_provisioning = form.jit_provisioning;
  if (!sameGroupRoles(settings.group_roles, form.group_roles)) body.group_roles = form.group_roles;
  return body;
}

/** What still keeps a tenant from requiring SSO: an active connection, and a confirmation that its IdP enforces MFA. */
export type SsoRequiredBlocker = 'connection' | 'mfa';

export function ssoRequiredBlockers(
  settings: Pick<TenantSsoSettings, 'connection' | 'sso_mfa_confirmed_at'>,
): SsoRequiredBlocker[] {
  const blockers: SsoRequiredBlocker[] = [];
  if (settings.connection?.status !== 'active') blockers.push('connection');
  if (!settings.sso_mfa_confirmed_at) blockers.push('mfa');
  return blockers;
}
