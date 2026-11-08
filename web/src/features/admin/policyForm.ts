import type { TenantPolicy, TenantPolicyUpdate } from '@/hooks/users';
import { fieldErrors, type ApiFailure } from '@/lib/problems';
import { normalizeDuration } from '@/lib/durations';

/**
 * The tenant policy form (#197; FR-3, FR-13, FR-18, FR-23, FR-33). `allowed_domains` and `blocked_domains` (FR-24)
 * arrive with M5 and are not shown, so the form never sends them.
 */
export interface PolicyForm {
  max_expiry: string;
  unscannable_policy: TenantPolicy['unscannable_policy'];
  received_file_retention_days: string;
  default_locale: TenantPolicy['default_locale'];
}

export const POLICY_FIELDS = ['max_expiry', 'unscannable_policy', 'received_file_retention_days', 'default_locale'] as const;
export type PolicyField = (typeof POLICY_FIELDS)[number];

export const MIN_RETENTION_DAYS = 1;
export const MAX_RETENTION_DAYS = 90;

export function formOf(policy: TenantPolicy): PolicyForm {
  return {
    max_expiry: normalizeDuration(policy.max_expiry) ?? policy.max_expiry,
    unscannable_policy: policy.unscannable_policy,
    received_file_retention_days: String(policy.received_file_retention_days),
    default_locale: policy.default_locale,
  };
}

/** The retention as a whole number of days from 1 to 90, or `null` when the field holds anything else. */
export function retentionDays(text: string): number | null {
  if (!/^\d+$/.test(text.trim())) return null;
  const days = Number(text.trim());
  return days >= MIN_RETENTION_DAYS && days <= MAX_RETENTION_DAYS ? days : null;
}

/**
 * The `PATCH` body: only the fields that changed (the contract's `TenantPolicyUpdate`: "only the fields sent are
 * changed"), so an admin's save never overwrites a field someone else changed meanwhile that they didn't touch.
 * `null` when the retention isn't valid; `{}` when nothing changed.
 */
export function changedFields(original: TenantPolicy, form: PolicyForm): TenantPolicyUpdate | null {
  const body: TenantPolicyUpdate = {};
  const days = retentionDays(form.received_file_retention_days);
  if (days === null) return null;
  if (normalizeDuration(form.max_expiry) !== normalizeDuration(original.max_expiry)) body.max_expiry = form.max_expiry;
  if (form.unscannable_policy !== original.unscannable_policy) body.unscannable_policy = form.unscannable_policy;
  if (days !== original.received_file_retention_days) body.received_file_retention_days = days;
  if (form.default_locale !== original.default_locale) body.default_locale = form.default_locale;
  return body;
}

/** `422 validation_failed`: each issue on the input its pointer names (`#/max_expiry`), the rest on the form. */
export function policyFieldErrors(failure: ApiFailure): { fields: Partial<Record<PolicyField, string>>; other: string[] } {
  const fields: Partial<Record<PolicyField, string>> = {};
  const other: string[] = [];
  for (const [field, detail] of Object.entries(fieldErrors(failure))) {
    if ((POLICY_FIELDS as readonly string[]).includes(field)) fields[field as PolicyField] = detail;
    else other.push(detail);
  }
  return { fields, other };
}
