import type { ApiKey, ApiKeyScope } from '@/api';

/**
 * API keys (#215; FR-32, authn-authz 5): what the create dialog offers, and what the users page lists before an admin
 * is deactivated or demoted. Pure functions, so the page's rules are tested without a browser.
 */

/** The contract's `ApiKeyScope`, in the order the dialog shows them. */
export const API_KEY_SCOPES: readonly ApiKeyScope[] = [
  'transfers:read',
  'transfers:write',
  'upload_requests:read',
  'upload_requests:write',
  'audit:read',
];

/** How long a new key lasts, in days: 90 by default, at most 365 (authn-authz 5.2). */
export const DEFAULT_KEY_DAYS = 90;
export const MAX_KEY_DAYS = 365;
export const KEY_DAY_CHOICES = [30, 90, 180, 365] as const;

/** The contract's `ApiKeyCreate.name`: 1 to 100 characters. */
export const MAX_KEY_NAME = 100;

export interface KeyForm {
  name: string;
  scopes: ApiKeyScope[];
  days: number;
}

export const EMPTY_KEY_FORM: KeyForm = { name: '', scopes: [], days: DEFAULT_KEY_DAYS };

export type KeyFormProblem = 'name' | 'scopes' | 'days';

/** What is wrong with the form, field by field; empty when it can be sent. */
export function keyFormProblems(form: KeyForm): KeyFormProblem[] {
  const problems: KeyFormProblem[] = [];
  const name = form.name.trim();
  if (name.length === 0 || name.length > MAX_KEY_NAME) problems.push('name');
  if (form.scopes.length === 0) problems.push('scopes');
  if (!Number.isInteger(form.days) || form.days < 1 || form.days > MAX_KEY_DAYS) problems.push('days');
  return problems;
}

/**
 * The `createApiKey` body. The default 90 days is left to the service (no `expires_at`), so the service's clock
 * decides it; any other choice is that many days from `now`.
 */
export function createBody(form: KeyForm, now: Date = new Date()) {
  const scopes = API_KEY_SCOPES.filter((scope) => form.scopes.includes(scope));
  const body: { name: string; scopes: ApiKeyScope[]; expires_at?: string } = { name: form.name.trim(), scopes };
  if (form.days !== DEFAULT_KEY_DAYS) body.expires_at = new Date(now.getTime() + form.days * 86_400_000).toISOString();
  return body;
}

export function toggleScope(scopes: readonly ApiKeyScope[], scope: ApiKeyScope): ApiKeyScope[] {
  return scopes.includes(scope) ? scopes.filter((s) => s !== scope) : [...scopes, scope];
}

export type KeyStatus = 'active' | 'expired' | 'revoked';

export function keyStatus(key: ApiKey, now: Date = new Date()): KeyStatus {
  if (key.revoked_at) return 'revoked';
  return Date.parse(key.expires_at) <= now.getTime() ? 'expired' : 'active';
}

/**
 * The keys a user owns that still work: what deactivating or demoting them revokes (authn-authz 5.2), so the dialog
 * names them and automation can move to another admin's key first.
 */
export function activeKeysOf(keys: readonly ApiKey[], userId: string, now: Date = new Date()): ApiKey[] {
  return keys.filter((key) => key.created_by === userId && keyStatus(key, now) === 'active');
}

/**
 * The create dialog's steps. The secret appears once, in `created`; the dialog can't be closed from there until the
 * admin says they stored it, and closing drops the secret from memory.
 */
export type SecretStep = { step: 'form' } | { step: 'created'; key: ApiKey; secret: string; stored: boolean };

export type SecretAction =
  | { type: 'created'; key: ApiKey; secret: string }
  | { type: 'stored'; value: boolean }
  | { type: 'reset' };

export function secretStep(state: SecretStep, action: SecretAction): SecretStep {
  switch (action.type) {
    case 'created':
      return { step: 'created', key: action.key, secret: action.secret, stored: false };
    case 'stored':
      return state.step === 'created' ? { ...state, stored: action.value } : state;
    case 'reset':
      return { step: 'form' };
  }
}

/** Whether the dialog may close now: always from the form, and from the secret only once it is stored. */
export function mayClose(state: SecretStep): boolean {
  return state.step === 'form' || state.stored;
}
