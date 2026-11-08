import axios from 'axios';
import type { TFunction } from 'i18next';
import type { Problem } from '@/api';

/**
 * The API's errors as the pages show them (#196). Every error is a problem document (docs/api/README.md 3) with a
 * stable `code`. `problemMessage` gives each code the pages handle its own en and ja text, and any other code the text
 * of its HTTP status: the contract says a client treats an unknown code by its status. A `Retry-After` on `429` and
 * `503` is shown as a wait.
 */

/** The codes with their own text (`problems.<code>` in i18n.ts); `problems.test.ts` checks both languages have each. */
export const HANDLED_PROBLEMS = [
  'malformed_request',
  'authentication_required',
  'session_expired',
  'reauthentication_required',
  'permission_denied',
  'passkey_required',
  'csrf_failed',
  'not_found',
  'idempotency_conflict',
  'idempotency_in_progress',
  'invalid_state',
  'transfer_revoked',
  'transfer_expired',
  'upload_request_revoked',
  'upload_request_expired',
  'transfer_empty',
  'upload_incomplete',
  'upload_size_mismatch',
  'file_not_shareable',
  'user_exists',
  'last_admin',
  'file_too_large',
  'total_too_large',
  'storage_quota_exceeded',
  'request_too_large',
  'too_many_files',
  'validation_failed',
  'expiry_out_of_range',
  'recipient_domain_not_allowed',
  'recipient_undeliverable',
  'dlp_decision_changed',
  'dlp_policy_conflict',
  'detector_in_use',
  'no_eligible_approver',
  'approval_limit_reached',
  'justification_required',
  'approvers_insufficient',
  'self_approval_forbidden',
  'rate_limited',
  'internal_error',
  'service_unavailable',
  'invalid_cursor',
  'export_too_large',
] as const satisfies readonly Problem['code'][];

export type HandledProblem = (typeof HANDLED_PROBLEMS)[number];

/** The HTTP statuses with a text of their own, for codes without one. */
export const STATUS_TEXTS = [400, 401, 403, 404, 409, 410, 413, 422, 429, 500, 503] as const;

/** What a page needs from a failed call: the status, the problem document if there was one, and any wait. */
export interface ApiFailure {
  status: number | null;
  problem: Problem | null;
  /** Seconds from `Retry-After`, on `429` and `503`. */
  retryAfter: number | null;
}

function isProblem(data: unknown): data is Problem {
  return typeof data === 'object' && data !== null && typeof (data as { code?: unknown }).code === 'string';
}

function retryAfterOf(value: unknown, now: number): number | null {
  if (typeof value !== 'string' || value.trim() === '') return null;
  if (/^\d+$/.test(value.trim())) return Number(value.trim());
  const date = Date.parse(value);
  return Number.isNaN(date) ? null : Math.max(0, Math.ceil((date - now) / 1000));
}

/** Reads any thrown value: an axios error with a problem document, a network error (`status: null`), or anything else. */
export function failureOf(error: unknown, now = Date.now()): ApiFailure {
  if (!axios.isAxiosError(error) || !error.response) return { status: null, problem: null, retryAfter: null };
  const { status, data, headers } = error.response;
  const header = typeof headers?.get === 'function' ? headers.get('retry-after') : headers?.['retry-after'];
  const waits = status === 429 || status === 503;
  return {
    status,
    problem: isProblem(data) ? data : null,
    retryAfter: waits ? retryAfterOf(header, now) : null,
  };
}

/** The problem's code when the error carries one. */
export function problemCode(error: unknown): Problem['code'] | null {
  return failureOf(error).problem?.code ?? null;
}

function isHandled(code: string): code is HandledProblem {
  return (HANDLED_PROBLEMS as readonly string[]).includes(code);
}

/**
 * The text for a failed call, in the page's language: the code's own text, else its status's, else the network or
 * generic text, then the wait when the API named one.
 */
export function problemMessage(failure: ApiFailure, t: TFunction): string {
  const code = failure.problem?.code;
  let text: string;
  if (code && isHandled(code)) {
    text = t(`problems.${code}`);
  } else if (failure.status !== null && (STATUS_TEXTS as readonly number[]).includes(failure.status)) {
    text = t(`problems.status${failure.status}`);
  } else if (failure.status === null) {
    text = t('problems.network');
  } else {
    text = t('problems.unknown');
  }
  if (failure.retryAfter !== null) text = `${text} ${t('problems.retryAfter', { count: failure.retryAfter })}`;
  return text;
}

/** The message for any thrown value. */
export function errorMessage(error: unknown, t: TFunction): string {
  return problemMessage(failureOf(error), t);
}

/**
 * `422 validation_failed` field errors by request body field, from each issue's JSON Pointer (`#/max_expiry`,
 * `#/recipients/3/email`): the pointer without `#/`, so a form puts each message by its input.
 */
export function fieldErrors(failure: ApiFailure): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const issue of failure.problem?.errors ?? []) {
    if (!issue.pointer) continue;
    const field = issue.pointer.replace(/^#?\//, '');
    fields[field] ??= issue.detail;
  }
  return fields;
}

/**
 * Whether the API wants a stronger sign-in for this (authn-authz 3.3): a step-up (`401 reauthentication_required`) or
 * a passkey (`403 passkey_required`). The admin pages explain these instead of showing the bare problem.
 */
export function isAccessProblem(error: unknown): boolean {
  const code = problemCode(error);
  return code === 'reauthentication_required' || code === 'passkey_required';
}
