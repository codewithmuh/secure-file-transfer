import type { Transfer, TransferState } from '@/api';
import { durationSeconds } from '@/lib/durations';
import { expiryCapSeconds } from './uploadRequests';
import { REVOCABLE_STATES } from './states';

/**
 * The "extend expiry" dialog's range (#214, FR-9; API README 10). The limits apply to the transfer's whole lifetime,
 * counted from `submitted_at`: the new time is at most 30 days, and at most the tenant's `max_expiry` as it is now,
 * after `submitted_at`, and never earlier than the current `expires_at`. The API checks again and answers
 * `422 expiry_out_of_range` when the two disagree (a policy changed meanwhile).
 */

/** The states `extendTransferExpiry` takes: submitted and not ended, the same as a revocation. */
export const EXTENDABLE_STATES: readonly TransferState[] = REVOCABLE_STATES;

/** The steps the dialog offers after the current expiry, each only while it stays within the limit. */
export const EXTENSION_STEPS = ['P1D', 'P3D', 'P7D', 'P14D'] as const;

export type ExtensionChoice =
  | { kind: 'step'; step: (typeof EXTENSION_STEPS)[number]; expiresAt: string }
  | { kind: 'latest'; expiresAt: string };

type Extendable = Pick<Transfer, 'state' | 'expires_at' | 'submitted_at'>;

/** The latest `expires_at` the transfer may get (ms), or `null` when it has no lifetime yet (a draft). */
export function extensionLimit(transfer: Pick<Transfer, 'submitted_at'>, maxExpiry: string | undefined): number | null {
  if (!transfer.submitted_at) return null;
  const submitted = Date.parse(transfer.submitted_at);
  if (Number.isNaN(submitted)) return null;
  return submitted + expiryCapSeconds(maxExpiry) * 1000;
}

/**
 * The times the member can choose, earliest first: each step after the current expiry that stays before the limit,
 * then the limit itself ("the latest allowed"). Empty when the transfer can't be extended: a state that doesn't take
 * it, no expiry yet, an expiry already past, or one already at the limit.
 */
export function extensionChoices(transfer: Extendable, maxExpiry: string | undefined, now: number): ExtensionChoice[] {
  if (!EXTENDABLE_STATES.includes(transfer.state) || !transfer.expires_at) return [];
  const current = Date.parse(transfer.expires_at);
  const limit = extensionLimit(transfer, maxExpiry);
  if (Number.isNaN(current) || limit === null || current <= now || limit <= current) return [];
  const choices: ExtensionChoice[] = [];
  for (const step of EXTENSION_STEPS) {
    const time = current + (durationSeconds(step) as number) * 1000;
    if (time < limit) choices.push({ kind: 'step', step, expiresAt: new Date(time).toISOString() });
  }
  choices.push({ kind: 'latest', expiresAt: new Date(limit).toISOString() });
  return choices;
}
