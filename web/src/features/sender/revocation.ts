import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { failureOf } from '@/lib/problems';

/**
 * Where a member's revocation stands on the detail page (#199, FR-20). `revokeTransfer` answers `200` once the record
 * is in both regions' audit archive; `503` means the revocation has taken effect but its record isn't confirmed yet.
 * The contract says the web app must not then say it failed: it says the transfer is revoked, retries in the
 * background, and offers a retry, which is always safe (a revoked transfer's revocation returns `200`).
 */
export type RevocationStatus = 'idle' | 'revoked' | 'unconfirmed' | 'failed';

/** The first background retry of an unconfirmed revocation waits this long; each next one twice as long. */
export const REVOKE_RETRY_MS = 15_000;

/** The longest wait between two background retries. */
export const REVOKE_RETRY_MAX_MS = 120_000;

/** The wait before background retry number `attempt` (from 0): 15 s, 30 s, 60 s, then every 2 minutes. */
export function revokeRetryDelay(attempt: number): number {
  return Math.min(REVOKE_RETRY_MS * 2 ** Math.max(0, attempt), REVOKE_RETRY_MAX_MS);
}

/**
 * The status after a `revokeTransfer` call: `revoked` on success, `unconfirmed` on `503`, and `failed` on any other
 * error, unless an earlier call already took effect: then the revocation stands, and it stays `unconfirmed`.
 */
export function nextRevocation(previous: RevocationStatus, error: unknown | null): RevocationStatus {
  if (error === null) return 'revoked';
  if (failureOf(error).status === 503 || previous === 'unconfirmed') return 'unconfirmed';
  return 'failed';
}

export interface RevocationState {
  status: RevocationStatus;
  /** True while a call runs; the status keeps saying what is known meanwhile. */
  busy: boolean;
  /** The error of a `failed` revocation, else null. */
  error: unknown;
}

/**
 * One transfer's revocation and its background retries, outside React so the retries can be tested with fake timers.
 * It is bound to the transfer it was made for: every call, background ones included, revokes that transfer. While its
 * status is `unconfirmed` it retries with a growing wait (`revokeRetryDelay`) until a call answers `200`; a manual
 * retry that answers `503` again arms the next one. `stop` (the page went away) cancels the pending retry.
 */
export class Revocation {
  private state: RevocationState = { status: 'idle', busy: false, error: null };
  private readonly listeners = new Set<() => void>();
  private timer: ReturnType<typeof setTimeout> | null = null;
  private attempt = 0;
  private running = true;

  constructor(
    readonly transferId: string,
    private readonly call: (transferId: string) => Promise<unknown>,
    private readonly onSettled: () => void,
  ) {}

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  getState = (): RevocationState => this.state;

  /** Revokes the transfer. Resolves with the new status once the call answered, whatever it was. */
  revoke = async (): Promise<RevocationStatus> => {
    this.cancelRetry();
    const previous = this.state.status;
    this.set({ ...this.state, busy: true });
    let failure: unknown = null;
    try {
      await this.call(this.transferId);
    } catch (caught) {
      failure = caught;
    }
    const status = nextRevocation(previous, failure);
    this.set({ status, busy: false, error: status === 'failed' ? failure : null });
    if (status !== 'unconfirmed') this.attempt = 0;
    this.armRetry();
    this.onSettled();
    return status;
  };

  /** Back to `idle` after a failed revocation (the dialog closed). */
  reset = (): void => {
    this.cancelRetry();
    this.attempt = 0;
    this.set({ status: 'idle', busy: false, error: null });
  };

  /** The page shows this transfer: retry an unconfirmed revocation in the background. */
  start(): void {
    this.running = true;
    this.armRetry();
  }

  /** The page no longer shows this transfer: no retry runs for it any more. */
  stop(): void {
    this.running = false;
    this.cancelRetry();
  }

  private armRetry(): void {
    if (!this.running || this.timer !== null || this.state.status !== 'unconfirmed' || this.state.busy) return;
    const delay = revokeRetryDelay(this.attempt);
    this.attempt += 1;
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.revoke();
    }, delay);
  }

  private cancelRetry(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }

  private set(next: RevocationState): void {
    this.state = next;
    for (const listener of this.listeners) listener();
  }
}

/**
 * A transfer's revocation for the detail page. The page keys its view by transfer ID, so another transfer gets a new
 * `Revocation`, and a retry still pending for the one before is stopped with its view.
 */
export function useRevocation(transferId: string, revoke: (transferId: string) => Promise<unknown>, onSettled: () => void) {
  const settled = useRef(onSettled);
  useEffect(() => {
    settled.current = onSettled;
  }, [onSettled]);
  const [revocation] = useState(() => new Revocation(transferId, revoke, () => settled.current()));

  useEffect(() => {
    revocation.start();
    return () => revocation.stop();
  }, [revocation]);

  const state = useSyncExternalStore(revocation.subscribe, revocation.getState);
  return { ...state, revoke: revocation.revoke, reset: revocation.reset };
}
