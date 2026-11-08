import axios from 'axios';

/**
 * `Idempotency-Key`s (docs/api/README.md 6) for the calls that create something: one key per attempt, from
 * `crypto.randomUUID()`, kept until the attempt succeeds, so a retry after a lost answer replays the first answer
 * instead of creating a second transfer, file or user (#196).
 *
 * The API refuses a key it has seen with another body (`409 idempotency_conflict`), so a key belongs to one body:
 * `keyForBody` gives a new key when what is sent changes, and the same key for an unchanged retry.
 */
export class IdempotencyKeys {
  private keys = new Map<string, { key: string; body: string | null }>();

  /** The key of this attempt at `name`, made on first use. */
  keyFor(name: string): string {
    let entry = this.keys.get(name);
    if (!entry) {
      entry = { key: crypto.randomUUID(), body: null };
      this.keys.set(name, entry);
    }
    return entry.key;
  }

  /** The key of this attempt at `name` with `body`: the same while the body is, a new one once it changes. */
  keyForBody(name: string, body: unknown): string {
    const fingerprint = JSON.stringify(body);
    const entry = this.keys.get(name);
    if (entry && entry.body === fingerprint) return entry.key;
    const key = crypto.randomUUID();
    this.keys.set(name, { key, body: fingerprint });
    return key;
  }

  /** The attempt at `name` succeeded, or was refused for good: the next one is a new attempt with a new key. */
  done(name: string): void {
    this.keys.delete(name);
  }

  /** Starts over: every name gets a new key. */
  reset(): void {
    this.keys.clear();
  }
}

/**
 * Whether a failed call may have been done anyway, so its retry must replay the same key: no answer (the network or a
 * timeout), `429`, or a server error. Any other `4xx` is a definite refusal the user changes their input for; the key
 * goes with it.
 */
export function mayHaveHappened(error: unknown): boolean {
  if (!axios.isAxiosError(error) || !error.response) return true;
  const { status } = error.response;
  return status === 408 || status === 429 || status >= 500;
}
