/**
 * ISO 8601 durations as the contract writes them (`PT1H`, `P7D`, `P1DT12H`): a transfer's `expires_in` and the tenant
 * policy's `max_expiry` (FR-3, FR-23), both between `PT1H` and `P30D`. Only days, hours, minutes and seconds: the API
 * writes nothing else (transfer_schemas.py, `_duration`).
 */

const PATTERN = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/;

export const MIN_EXPIRY = 'PT1H';
export const MAX_EXPIRY = 'P30D';
export const DEFAULT_EXPIRY = 'P7D';

/** The choices the pages offer, shortest first: the create-transfer form and the tenant policy. */
export const EXPIRY_CHOICES = ['PT1H', 'PT6H', 'PT12H', 'P1D', 'P3D', 'P7D', 'P14D', 'P30D'] as const;

/** Seconds in a duration, or `null` if it isn't one the contract writes. */
export function durationSeconds(value: string): number | null {
  const match = PATTERN.exec(value);
  if (!match || value === 'P' || value.endsWith('T')) return null;
  const [days, hours, minutes, seconds] = match.slice(1).map((part) => Number(part ?? 0)) as [number, number, number, number];
  return ((days * 24 + hours) * 60 + minutes) * 60 + seconds;
}

/** The contract's spelling of a number of seconds, as the API writes it: `P30D`, `PT12H`, `P1DT12H`. */
export function formatDuration(totalSeconds: number): string {
  const days = Math.floor(totalSeconds / 86400);
  let rest = totalSeconds % 86400;
  const hours = Math.floor(rest / 3600);
  rest %= 3600;
  const minutes = Math.floor(rest / 60);
  const seconds = rest % 60;
  const time = [
    [hours, 'H'],
    [minutes, 'M'],
    [seconds, 'S'],
  ]
    .filter(([n]) => n)
    .map(([n, unit]) => `${n}${unit}`)
    .join('');
  const text = `P${days ? `${days}D` : ''}${time ? `T${time}` : ''}`;
  return text === 'P' ? 'PT0S' : text;
}

/** The same duration in the contract's spelling (`P1DT0H` → `P1D`), or `null`. */
export function normalizeDuration(value: string): string | null {
  const seconds = durationSeconds(value);
  return seconds === null ? null : formatDuration(seconds);
}

/**
 * The expiry choices for a new transfer: every choice up to the tenant's `max_expiry`, with the cap itself when it
 * isn't one of them, so the form never offers more than the policy allows.
 */
export function expiryOptions(maxExpiry: string | undefined): string[] {
  const cap = maxExpiry === undefined ? null : durationSeconds(maxExpiry);
  const limit = cap ?? (durationSeconds(MAX_EXPIRY) as number);
  const options: string[] = EXPIRY_CHOICES.filter((choice) => (durationSeconds(choice) as number) <= limit);
  const capText = formatDuration(limit);
  if (!options.includes(capText)) options.push(capText);
  return options.sort((a, b) => (durationSeconds(a) as number) - (durationSeconds(b) as number));
}

/** The contract's default: `P7D`, or the tenant's maximum if that is shorter. */
export function defaultExpiry(maxExpiry: string | undefined): string {
  const cap = maxExpiry === undefined ? null : durationSeconds(maxExpiry);
  const seven = durationSeconds(DEFAULT_EXPIRY) as number;
  return cap !== null && cap < seven ? formatDuration(cap) : DEFAULT_EXPIRY;
}

/** The parts of a duration for a translated label: whole days, else whole hours, else minutes. */
export function durationLabelParts(value: string): { unit: 'days' | 'hours' | 'minutes'; count: number } {
  const seconds = durationSeconds(value) ?? 0;
  if (seconds % 86400 === 0) return { unit: 'days', count: seconds / 86400 };
  if (seconds % 3600 === 0) return { unit: 'hours', count: seconds / 3600 };
  return { unit: 'minutes', count: Math.round(seconds / 60) };
}
