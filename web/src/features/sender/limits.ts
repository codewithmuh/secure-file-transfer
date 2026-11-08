/**
 * The client-side checks of the create-transfer form (#196), mirroring the API's rules so a member hears about a
 * problem before uploading anything. The API checks again and has the last word: its `413` and `422` codes are shown
 * when the two disagree.
 */

/** FR-1: 1 to 50 recipients, no address twice. */
export const MAX_RECIPIENTS = 50;
/** FR-2: 50 files, 5 GB each, 20 GB in total (decimal, as the API counts: sft.service.uploads). */
export const MAX_FILES = 50;
export const MAX_FILE_BYTES = 5_000_000_000;
export const MAX_TOTAL_BYTES = 20_000_000_000;
/** The message and the download limit (TransferCreate). */
export const MAX_MESSAGE = 2000;
export const MIN_DOWNLOAD_LIMIT = 1;
export const MAX_DOWNLOAD_LIMIT = 100;
/** EmailAddress: format email, at most 254 characters. */
export const MAX_ADDRESS = 254;

/**
 * One plain address the mail adapter takes (sft.core.addresses): `local@domain`, no whitespace, no `@` but the one, none
 * of `< > " , ;`, and no control or invisible format character. The domain needs a dot, as every deliverable one has.
 */
const ADDRESS_CHAR = '[^\\s@<>",;\\u0000-\\u001f\\u007f-\\u009f\\u00ad\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u206f\\ufeff]';
const PLAIN_ADDRESS = new RegExp(`^${ADDRESS_CHAR}{1,64}@${ADDRESS_CHAR}+\\.${ADDRESS_CHAR}+$`, 'u');

export function isPlainAddress(value: string): boolean {
  return value.length <= MAX_ADDRESS && PLAIN_ADDRESS.test(value);
}

/** How the API compares addresses: trimmed, lower case. */
export function normalizeAddress(value: string): string {
  return value.trim().toLowerCase();
}

export type RecipientProblem = 'invalid' | 'duplicate' | 'too_many';

/** Why an address can't be added to `existing`, or `null` when it can. */
export function recipientProblem(value: string, existing: readonly string[]): RecipientProblem | null {
  const address = value.trim();
  if (!isPlainAddress(address)) return 'invalid';
  if (existing.some((other) => normalizeAddress(other) === normalizeAddress(address))) return 'duplicate';
  if (existing.length >= MAX_RECIPIENTS) return 'too_many';
  return null;
}

export type FileProblem = 'empty' | 'too_large' | 'total_too_large' | 'too_many';

/** Why `size` can't join files whose sizes are `existing`, or `null` when it can (FR-2). */
export function fileProblem(size: number, existing: readonly number[]): FileProblem | null {
  if (size <= 0) return 'empty';
  if (size > MAX_FILE_BYTES) return 'too_large';
  if (existing.length >= MAX_FILES) return 'too_many';
  if (existing.reduce((sum, n) => sum + n, 0) + size > MAX_TOTAL_BYTES) return 'total_too_large';
  return null;
}

/** A download limit from the form: empty is no limit; otherwise a whole number from 1 to 100, or `undefined` if not. */
export function downloadLimitOf(text: string): number | null | undefined {
  if (text.trim() === '') return null;
  if (!/^\d+$/.test(text.trim())) return undefined;
  const value = Number(text.trim());
  return value >= MIN_DOWNLOAD_LIMIT && value <= MAX_DOWNLOAD_LIMIT ? value : undefined;
}
