import { describe, expect, it } from 'vitest';
import {
  downloadLimitOf,
  fileProblem,
  isPlainAddress,
  MAX_FILE_BYTES,
  MAX_RECIPIENTS,
  recipientProblem,
} from './limits';

describe('recipients: the contract\'s address rule, 1 to 50, no address twice (FR-1)', () => {
  it('takes plain addresses', () => {
    for (const ok of ['a@example.com', 'aiko.tanaka+files@example.co.jp', 'x@sub.example.org', '山田@例え.jp']) {
      expect(isPlainAddress(ok), ok).toBe(true);
    }
  });

  it('refuses anything a mail header could misread', () => {
    for (const bad of ['', 'a', 'a@', '@example.com', 'a@@example.com', 'a b@example.com', 'a@example', '<a@example.com>', 'a@example.com,b@example.com', 'a;b@example.com', '"a"@example.com', 'a​@example.com', 'a\n@example.com', `${'a'.repeat(65)}@example.com`, `a@${'b'.repeat(250)}.com`]) {
      expect(isPlainAddress(bad), JSON.stringify(bad)).toBe(false);
    }
  });

  it('refuses a duplicate in any case, and a 51st recipient', () => {
    expect(recipientProblem(' Bob@Example.com ', ['bob@example.com'])).toBe('duplicate');
    expect(recipientProblem('not-an-address', [])).toBe('invalid');
    const fifty = Array.from({ length: MAX_RECIPIENTS }, (_, i) => `r${i}@example.com`);
    expect(recipientProblem('new@example.com', fifty)).toBe('too_many');
    expect(recipientProblem('new@example.com', fifty.slice(1))).toBeNull();
  });
});

describe('files: 50 files, 5 GB each, 20 GB in total (FR-2)', () => {
  it('checks each file against the others', () => {
    expect(fileProblem(1, [])).toBeNull();
    expect(fileProblem(0, [])).toBe('empty');
    expect(fileProblem(MAX_FILE_BYTES + 1, [])).toBe('too_large');
    expect(fileProblem(MAX_FILE_BYTES, [MAX_FILE_BYTES, MAX_FILE_BYTES, MAX_FILE_BYTES])).toBeNull();
    expect(fileProblem(1, [MAX_FILE_BYTES, MAX_FILE_BYTES, MAX_FILE_BYTES, MAX_FILE_BYTES])).toBe('total_too_large');
    expect(fileProblem(1, Array.from({ length: 50 }, () => 1))).toBe('too_many');
  });
});

describe('download limit: empty or 1 to 100 (FR-4)', () => {
  it('reads the field', () => {
    expect(downloadLimitOf('')).toBeNull();
    expect(downloadLimitOf(' 5 ')).toBe(5);
    expect(downloadLimitOf('100')).toBe(100);
    for (const bad of ['0', '101', '1.5', '-1', 'x']) expect(downloadLimitOf(bad)).toBeUndefined();
  });
});
