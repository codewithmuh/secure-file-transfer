import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { formatFileSize, formatRelativeTime } from './formatters';

describe('formatFileSize', () => {
  it.each([
    [0, '0 B'],
    [512, '512 B'],
    [1024, '1.0 KB'],
    [1536, '1.5 KB'],
    [5 * 1024 ** 3, '5.0 GB'],
  ])('formats %d bytes as %s', (bytes, expected) => {
    expect(formatFileSize(bytes)).toBe(expected);
  });
});

describe('formatRelativeTime', () => {
  const now = new Date('2026-11-04T12:00:00Z');

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(now);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const at = (offsetMs: number) => new Date(now.getTime() + offsetMs).toISOString();

  it.each([
    [30 * 60_000, 'in 30m'],
    [-5 * 60_000, '5m ago'],
    [2 * 3_600_000, 'in 2h'],
    [-3 * 3_600_000, '3h ago'],
    [7 * 86_400_000, 'in 7d'],
    [-2 * 86_400_000, '2d ago'],
  ])('formats an offset of %d ms as %s', (offsetMs, expected) => {
    expect(formatRelativeTime(at(offsetMs))).toBe(expected);
  });
});
