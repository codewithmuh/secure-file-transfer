import { describe, expect, it } from 'vitest';
import {
  defaultExpiry,
  durationLabelParts,
  durationSeconds,
  EXPIRY_CHOICES,
  expiryOptions,
  formatDuration,
  normalizeDuration,
} from './durations';

describe('durations: the contract\'s ISO 8601 spelling (#196, #197)', () => {
  it('round-trips every choice with the API\'s own spelling', () => {
    for (const choice of EXPIRY_CHOICES) {
      expect(formatDuration(durationSeconds(choice) as number)).toBe(choice);
    }
    expect(durationSeconds('PT1H')).toBe(3600);
    expect(durationSeconds('P30D')).toBe(30 * 86400);
    expect(formatDuration(36 * 3600)).toBe('P1DT12H');
    expect(normalizeDuration('P1DT0H')).toBe('P1D');
    expect(normalizeDuration('PT24H')).toBe('P1D');
  });

  it('refuses what the contract never writes', () => {
    for (const bad of ['', 'P', 'PT', 'P1W', 'P1M', 'P1Y', '7D', 'P7DT', 'p7d', 'P-1D', 'PT1.5H']) {
      expect(durationSeconds(bad)).toBeNull();
    }
  });

  it('labels a duration in its largest whole unit', () => {
    expect(durationLabelParts('P7D')).toEqual({ unit: 'days', count: 7 });
    expect(durationLabelParts('PT12H')).toEqual({ unit: 'hours', count: 12 });
    expect(durationLabelParts('P1DT12H')).toEqual({ unit: 'hours', count: 36 });
    expect(durationLabelParts('PT90M')).toEqual({ unit: 'minutes', count: 90 });
  });
});

describe('expiry options: cut at the tenant\'s max_expiry (FR-3, FR-23)', () => {
  it('offers everything up to P30D without a policy', () => {
    expect(expiryOptions(undefined)).toEqual([...EXPIRY_CHOICES]);
  });

  it('offers nothing longer than the cap, and the cap itself', () => {
    expect(expiryOptions('P3D')).toEqual(['PT1H', 'PT6H', 'PT12H', 'P1D', 'P3D']);
    expect(expiryOptions('P10D')).toEqual(['PT1H', 'PT6H', 'PT12H', 'P1D', 'P3D', 'P7D', 'P10D']);
    expect(expiryOptions('PT1H')).toEqual(['PT1H']);
    expect(expiryOptions('P1DT12H')).toEqual(['PT1H', 'PT6H', 'PT12H', 'P1D', 'P1DT12H']);
  });

  it('defaults to P7D, or to the cap when it is shorter', () => {
    expect(defaultExpiry(undefined)).toBe('P7D');
    expect(defaultExpiry('P30D')).toBe('P7D');
    expect(defaultExpiry('P7D')).toBe('P7D');
    expect(defaultExpiry('P3D')).toBe('P3D');
    expect(defaultExpiry('PT12H')).toBe('PT12H');
  });
});
