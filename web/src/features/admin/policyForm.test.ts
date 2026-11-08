import { describe, expect, it } from 'vitest';
import type { TenantPolicy } from '@/hooks/users';
import type { ApiFailure } from '@/lib/problems';
import { changedFields, formOf, policyFieldErrors, retentionDays } from './policyForm';

const policy: TenantPolicy = {
  max_expiry: 'P30D',
  unscannable_policy: 'block',
  received_file_retention_days: 30,
  allowed_domains: [],
  blocked_domains: [],
  default_locale: 'ja',
  updated_at: '2026-11-01T00:00:00Z',
};

describe('the tenant policy form (#197)', () => {
  it('sends nothing when nothing changed', () => {
    expect(changedFields(policy, formOf(policy))).toEqual({});
  });

  it('sends only the fields that changed, in the contract\'s spelling', () => {
    expect(changedFields(policy, { ...formOf(policy), max_expiry: 'P3D' })).toEqual({ max_expiry: 'P3D' });
    expect(changedFields(policy, { ...formOf(policy), unscannable_policy: 'allow_with_warning', default_locale: 'en' })).toEqual({
      unscannable_policy: 'allow_with_warning',
      default_locale: 'en',
    });
    expect(changedFields(policy, { ...formOf(policy), received_file_retention_days: ' 7 ' })).toEqual({
      received_file_retention_days: 7,
    });
  });

  it('never sends the domain lists (FR-24, M5)', () => {
    const body = changedFields(policy, { ...formOf(policy), max_expiry: 'PT1H' }) ?? {};
    expect(Object.keys(body)).not.toContain('allowed_domains');
    expect(Object.keys(body)).not.toContain('blocked_domains');
  });

  it('treats the same duration in another spelling as unchanged', () => {
    expect(changedFields({ ...policy, max_expiry: 'PT720H' }, { ...formOf(policy), max_expiry: 'P30D' })).toEqual({});
    expect(formOf({ ...policy, max_expiry: 'PT72H' }).max_expiry).toBe('P3D');
  });

  it('refuses a retention outside 1 to 90 days', () => {
    for (const bad of ['0', '91', '', 'x', '1.5']) {
      expect(retentionDays(bad)).toBeNull();
      expect(changedFields(policy, { ...formOf(policy), received_file_retention_days: bad })).toBeNull();
    }
    expect(retentionDays('90')).toBe(90);
  });

  it('puts each 422 field error on its input, and the rest on the form', () => {
    const failure: ApiFailure = {
      status: 422,
      retryAfter: null,
      problem: {
        type: 'https://secure-file-transfer.example/problems/validation_failed',
        title: 'Validation failed',
        status: 422,
        code: 'validation_failed',
        errors: [
          { detail: 'Between PT1H and P30D.', pointer: '#/max_expiry' },
          { detail: 'From 1 to 90.', pointer: '#/received_file_retention_days' },
          { detail: 'Unknown field.', pointer: '#/colour' },
          { detail: 'Bad header.', header: 'X-CSRF-Token' },
        ],
      },
    };
    expect(policyFieldErrors(failure)).toEqual({
      fields: { max_expiry: 'Between PT1H and P30D.', received_file_retention_days: 'From 1 to 90.' },
      other: ['Unknown field.'],
    });
  });
});
