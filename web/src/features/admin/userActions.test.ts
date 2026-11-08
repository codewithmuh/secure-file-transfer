import { describe, expect, it } from 'vitest';
import { resources } from '@/lib/i18n';
import { userActions } from './userActions';

describe('userActions: the users page row menu (#197)', () => {
  it('offers an invited user "Resend invitation", the reset that sends a new one (#197 review)', () => {
    expect(userActions({ status: 'invited' })).toContain('resend');
    expect(userActions({ status: 'invited' })).not.toContain('signOut');
    for (const language of ['en', 'ja'] as const) {
      const admin = resources[language].translation.admin;
      expect(admin.resendInvitation).toBeTruthy();
      expect(admin.confirm.resend.action).toBeTruthy();
    }
  });

  it('offers an active user sign-out and reset, and a deactivated user nothing', () => {
    expect(userActions({ status: 'active' })).toEqual(['role', 'approver', 'signOut', 'reset', 'deactivate']);
    expect(userActions({ status: 'deactivated' })).toEqual([]);
  });
});
