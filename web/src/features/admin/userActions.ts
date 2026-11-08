import type { User } from '@/api';

/** What the users page's row menu offers (#197). */
export type UserAction = 'role' | 'approver' | 'signOut' | 'reset' | 'resend' | 'deactivate';

/**
 * The actions for one user, in menu order. An invited user who hasn't joined gets "Resend invitation": the reset
 * operation, which sends a new invitation (#197 review). A deactivated user gets none: they can't be changed.
 */
export function userActions(user: Pick<User, 'status'>): UserAction[] {
  switch (user.status) {
    case 'active':
      return ['role', 'approver', 'signOut', 'reset', 'deactivate'];
    case 'invited':
      return ['role', 'approver', 'resend', 'deactivate'];
    case 'deactivated':
      return [];
  }
}
