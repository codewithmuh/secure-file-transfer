import { describe, expect, it } from 'vitest';
import { routeAccess } from './routeAccess';

describe('routeAccess: what a protected route shows (#73 defect 1)', () => {
  it('waits while the member status is unknown or being checked', () => {
    expect(routeAccess('unknown', undefined)).toBe('wait');
    expect(routeAccess('checking', undefined, 'admin')).toBe('wait');
  });

  it('sends a signed-out tab to sign-in, and a member away from admin pages', () => {
    expect(routeAccess('anonymous', undefined)).toBe('sign-in');
    expect(routeAccess('authenticated', 'member', 'admin')).toBe('forbidden');
    expect(routeAccess('authenticated', 'admin', 'admin')).toBe('allow');
    expect(routeAccess('authenticated', 'member')).toBe('allow');
  });
});
