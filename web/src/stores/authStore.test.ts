import { beforeEach, describe, expect, it } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import { csrfToken, member } from '@/test/apiHarness';

const memberToken = csrfToken('member');
const linkToken = csrfToken('link');

beforeEach(() => {
  useAuthStore.setState(useAuthStore.getInitialState(), true);
});

describe('authStore keeps the member and link sessions apart (#73 defect 2)', () => {
  it('opening a link session leaves the member CSRF token as it was', () => {
    useAuthStore.getState().setAuth(member, memberToken);
    useAuthStore.getState().setLinkSession('ls-1', linkToken);

    const state = useAuthStore.getState();
    expect(state.memberCsrfToken).toBe(memberToken);
    expect(state.linkSession).toEqual({ id: 'ls-1', csrfToken: linkToken });
  });

  it('clearing the link session removes only the link session', () => {
    useAuthStore.getState().setAuth(member, memberToken);
    useAuthStore.getState().setLinkSession('ls-1', linkToken);
    useAuthStore.getState().clearLinkSession();

    const state = useAuthStore.getState();
    expect(state.linkSession).toBeNull();
    expect(state.memberCsrfToken).toBe(memberToken);
    expect(state.memberStatus).toBe('authenticated');
  });

  it('clearing the link session never leaves a link CSRF token behind for a signed-out tab', () => {
    useAuthStore.getState().setLinkSession('ls-1', linkToken);
    useAuthStore.getState().clearLinkSession();

    const state = useAuthStore.getState();
    expect(state.memberCsrfToken).toBeNull();
    expect(Object.values(state)).not.toContain(linkToken);
  });

  it('signing the member out leaves the link session alone', () => {
    useAuthStore.getState().setAuth(member, memberToken);
    useAuthStore.getState().setLinkSession('ls-1', linkToken);
    useAuthStore.getState().clearAuth();

    expect(useAuthStore.getState().linkSession?.id).toBe('ls-1');
  });
});
