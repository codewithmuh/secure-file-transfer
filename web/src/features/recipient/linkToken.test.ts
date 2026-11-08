import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import { captureLinkToken } from './linkToken';

/** `main.tsx` as written, to check the order its statements run in. */
const main = Object.values(import.meta.glob('/src/main.tsx', { query: '?raw', import: 'default', eager: true }))[0] as string;

const token = 'Ab3_-'.repeat(9);

function page(pathname: string, hash: string, search = '') {
  const replaceState = vi.fn();
  return { location: { pathname, hash, search }, history: { replaceState } };
}

beforeEach(() => {
  useAuthStore.setState(useAuthStore.getInitialState(), true);
});

describe('captureLinkToken (architecture 4.2)', () => {
  it('removes the fragment from the address bar and keeps the token in memory only', () => {
    const { location, history } = page('/t', `#${token}`, '?utm=x');
    expect(captureLinkToken(location, history)).toBe('recipient');
    expect(history.replaceState).toHaveBeenCalledWith(null, '', '/t?utm=x');
    expect(useAuthStore.getState().linkToken).toEqual({ mode: 'recipient', value: token });
  });

  it('keeps the uploader\'s token for /u, with a trailing slash too', () => {
    const { location, history } = page('/u/', `#${token}`);
    expect(captureLinkToken(location, history)).toBe('uploader');
    expect(useAuthStore.getState().linkToken?.mode).toBe('uploader');
  });

  it('removes an empty fragment, and keeps nothing', () => {
    const { location, history } = page('/t', '#');
    expect(captureLinkToken(location, history)).toBeNull();
    expect(history.replaceState).toHaveBeenCalledOnce();
    expect(useAuthStore.getState().linkToken).toBeNull();
  });

  it('leaves every other page and its fragment alone', () => {
    const { location, history } = page('/transfers', '#section');
    expect(captureLinkToken(location, history)).toBeNull();
    expect(history.replaceState).not.toHaveBeenCalled();
  });

  it('runs before the app renders, and so before any request: main.tsx calls it first', () => {
    const capture = main.indexOf('captureLinkToken();');
    expect(capture).toBeGreaterThan(0);
    expect(capture).toBeLessThan(main.indexOf('createRoot('));
    // Only imports come before it: no statement that could start a request.
    const before = main.slice(0, capture).split('\n').filter((line) => line.trim() && !line.trim().startsWith('//'));
    expect(before.every((line) => line.startsWith('import '))).toBe(true);
  });
});
