import { afterEach, describe, expect, it, vi } from 'vitest';
import { renderToString } from 'react-dom/server';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { csrfToken, currentMember, setUpApi } from '@/test/apiHarness';
import { ProtectedRoute } from './ProtectedRoute';

/**
 * Renders a deep link to a protected page as the first render after a page load. Vitest runs in Node without a DOM,
 * so this renders to a string: effects don't run, a redirect (`<Navigate>`) renders nothing, and the store is read at
 * its initial state, which is exactly a fresh page load. What happens once `GET /me` answers is covered by
 * routeAccess.test.ts and memberSession.test.ts.
 */
function renderDeepLink(path = '/transfers/abc') {
  return renderToString(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/sign-in" element={<p>sign-in page</p>} />
        <Route
          path="/transfers/:id"
          element={
            <ProtectedRoute>
              <p>transfer detail</p>
            </ProtectedRoute>
          }
        />
      </Routes>
    </MemoryRouter>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('ProtectedRoute after a refresh or a deep link (#73 defect 1)', () => {
  it('waits with a loading state instead of redirecting before the session check answers', async () => {
    await setUpApi(() => ({ status: 200, data: currentMember(csrfToken('m')) }));

    const html = renderDeepLink();

    expect(html).toContain('animate-spin');
    expect(html).not.toContain('transfer detail');
  });
});
