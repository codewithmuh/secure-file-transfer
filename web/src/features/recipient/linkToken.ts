import { useAuthStore, type LinkMode } from '@/stores/authStore';

/** The public link pages and whose they are: `/t` the recipient's, `/u` the uploader's. */
const LINK_PAGES: Record<string, LinkMode> = { '/t': 'recipient', '/u': 'uploader' };

interface PageLocation {
  pathname: string;
  hash: string;
  search: string;
}

interface PageHistory {
  replaceState(data: unknown, unused: string, url?: string | URL | null): void;
}

/**
 * Reads the link token from the URL fragment (`/t#<token>`) and removes it from the address bar with
 * `history.replaceState`, before anything else runs (architecture 4.2): `main.tsx` calls this before the config is
 * loaded and before React renders, so no request, script or later navigation sees the fragment. The token goes to the
 * store, in memory only, and from there only into request bodies. Returns the mode it was kept for, or null when this
 * isn't a link page or there is no fragment.
 */
export function captureLinkToken(
  location: PageLocation = window.location,
  history: PageHistory = window.history,
): LinkMode | null {
  const mode = LINK_PAGES[location.pathname.replace(/\/+$/, '') || '/'];
  const token = location.hash.replace(/^#/, '');
  if (!mode || location.hash === '') return null;
  history.replaceState(null, '', `${location.pathname}${location.search}`);
  if (token === '') return null;
  useAuthStore.getState().setLinkToken(mode, token);
  return mode;
}
