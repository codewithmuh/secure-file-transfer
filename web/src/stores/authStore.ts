import { create } from 'zustand';

interface AuthState {
  isAuthenticated: boolean;
  csrfToken: string | null;
  linkSessionId: string | null;
  user: {
    id: string;
    email: string;
    name: string;
    role: 'admin' | 'member';
    tenantId: string;
    tenantName: string;
  } | null;
  setAuth: (user: AuthState['user'], csrfToken: string) => void;
  setLinkSession: (sessionId: string, csrfToken: string) => void;
  clearLinkSession: () => void;
  clearAuth: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  isAuthenticated: false,
  csrfToken: null,
  linkSessionId: null,
  user: null,
  setAuth: (user, csrfToken) =>
    set({ isAuthenticated: true, user, csrfToken }),
  setLinkSession: (sessionId, csrfToken) =>
    set({ linkSessionId: sessionId, csrfToken }),
  clearLinkSession: () =>
    set({ linkSessionId: null }),
  clearAuth: () =>
    set({ isAuthenticated: false, user: null, csrfToken: null, linkSessionId: null }),
}));
