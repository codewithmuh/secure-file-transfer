import axios from 'axios';
import { getConfig } from './config';
import { useAuthStore } from '@/stores/authStore';

export const apiClient = axios.create({
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use((config) => {
  const appConfig = getConfig();
  config.baseURL = appConfig.apiOrigin;

  const csrfToken = useAuthStore.getState().csrfToken;
  if (csrfToken && ['post', 'put', 'patch', 'delete'].includes(config.method ?? '')) {
    config.headers['X-CSRF-Token'] = csrfToken;
  }

  const linkSessionId = useAuthStore.getState().linkSessionId;
  if (linkSessionId) {
    config.headers['X-Link-Session'] = linkSessionId;
  }

  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (axios.isAxiosError(error) && error.response) {
      const { status, data } = error.response;
      if (status === 401) {
        const code = data?.code;
        if (code === 'session_expired' || code === 'authentication_required') {
          useAuthStore.getState().clearAuth();
          window.location.href = '/sign-in';
        }
      }
    }
    return Promise.reject(error);
  },
);
