import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from '@/app/App';
import '@/styles/index.css';
import '@/lib/i18n';
import { captureLinkToken } from '@/features/recipient/linkToken';

// Before anything else: the link token leaves the address bar before any request or render (architecture 4.2). A
// link opened again in the same tab changes only the fragment, so that is read too.
captureLinkToken();
window.addEventListener('hashchange', () => captureLinkToken());

const root = document.getElementById('root');
if (!root) throw new Error('Root element not found');

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
