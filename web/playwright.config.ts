import { defineConfig, devices } from '@playwright/test';

/**
 * Accessibility checks (NFR-22, #110): axe against the built app, served by `vite preview`, in English and in
 * Japanese. Run them with `make web-a11y`, which uses the Playwright image pinned there, so no browser is installed
 * on the host. The image's version must equal `@playwright/test` in package.json.
 */
const PORT = 4173;

export default defineConfig({
  testDir: 'e2e',
  testMatch: '*.a11y.ts',
  fullyParallel: true,
  forbidOnly: true,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    ...devices['Desktop Chrome'],
  },
  // One project per language (FR-33). The app picks its language from the browser's (lib/i18n.ts).
  projects: [
    { name: 'en', use: { locale: 'en-US' } },
    { name: 'ja', use: { locale: 'ja-JP' } },
  ],
  webServer: {
    command: `npx vite preview --host 127.0.0.1 --port ${PORT} --strictPort`,
    url: `http://127.0.0.1:${PORT}/config.json`,
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
