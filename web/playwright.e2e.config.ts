import { defineConfig, devices } from '@playwright/test';

/**
 * Browser flows against the running local stack (`make up` and `make seed`): the web app at http://localhost:3000,
 * the API, Keycloak, Mailpit and the S3 stand-in, as a person reaches them. `make web-e2e` runs them in the Playwright
 * image pinned in the Makefile, so no browser is installed on the host.
 *
 * - `en`: every flow (`*.e2e.ts`): #195's sign-in, #196's uploads, #197's admin pages, #199's lockout and unlock,
 *   #200's M3 journey and the DLP flows of #218 to #220, in English.
 * - `ja`: the M3 journey and the DLP flows in Japanese (`journey.e2e.ts`, `dlp.e2e.ts`), with a Japanese browser. The
 *   other flows name English labels, so they run in `en` only.
 *
 * Chromium only (#200, web/README.md "Browser journey"). Flows sign in through Keycloak and change the stack's data
 * (they create transfers and users, and the journey moves the jobs' clock), so they run one at a time, in order.
 * A failure keeps the traces of every browser context the test opened and a screenshot; the journey adds screenshots
 * of its other browsers.
 */
export default defineConfig({
  testDir: 'e2e',
  testMatch: '*.e2e.ts',
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'test-results/e2e-report' }]],
  outputDir: 'test-results/e2e',
  use: {
    baseURL: 'http://localhost:3000',
    ...devices['Desktop Chrome'],
    locale: 'en-US',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'en', use: { locale: 'en-US' } },
    { name: 'ja', use: { locale: 'ja-JP' }, testMatch: ['journey.e2e.ts', 'dlp.e2e.ts'] },
  ],
});
