import { defineConfig, devices } from '@playwright/test';

/**
 * Browser flows against the running local stack (`make up` and `make seed`): the web app at http://localhost:3000,
 * the API, Keycloak, Mailpit and the S3 stand-in, as a person reaches them. `make web-e2e` runs them in the Playwright
 * image pinned in the Makefile, so no browser is installed on the host. #195, #196 and #197 add their flows here
 * (`*.e2e.ts`); #200 adds the M3 journey and the Japanese project.
 *
 * Flows sign in through Keycloak and change the stack's data (they create transfers and users), so they run one at a
 * time, in the order of their files.
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
  reporter: [['list']],
  outputDir: 'test-results/e2e',
  use: {
    baseURL: 'http://localhost:3000',
    ...devices['Desktop Chrome'],
    locale: 'en-US',
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'en', use: { locale: 'en-US' } }],
});
