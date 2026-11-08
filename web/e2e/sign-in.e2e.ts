import { expect, test } from '@playwright/test';
import { fillKeycloak, signIn, USERS } from './support/stack';

/**
 * #195: the web app in the stack, on its own origin. Sign-in from a deep link comes back to it, an unsafe call from
 * http://localhost:3000 passes the API's Origin, Sec-Fetch-Site and CSRF checks across origins, sign-out reaches
 * Keycloak's logout, and http://127.0.0.1:3000 goes to localhost.
 */

test('a deep link signs in through Keycloak, lands back on it, and sign-out reaches Keycloak', async ({ page }) => {
  const errors: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'error' && /Content Security Policy|CSP/i.test(message.text())) errors.push(message.text());
  });
  page.on('pageerror', (error) => errors.push(error.message));

  // The deep link: after Keycloak, the app is back on /transfers/new with the member loaded (GET /me).
  await signIn(page, 'member', '/transfers/new');
  await expect(page.getByRole('heading', { level: 1, name: 'Send files securely' })).toBeVisible();

  // Sign-out is a cross-origin POST with the CSRF token; the API answers 200 and sends the browser to Keycloak.
  const signedOut = page.waitForResponse((response) => response.url() === 'http://localhost:8000/v1/auth/sign-out');
  await page.getByRole('banner').getByRole('button', { name: 'Sign out' }).click();
  const response = await signedOut;
  expect(response.status()).toBe(200);
  const sent = await response.request().allHeaders();
  expect(sent['origin']).toBe('http://localhost:3000');
  expect(sent['sec-fetch-site']).toBe('same-site');
  expect(sent['x-csrf-token']).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
  await expect(page).toHaveURL(/^http:\/\/localhost:8180\/realms\/sft\/protocol\/openid-connect\/logout/);

  // The session cookie is gone: the app asks for a sign-in again, and Keycloak asks for the password again.
  await page.goto('/transfers');
  await expect(page).toHaveURL(/\/sign-in$/);
  await page.getByRole('button', { name: 'Sign in with password or passkey' }).click();
  await expect(page.locator('#password')).toBeVisible();
  await fillKeycloak(page, USERS.member.email, USERS.member.password);
  await expect(page).toHaveURL('http://localhost:3000/transfers');

  expect(errors, 'no CSP report or page error').toEqual([]);
});

test('http://127.0.0.1:3000 goes to http://localhost:3000', async ({ page }) => {
  const response = await page.request.get('http://127.0.0.1:3000/transfers?x=1', { maxRedirects: 0 });
  expect(response.status()).toBe(308);
  expect(response.headers()['location']).toBe('http://localhost:3000/transfers?x=1');
  await page.goto('http://127.0.0.1:3000/sign-in');
  await expect(page).toHaveURL('http://localhost:3000/sign-in');
});

test('M5 pages are live: each has its navigation entry', async ({ page }) => {
  await signIn(page, 'admin');
  const nav = page.getByRole('navigation');
  await expect(nav.getByRole('link', { name: 'Transfers' })).toBeVisible();
  // Upload requests (#212), the audit log (#216), API keys (#215) and the DLP policy (#218).
  for (const name of ['Upload Requests', 'Audit Log', 'API Keys', 'Data loss prevention']) {
    await expect(nav.getByRole('link', { name })).toBeVisible();
  }
});
