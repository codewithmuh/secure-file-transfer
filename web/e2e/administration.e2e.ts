import { expect, test, type Page } from '@playwright/test';
import { payload, readBytes, sendPastWarning, signIn, unique, USERS, wordsText } from './support/stack';

/** The API's own origin: the web app's nginx serves only the bundle, so a relative /v1 path never reaches the API. */
const API = 'http://localhost:8000';

/**
 * M5's administration in the browser (#215, #216, #217), against `make up` and `make seed`: an admin creates an API
 * key, sees it once, uses it from the test and revokes it; searches, pages, opens and exports the audit log; and
 * lists and revokes another member's transfer from the tenant-wide list.
 */

function row(page: Page, text: string) {
  return page.getByRole('row').filter({ has: page.getByText(text, { exact: true }) });
}

test('an API key: created, shown once, used with curl, revoked, then refused (#215)', async ({ page, request }) => {
  await signIn(page, 'admin', '/admin/api-keys');
  const name = unique('e2e-key');

  await page.getByRole('button', { name: 'Create API key' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Create API key' });
  await dialog.getByLabel('Name').fill(name);
  await dialog.getByRole('checkbox', { name: /transfers:read/ }).check();
  await dialog.getByRole('button', { name: 'Create' }).click();

  const shown = page.getByRole('dialog', { name: 'Copy your new API key' });
  const secret = await shown.getByRole('textbox').inputValue();
  expect(secret).toMatch(/^sft_dev_[0-9A-Za-z]{43}_[0-9A-Za-z]{6}$/);
  await shown.getByRole('checkbox', { name: 'I have stored the key somewhere safe.' }).check();
  await shown.getByRole('button', { name: 'Done' }).click();
  await expect(shown).toBeHidden();

  // The list shows its prefix only; the secret never comes back.
  const keyRow = row(page, name);
  await expect(keyRow.getByText(`${secret.slice(0, 16)}…`)).toBeVisible();
  await page.reload();
  await expect(page.getByText(secret)).toHaveCount(0);

  // The key works as a bearer token, the way automation uses it.
  const bearer = { Authorization: `Bearer ${secret}` };
  const listed = await request.get(`${API}/v1/transfers?scope=tenant`, { headers: bearer });
  expect(listed.status()).toBe(200);
  // A web-only operation is refused (T-55), and a scope the key lacks too.
  expect((await request.get(`${API}/v1/users`, { headers: bearer })).status()).toBe(403);
  expect((await request.post(`${API}/v1/audit/events/search`, { headers: bearer, data: {} })).status()).toBe(403);

  await row(page, name).getByRole('button', { name: `Revoke ${name}` }).click();
  await page.getByRole('dialog', { name: 'Revoke API key' }).getByRole('button', { name: 'Revoke' }).click();
  await expect(row(page, name).getByText('Revoked', { exact: true })).toBeVisible();

  // Lookups aren't cached: the next request is refused.
  const refused = await request.get(`${API}/v1/transfers`, { headers: bearer });
  expect(refused.status()).toBe(401);
  expect(((await refused.json()) as { code: string }).code).toBe('credentials_invalid');
});

test('the audit log: search, page, open an event, export CSV and JSON (#216)', async ({ page }) => {
  await signIn(page, 'admin', '/admin/audit');
  await expect(page.locator('main .animate-spin')).toHaveCount(0);

  // The admin's own sign-in is in the log: filter by it.
  await page.getByText(/^Actions \(/).click();
  await page.getByRole('checkbox', { name: 'member.signed_in' }).check();
  await page.getByLabel('Email address').fill(USERS.admin.email);
  const searched = page.waitForResponse((r) => r.url().endsWith('/v1/audit/events/search') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  expect((await searched).request().postDataJSON()).toMatchObject({ filter: { email: USERS.admin.email, actions: ['member.signed_in'] } });
  expect(page.url()).not.toContain(USERS.admin.email); // T-47
  const first = page.getByRole('row').filter({ hasText: 'member.signed_in' }).first();
  await expect(first).toBeVisible();

  // Paging, when the tenant has more than one page of sign-ins.
  const older = page.getByRole('button', { name: 'Older' });
  await expect(page.getByRole('button', { name: 'Search', exact: true })).toBeEnabled();
  if (await older.isVisible()) {
    await expect(older).toBeEnabled();
    await older.click();
    await expect(page.getByText('Page 2')).toBeVisible();
    await page.getByRole('button', { name: 'Newer' }).click();
    await expect(page.getByText('Page 1')).toBeVisible();
  }

  await first.getByRole('button').click();
  const drawer = page.getByRole('dialog', { name: 'Audit event' });
  await expect(drawer.getByText('member.signed_in')).toBeVisible();
  await expect(drawer.getByText(USERS.admin.email)).toBeVisible();
  await page.keyboard.press('Escape');

  for (const format of ['csv', 'json'] as const) {
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: `Export as ${format.toUpperCase()}` }).click();
    const file = await download;
    expect(file.suggestedFilename()).toMatch(new RegExp(`\\.${format}$`));
    const text = new TextDecoder().decode(readBytes(await file.path()));
    if (format === 'csv') {
      const [header] = text.split('\r\n');
      expect(header).toMatch(/^"id","occurred_at",/); // every cell quoted (RFC 4180)
      expect(text).toContain('"member.signed_in"');
    } else {
      const events = JSON.parse(text) as { action: string }[];
      expect(events.length).toBeGreaterThan(0);
      expect(events.every((event) => event.action === 'member.signed_in')).toBe(true);
    }
  }
});

test('an admin lists every transfer of the tenant and revokes another member\'s (#217)', async ({ page, browser }) => {
  // The member sends a small transfer.
  const context = await browser.newContext();
  const member = await context.newPage();
  await signIn(member, 'member', '/transfers/new');
  const recipient = `${unique('e2e-tenant')}@partner.example`;
  await member.getByLabel("Recipient's email address").fill(recipient);
  await member.getByRole('button', { name: 'Add recipient' }).click();
  await member.getByTestId('transfer-files').setInputFiles(payload(`${unique('tenant')}.txt`, wordsText(4096)));
  await member.getByRole('button', { name: 'Send transfer' }).click();
  await expect(member).toHaveURL(/\/transfers\/[0-9a-f-]{36}$/, { timeout: 90_000 });
  const transferId = new URL(member.url()).pathname.split('/').pop() as string;
  // A first send to the domain waits for the member's confirmation under the default DLP policy (#219).
  await sendPastWarning(member);

  // The admin's own list doesn't show it; the tenant-wide list does, with its owner.
  await signIn(page, 'admin', '/transfers');
  const link = page.locator(`a[href="/transfers/${transferId}"]`);
  await expect(page.locator('main .animate-spin')).toHaveCount(0);
  await expect(link).toHaveCount(0);
  await page.getByRole('checkbox', { name: 'Show every transfer in the organization' }).check();
  const transferRow = page.getByRole('row').filter({ has: link });
  await expect(transferRow.getByText(USERS.member.email)).toBeVisible();

  await transferRow.getByRole('button', { name: /^Revoke/ }).click();
  await page.getByRole('dialog', { name: 'Revoke this transfer?' }).getByRole('button', { name: 'Revoke' }).click();
  await expect(transferRow.getByText('Revoked', { exact: true })).toBeVisible();

  // The member sees it revoked; a member never sees the switch.
  await member.goto('/transfers');
  await expect(member.getByRole('checkbox', { name: 'Show every transfer in the organization' })).toHaveCount(0);
  await member.goto(`/transfers/${transferId}`);
  await expect(member.getByText('Revoked', { exact: true }).first()).toBeVisible();
  await context.close();
});
