import { expect, test, type APIRequestContext } from '@playwright/test';
import { checkAxe } from './support/axe';
import { codesTo, escapeRegExp, linkEmail, newCode, payload, sendPastWarning, signIn, unique, wordsText } from './support/stack';

/**
 * #199: a recipient locked out after 20 failed attempts (NFR-14) shows `locked` on the member's page; unlocking
 * emails a new link, the old link is then not found, and the new one works (authn-authz 4.4). Against `make up` and
 * `make seed`, in English only (the journey runs both languages).
 *
 * The 20 failures are driven through `createLinkSession` from the test, as the issue decides: five attempts per code
 * and one code every 30 seconds per link make it too slow in a page. They count against the per-IP failed-code quota
 * (30 an hour, abuse-and-rate-limits 2.2 A), so one `make web-e2e` run an hour fits: `make down` and `make up` clear
 * the counters (Valkey keeps no volume).
 */

const API = 'http://localhost:8000/v1';
const WEB = 'http://localhost:3000';

/** A link step as the web app calls it, from its origin. */
function linkCall(request: APIRequestContext, path: string, data: object) {
  return request.post(`${API}${path}`, { data, headers: { origin: WEB } });
}

/** A code for the link: waits out the per-link 30 seconds (and any Retry-After) between codes. */
async function askForCode(request: APIRequestContext, token: string): Promise<void> {
  for (;;) {
    const answer = await linkCall(request, '/links/codes', { token });
    if (answer.status() === 202) return;
    expect(answer.status(), await answer.text()).toBe(429);
    const wait = Number(answer.headers()['retry-after'] ?? '30');
    await new Promise((resolve) => setTimeout(resolve, (wait + 1) * 1000));
  }
}

test('a locked recipient shows locked; unlock sends a new link, the old one is not found, the new one works', async ({
  page,
  browser,
  request,
}) => {
  test.setTimeout(10 * 60_000);
  const address = `${unique('e2e-locked')}@partner.example`;
  const name = `${unique('locked')}.txt`;

  // A sent transfer with one recipient.
  await signIn(page, 'member', '/transfers/new');
  await page.getByLabel("Recipient's email address").fill(address);
  await page.getByRole('button', { name: 'Add recipient' }).click();
  await page.getByTestId('transfer-files').setInputFiles(payload(name, wordsText(64 * 1024, 5)));
  await page.getByRole('button', { name: 'Send transfer' }).click();
  await expect(page).toHaveURL(/\/transfers\/[0-9a-f-]{36}$/, { timeout: 120_000 });
  // A recipient domain new to the tenant is warned about (DLP-4, #219): confirm it.
  await sendPastWarning(page);
  const detail = page.url();

  const old = await linkEmail(request, address);
  const token = old.url.split('#')[1] ?? '';

  // 20 wrong codes: four codes, five attempts each. A wrong code is the real one with its last digit changed.
  let failures = 0;
  let locked = false;
  while (!locked) {
    const seen = (await codesTo(request, address)).length;
    await askForCode(request, token);
    const code = await newCode(request, address, seen);
    const wrong = code.slice(0, -1) + String((Number(code.slice(-1)) + 1) % 10);
    for (let attempt = 0; attempt < 5 && !locked; attempt++) {
      const answer = await linkCall(request, '/links/sessions', { token, code: wrong });
      const body = (await answer.json()) as { code: string };
      failures += 1;
      if (answer.status() === 403) {
        expect(body.code).toBe('recipient_locked');
        locked = true;
      } else {
        expect([answer.status(), body.code]).toEqual([422, 'code_invalid']);
      }
    }
    expect(failures, 'locked by the 20th failure').toBeLessThanOrEqual(20);
  }
  expect(failures).toBe(20);

  // The member's page shows the lockout, and unlocks: a new link by email.
  await page.goto(detail);
  const row = page.getByRole('row').filter({ has: page.getByRole('rowheader', { name: new RegExp(escapeRegExp(address)) }) });
  await expect(row.getByText('Locked', { exact: true })).toBeVisible({ timeout: 30_000 });
  await row.getByRole('button', { name: `Unlock and send a new link to ${address}` }).click();
  const dialog = page.getByRole('dialog', { name: 'Unlock this recipient?' });
  await expect(dialog.getByText('The old link stops working.', { exact: false })).toBeVisible();
  await checkAxe(page, 'unlock dialog', 'en');
  await dialog.getByRole('button', { name: 'Unlock and send' }).click();
  await expect(dialog).toBeHidden();
  await expect(row.getByText('Not verified yet', { exact: true })).toBeVisible();
  const fresh = await linkEmail(request, address, { except: old.url });

  // The old link is not found; the new one asks for a code and works.
  const context = await browser.newContext({ locale: 'en-US' });
  const recipient = await context.newPage();
  await recipient.goto(old.url);
  await expect(recipient.getByRole('heading', { level: 1, name: "This link doesn't work" })).toBeVisible();
  await checkAxe(recipient, 'old link after unlock', 'en');
  await recipient.goto('about:blank');
  await recipient.goto(fresh.url);
  await expect(recipient.getByRole('heading', { level: 1, name: 'Verify your email address' })).toBeVisible();
  const seen = (await codesTo(request, address)).length;
  await recipient.getByRole('button', { name: 'Email me a code' }).click();
  const code = await newCode(request, address, seen);
  await recipient.getByRole('textbox', { name: 'Verification code' }).fill(code);
  await recipient.getByRole('button', { name: 'Verify', exact: true }).click();
  await expect(recipient.getByRole('heading', { level: 1, name: 'Your files' })).toBeVisible();
  await expect(recipient.getByText(name, { exact: true })).toBeVisible();
  await context.close();
});
