import { expect, test, type Page } from '@playwright/test';
import { eicar, MIB, myNumber, payload, signIn, unique, watchParts, wordsText } from './support/stack';

/**
 * #196: a member creates a transfer, uploads it in parts straight to the S3 stand-in, sends it, and watches scan and
 * DLP status, against `make up` and `make seed`.
 */

async function addRecipient(page: Page, address: string): Promise<void> {
  await page.getByLabel("Recipient's email address").fill(address);
  await page.getByRole('button', { name: 'Add recipient' }).click();
  await expect(page.getByText(address, { exact: true })).toBeVisible();
}

function fileRow(page: Page, name: string) {
  return page.getByRole('listitem').filter({ has: page.getByText(name, { exact: true }) });
}

test('create, upload in parts with an aborted part, send, and watch clean and inspected', async ({ page }) => {
  await signIn(page, 'member', '/transfers/new');
  await addRecipient(page, `${unique('e2e-a')}@partner.example`);
  await addRecipient(page, `${unique('e2e-b')}@partner.example`);

  const plain = `${unique('plain')}.txt`;
  const staff = `${unique('staff')}.txt`;
  // Two files of two parts each (parts are at least 5 MiB). One holds a synthetic My Number.
  await page.getByTestId('transfer-files').setInputFiles([
    payload(plain, wordsText(6 * MIB)),
    payload(staff, `個人番号: ${myNumber()}\n${wordsText(6 * MIB, 7)}`),
  ]);

  // The first PUT of the first file's second part fails on the wire; the engine tries it again.
  let aborted = '';
  const parts = watchParts(page, async (part, attempt, route) => {
    if (!aborted && part.endsWith('#2') && attempt === 1) {
      aborted = part;
      await route.abort('failed');
      return true;
    }
    return false;
  });

  await page.getByRole('button', { name: 'Send transfer' }).click();
  await expect(page).toHaveURL(/\/transfers\/[0-9a-f-]{36}$/, { timeout: 90_000 });

  expect(aborted, 'a part was interrupted').not.toBe('');
  expect(parts.tries.get(aborted)).toBe(2);
  expect(parts.tries.size, 'four parts').toBe(4);
  for (const [part, count] of parts.landed) expect(count, `${part} landed once`).toBe(1);
  for (const [part, count] of parts.tries) if (part !== aborted) expect(count, `${part} sent once`).toBe(1);

  // Scan and DLP status, polled by the page.
  for (const name of [plain, staff]) {
    await expect(fileRow(page, name).getByText('Clean', { exact: true })).toBeVisible({ timeout: 90_000 });
    await expect(fileRow(page, name).getByText('Inspected', { exact: true })).toBeVisible();
  }
  await expect(page.getByText('Sent', { exact: true }).first()).toBeVisible({ timeout: 60_000 });
  await expect(fileRow(page, staff).getByText('My Number (Individual Number)')).toBeVisible();
  await expect(fileRow(page, plain).getByText('Sensitive data found:')).toHaveCount(0);

  // Findings on demand.
  const inspection = page.waitForResponse((r) => /\/v1\/files\/[0-9a-f-]+\/inspection$/.test(r.url()));
  await fileRow(page, staff).getByRole('button', { name: `Show findings for ${staff}` }).click();
  expect((await inspection).status()).toBe(200);
  const findings = page.getByRole('region', { name: 'Findings' });
  await expect(findings.getByRole('cell', { name: 'My Number (Individual Number)' })).toBeVisible();
});

test('a reload mid-upload, then the same file picked again, finishes from the missing parts', async ({ page }) => {
  await signIn(page, 'member', '/transfers/new');
  await addRecipient(page, `${unique('e2e-c')}@partner.example`);
  const name = `${unique('resume')}.txt`;
  const content = wordsText(6 * MIB, 11);
  await page.getByTestId('transfer-files').setInputFiles(payload(name, content));

  // Part 1 lands; part 2 fails on every try, and the page is reloaded while the engine waits to try it again.
  let held = false;
  const before = watchParts(page, async (part, _attempt, route) => {
    if (!part.endsWith('#2')) return false;
    held = true;
    await route.abort('failed');
    return true;
  });
  const created = page.waitForResponse((r) => r.url() === 'http://localhost:8000/v1/transfers' && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Send transfer' }).click();
  const transferId = ((await created).json() as Promise<{ id: string }>).then((body) => body.id);
  const id = await transferId;
  await expect.poll(() => [...before.landed.keys()].some((part) => part.endsWith('#1')), { timeout: 60_000 }).toBe(true);
  await expect.poll(() => held).toBe(true);
  await page.reload();
  await page.unrouteAll({ behavior: 'ignoreErrors' });

  const after = watchParts(page);
  await page.goto(`/transfers/${id}`);
  await expect(page.getByText("Some files didn't finish uploading", { exact: false })).toBeVisible();
  const resume = page.locator('input[type="file"][data-testid^="resume-"]');
  await resume.setInputFiles(payload(name, content));
  await expect(page.getByRole('button', { name: 'Send transfer' })).toBeEnabled({ timeout: 60_000 });
  expect([...after.tries.keys()].every((part) => part.endsWith('#2')), 'only the missing part was sent').toBe(true);
  expect(after.tries.size).toBe(1);

  await page.getByRole('button', { name: 'Send transfer' }).click();
  await expect(fileRow(page, name).getByText('Clean', { exact: true })).toBeVisible({ timeout: 90_000 });
});

test('an EICAR file shows infected, and the transfer held with file_blocked', async ({ page }) => {
  await signIn(page, 'member', '/transfers/new');
  await addRecipient(page, `${unique('e2e-d')}@partner.example`);
  const name = `${unique('eicar')}.com`;
  await page.getByTestId('transfer-files').setInputFiles(payload(name, eicar()));
  await page.getByRole('button', { name: 'Send transfer' }).click();
  await expect(page).toHaveURL(/\/transfers\/[0-9a-f-]{36}$/, { timeout: 60_000 });
  await expect(fileRow(page, name).getByText('Infected', { exact: true })).toBeVisible({ timeout: 90_000 });
  await expect(page.getByText('Held: a file is infected', { exact: false })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByText('Held', { exact: true }).first()).toBeVisible();
});
