import { expect, test, type APIRequestContext, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { resources, type Language } from '../src/lib/i18n';
import { checkAxe } from './support/axe';
import {
  codesTo,
  eicar,
  escapeRegExp,
  fillKeycloak,
  linkEmail,
  messagesTo,
  myNumber,
  newCode,
  payload,
  readBytes,
  sendPastWarning,
  sha256,
  signIn,
  transferStatus,
  unique,
  USERS,
  wordsText,
} from './support/stack';

/**
 * The M5 journey in the browser (#223; delivery plan 3, M5's exit criterion), once in English and once in Japanese
 * (playwright.e2e.config.ts's `en` and `ja` projects), against `make up` and `make seed`. Its API twin is
 * `services/api/tests/test_journey_m5.py`; this one goes through the pages, each person in their own browser:
 *
 * 1. the admin adds two rules: My Numbers to an untrusted domain need approval, credentials and private keys block;
 * 2. the member asks an outsider for files; the uploader verifies on `/u` and uploads two files, one EICAR;
 * 3. the member sees one file received and one blocked on the request's page, and downloads the clean one;
 * 4. a My Number file to the trusted `partner.example` is warned, the member confirms, the recipient is emailed;
 * 5. the same file to an untrusted domain needs approval: the member asks with a reason, and no link goes out;
 * 6. the seed's approver (`dev.approver`) approves from the queue after "Confirm it's you" in a popup, and only then
 *    is the recipient emailed;
 * 7. a file with a synthetic private key is blocked and held, with the rule named; its recipient is never emailed;
 * 8. the admin searches the audit log for the approval and downloads the export;
 * 9. both sides got the notice of the blocked file (sent 5 minutes after the files settle, so checked last), the
 *    uploader's without a file name.
 *
 * Every page the journey visits is scanned by axe (support/axe.ts), in the run's language; the uploader's page is in
 * the request's language, which is the run's. Only Mailpit's API is read besides the pages; the clock isn't moved
 * (the API journey runs the retention deletion). One answer is stubbed: the first approval gets
 * `401 reauthentication_required`, so the real step-up popup signs the approver in again before the real approval.
 * The rules are deleted at the end, so the flows after this one see the default policy.
 */

const language = () => test.info().project.name as Language;
const text = () => resources[language()].translation;
const BROWSER_LOCALE: Record<Language, string> = { en: 'en-US', ja: 'ja-JP' };
const UPLOAD_LINK = /(http:\/\/localhost:3000\/u#[A-Za-z0-9_-]{22,128})/;

/** A template's `{{name}}`s filled in, as i18next does. */
function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, name: string) => String(values[name]));
}

interface Opened {
  name: string;
  page: Page;
  context?: BrowserContext;
}

/** Every page the journey has open, so a failure attaches a screenshot of each (journey.e2e.ts does the same). */
const opened: Opened[] = [];

async function step<R>(number: number, name: string, body: () => Promise<R>): Promise<R> {
  return test.step(`step ${number}: ${name}`, async () => {
    try {
      return await body();
    } catch (error) {
      for (const { name: pageName, page } of opened) {
        const shot = page.isClosed() ? null : await page.screenshot({ fullPage: true }).catch(() => null);
        if (shot) await test.info().attach(`step-${number}-${pageName}.png`, { body: shot, contentType: 'image/png' });
      }
      if (error instanceof Error) error.message = `M5 journey step ${number} (${name}) failed: ${error.message}`;
      throw error;
    }
  });
}

async function newPage(browser: Browser, lang: Language, name: string): Promise<Opened & { context: BrowserContext }> {
  const context = await browser.newContext({ locale: BROWSER_LOCALE[lang], acceptDownloads: true });
  const opening = { name, context, page: await context.newPage() };
  opened.push(opening);
  return opening;
}

async function close(person: Opened & { context: BrowserContext }): Promise<void> {
  opened.splice(opened.indexOf(person), 1);
  await person.context.close();
}

/** A synthetic private key in a note, built when the test runs: never a key in the repository. */
function privateKeyNote(): string {
  const der = new Uint8Array(320);
  crypto.getRandomValues(der);
  der.set([0x30, 0x82]);
  const body = btoa(String.fromCharCode(...der)).replace(/(.{64})/g, '$1\n').trim();
  const label = ['PRIVATE', 'KEY'].join(' ');
  return `Deploy notes\n-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n${wordsText(2048, 11)}`;
}

/** The upload request email's `/u#` link to `address`, waiting for it to arrive. */
async function uploadLink(request: APIRequestContext, address: string): Promise<string> {
  let found = '';
  await expect
    .poll(
      async () => {
        for (const message of await messagesTo(request, address)) {
          const url = UPLOAD_LINK.exec(message.text)?.[1];
          if (url) found = url;
        }
        return found;
      },
      { timeout: 120_000, message: `the upload request email to ${address}` },
    )
    .not.toBe('');
  return found;
}

/** The link page's code step, as a recipient or an uploader does it: a code from Mailpit, then verify. */
async function verify(page: Page, request: APIRequestContext, address: string, lang: Language, what: string): Promise<void> {
  const t = resources[lang].translation;
  await expect(page.getByRole('heading', { level: 1, name: t.recipient.verifyTitle })).toBeFocused();
  await checkAxe(page, `${what}: code step`, lang);
  const seen = (await codesTo(request, address)).length;
  await page.getByRole('button', { name: t.recipient.sendCode }).click();
  await expect(page.getByText(fill(t.recipient.codeSent, { minutes: 10 }))).toBeVisible();
  const code = await newCode(request, address, seen);
  await page.getByRole('textbox', { name: t.recipient.codeLabel }).fill(code);
  await page.getByRole('button', { name: t.recipient.verifyButton, exact: true }).click();
}

/** The admin's rule form, filled in and confirmed: content detectors, the recipients it applies to, and its action. */
async function addRule(
  page: Page,
  name: string,
  detectors: (keyof ReturnType<typeof text>['detectors'])[],
  scope: 'any' | 'untrusted',
  action: 'require_approval' | 'block',
): Promise<void> {
  const t = text();
  await page.goto('/admin/dlp/rules/new');
  await page.getByLabel(t.common.name, { exact: true }).fill(name);
  for (const detector of detectors) {
    await page.getByRole('checkbox', { name: new RegExp(`^${escapeRegExp(t.detectors[detector])}`) }).check();
  }
  await page.getByRole('radio', { name: t.dlpAdmin.scopeHint[scope] }).check();
  await page.getByRole('radio', { name: new RegExp(`^${escapeRegExp(t.dlpAction[action])}`) }).check();
  await checkAxe(page, `rule form: ${action}`, language());
  await page.getByRole('button', { name: t.dlpAdmin.addRule, exact: true }).click();
  const dialog = page.getByRole('dialog', { name: t.dlpAdmin.confirmAddRule });
  await expect(dialog).toBeVisible();
  await checkAxe(page, `rule confirmation: ${action}`, language());
  const answer = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/dlp/rules' && r.request().method() === 'POST');
  await dialog.getByRole('button', { name: t.dlpAdmin.addRule, exact: true }).click();
  expect((await answer).status(), `add the rule ${name}`).toBe(201);
  await expect(page).toHaveURL(/\/admin\/dlp\/rules$/);
  await expect(page.getByRole('rowheader', { name, exact: true })).toBeVisible();
}

/** Deletes the journey's rules, best effort, so the flows after this one see the default policy. */
async function removeRules(page: Page, names: string[]): Promise<void> {
  const t = text();
  for (const name of names) {
    await page.goto('/admin/dlp/rules');
    const remove = page.getByRole('button', { name: fill(t.dlpAdmin.deleteNamed, { name }) });
    if (!(await remove.isVisible().catch(() => false))) continue;
    await remove.click();
    const dialog = page.getByRole('dialog', { name: t.dlpAdmin.confirmDeleteRule });
    const answer = page.waitForResponse((r) => /\/v1\/dlp\/rules\/[^/]+$/.test(new URL(r.url()).pathname) && r.request().method() === 'DELETE');
    await dialog.getByRole('button', { name: t.common.delete, exact: true }).click();
    await answer;
  }
}

/** The member's transfer of one file to one recipient in `lang`; resolves on its detail page with its ID. */
async function sendTransfer(page: Page, recipient: string, lang: Language, file: ReturnType<typeof payload>): Promise<string> {
  const t = text();
  await page.goto('/transfers/new');
  await page.getByLabel(t.sender.recipientEmail).fill(recipient);
  await page.getByLabel(t.sender.newRecipientLocale).selectOption(lang);
  await page.getByRole('button', { name: t.sender.addRecipient }).click();
  await expect(page.getByText(recipient, { exact: true })).toBeVisible();
  await page.getByTestId('transfer-files').setInputFiles(file);
  await page.getByRole('button', { name: t.sender.send }).click();
  await expect(page).toHaveURL(/\/transfers\/[0-9a-f-]{36}$/, { timeout: 120_000 });
  return new URL(page.url()).pathname.split('/').pop() ?? '';
}

/** Mailpit has no message to `address` now, nor a few seconds later, when a link email would have been sent. */
async function neverEmailed(request: APIRequestContext, address: string, why: string): Promise<void> {
  expect(await messagesTo(request, address), why).toEqual([]);
  await new Promise((resolve) => setTimeout(resolve, 5000));
  expect(await messagesTo(request, address), why).toEqual([]);
}

test('the M5 journey through the browser: an upload request and the three DLP outcomes', async ({ page: member, browser, request }) => {
  test.setTimeout(30 * 60_000);
  const lang = language();
  const t = text();
  opened.length = 0;
  opened.push({ name: 'member', page: member });
  const axe = (page: Page, name: string) => checkAxe(page, name, lang);
  const approvalRule = unique(`M5 approval ${lang}`);
  const blockRule = unique(`M5 block ${lang}`);
  const staff = `${unique('staff')}.txt`;
  const staffText = `個人番号: ${myNumber()}\n${wordsText(4096, 5)}`;

  try {
    await step(1, 'the admin adds the rules: approval for My Numbers to untrusted domains, a block for keys', async () => {
      const admin = await newPage(browser, lang, 'admin');
      await signIn(admin.page, 'admin', '/admin/dlp/rules', lang);
      await expect(admin.page.locator('main .animate-spin')).toHaveCount(0);
      await axe(admin.page, 'DLP rules');
      await addRule(admin.page, approvalRule, ['jp_my_number'], 'untrusted', 'require_approval');
      await addRule(admin.page, blockRule, ['cloud_credential', 'private_key'], 'any', 'block');
      await axe(admin.page, 'DLP rules with the journey\'s rules');
      await close(admin);
    });

    const uploaderAddress = `${unique(`m5-${lang}-uploader`)}@partner.example`;
    const clean = `${unique('delivery')}.txt`;
    const cleanText = wordsText(256 * 1024, 13);
    const blocked = `${unique('setup')}.txt`;
    let requestPath = '';
    const uploader = await newPage(browser, lang, 'uploader');
    await step(2, 'the member asks for files; the uploader verifies on /u and uploads two, one EICAR', async () => {
      await signIn(member, 'member', '/upload-requests/new', lang);
      await member.getByLabel(t.requests.uploaderEmail).fill(uploaderAddress);
      await member.getByLabel(t.requests.uploaderLocale).selectOption(lang);
      await member.getByLabel(t.requests.messageLabel).fill('The signed delivery notes, please.');
      await axe(member, 'new upload request');
      await member.getByRole('button', { name: t.requests.create }).click();
      await expect(member).toHaveURL(/\/upload-requests\/[0-9a-f-]{36}$/, { timeout: 30_000 });
      requestPath = new URL(member.url()).pathname;
      await axe(member, 'upload request');

      await uploader.page.goto(await uploadLink(request, uploaderAddress));
      await expect(uploader.page).toHaveURL('http://localhost:3000/u'); // the fragment is gone
      await verify(uploader.page, request, uploaderAddress, lang, 'uploader');
      await expect(uploader.page.getByRole('heading', { level: 1, name: t.uploader.title })).toBeFocused();
      await axe(uploader.page, 'uploader: the request');
      await uploader.page.getByTestId('uploader-files').setInputFiles([payload(clean, cleanText), payload(blocked, eicar())]);
      const row = (name: string) => uploader.page.getByRole('listitem').filter({ hasText: name });
      await expect(row(clean).getByText(t.uploader.status.received, { exact: true })).toBeVisible({ timeout: 180_000 });
      // The API marks a malware file blocked, so the uploader reads "not accepted", never why (FR-12, #229).
      await expect(row(blocked).getByText(t.uploader.status.notAccepted, { exact: true })).toBeVisible({ timeout: 180_000 });
      await axe(uploader.page, 'uploader: one file received, one blocked');
    });
    await close(uploader);

    await step(3, 'the member sees one file received and one blocked, and downloads the clean one', async () => {
      await member.goto(requestPath);
      const table = member.getByRole('table', { name: t.requests.receivedCaption });
      const row = (name: string) => table.getByRole('row').filter({ has: member.getByRole('rowheader', { name, exact: true }) });
      await expect(row(clean).getByText(t.fileState.clean, { exact: true })).toBeVisible({ timeout: 180_000 });
      await expect(row(blocked).getByText(t.fileState.infected, { exact: true })).toBeVisible({ timeout: 180_000 });
      await expect(row(blocked).getByRole('button', { name: fill(t.requests.downloadFile, { name: blocked }) })).toHaveCount(0);
      await axe(member, 'upload request with received files');
      const saved = member.waitForEvent('download');
      await row(clean).getByRole('button', { name: fill(t.requests.downloadFile, { name: clean }) }).click();
      const bytes = readBytes(await (await saved).path());
      expect(await sha256(bytes), 'the saved file is the uploaded one').toBe(await sha256(new TextEncoder().encode(cleanText)));
      await expect(member.getByText(fill(t.requests.downloadStarted, { name: clean }))).toBeVisible();
    });

    await step(4, 'transfer 1, to the trusted partner: warned, the member confirms, the recipient is emailed', async () => {
      const recipient = `${unique(`m5-${lang}-warned`)}@partner.example`;
      await sendTransfer(member, recipient, lang, payload(staff, staffText));
      await expect(transferStatus(member, 'awaiting_confirmation', lang)).toBeVisible({ timeout: 180_000 });
      await expect(member.getByText(approvalRule, { exact: true })).toHaveCount(0); // a trusted recipient
      await axe(member, 'transfer 1 warned');
      await sendPastWarning(member, lang, 'Payroll for the partner.');
      const email = await linkEmail(request, recipient);
      expect(email.subject).toMatch(lang === 'ja' ? /からファイルが届いています$/ : / sent you files$/);
    });

    let approvalPath = '';
    const untrusted = `${unique(`m5-${lang}-approved`)}@${unique('untrusted')}.example`;
    await step(5, 'transfer 2, to an untrusted domain: the member asks for approval with a reason', async () => {
      await sendTransfer(member, untrusted, lang, payload(staff, staffText));
      const ask = member.getByRole('button', { name: t.dlp.confirm.approval.button });
      await expect(ask).toBeVisible({ timeout: 180_000 });
      await expect(member.getByText(approvalRule, { exact: true })).toBeVisible();
      await axe(member, 'transfer 2 needs approval');
      await ask.click();
      const dialog = member.getByRole('dialog', { name: t.dlp.confirm.approval.title });
      await dialog.getByLabel(t.dlp.justificationRequired).fill('Their auditor needs it this week.');
      await axe(member, 'request approval dialog');
      await dialog.getByRole('button', { name: t.dlp.confirm.approval.action }).click();
      await expect(dialog).toBeHidden();
      await expect(transferStatus(member, 'pending_approval', lang)).toBeVisible();
      const link = member.getByRole('link', { name: t.dlp.openRequest });
      approvalPath = (await link.getAttribute('href')) ?? '';
      expect(approvalPath).toMatch(/^\/approvals\/[0-9a-f-]{36}$/);
      await neverEmailed(request, untrusted, 'no link before the approval');
    });

    const approver = await newPage(browser, lang, 'approver');
    await step(6, 'the approver approves from the queue after "Confirm it\'s you"; then the recipient is emailed', async () => {
      const page = approver.page;
      await signIn(page, 'approver', '/approvals', lang);
      const row = page.getByRole('row').filter({ has: page.locator(`a[href="${approvalPath}"]`) });
      await expect(row.getByText(approvalRule)).toBeVisible();
      await axe(page, 'approver queue');
      await row.getByRole('link').click();
      await expect(page).toHaveURL(new RegExp(`${escapeRegExp(approvalPath)}$`));
      await expect(page.getByText('Their auditor needs it this week.')).toBeVisible();
      await axe(page, 'approval request');

      // The first answer says the sign-in is too old, as it is 15 minutes after a sign-in (authn and authz 3.3).
      await page.route(
        /\/v1\/dlp\/approval-requests\/[^/]+\/approve$/,
        (route) =>
          route.fulfill({
            status: 401,
            contentType: 'application/problem+json',
            headers: { 'access-control-allow-origin': 'http://localhost:3000', 'access-control-allow-credentials': 'true' },
            body: JSON.stringify({ type: 'about:blank', title: 'Unauthorized', status: 401, code: 'reauthentication_required' }),
          }),
        { times: 1 },
      );
      await page.getByRole('button', { name: t.approvals.approve.button, exact: true }).click();
      const approve = page.getByRole('dialog', { name: t.approvals.approve.title });
      await axe(page, 'approve dialog');
      await approve.getByRole('button', { name: t.approvals.approve.action }).click();
      const stepUp = page.getByRole('dialog', { name: t.stepUp.title });
      await expect(stepUp).toBeVisible();
      await axe(page, 'confirm it\'s you');
      const popup = page.waitForEvent('popup');
      const approved = page.waitForResponse(
        (r) => /\/v1\/dlp\/approval-requests\/[^/]+\/approve$/.test(r.url()) && r.request().method() === 'POST' && r.status() !== 401,
      );
      await stepUp.getByRole('button', { name: t.stepUp.signIn }).click();
      const signInAgain = await popup;
      await fillKeycloak(signInAgain, USERS.approver.email, USERS.approver.password);
      expect((await approved).status(), 'the approval after the step-up').toBe(200);
      await expect(approve).toBeHidden();
      await expect(page.getByText(t.approvalState.approved, { exact: true }).first()).toBeVisible();
      await axe(page, 'approval request approved');

      await member.reload();
      await expect(transferStatus(member, 'sent', lang)).toBeVisible({ timeout: 60_000 });
      await linkEmail(request, untrusted);
    });
    await close(approver);

    await step(7, 'transfer 3: a private key is blocked and held, the rule named; its recipient is never emailed', async () => {
      const recipient = `${unique(`m5-${lang}-blocked`)}@partner.example`;
      await sendTransfer(member, recipient, lang, payload(`${unique('deploy')}.txt`, privateKeyNote()));
      await expect(transferStatus(member, 'held', lang)).toBeVisible({ timeout: 180_000 });
      await expect(member.getByText(t.holdReason.dlp_blocked)).toBeVisible();
      await expect(member.getByText(blockRule, { exact: true })).toBeVisible();
      await axe(member, 'transfer 3 held');
      await neverEmailed(request, recipient, 'a held transfer emails no recipient');
    });

    await step(8, 'the admin finds the approval in the audit log and downloads the export', async () => {
      // A new sign-in: exporting needs one in the last 15 minutes, and step 1's may be older by now.
      const auditor = await newPage(browser, lang, 'auditor');
      const page = auditor.page;
      await signIn(page, 'admin', '/admin/audit', lang);
      await axe(page, 'audit log');
      const approvalId = approvalPath.split('/').pop() ?? '';
      await page.getByLabel(t.audit.targetId).fill(approvalId);
      await page.getByRole('button', { name: t.common.search }).click();
      const row = page.getByRole('row').filter({ hasText: 'dlp_approval.approved' });
      await expect(row).toBeVisible();
      await expect(row.getByText(USERS.approver.email)).toBeVisible();
      await axe(page, 'audit search for the approval');
      const saved = page.waitForEvent('download');
      await page.getByRole('button', { name: t.audit.exportCsv }).click();
      const csv = new TextDecoder().decode(readBytes(await (await saved).path()));
      expect(csv).toContain('dlp_approval.approved');
      expect(csv).toContain(approvalId);
      await axe(page, 'audit log after the export');
      await close(auditor);
    });

    await step(9, 'both sides got the notice of the blocked file, the uploader\'s without its name', async () => {
      const requestId = requestPath.split('/').pop() ?? '';
      await expect
        .poll(
          async () =>
            (await messagesTo(request, 'dev.member@example.com')).filter((m) => m.text.includes(`/upload-requests/${requestId}`))
              .length,
          { timeout: 600_000, intervals: [5000], message: 'the member\'s arrived and blocked notices' },
        )
        .toBeGreaterThanOrEqual(2);
      let told: { subject: string; text: string }[] = [];
      // Not the upload link's email, nor a code's: the notice.
      const notice = (m: { text: string }) => !UPLOAD_LINK.test(m.text) && !/(?<![0-9])[0-9]{6,10}(?![0-9])/.test(m.text);
      await expect
        .poll(async () => (told = (await messagesTo(request, uploaderAddress)).filter(notice)).length, {
          timeout: 120_000,
          message: 'the uploader\'s notice',
        })
        .toBeGreaterThan(0);
      for (const message of told) {
        expect(message.text).not.toContain(blocked);
        expect(message.text).not.toContain(clean);
      }
    });
  } finally {
    // Deleting a rule needs a recent sign-in too, so the admin signs in once more to clean up.
    const cleanup = await browser.newContext({ locale: BROWSER_LOCALE[lang] });
    try {
      const page = await cleanup.newPage();
      await signIn(page, 'admin', '/admin/dlp/rules', lang);
      await removeRules(page, [approvalRule, blockRule]);
    } catch (error) {
      console.log(`the M5 journey's rules may be left over: ${String(error)}`);
    } finally {
      await cleanup.close();
    }
  }
});
