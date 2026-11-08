import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { resources, type Language } from '../src/lib/i18n';
import { checkAxe } from './support/axe';
import {
  codesTo,
  escapeRegExp,
  linkEmail,
  MIB,
  myNumber,
  newCode,
  payload,
  readBytes,
  runJob,
  sendPastWarning,
  sha256,
  signIn,
  unique,
  USERS,
  watchParts,
  wordsText,
} from './support/stack';

/**
 * The M3 journey (#200; delivery plan 3, M3's exit criterion): #182's M2 journey, steps 1 to 9, through the React app
 * in a browser, once in English and once in Japanese (playwright.e2e.config.ts's `en` and `ja` projects), against
 * `make up` and `make seed`. It uses only the browser, Mailpit's API for links and codes, the seed, and the lifecycle
 * jobs with the clock's test hook (`runJob`); the one request outside a page is the `Range` check, made with the
 * recipient's own browser cookies, and the one stubbed answer is step 6's `503`, which interrupts a download's start. Each step's axe scan is the one `pages.a11y.ts` runs (support/axe.ts), here on
 * live pages with real data. A failure names its step; the screenshots of every open page and the traces of every browser are attached.
 */

const language = () => test.info().project.name as Language;
const text = () => resources[language()].translation;
const BROWSER_LOCALE: Record<Language, string> = { en: 'en-US', ja: 'ja-JP' };
const API = 'http://localhost:8000';

/** A template's `{{name}}`s filled in, as i18next does. */
function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, name: string) => String(values[name]));
}

/** A plural message for `count`, in the run's language (Japanese has only `_other`). */
function plural(tree: object, key: string, count: number, values: Record<string, string> = {}): string {
  const forms = tree as Record<string, string | undefined>;
  return fill((count === 1 ? forms[`${key}_one`] : undefined) ?? forms[`${key}_other`] ?? '', { ...values, count });
}

interface Opened {
  name: string;
  page: Page;
  /** Its own browser context; the member's page is the test's. */
  context?: BrowserContext;
}

/**
 * Every page the journey has open, so a failure attaches a screenshot of each. Their traces come from the config's
 * `trace: 'retain-on-failure'`, which records every context the test opens, `browser.newContext()` ones included, and
 * keeps them all when it fails; starting tracing here as well would throw ("Tracing has been already started").
 */
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
      opened.length = 0;
      if (error instanceof Error) error.message = `journey step ${number} (${name}) failed: ${error.message}`;
      throw error;
    }
  });
}

/** A new person's browser (a recipient, the admin), in `lang`; the config traces it. */
async function newPage(browser: Browser, lang: Language, name: string): Promise<Opened & { context: BrowserContext }> {
  const context = await browser.newContext({ locale: BROWSER_LOCALE[lang], acceptDownloads: true });
  const opening = { name, context, page: await context.newPage() };
  opened.push(opening);
  return opening;
}

/** Closes a browser whose part is done. */
async function close(person: Opened & { context: BrowserContext }): Promise<void> {
  opened.splice(opened.indexOf(person), 1);
  await person.context.close();
}

function fileRow(page: Page, name: string) {
  return page.getByRole('listitem').filter({ has: page.getByText(name, { exact: true }) });
}

function recipientRow(page: Page, email: string) {
  return page.getByRole('row').filter({ has: page.getByRole('rowheader', { name: new RegExp(escapeRegExp(email)) }) });
}

function userRow(page: Page, email: string) {
  return page.getByRole('row').filter({ has: page.getByText(email, { exact: true }) });
}

async function addRecipient(page: Page, address: string, locale: Language): Promise<void> {
  const t = text();
  await page.getByLabel(t.sender.recipientEmail).fill(address);
  await page.getByLabel(t.sender.newRecipientLocale).selectOption(locale);
  await page.getByRole('button', { name: t.sender.addRecipient }).click();
  await expect(page.getByText(address, { exact: true })).toBeVisible();
}

/** The recipient's verification in the browser: the code from Mailpit, after one wrong code when `wrongFirst`. */
async function verify(page: Page, request: Parameters<typeof codesTo>[0], address: string, wrongFirst: boolean, lang: Language) {
  const t = resources[lang].translation;
  await expect(page.getByRole('heading', { level: 1, name: t.recipient.verifyTitle })).toBeFocused();
  await checkAxe(page, 'code step', lang);
  const seen = (await codesTo(request, address)).length;
  await page.getByRole('button', { name: t.recipient.sendCode }).click();
  await expect(page.getByText(fill(t.recipient.codeSent, { minutes: 10 }))).toBeVisible();
  const code = await newCode(request, address, seen);
  const input = page.getByRole('textbox', { name: t.recipient.codeLabel });
  if (wrongFirst) {
    const wrong = code.slice(0, -1) + String((Number(code.slice(-1)) + 1) % 10);
    await input.fill(wrong);
    await page.getByRole('button', { name: t.recipient.verifyButton, exact: true }).click();
    // Five attempts per code: four left, tied to the input.
    await expect(input).toHaveAccessibleDescription(new RegExp(escapeRegExp(plural(t.recipient.problems, 'code_invalid', 4))));
    await checkAxe(page, 'code step, wrong code', lang);
  }
  await input.fill(code);
  await page.getByRole('button', { name: t.recipient.verifyButton, exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: t.recipient.filesTitle })).toBeFocused();
}

/** Opens a link afresh, as a click in the email does: the app reads the fragment again. */
async function openLink(page: Page, url: string): Promise<void> {
  await page.goto('about:blank');
  await page.goto(url);
}

test('the M3 journey through the browser, steps 1 to 9', async ({ page: member, browser, request }) => {
  test.setTimeout(20 * 60_000);
  const lang = language();
  const t = text();
  opened.length = 0;
  opened.push({ name: 'member', page: member });
  const axe = (page: Page, name: string, inLanguage: Language = lang) => checkAxe(page, name, inLanguage);

  const first = `${unique(`m3-${lang}-a`)}@partner.example`;
  const second = `${unique(`m3-${lang}-b`)}@partner.example`;
  // The English run adds a Japanese recipient: their email and page are Japanese in an English browser (FR-33).
  const crossCheck = lang === 'en' ? `${unique('m3-en-ja')}@partner.example` : null;
  const plain = `${unique('plain')}.txt`;
  const staff = `${unique('staff')}.txt`;
  const plainText = wordsText(6 * MIB, Date.now());
  const plainBytes = new TextEncoder().encode(plainText);
  let transferId = '';

  await step(1, 'member signs in through Keycloak', async () => {
    // The callback's error state; the successful callback moves on too fast to scan, so its result is scanned.
    await member.goto('/auth/callback?error=access_denied');
    await expect(member.getByText(t.auth.signInFailed)).toBeVisible();
    await axe(member, 'sign-in callback failed');
    await signIn(member, 'member', '/', lang);
    await expect(member.locator('main').getByRole('heading', { level: 1 })).toBeVisible();
    await axe(member, 'dashboard');
  });

  await step(2, 'creates a transfer: recipients, a download limit, a plain file and a My Number file', async () => {
    await member.goto('/transfers/new');
    await addRecipient(member, first, lang);
    await addRecipient(member, second, lang);
    if (crossCheck) await addRecipient(member, crossCheck, 'ja');
    await member.getByLabel(t.sender.downloadLimit).fill('2');
    // Two parts each (parts are at least 5 MiB); the second holds a synthetic My Number (the DLP corpus's rule).
    await member.getByTestId('transfer-files').setInputFiles([
      payload(plain, plainText),
      payload(staff, `個人番号: ${myNumber()}\n${wordsText(6 * MIB, 7)}`),
    ]);
  });

  await step(3, 'uploads with one aborted part; only the missing part is sent again', async () => {
    let aborted = '';
    const parts = watchParts(member, async (part, attempt, route) => {
      if (!aborted && part.endsWith('#2') && attempt === 1) {
        aborted = part;
        await route.abort('failed');
        return true;
      }
      return false;
    });
    await member.getByRole('button', { name: t.sender.send }).click();
    await expect(member).toHaveURL(/\/transfers\/[0-9a-f-]{36}$/, { timeout: 120_000 });
    transferId = new URL(member.url()).pathname.split('/').pop() ?? '';
    expect(aborted, 'a part was interrupted').not.toBe('');
    expect(parts.tries.get(aborted), 'the interrupted part was sent again').toBe(2);
    expect(parts.tries.size, 'four parts').toBe(4);
    for (const [part, count] of parts.tries) if (part !== aborted) expect(count, `${part} sent once`).toBe(1);
    for (const [part, count] of parts.landed) expect(count, `${part} landed once`).toBe(1);
    await member.unrouteAll({ behavior: 'ignoreErrors' });
  });

  await step(4, 'sends past the My Number warning; the detail page shows clean and inspected, and the finding on demand', async () => {
    // The default policy warns about the My Number (DLP-4, #219): the member confirms it, then it is sent. Once sent,
    // the DLP panel (which lists the files too) is gone, so each file's row is the Files card's.
    await sendPastWarning(member, lang);
    for (const name of [plain, staff]) {
      await expect(fileRow(member, name).getByText(t.fileState.clean, { exact: true })).toBeVisible({ timeout: 180_000 });
      await expect(fileRow(member, name).getByText(t.inspectionState.inspected, { exact: true })).toBeVisible();
    }
    await fileRow(member, staff).getByRole('button', { name: fill(t.sender.showFindings, { name: staff }) }).click();
    const findings = member.getByRole('region', { name: t.sender.findings });
    await expect(findings.getByRole('cell', { name: t.detectors.jp_my_number })).toBeVisible();
    await axe(member, 'transfer detail with findings');
  });

  const recipient = await newPage(browser, lang, 'recipient');
  let link = '';
  await step(5, 'the recipient opens the emailed link, asks for a code and verifies', async () => {
    const email = await linkEmail(request, first);
    link = email.url;
    expect(email.subject).toMatch(lang === 'ja' ? /からファイルが届いています$/ : / sent you files$/);
    await recipient.page.goto(link);
    await expect(recipient.page).toHaveURL('http://localhost:3000/t'); // the fragment is gone
    await verify(recipient.page, request, first, true, lang);
    for (const name of [plain, staff]) await expect(recipient.page.getByText(name, { exact: true })).toBeVisible();
    await axe(recipient.page, 'recipient files');

    if (crossCheck) {
      const japanese = await linkEmail(request, crossCheck);
      expect(japanese.subject).toMatch(/からファイルが届いています$/);
      const cross = await newPage(browser, 'en', 'cross-check');
      await cross.page.goto(japanese.url);
      await expect(cross.page.locator('html')).toHaveAttribute('lang', 'ja');
      await expect(
        cross.page.getByRole('heading', { level: 1, name: resources.ja.translation.recipient.verifyTitle }),
      ).toBeVisible();
      await axe(cross.page, 'Japanese link in an English browser', 'ja');
      await close(cross);
    }
  });

  await step(6, 'an interrupted start resumes its grant after a reload, uncounted; the download resumes by Range', async () => {
    const page = recipient.page;
    const downloadButton = () => page.getByRole('button', { name: fill(t.recipient.downloadFile, { name: plain }) });
    const grantAnswer = () =>
      page.waitForResponse((r) => /\/v1\/session\/files\/[^/]+\/downloads$/.test(r.url()) && r.request().method() === 'POST');
    const keptGrants = () =>
      page.evaluate(() => Object.keys(sessionStorage).filter((key) => key.startsWith('sft.grant.')).length);

    // The start is interrupted: the app's check of the content answers 503 once. The page explains it, in the app,
    // and keeps the counted grant.
    await page.route(
      /\/v1\/session\/downloads\/[^/]+\/content$/,
      (route) =>
        route.fulfill({
          status: 503,
          contentType: 'application/problem+json',
          headers: { 'access-control-allow-origin': 'http://localhost:3000', 'access-control-allow-credentials': 'true' },
          body: JSON.stringify({ type: 'about:blank', title: 'Service unavailable', status: 503, code: 'service_unavailable' }),
        }),
      { times: 1 },
    );
    const granted = grantAnswer();
    await downloadButton().click();
    const grant = (await (await granted).json()) as { grant_id: string; url: string };
    await expect(page.getByText(t.recipient.problems.service_unavailable)).toBeVisible();
    expect(await keptGrants(), 'the interrupted grant is kept').toBe(1);

    // A reload forgets the token (it is in memory only); opening the link again resumes the session, no new code.
    await page.reload();
    await expect(page.getByRole('heading', { level: 1, name: t.recipient.missingTitle })).toBeVisible();
    await axe(page, 'link page after a reload');
    await page.goto(link);
    await expect(page.getByRole('heading', { level: 1, name: t.recipient.filesTitle })).toBeFocused();

    // The next click resumes the same grant, uncounted, and the browser saves the file.
    const resumed = grantAnswer();
    const saved = page.waitForEvent('download');
    await downloadButton().click();
    const answer = await resumed;
    expect(answer.request().postDataJSON()).toEqual({ resume_grant_id: grant.grant_id });
    expect(((await answer.json()) as { grant_id: string }).grant_id).toBe(grant.grant_id);
    const bytes = readBytes(await (await saved).path());
    expect(await sha256(bytes), 'the saved file is the uploaded one').toBe(await sha256(plainBytes));
    await expect(page.getByText(fill(t.recipient.downloadStarted, { name: plain }))).toBeVisible();
    expect(await keptGrants(), 'a grant handed to the browser is forgotten').toBe(0);

    // The second half under the same grant, with the browser's own cookies: 206, and the halves join to the file.
    const half = Math.floor(plainBytes.length / 2);
    const cookies = await recipient.context.cookies(API);
    const tail = await request.get(new URL(grant.url, API).href, {
      headers: {
        range: `bytes=${half}-`,
        cookie: cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join('; '),
      },
    });
    expect(tail.status()).toBe(206);
    const joined = new Uint8Array(plainBytes.length);
    joined.set(bytes.subarray(0, half));
    joined.set(new Uint8Array(await tail.body()), half);
    expect(await sha256(joined), 'the halves join to the file').toBe(await sha256(plainBytes));

    // The member's page: this recipient verified, with one download of that file; the other emailed, with none.
    await member.goto(`/transfers/${transferId}`);
    const mine = recipientRow(member, first);
    await expect(mine.getByText(t.accessState.verified, { exact: true })).toBeVisible({ timeout: 30_000 });
    await expect(mine.getByText(plural(t.delivery, 'downloadCount', 1, { name: plain }), { exact: true })).toBeVisible();
    const other = recipientRow(member, second);
    await expect(other.getByText(t.deliveryState.sent, { exact: true })).toBeVisible();
    await expect(other.getByText(t.delivery.none, { exact: true }).last()).toBeVisible();
    await axe(member, 'recipients table');
  });

  await step(7, 'the member revokes; the recipient page shows revoked and a new grant is refused', async () => {
    await member.getByRole('button', { name: t.delivery.revoke }).click();
    const dialog = member.getByRole('dialog', { name: t.delivery.revokeTitle });
    await expect(dialog).toBeVisible();
    await axe(member, 'revoke dialog');
    await dialog.getByRole('button', { name: t.delivery.revokeConfirm }).click();
    await expect(dialog).toBeHidden();
    await expect(member.getByText(t.delivery.revoked, { exact: false })).toBeVisible();
    await expect(member.getByText(t.transferState.revoked, { exact: true }).first()).toBeVisible();

    const page = recipient.page;
    const refused = page.waitForResponse((r) => /\/v1\/session\/files\/[^/]+\/downloads$/.test(r.url()));
    await page.getByRole('button', { name: fill(t.recipient.downloadFile, { name: staff }) }).click();
    const answer = await refused;
    expect(answer.status()).toBe(410);
    expect(((await answer.json()) as { code: string }).code).toBe('link_revoked');
    await expect(page.getByRole('heading', { level: 1, name: t.recipient.revokedTitle })).toBeFocused();
    await axe(page, 'link revoked');

    await member.goto('/transfers');
    const row = member.getByRole('row').filter({ has: member.locator(`a[href="/transfers/${transferId}"]`) });
    await expect(row.getByText(t.transferState.revoked, { exact: true })).toBeVisible();
  });
  await close(recipient);

  await step(8, 'expiry: the jobs move the clock past expires_at; the link shows expired, the list expired', async () => {
    const later = `${unique(`m3-${lang}-later`)}@partner.example`;
    const name = `${unique('later')}.txt`;
    await member.goto('/transfers/new');
    await addRecipient(member, later, lang);
    await member.getByLabel(t.sender.expiry).selectOption('PT1H');
    await member.getByTestId('transfer-files').setInputFiles(payload(name, wordsText(64 * 1024, 3)));
    await member.getByRole('button', { name: t.sender.send }).click();
    await expect(member).toHaveURL(/\/transfers\/[0-9a-f-]{36}$/, { timeout: 120_000 });
    const expiringId = new URL(member.url()).pathname.split('/').pop() ?? '';
    await sendPastWarning(member, lang);

    const expiring = await newPage(browser, lang, 'expiring-recipient');
    const email = await linkEmail(request, later);
    await expiring.page.goto(email.url);
    await verify(expiring.page, request, later, false, lang);

    // The clock's test hook moves the jobs two hours on, past the one-hour expiry.
    await runJob('expiry', 2 * 3600);
    await runJob('deletion', 2 * 3600);
    await openLink(expiring.page, email.url);
    await expect(expiring.page.getByRole('heading', { level: 1, name: t.recipient.expiredTitle })).toBeFocused();
    await axe(expiring.page, 'link expired');
    await close(expiring);

    await member.goto('/transfers');
    const row = member.getByRole('row').filter({ has: member.locator(`a[href="/transfers/${expiringId}"]`) });
    await expect(row.getByText(t.transferState.expired, { exact: true })).toBeVisible();
  });

  await step(9, 'an admin invites, changes the DLP approver, deactivates, and sets max_expiry', async () => {
    const admin = await newPage(browser, lang, 'admin');
    const page = admin.page;
    await signIn(page, 'admin', '/admin/users', lang);
    await expect(page.locator('main .animate-spin')).toHaveCount(0);
    await axe(page, 'users');
    const menuAction = async (email: string, action: string) => {
      await page.getByRole('button', { name: fill(t.admin.actionsFor, { email }) }).click();
      await page.getByRole('menuitem', { name: action }).click();
    };

    const invited = `${unique(`m3-${lang}-invite`)}@example.com`;
    await page.getByRole('button', { name: t.admin.inviteUser }).click();
    const invite = page.getByRole('dialog', { name: t.admin.inviteUser });
    await expect(invite).toBeVisible();
    await axe(page, 'invite dialog');
    await invite.getByLabel(t.admin.emailAddress).fill(invited);
    await invite.getByRole('button', { name: t.admin.sendInvitation }).click();
    await expect(userRow(page, invited).getByText(t.admin.invited, { exact: true })).toBeVisible();

    const memberEmail = USERS.member.email;
    await menuAction(memberEmail, t.admin.makeApprover);
    await expect(userRow(page, memberEmail).getByRole('cell', { name: t.common.yes, exact: true })).toBeVisible();
    await menuAction(memberEmail, t.admin.removeApprover);
    await expect(userRow(page, memberEmail).getByRole('cell', { name: t.common.yes, exact: true })).toHaveCount(0);

    await menuAction(invited, t.admin.deactivate);
    const confirm = page.getByRole('dialog', { name: t.admin.confirm.deactivate.title });
    await expect(confirm).toBeVisible();
    await axe(page, 'deactivate dialog');
    await confirm.getByRole('button', { name: t.admin.confirm.deactivate.action }).click();
    await expect(userRow(page, invited).getByText(t.admin.deactivated, { exact: true })).toBeVisible();

    await page.goto('/admin/policy');
    const maxExpiry = page.getByLabel(t.admin.maxExpiry);
    await expect(maxExpiry).toBeVisible();
    await axe(page, 'tenant policy');
    const before = await maxExpiry.inputValue();
    const save = page.getByRole('button', { name: t.common.save });
    const saved = () => page.waitForResponse((r) => r.url().endsWith('/v1/tenant/policy') && r.request().method() === 'PATCH');
    try {
      await maxExpiry.selectOption('P3D');
      let answer = saved();
      await save.click();
      expect((await answer).status()).toBe(200);
      await member.goto('/transfers/new');
      await expect(member.getByLabel(t.sender.expiry)).toHaveValue('P3D');
      const offered = await member
        .getByLabel(t.sender.expiry)
        .locator('option')
        .evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value));
      expect(offered).not.toContain('P7D');
      if (before !== 'P3D') {
        await maxExpiry.selectOption(before);
        answer = saved();
        await save.click();
        expect((await answer).status()).toBe(200);
      }
    } catch (error) {
      if (before !== 'P3D') {
        await maxExpiry.selectOption(before).catch(() => undefined);
        await save.click().catch(() => undefined);
      }
      throw error;
    }
    await close(admin);
  });
});
