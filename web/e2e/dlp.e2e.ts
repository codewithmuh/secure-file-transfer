import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { resources, type Language } from '../src/lib/i18n';
import { checkAxe } from './support/axe';
import { escapeRegExp, linkEmail, payload, sendPastWarning, signIn, transferStatus, unique, USERS, wordsText } from './support/stack';

/**
 * DLP in the browser (#218 to #220), in English and Japanese (playwright.e2e.config.ts), against `make up` and
 * `make seed`:
 * - #218: the admin adds a trusted domain, a keyword list and a rule;
 * - #219: a warning the member confirms, and a block the member clears by removing the file;
 * - #220: the member requests approval, the admin (another seeded user, an approver) approves it from `/approvals`
 *   and the recipient is emailed; and a rejection the member sees with its comment.
 * Each test makes its own keyword list (a unique term), so its rule matches only its own files, and removes what it
 * made at the end, so the other flows see the default policy again.
 */

const language = () => test.info().project.name as Language;
const text = () => resources[language()].translation;
const BROWSER_LOCALE: Record<Language, string> = { en: 'en-US', ja: 'ja-JP' };

function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, name: string) => String(values[name]));
}

async function person(browser: Browser, who: keyof typeof USERS, path: string): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ locale: BROWSER_LOCALE[language()] });
  const page = await context.newPage();
  await signIn(page, who, path, language());
  return { context, page };
}

/** The admin confirms the dialog that names a DLP change, and waits for its write to succeed. */
async function confirmChange(page: Page, title: string, action: string, write: RegExp): Promise<void> {
  const dialog = page.getByRole('dialog', { name: title });
  await expect(dialog).toBeVisible();
  const answer = page.waitForResponse((r) => write.test(new URL(r.url()).pathname) && r.request().method() !== 'GET');
  await dialog.getByRole('button', { name: action, exact: true }).click();
  expect((await answer).status(), `${title}: ${action}`).toBeLessThan(300);
  await expect(dialog).toBeHidden();
}

async function addKeywordList(page: Page, name: string, term: string): Promise<void> {
  const t = text();
  await page.goto('/admin/dlp/keywords/new');
  await page.getByLabel(t.common.name, { exact: true }).fill(name);
  await page.getByLabel(t.dlpAdmin.terms, { exact: true }).fill(`${term}\n`);
  await page.getByRole('button', { name: t.dlpAdmin.addKeywordList }).click();
  await confirmChange(page, t.dlpAdmin.confirmAddKeywordList, t.dlpAdmin.addKeywordList, /\/v1\/dlp\/detectors$/);
  await expect(page).toHaveURL(/\/admin\/dlp\/keywords$/);
  await expect(page.getByRole('rowheader', { name, exact: true })).toBeVisible();
}

async function addRule(page: Page, name: string, list: string, action: keyof ReturnType<typeof text>['dlpAction']): Promise<void> {
  const t = text();
  await page.goto('/admin/dlp/rules/new');
  await page.getByLabel(t.common.name, { exact: true }).fill(name);
  await page.getByRole('checkbox', { name: new RegExp(`^${escapeRegExp(list)}`) }).check();
  await page.getByRole('radio', { name: new RegExp(`^${escapeRegExp(t.dlpAction[action])}`) }).check();
  await page.getByRole('button', { name: t.dlpAdmin.addRule }).click();
  await confirmChange(page, t.dlpAdmin.confirmAddRule, t.dlpAdmin.addRule, /\/v1\/dlp\/rules$/);
  await expect(page).toHaveURL(/\/admin\/dlp\/rules$/);
  await expect(page.getByRole('rowheader', { name, exact: true })).toBeVisible();
}

/** Removes what a test made, best effort: its rule first (a list a rule uses can't be deleted), then its list. */
async function removeRuleAndList(page: Page, rule: string, list: string): Promise<void> {
  const t = text();
  await page.goto('/admin/dlp/rules');
  const deleteRule = page.getByRole('button', { name: fill(t.dlpAdmin.deleteNamed, { name: rule }) });
  if (await deleteRule.isVisible().catch(() => false)) {
    await deleteRule.click();
    await confirmChange(page, t.dlpAdmin.confirmDeleteRule, t.common.delete, /\/v1\/dlp\/rules\/[^/]+$/);
  }
  await page.goto('/admin/dlp/keywords');
  const deleteList = page.getByRole('button', { name: fill(t.dlpAdmin.deleteNamed, { name: list }) });
  if (await deleteList.isVisible().catch(() => false)) {
    await deleteList.click();
    await confirmChange(page, t.dlpAdmin.confirmDeleteKeywordList, t.common.delete, /\/v1\/dlp\/detectors\/[^/]+$/);
  }
}

/** The member's transfer: one recipient and the files, sent; resolves on its detail page with its ID. */
async function sendTransfer(page: Page, recipient: string, files: ReturnType<typeof payload>[]): Promise<string> {
  const t = text();
  await page.goto('/transfers/new');
  await page.getByLabel(t.sender.recipientEmail).fill(recipient);
  await page.getByRole('button', { name: t.sender.addRecipient }).click();
  await page.getByTestId('transfer-files').setInputFiles(files);
  await page.getByRole('button', { name: t.sender.send }).click();
  await expect(page).toHaveURL(/\/transfers\/[0-9a-f-]{36}$/, { timeout: 120_000 });
  return new URL(page.url()).pathname.split('/').pop() ?? '';
}

test('the admin adds a trusted domain, a keyword list and a warning rule; the member confirms the warning (#218, #219)', async ({
  page: admin,
  browser,
  request,
}) => {
  test.setTimeout(10 * 60_000);
  const lang = language();
  const t = text();
  const domain = `${unique(`dlp-${lang}`)}.example`;
  const list = unique(`List-${lang}`);
  const rule = unique(`Warn-${lang}`);
  const term = unique('Bluebird').replace(/-/g, '');

  await signIn(admin, 'admin', '/admin/dlp', lang);
  try {
    // A trusted domain.
    await admin.getByLabel(t.dlpAdmin.addDomain).fill(domain);
    await admin.getByRole('button', { name: t.dlpAdmin.add, exact: true }).click();
    await expect(admin.getByRole('button', { name: fill(t.dlpAdmin.removeDomain, { domain }) })).toBeVisible();
    await checkAxe(admin, 'DLP settings', lang);
    await admin.getByRole('button', { name: t.common.save }).click();
    await expect(admin.getByRole('dialog').getByText(fill(t.dlpAdmin.change.trust, { domains: domain }))).toBeVisible();
    await confirmChange(admin, t.dlpAdmin.confirmSettings, t.common.save, /\/v1\/dlp\/policy$/);
    await admin.reload();
    await expect(admin.getByRole('button', { name: fill(t.dlpAdmin.removeDomain, { domain }) })).toBeVisible();

    // A keyword list and a rule that warns about it.
    await addKeywordList(admin, list, term);
    await checkAxe(admin, 'DLP keyword lists', lang);
    await addRule(admin, rule, list, 'warn');
    await checkAxe(admin, 'DLP rules', lang);

    // The member sends a file with the term to the trusted domain: the rule warns; the member confirms.
    const member = await person(browser, 'member', '/transfers/new');
    try {
      const recipient = `${unique(`dlp-${lang}-warn`)}@${domain}`;
      await sendTransfer(member.page, recipient, [payload(`${unique('notes')}.txt`, `${term}\n${wordsText(2048, 3)}`)]);
      await expect(transferStatus(member.page, 'awaiting_confirmation', lang)).toBeVisible({ timeout: 180_000 });
      await expect(member.page.getByText(rule, { exact: true })).toBeVisible();
      await checkAxe(member.page, 'transfer awaiting confirmation', lang);
      await member.page.getByRole('button', { name: t.dlp.confirm.warning.button }).click();
      const dialog = member.page.getByRole('dialog', { name: t.dlp.confirm.warning.title });
      await expect(dialog.getByText(rule)).toBeVisible();
      await checkAxe(member.page, 'confirm dialog', lang);
      await dialog.getByLabel(t.dlp.justificationOptional).fill('Agreed with the client.');
      await dialog.getByRole('button', { name: t.dlp.confirm.warning.action, exact: true }).click();
      await expect(dialog).toBeHidden();
      await expect(transferStatus(member.page, 'sent', lang)).toBeVisible({ timeout: 60_000 });
      const email = await linkEmail(request, recipient);
      expect(email.url).toMatch(/^http:\/\/localhost:3000\/t#/);
    } finally {
      await member.context.close();
    }

    // The domain comes off the list again.
    await admin.goto('/admin/dlp');
    await admin.getByRole('button', { name: fill(t.dlpAdmin.removeDomain, { domain }) }).click();
    await admin.getByRole('button', { name: t.common.save }).click();
    await confirmChange(admin, t.dlpAdmin.confirmSettings, t.common.save, /\/v1\/dlp\/policy$/);
  } finally {
    await removeRuleAndList(admin, rule, list);
  }
});

test('a block rule holds the transfer; removing the file sends the rest (#219)', async ({ page: admin, browser, request }) => {
  test.setTimeout(10 * 60_000);
  const lang = language();
  const t = text();
  const list = unique(`Blocked-${lang}`);
  const rule = unique(`Block-${lang}`);
  const term = unique('Kingfisher').replace(/-/g, '');

  await signIn(admin, 'admin', '/admin/dlp/keywords', lang);
  try {
    await addKeywordList(admin, list, term);
    await addRule(admin, rule, list, 'block');

    const member = await person(browser, 'member', '/transfers/new');
    try {
      const recipient = `${unique(`dlp-${lang}-block`)}@partner.example`;
      const secret = `${unique('secret')}.txt`;
      await sendTransfer(member.page, recipient, [
        payload(`${unique('plain')}.txt`, wordsText(2048, 5)),
        payload(secret, `${term}\n${wordsText(2048, 6)}`),
      ]);
      await expect(transferStatus(member.page, 'held', lang)).toBeVisible({ timeout: 180_000 });
      await expect(member.page.getByText(t.holdReason.dlp_blocked)).toBeVisible();
      await expect(member.page.getByText(rule, { exact: true })).toBeVisible();
      await checkAxe(member.page, 'transfer held by a DLP rule', lang);

      await member.page.getByRole('button', { name: fill(t.dlp.removeFileNamed, { name: secret }) }).click();
      const dialog = member.page.getByRole('dialog', { name: t.dlp.removeTitle });
      await checkAxe(member.page, 'remove file dialog', lang);
      await dialog.getByRole('button', { name: t.dlp.removeFile, exact: true }).click();
      await expect(dialog).toBeHidden();
      // The rest is checked again: sent, or a warning about a new domain first.
      await sendPastWarning(member.page, lang);
      await linkEmail(request, recipient);
    } finally {
      await member.context.close();
    }
  } finally {
    await removeRuleAndList(admin, rule, list);
  }
});

test('the member requests approval; the admin approves one and rejects another from /approvals (#220)', async ({
  page: admin,
  browser,
  request,
}) => {
  test.setTimeout(15 * 60_000);
  const lang = language();
  const t = text();
  const list = unique(`Approval-${lang}`);
  const rule = unique(`Approve-${lang}`);
  const term = unique('Heron').replace(/-/g, '');

  await signIn(admin, 'admin', '/admin/users', lang);
  // A rule that requires approval needs more active approvers than it asks for: both seeded users approve here.
  const madeApprover: string[] = [];
  const userRow = (email: string) => admin.getByRole('row').filter({ has: admin.getByText(email, { exact: true }) });
  const makeApprover = async (email: string) => {
    if ((await userRow(email).getByRole('cell', { name: t.common.yes, exact: true }).count()) > 0) return;
    await admin.getByRole('button', { name: fill(t.admin.actionsFor, { email }) }).click();
    await admin.getByRole('menuitem', { name: t.admin.makeApprover }).click();
    await expect(userRow(email).getByRole('cell', { name: t.common.yes, exact: true })).toBeVisible();
    madeApprover.push(email);
  };
  try {
    await expect(admin.getByText(t.admin.approverNote)).toBeVisible();
    await makeApprover(USERS.admin.email);
    await makeApprover(USERS.member.email);
    await addKeywordList(admin, list, term);
    await addRule(admin, rule, list, 'require_approval');

    const member = await person(browser, 'member', '/transfers/new');
    try {
      /** Sends a transfer the rule holds for approval, requests it, and resolves with the request's address. */
      const requestApproval = async (recipient: string): Promise<string> => {
        await sendTransfer(member.page, recipient, [payload(`${unique('plan')}.txt`, `${term}\n${wordsText(2048, 8)}`)]);
        await expect(member.page.getByRole('button', { name: t.dlp.confirm.approval.button })).toBeVisible({ timeout: 180_000 });
        await member.page.getByRole('button', { name: t.dlp.confirm.approval.button }).click();
        const dialog = member.page.getByRole('dialog', { name: t.dlp.confirm.approval.title });
        await dialog.getByRole('button', { name: t.dlp.confirm.approval.action }).click();
        await expect(dialog.getByText(t.dlp.justificationProblem.required)).toBeVisible();
        await checkAxe(member.page, 'request approval dialog', lang);
        await dialog.getByLabel(t.dlp.justificationRequired).fill('The client needs the plan before Friday.');
        await dialog.getByRole('button', { name: t.dlp.confirm.approval.action }).click();
        await expect(dialog).toBeHidden();
        await expect(transferStatus(member.page, 'pending_approval', lang)).toBeVisible();
        await checkAxe(member.page, 'transfer pending approval', lang);
        const link = member.page.getByRole('link', { name: t.dlp.openRequest });
        await expect(link).toBeVisible();
        return (await link.getAttribute('href')) ?? '';
      };

      /** Opens the member's request from the admin's queue: its row links to the request's page. */
      const openFromQueue = async (requestPath: string) => {
        await admin.goto('/approvals');
        const row = admin.getByRole('row').filter({ has: admin.locator(`a[href="${requestPath}"]`) });
        await expect(row.getByText(rule)).toBeVisible();
        await checkAxe(admin, 'approvals queue', lang);
        await row.getByRole('link').click();
        await expect(admin).toHaveURL(new RegExp(`${escapeRegExp(requestPath)}$`));
        await expect(admin.getByRole('button', { name: t.approvals.approve.button, exact: true })).toBeVisible();
        await checkAxe(admin, 'approval request', lang);
      };

      // Approve: the transfer is sent and the recipient emailed.
      const approvedRecipient = `${unique(`dlp-${lang}-approved`)}@partner.example`;
      await openFromQueue(await requestApproval(approvedRecipient));
      await expect(admin.getByText('The client needs the plan before Friday.')).toBeVisible();
      await admin.getByRole('button', { name: t.approvals.approve.button, exact: true }).click();
      const approve = admin.getByRole('dialog', { name: t.approvals.approve.title });
      await checkAxe(admin, 'approve dialog', lang);
      await approve.getByRole('button', { name: t.approvals.approve.action }).click();
      await expect(approve).toBeHidden();
      await expect(admin.getByText(t.approvalState.approved, { exact: true }).first()).toBeVisible();
      await member.page.reload();
      await expect(transferStatus(member.page, 'sent', lang)).toBeVisible({ timeout: 60_000 });
      await linkEmail(request, approvedRecipient);

      // Reject: the transfer is held, and the member reads the comment.
      await openFromQueue(await requestApproval(`${unique(`dlp-${lang}-rejected`)}@partner.example`));
      await admin.getByRole('button', { name: t.approvals.reject.button, exact: true }).click();
      const reject = admin.getByRole('dialog', { name: t.approvals.reject.title });
      await reject.getByRole('button', { name: t.approvals.reject.action, exact: true }).click();
      await expect(reject.getByText(t.approvals.commentProblem.required)).toBeVisible();
      await checkAxe(admin, 'reject dialog', lang);
      const comment = 'Send a summary without the plan instead.';
      await reject.getByLabel(t.approvals.commentRequired).fill(comment);
      await reject.getByRole('button', { name: t.approvals.reject.action, exact: true }).click();
      await expect(reject).toBeHidden();
      await member.page.reload();
      await expect(transferStatus(member.page, 'held', lang)).toBeVisible({ timeout: 60_000 });
      await expect(member.page.getByText(comment)).toBeVisible();
      await checkAxe(member.page, 'transfer held, approval rejected', lang);
    } finally {
      await member.context.close();
    }
  } finally {
    await removeRuleAndList(admin, rule, list);
    await admin.goto('/admin/users');
    for (const email of madeApprover) {
      await admin.getByRole('button', { name: fill(t.admin.actionsFor, { email }) }).click();
      await admin.getByRole('menuitem', { name: t.admin.removeApprover }).click();
      await expect(userRow(email).getByRole('cell', { name: t.common.yes, exact: true })).toHaveCount(0);
    }
  }
});
