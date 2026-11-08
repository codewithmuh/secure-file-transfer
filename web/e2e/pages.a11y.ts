import { expect, test, type Page } from '@playwright/test';
import { resources, type Language } from '../src/lib/i18n';
import { checkAxe } from './support/axe';
import { escapeRegExp } from './support/stack';
import {
  codeRequested,
  draft,
  draftId,
  expired,
  expiredId,
  fakeAdmin,
  inspection,
  linkSession,
  myNumberFileId,
  policy,
  problemOf,
  recipientStatuses,
  resolution,
  sessionFiles,
  transfer,
  transferId,
  transferPage,
  userPage,
} from './apiFixtures';

/**
 * axe on every page of the web app (NFR-22, #110), once per language project (playwright.config.ts), with the check
 * the browser journey shares (support/axe.ts): any WCAG 2.0, 2.1 or 2.2 A or AA violation fails. The API is answered
 * from contract-typed fixtures (apiFixtures.ts), so the live pages are checked with real shapes and no backend is
 * needed: every page, every dialog, every link state and step of the recipient's page, and the sign-in callback's
 * error state (#168, #198, #199).
 */

/** What the API answers, by path: contract-typed fixtures (apiFixtures.ts), so the live pages show real shapes. */
const answers: Record<string, unknown> = {
  '/v1/me': fakeAdmin,
  '/v1/tenant/policy': policy,
  '/v1/transfers': transferPage,
  [`/v1/transfers/${transferId}`]: transfer,
  [`/v1/transfers/${draftId}`]: draft,
  [`/v1/transfers/${expiredId}`]: expired,
  [`/v1/transfers/${transferId}/recipients`]: recipientStatuses,
  [`/v1/transfers/${draftId}/recipients`]: recipientStatuses,
  [`/v1/transfers/${expiredId}/recipients`]: recipientStatuses,
  [`/v1/files/${myNumberFileId}/inspection`]: inspection,
  '/v1/users': userPage,
};

async function mockApi(page: Page): Promise<void> {
  // Anything else the app asks the API for is a test bug: answer 404 rather than reach a real server.
  await page.route('**/v1/**', (route) => {
    const answer = answers[new URL(route.request().url()).pathname];
    return answer === undefined
      ? route.fulfill({ status: 404, json: { code: 'not_found' } })
      : route.fulfill({ status: 200, json: answer });
  });
}

// The project's name is the language it runs in (playwright.config.ts).
const language = () => test.info().project.name as Language;

/** The shared axe check (support/axe.ts), in the project's language. */
const expectNoWcagViolations = (page: Page, name: string) => checkAxe(page, name, language());

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test('sign-in', async ({ page }) => {
  await page.goto('/sign-in');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await expectNoWcagViolations(page, 'sign-in');
});

const memberPages = [
  ['dashboard', '/'],
  ['transfer list', '/transfers'],
  ['new transfer', '/transfers/new'],
  ['transfer detail', `/transfers/${transferId}`],
  ['draft to resume', `/transfers/${draftId}`],
  ['expired transfer, read-only', `/transfers/${expiredId}`],
  ['admin users', '/admin/users'],
  ['admin tenant policy', '/admin/policy'],
  // M5's pages, hidden (#195): their routes show NotAvailableYet.
  ['upload requests (not available yet)', '/upload-requests'],
  ['new upload request (not available yet)', '/upload-requests/new'],
  ['audit log (not available yet)', '/admin/audit'],
  ['API keys (not available yet)', '/admin/api-keys'],
] as const;

for (const [name, path] of memberPages) {
  test(name, async ({ page }) => {
    await page.goto(path);
    await expect(page.locator('main').getByRole('heading', { level: 1 })).toBeVisible();
    // The live pages load from the (mocked) API: check them once loaded, not their spinner.
    await expect(page.locator('main .animate-spin')).toHaveCount(0);
    await expectNoWcagViolations(page, name);
  });
}

const text = () => resources[language()].translation;

/** A Node Buffer of zeros: Playwright's file payload. The tests run in Node, whose types this project doesn't load. */
const bytes = (size: number) => (globalThis as unknown as { Buffer: { alloc(size: number): never } }).Buffer.alloc(size);

test('transfer detail with findings shown', async ({ page }) => {
  await page.goto(`/transfers/${transferId}`);
  await page.getByRole('button', { name: text().sender.showFindings.replace('{{name}}', 'staff-list.txt') }).click();
  await expect(page.getByRole('region', { name: text().sender.findings })).toBeVisible();
  await expectNoWcagViolations(page, 'transfer findings');
});

test('new transfer with recipients and files', async ({ page }) => {
  await page.goto('/transfers/new');
  await page.getByLabel(text().sender.recipientEmail).fill('tanaka@example.co.jp');
  await page.getByRole('button', { name: text().sender.addRecipient }).click();
  await page.getByTestId('transfer-files').setInputFiles({ name: 'report.pdf', mimeType: 'application/pdf', buffer: bytes(1024) });
  await expect(page.getByText('report.pdf')).toBeVisible();
  await expectNoWcagViolations(page, 'new transfer, filled in');
});

test('admin users: action menu, invite and deactivate dialogs', async ({ page }) => {
  await page.goto('/admin/users');
  const menu = page.getByRole('button', { name: text().admin.actionsFor.replace('{{email}}', 'member@example.com') });
  await menu.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('menu')).toBeVisible();
  await expect(page.getByRole('menuitem').first()).toBeFocused();
  await expectNoWcagViolations(page, 'users action menu');

  await page.keyboard.press('End');
  await expect(page.getByRole('menuitem', { name: text().admin.deactivate })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('dialog', { name: text().admin.confirm.deactivate.title })).toBeVisible();
  await expectNoWcagViolations(page, 'deactivate dialog');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toBeHidden();
  await expect(menu).toBeFocused();

  await page.getByRole('button', { name: text().admin.inviteUser }).click();
  const dialog = page.getByRole('dialog', { name: text().admin.inviteUser });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel(text().admin.emailAddress)).toBeFocused();
  await expectNoWcagViolations(page, 'invite dialog');
});

test('transfer detail: the recipients table, then the unlock and revoke dialogs, by keyboard (#199)', async ({ page }) => {
  await page.goto(`/transfers/${transferId}`);
  const table = page.getByRole('table', { name: text().delivery.caption });
  await expect(table.getByRole('rowheader', { name: /tanaka@example\.co\.jp/ })).toBeVisible();
  await expectNoWcagViolations(page, 'recipients table');

  const unlock = page.getByRole('button', { name: text().delivery.unlockFor.replace('{{email}}', 'tanaka@example.co.jp') });
  await unlock.focus();
  await page.keyboard.press('Enter');
  const unlockDialog = page.getByRole('dialog', { name: text().delivery.unlockTitle });
  await expect(unlockDialog).toBeVisible();
  await expect(unlockDialog.getByRole('button', { name: text().common.cancel })).toBeFocused();
  await expectNoWcagViolations(page, 'unlock dialog');
  await page.keyboard.press('Escape');
  await expect(unlockDialog).toBeHidden();
  await expect(unlock).toBeFocused();

  const revoke = page.getByRole('button', { name: text().delivery.revoke });
  await revoke.focus();
  await page.keyboard.press('Enter');
  const revokeDialog = page.getByRole('dialog', { name: text().delivery.revokeTitle });
  await expect(revokeDialog).toBeVisible();
  await expect(revokeDialog.getByText(text().delivery.revokeBody)).toBeVisible();
  await expectNoWcagViolations(page, 'revoke dialog');
  await page.keyboard.press('Escape');
  await expect(revoke).toBeFocused();
});

test('transfer detail: a revocation not yet confirmed (503) says it stands and offers a retry (#199)', async ({ page }) => {
  await page.route(`**/v1/transfers/${transferId}/revoke`, (route) =>
    route.fulfill({ status: 503, json: problemOf(503, 'service_unavailable') }),
  );
  await page.goto(`/transfers/${transferId}`);
  await page.getByRole('button', { name: text().delivery.revoke }).click();
  await page.getByRole('dialog').getByRole('button', { name: text().delivery.revokeConfirm }).click();
  await expect(page.getByRole('dialog')).toBeHidden();
  await expect(page.getByText(text().delivery.revokeUnconfirmed)).toBeVisible();
  await expect(page.getByRole('button', { name: text().delivery.revokeRetry })).toBeVisible();
  await expectNoWcagViolations(page, 'revocation unconfirmed');
});

test('admin users: every confirmation dialog (#168)', async ({ page }) => {
  await page.goto('/admin/users');
  const dialogs = [
    ['member@example.com', text().admin.makeAdmin, text().admin.confirm.role.title_admin],
    ['member@example.com', text().admin.signOutUser, text().admin.confirm.signOut.title],
    ['member@example.com', text().admin.resetSignIn, text().admin.confirm.reset.title],
    ['new@example.com', text().admin.resendInvitation, text().admin.confirm.resend.title],
  ] as const;
  for (const [email, action, title] of dialogs) {
    await page.getByRole('button', { name: text().admin.actionsFor.replace('{{email}}', email) }).click();
    await page.getByRole('menuitem', { name: action }).click();
    const dialog = page.getByRole('dialog', { name: title });
    await expect(dialog).toBeVisible();
    await expectNoWcagViolations(page, `${title} dialog`);
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
  }
});

test('sign-in callback that failed lands on the sign-in page with its error (#168)', async ({ page }) => {
  await page.goto('/auth/callback?error=access_denied');
  await expect(page).toHaveURL(/\/sign-in\?error=sign_in_failed$/);
  await expect(page.getByText(text().auth.signInFailed)).toBeVisible();
  await expectNoWcagViolations(page, 'sign-in failed');
});

// ---- the recipient's link page (#198): every link state and step, with the link in the project's language ----

type LinkAnswers = Record<string, { status: number; json?: unknown }>;

/** Answers the link and session routes, by method and path, over the member fixtures. */
async function answerLinks(page: Page, links: LinkAnswers): Promise<void> {
  await page.route(
    (url) => url.pathname.startsWith('/v1/links/') || url.pathname.startsWith('/v1/session'),
    (route) => {
      const request = route.request();
      const answer = links[`${request.method()} ${new URL(request.url()).pathname}`];
      if (!answer) return route.fulfill({ status: 404, json: problemOf(404, 'not_found') });
      return answer.json === undefined ? route.fulfill({ status: answer.status }) : route.fulfill({ status: answer.status, json: answer.json });
    },
  );
}

const LINK = '/t#Fake-link-token_0000000000000000000000';

const resolved = (access: Parameters<typeof resolution>[1] = 'verification_required') => ({
  'POST /v1/links/resolve': { status: 200, json: resolution(language(), access) },
});

test('recipient link without its fragment', async ({ page }) => {
  await page.goto('/t');
  await expect(page.getByRole('heading', { level: 1, name: text().recipient.missingTitle })).toBeFocused();
  await expectNoWcagViolations(page, 'link without fragment');
});

const gone = [
  ['not found', { status: 404, json: problemOf(404, 'link_not_found') }, 'notFoundTitle'],
  ['revoked', { status: 410, json: problemOf(410, 'link_revoked') }, 'revokedTitle'],
  ['expired', { status: 410, json: problemOf(410, 'link_expired') }, 'expiredTitle'],
] as const;

for (const [name, answer, title] of gone) {
  test(`recipient link ${name}`, async ({ page }) => {
    await answerLinks(page, { 'POST /v1/links/resolve': answer });
    await page.goto(LINK);
    await expect(page).toHaveURL(/\/t$/); // the fragment is gone from the address bar
    await expect(page.getByRole('heading', { level: 1, name: text().recipient[title] })).toBeFocused();
    await expectNoWcagViolations(page, `link ${name}`);
  });
}

test('recipient link locked', async ({ page }) => {
  await answerLinks(page, resolved('locked'));
  await page.goto(LINK);
  await expect(page.getByRole('heading', { level: 1, name: text().recipient.lockedTitle })).toBeFocused();
  await expectNoWcagViolations(page, 'link locked');
});

test('recipient: code step, a wrong code, then the files and done, by keyboard alone', async ({ page }) => {
  let attempts = 0;
  await answerLinks(page, {
    ...resolved(),
    'POST /v1/links/codes': { status: 202, json: codeRequested },
    'GET /v1/session/files': { status: 200, json: sessionFiles },
    'DELETE /v1/session': { status: 204 },
  });
  await page.route('**/v1/links/sessions', (route) =>
    ++attempts === 1
      ? route.fulfill({ status: 422, json: problemOf(422, 'code_invalid', { attempts_remaining: 4 }) })
      : route.fulfill({ status: 201, json: linkSession(language()) }),
  );
  await page.goto(LINK);
  const heading = page.getByRole('heading', { level: 1, name: text().recipient.verifyTitle });
  await expect(heading).toBeFocused();
  await expectNoWcagViolations(page, 'code step');

  // Tab to "Email me a code", Enter; the countdown starts and the code input is next.
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: text().recipient.sendCode })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('status').getByText(text().recipient.codeSent.replace('{{minutes}}', '10'))).toBeVisible();
  await expect(page.getByRole('button', { name: text().recipient.sendAgain })).toBeDisabled();
  const code = page.getByRole('textbox', { name: text().recipient.codeLabel });
  await expect(code).toHaveAttribute('inputmode', 'numeric');
  await expect(code).toHaveAttribute('autocomplete', 'one-time-code');
  await page.keyboard.press('Tab'); // the button waits out its countdown, so the code input is next
  await expect(code).toBeFocused();
  await page.keyboard.type('111111');
  await page.keyboard.press('Enter');
  const wrong = text().recipient.problems.code_invalid_other.replace('{{count}}', '4');
  await expect(code).toHaveAccessibleDescription(new RegExp(escapeRegExp(wrong)));
  await expect(code).toBeFocused();
  await expectNoWcagViolations(page, 'code step, wrong code');

  await page.keyboard.press('Control+A');
  await page.keyboard.type('123456');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { level: 1, name: text().recipient.filesTitle })).toBeFocused();
  await expect(page.getByText(text().recipient.unscannableWarning)).toBeVisible();
  await expect(page.getByText(text().recipient.limitReached)).toBeVisible();
  await expectNoWcagViolations(page, 'files');

  await page.getByRole('button', { name: text().recipient.done }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { level: 1, name: text().recipient.doneTitle })).toBeFocused();
  await expectNoWcagViolations(page, 'done');
});

test('recipient: a session the API ended (401) goes back to the code step with a note', async ({ page }) => {
  await answerLinks(page, {
    ...resolved('verified'),
    'GET /v1/session': { status: 200, json: linkSession(language()) },
    'GET /v1/session/files': { status: 401, json: problemOf(401, 'session_expired') },
  });
  await page.goto(LINK);
  await expect(page.getByRole('heading', { level: 1, name: text().recipient.verifyTitle })).toBeFocused();
  await expect(page.getByText(text().recipient.sessionEnded)).toBeVisible();
  await expectNoWcagViolations(page, 'session ended');
});

test('recipient: a verified browser resumes its session with no new code', async ({ page }) => {
  await answerLinks(page, {
    ...resolved('verified'),
    'GET /v1/session': { status: 200, json: linkSession(language()) },
    'GET /v1/session/files': { status: 200, json: sessionFiles },
  });
  await page.goto(LINK);
  await expect(page.getByRole('heading', { level: 1, name: text().recipient.filesTitle })).toBeFocused();
});

test('a Japanese link opened in an English browser shows Japanese (FR-33)', async ({ page }) => {
  test.skip(language() !== 'en', 'the English browser only');
  await answerLinks(page, { 'POST /v1/links/resolve': { status: 200, json: resolution('ja') } });
  await page.goto(LINK);
  await expect(page.locator('html')).toHaveAttribute('lang', 'ja');
  await expect(page.getByRole('heading', { level: 1, name: resources.ja.translation.recipient.verifyTitle })).toBeVisible();
});

// The uploader's link page is M5's: NotAvailableYet in the public layout (#195).
test('uploader link (not available yet)', async ({ page }) => {
  await page.goto('/u#fake-link-token');
  await expect(page.getByRole('heading', { level: 1, name: text().notAvailable.title })).toBeVisible();
  await expectNoWcagViolations(page, 'uploader link');
});
