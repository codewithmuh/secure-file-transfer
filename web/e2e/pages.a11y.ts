import { expect, test, type Page } from '@playwright/test';
import { resources, type Language } from '../src/lib/i18n';
import { checkAxe } from './support/axe';
import { escapeRegExp } from './support/stack';
import {
  apiKeyCreated,
  apiKeyPage,
  approvalNeeded,
  approvalNeededDlp,
  approvalNeededId,
  approvalQueue,
  auditPage,
  blocked,
  blockedDlp,
  blockedId,
  codeRequested,
  detectorTestResult,
  dlpBlockedFileId,
  dlpDecisionPage,
  dlpDetectors,
  dlpPolicy,
  dlpPolicyMonitor,
  dlpReport,
  dlpRules,
  draft,
  draftId,
  expired,
  expiredId,
  extendableTransfer,
  fakeAdmin,
  inspection,
  keywordList,
  keywordListPath,
  linkSession,
  myNumberFileId,
  myNumberRuleId,
  openRequest,
  pending,
  pendingDlp,
  pendingId,
  pendingRequest,
  pendingRequestId,
  patternDetector,
  patternPath,
  policy,
  problemOf,
  queueRequest,
  queueRequestId,
  receivedFiles,
  receivedFindingsFileId,
  receivedInspection,
  receivedRuleId,
  recipientStatuses,
  rejected,
  rejectedDlp,
  rejectedId,
  rejectedRequest,
  rejectedRequestId,
  resolution,
  sessionFiles,
  ssoDomainPendingId,
  tenantSso,
  tenantTransferPage,
  tenantUploadRequestPage,
  transfer,
  transferId,
  transferPage,
  unsentRecipients,
  uploaderFiles,
  uploaderResolution,
  uploaderSession,
  uploadRequestId,
  uploadRequestPage,
  userPage,
  warned,
  warnedDlp,
  warnedId,
} from './apiFixtures';

/**
 * axe on every page of the web app (NFR-22, #110), once per language project (playwright.config.ts), with the check
 * the browser journey shares (support/axe.ts): any WCAG 2.0, 2.1 or 2.2 A or AA violation fails. The API is answered
 * from contract-typed fixtures (apiFixtures.ts), so the live pages are checked with real shapes and no backend is
 * needed: every page, every dialog, every link state and step of the recipient's and the uploader's pages, and the
 * sign-in callback's error state (#168, #198, #199, #212, #213, #214), and the DLP policy, its patterns, detector tests,
 * monitor mode, received-file rules and blocks, message findings and reports (#218 to #222).
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
  '/v1/upload-requests': uploadRequestPage,
  [`/v1/upload-requests/${uploadRequestId}`]: openRequest,
  [`/v1/upload-requests/${uploadRequestId}/files`]: receivedFiles,
  [`/v1/files/${receivedFindingsFileId}/inspection`]: receivedInspection,
  '/v1/api-keys': apiKeyPage,
  '/v1/audit/events/search': auditPage,
  // Single sign-on (#231).
  '/v1/tenant/sso': tenantSso,
  // DLP (#218 to #220).
  '/v1/dlp/policy': dlpPolicy,
  '/v1/dlp/rules': dlpRules,
  '/v1/dlp/detectors': dlpDetectors,
  [`/v1/dlp/detectors/${keywordListPath}`]: keywordList,
  [`/v1/dlp/detectors/${patternPath}`]: patternDetector,
  '/v1/dlp/report': dlpReport,
  '/v1/dlp/decisions': dlpDecisionPage,
  '/v1/dlp/approval-requests': approvalQueue,
  [`/v1/dlp/approval-requests/${queueRequestId}`]: queueRequest,
  [`/v1/dlp/approval-requests/${pendingRequestId}`]: pendingRequest,
  [`/v1/dlp/approval-requests/${rejectedRequestId}`]: rejectedRequest,
  ...Object.fromEntries(
    (
      [
        [warned, warnedDlp],
        [approvalNeeded, approvalNeededDlp],
        [pending, pendingDlp],
        [blocked, blockedDlp],
        [rejected, rejectedDlp],
      ] as const
    ).flatMap(([item, dlp]) => [
      [`/v1/transfers/${item.id}`, item],
      [`/v1/transfers/${item.id}/dlp`, dlp],
      [`/v1/transfers/${item.id}/recipients`, unsentRecipients],
    ]),
  ),
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
  ['upload requests', '/upload-requests'],
  ['new upload request', '/upload-requests/new'],
  ['upload request detail', `/upload-requests/${uploadRequestId}`],
  ['admin audit log', '/admin/audit'],
  ['admin API keys', '/admin/api-keys'],
  ['admin single sign-on', '/admin/sso'],
  // DLP (#218 to #220): each section of the policy, each DLP state of a transfer, the approvals queue and a request.
  ['DLP settings', '/admin/dlp'],
  ['DLP rules', '/admin/dlp/rules'],
  ['DLP new rule', '/admin/dlp/rules/new'],
  ['DLP rule', `/admin/dlp/rules/${myNumberRuleId}`],
  ['DLP keyword lists', '/admin/dlp/keywords'],
  ['DLP new keyword list', '/admin/dlp/keywords/new'],
  ['DLP keyword list', `/admin/dlp/keywords/${keywordListPath}`],
  // #221, #222: patterns, a rule for received files, and the report.
  ['DLP new pattern', '/admin/dlp/patterns/new'],
  ['DLP pattern stopped for its budget', `/admin/dlp/patterns/${patternPath}`],
  ['DLP rule for received files', `/admin/dlp/rules/${receivedRuleId}`],
  ['DLP reports', '/admin/dlp/reports'],
  ['transfer awaiting confirmation, warned', `/transfers/${warnedId}`],
  ['transfer awaiting confirmation, approval required', `/transfers/${approvalNeededId}`],
  ['transfer pending approval', `/transfers/${pendingId}`],
  ['transfer held by a DLP rule', `/transfers/${blockedId}`],
  ['transfer held, approval rejected', `/transfers/${rejectedId}`],
  ['approvals queue', '/approvals'],
  ['approval request', `/approvals/${queueRequestId}`],
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

// ---- M5 administration (#215, #216, #217) ----

test('API keys: the create dialog, the secret shown once, and the revoke dialog, by keyboard (#215)', async ({ page }) => {
  await page.route('**/v1/api-keys', (route) =>
    route.request().method() === 'POST'
      ? route.fulfill({ status: 201, json: apiKeyCreated() })
      : route.fulfill({ status: 200, json: apiKeyPage }),
  );
  await page.goto('/admin/api-keys');
  await expect(page.getByRole('cell', { name: 'CI pipeline', exact: true })).toBeVisible();

  const create = page.getByRole('button', { name: text().admin.createApiKey }).first();
  await create.focus();
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog', { name: text().admin.createApiKey });
  await expect(dialog.getByLabel(text().common.name)).toBeFocused();
  // Sending it empty marks both fields in place.
  await dialog.getByRole('button', { name: text().common.create }).click();
  await expect(dialog.getByText(text().apiKeys.scopesRequired)).toBeVisible();
  await expectNoWcagViolations(page, 'create API key dialog, with errors');

  await dialog.getByLabel(text().common.name).fill('New integration');
  await dialog.getByRole('checkbox', { name: /transfers:read/ }).check();
  await dialog.getByRole('button', { name: text().common.create }).click();
  const secret = page.getByRole('dialog', { name: text().apiKeys.createdTitle });
  await expect(secret).toBeVisible();
  await expect(secret.getByRole('textbox')).toBeFocused();
  // Escape doesn't close it until the admin says the key is stored.
  await page.keyboard.press('Escape');
  await expect(secret).toBeVisible();
  await expect(secret.getByRole('button', { name: text().apiKeys.done })).toBeDisabled();
  await expectNoWcagViolations(page, 'API key secret');
  await secret.getByRole('checkbox', { name: text().apiKeys.stored }).check();
  await secret.getByRole('button', { name: text().apiKeys.done }).click();
  await expect(page.getByRole('dialog')).toBeHidden();
  await expect(create).toBeFocused();

  const revoke = page.getByRole('button', { name: text().apiKeys.revokeKey.replace('{{name}}', 'CI pipeline') });
  await revoke.focus();
  await page.keyboard.press('Enter');
  const revokeDialog = page.getByRole('dialog', { name: text().apiKeys.revokeTitle });
  await expect(revokeDialog).toBeVisible();
  await expectNoWcagViolations(page, 'revoke API key dialog');
  await page.keyboard.press('Escape');
  await expect(revoke).toBeFocused();
});

test('admin users: demoting an admin lists the API keys it revokes (#215)', async ({ page }) => {
  await page.goto('/admin/users');
  await page.getByRole('button', { name: text().admin.actionsFor.replace('{{email}}', 'admin@example.com') }).click();
  await page.getByRole('menuitem', { name: text().admin.makeMember }).click();
  const dialog = page.getByRole('dialog', { name: text().admin.confirm.role.title_member });
  await expect(dialog.getByText('CI pipeline', { exact: false })).toBeVisible();
  await expect(dialog.getByText('Old sync', { exact: false })).toHaveCount(0); // expired: nothing to revoke
  await expectNoWcagViolations(page, 'demote dialog with keys');
});

test('audit log: filters, the actions list, paging and an event\'s details (#216)', async ({ page }) => {
  await page.goto('/admin/audit');
  await expect(page.getByRole('cell', { name: 'alice@example.com', exact: false })).toBeVisible();
  await page.getByText(text().audit.actions_other.replace('{{count}}', '0')).click();
  await page.getByRole('checkbox', { name: 'download.granted' }).check();
  await page.getByLabel(text().audit.email).fill('alice@example.com');
  await page.getByLabel(text().audit.ipAddress).fill('not an address');
  await page.getByRole('button', { name: text().common.search }).click();
  await expect(page.getByText(text().audit.invalid.sourceIp)).toBeVisible();
  await expectNoWcagViolations(page, 'audit filters, with an error');

  await page.getByLabel(text().audit.ipAddress).fill('198.51.100.5');
  const searched = page.waitForRequest((request) => request.url().endsWith('/v1/audit/events/search') && request.method() === 'POST');
  await page.getByRole('button', { name: text().common.search }).click();
  const body = (await searched).postDataJSON() as { filter: Record<string, unknown> };
  expect(body.filter).toEqual({ email: 'alice@example.com', actions: ['download.granted'], source_ip: '198.51.100.5' });
  expect(page.url()).not.toContain('alice'); // T-47: never in the address

  const details = page.getByRole('row').filter({ hasText: 'download.granted' }).getByRole('button');
  await details.focus();
  await page.keyboard.press('Enter');
  const drawer = page.getByRole('dialog', { name: text().audit.eventTitle });
  await expect(drawer.getByText('198.51.100.5')).toBeVisible();
  await expect(drawer.getByText('recipient_id')).toBeVisible();
  await expectNoWcagViolations(page, 'audit event details');
  await page.keyboard.press('Escape');
  await expect(details).toBeFocused();
  await expect(page.getByRole('button', { name: text().audit.older })).toBeEnabled();
});

test('tenant policy: the domain lists and the suppression form (#217)', async ({ page }) => {
  await page.route('**/v1/email-suppressions/clear', (route) => route.fulfill({ status: 204 }));
  await page.goto('/admin/policy');
  const allowed = page.getByRole('textbox', { name: text().domains.allowed });
  await allowed.fill('not a domain');
  await page.keyboard.press('Enter');
  await expect(page.getByText(text().domains.problem.invalid)).toBeVisible();
  await allowed.fill('Partner.Example');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('list', { name: text().domains.allowed }).getByText('partner.example')).toBeVisible();
  await page.getByRole('textbox', { name: text().domains.blocked }).fill('partner.example');
  await page.getByRole('button', { name: text().domains.addTo.replace('{{list}}', text().domains.blocked) }).click();
  await expect(page.getByText(text().domains.overlap.replace('{{domains}}', 'partner.example'))).toBeVisible();
  await expectNoWcagViolations(page, 'tenant policy, domain lists');

  await page.getByLabel(text().suppression.email).fill('bounced@example.org');
  await page.getByRole('button', { name: text().suppression.action }).click();
  await expect(page.getByText(text().suppression.done.replace('{{email}}', 'bounced@example.org'))).toBeVisible();
  await expectNoWcagViolations(page, 'suppression cleared');
});

test('transfers: the admin\'s tenant-wide list with the owner and a revoke dialog (#217)', async ({ page }) => {
  await page.route(
    (url) => url.pathname === '/v1/transfers' && url.searchParams.get('scope') === 'tenant',
    (route) => route.fulfill({ status: 200, json: tenantTransferPage }),
  );
  await page.goto('/transfers');
  const toggle = page.getByRole('checkbox', { name: text().tenantScope.allTransfers });
  await toggle.check();
  await expect(page.getByRole('columnheader', { name: text().tenantScope.owner })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'member@example.com', exact: true })).toBeVisible();
  await expectNoWcagViolations(page, 'tenant-wide transfers');
  await page.getByRole('button', { name: new RegExp(`^${text().tenantScope.revoke}`) }).first().click();
  await expect(page.getByRole('dialog', { name: text().delivery.revokeTitle })).toBeVisible();
  await expectNoWcagViolations(page, 'tenant-wide revoke dialog');
});

test('upload requests: the admin\'s tenant-wide list with the owner and a revoke dialog (#217)', async ({ page }) => {
  await page.route(
    (url) => url.pathname === '/v1/upload-requests' && url.searchParams.get('scope') === 'tenant',
    (route) => route.fulfill({ status: 200, json: tenantUploadRequestPage }),
  );
  await page.goto('/upload-requests');
  const toggle = page.getByRole('checkbox', { name: text().tenantScope.allUploadRequests });
  await toggle.check();
  await expect(page.getByRole('columnheader', { name: text().tenantScope.owner })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'member@example.com', exact: true })).toBeVisible();
  await expectNoWcagViolations(page, 'tenant-wide upload requests');
  await page.getByRole('button', { name: new RegExp(`^${text().tenantScope.revoke}`) }).first().click();
  await expect(page.getByRole('dialog', { name: text().requests.revokeTitle })).toBeVisible();
  await expectNoWcagViolations(page, 'tenant-wide upload request revoke dialog');
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

// ---- the member's upload requests (#212, #213) and extend expiry (#214) ----

test('new upload request, filled in', async ({ page }) => {
  await page.goto('/upload-requests/new');
  await page.getByLabel(text().requests.uploaderEmail).fill('supplier@example.com');
  await page.getByLabel(text().requests.messageLabel).fill('The signed contract, please.');
  await expectNoWcagViolations(page, 'new upload request, filled in');
});

test('upload request: received files with findings shown, then the unlock, revoke and delete dialogs, by keyboard', async ({ page }) => {
  await page.goto(`/upload-requests/${uploadRequestId}`);
  const table = page.getByRole('table', { name: text().requests.receivedCaption });
  await expect(table.getByRole('rowheader', { name: 'contract.pdf' })).toBeVisible();
  await expect(page.getByText(text().recipient.unscannableWarning)).toBeVisible();
  await page.getByRole('button', { name: text().sender.showFindings.replace('{{name}}', 'staff-list.xlsx') }).click();
  await expect(page.getByRole('region', { name: text().sender.findings })).toBeVisible();
  await expectNoWcagViolations(page, 'received files with findings');

  const unlock = page.getByRole('button', { name: text().requests.unlockFor.replace('{{email}}', 'supplier@example.com') });
  await unlock.focus();
  await page.keyboard.press('Enter');
  const unlockDialog = page.getByRole('dialog', { name: text().requests.unlockTitle });
  await expect(unlockDialog).toBeVisible();
  await expect(unlockDialog.getByRole('button', { name: text().common.cancel })).toBeFocused();
  await expectNoWcagViolations(page, 'unlock uploader dialog');
  await page.keyboard.press('Escape');
  await expect(unlockDialog).toBeHidden();
  await expect(unlock).toBeFocused();

  const revoke = page.getByRole('button', { name: text().requests.revoke });
  await revoke.focus();
  await page.keyboard.press('Enter');
  const revokeDialog = page.getByRole('dialog', { name: text().requests.revokeTitle });
  await expect(revokeDialog.getByText(text().requests.revokeBody)).toBeVisible();
  await expectNoWcagViolations(page, 'revoke upload request dialog');
  await page.keyboard.press('Escape');
  await expect(revoke).toBeFocused();

  const remove = page.getByRole('button', { name: text().requests.deleteFile.replace('{{name}}', 'setup.exe') });
  await remove.focus();
  await page.keyboard.press('Enter');
  const deleteDialog = page.getByRole('dialog', { name: text().requests.deleteTitle });
  await expect(deleteDialog).toBeVisible();
  await expectNoWcagViolations(page, 'delete received file dialog');
  await page.keyboard.press('Escape');
  await expect(remove).toBeFocused();
});

test('upload request: a revocation not yet confirmed (503) says it stands and offers a retry (#212)', async ({ page }) => {
  await page.route(`**/v1/upload-requests/${uploadRequestId}/revoke`, (route) =>
    route.fulfill({ status: 503, json: problemOf(503, 'service_unavailable') }),
  );
  await page.goto(`/upload-requests/${uploadRequestId}`);
  await page.getByRole('button', { name: text().requests.revoke }).click();
  await page.getByRole('dialog').getByRole('button', { name: text().delivery.revokeConfirm }).click();
  await expect(page.getByRole('dialog')).toBeHidden();
  await expect(page.getByText(text().requests.revokeUnconfirmed)).toBeVisible();
  await expect(page.getByRole('button', { name: text().delivery.revokeRetry })).toBeVisible();
  await expectNoWcagViolations(page, 'upload request revocation unconfirmed');
});

test('upload request: the uploader\'s address bounced (#228)', async ({ page }) => {
  await page.route(`**/v1/upload-requests/${uploadRequestId}`, (route) =>
    route.fulfill({ status: 200, json: { ...openRequest, delivery_state: 'bounced' } }),
  );
  await page.goto(`/upload-requests/${uploadRequestId}`);
  await expect(page.getByText(text().requests.deliveryExplain.bounced)).toBeVisible();
  await expectNoWcagViolations(page, 'upload request with a bounced address');
});

test('transfer detail: the extend expiry dialog (#214)', async ({ page }) => {
  await page.route(`**/v1/transfers/${transferId}`, (route) => route.fulfill({ status: 200, json: extendableTransfer() }));
  await page.goto(`/transfers/${transferId}`);
  const extend = page.getByRole('button', { name: text().extend.button });
  await extend.focus();
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog', { name: text().extend.title });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel(text().extend.newExpiry)).toBeFocused();
  await expectNoWcagViolations(page, 'extend expiry dialog');
  await page.keyboard.press('Escape');
  await expect(extend).toBeFocused();
});

// ---- the uploader's link page (#212, #213) ----

const UPLOAD_LINK = '/u#test-only-token-aaaaaaaaaaaaaaaa';

test('uploader: the code step, in the link\'s language', async ({ page }) => {
  await answerLinks(page, { 'POST /v1/links/resolve': { status: 200, json: uploaderResolution(language()) } });
  await page.goto(UPLOAD_LINK);
  await expect(page).toHaveURL(/\/u$/);
  await expect(page.getByRole('heading', { level: 1, name: text().recipient.verifyTitle })).toBeFocused();
  await expect(page.getByText(text().uploader.verifyIntro)).toBeVisible();
  await expectNoWcagViolations(page, 'uploader code step');
});

test('uploader: the request and the files, each state in plain words', async ({ page }) => {
  await answerLinks(page, {
    'POST /v1/links/resolve': { status: 200, json: uploaderResolution(language(), 'verified') },
    'GET /v1/session': { status: 200, json: uploaderSession(language()) },
    'GET /v1/session/files': { status: 200, json: uploaderFiles },
  });
  await page.goto(UPLOAD_LINK);
  await expect(page.getByRole('heading', { level: 1, name: text().uploader.title })).toBeFocused();
  await expect(page.getByText(text().uploader.status.blocked)).toBeVisible();
  await expect(page.getByText(text().uploader.status.unscannable)).toBeVisible();
  await expect(page.getByText(text().uploader.resumeHint)).toBeVisible();
  await expectNoWcagViolations(page, 'uploader files');
});

test('uploader: an accepted unscannable file, then taking a file back, by keyboard (#229)', async ({ page }) => {
  const accepted = {
    id: '0190c0de-0000-7000-8000-0000000000c7',
    display_name: 'scan.tif',
    content_type: 'image/tiff',
    size: 3_145_728,
    state: 'unscannable' as const,
    warning: 'unscannable' as const,
  };
  const removable = uploaderFiles.items[0];
  if (!removable) throw new Error('the fixture lists files');
  await answerLinks(page, {
    'POST /v1/links/resolve': { status: 200, json: uploaderResolution(language(), 'verified') },
    'GET /v1/session': { status: 200, json: uploaderSession(language()) },
    'GET /v1/session/files': { status: 200, json: { items: [...uploaderFiles.items, accepted] } },
    [`DELETE /v1/session/files/${removable.id}`]: { status: 204 },
  });
  await page.goto(UPLOAD_LINK);
  await expect(page.getByRole('heading', { level: 1, name: text().uploader.title })).toBeFocused();
  await expect(page.getByText(text().uploader.status.accepted, { exact: true })).toBeVisible();
  await expect(page.getByText(text().uploader.acceptedHint)).toBeVisible();
  // A blocked file can't be taken back: it has no "Remove".
  await expect(page.getByRole('button', { name: fill(text().uploader.removeFile, { name: 'setup.exe' }) })).toHaveCount(0);

  const remove = page.getByRole('button', { name: fill(text().uploader.removeFile, { name: removable.display_name }), exact: true });
  await remove.focus();
  await page.keyboard.press('Enter');
  const keep = page.getByRole('button', { name: text().uploader.removeKeep, exact: true });
  await expect(keep).toBeFocused();
  await expect(page.getByRole('group', { name: fill(text().uploader.removeConfirm, { name: removable.display_name }) })).toBeVisible();
  await expectNoWcagViolations(page, 'uploader remove confirmation');
  await page.keyboard.press('Enter');
  await expect(remove).toBeFocused();

  await page.keyboard.press('Enter');
  await page.getByRole('button', { name: text().uploader.removeYes, exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: fill(text().uploader.removed, { name: removable.display_name }) })).toHaveCount(1);
  await expectNoWcagViolations(page, 'uploader file removed');
});

test('uploader: a revoked request says so', async ({ page }) => {
  await answerLinks(page, {
    'POST /v1/links/resolve': { status: 200, json: uploaderResolution(language(), 'verified') },
    'GET /v1/session': { status: 200, json: uploaderSession(language()) },
    'GET /v1/session/files': { status: 410, json: problemOf(410, 'link_revoked') },
  });
  await page.goto(UPLOAD_LINK);
  await expect(page.getByRole('heading', { level: 1, name: text().recipient.revokedTitle })).toBeFocused();
  await expect(page.getByText(text().uploader.revokedBody)).toBeVisible();
  await expectNoWcagViolations(page, 'uploader link revoked');
});

// ---- DLP (#218 to #220): every dialog and error state, by keyboard where it matters ----

/** A template's `{{name}}`s filled in, as i18next does. */
const fill = (template: string, values: Record<string, string | number>) =>
  template.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, name: string) => String(values[name]));

test('DLP settings: a domain added, the confirmation, then a conflict with another admin (#218)', async ({ page }) => {
  await page.route('**/v1/dlp/policy', (route) =>
    route.request().method() === 'PATCH'
      ? route.fulfill({ status: 409, json: problemOf(409, 'dlp_policy_conflict') })
      : route.fulfill({ status: 200, json: dlpPolicy }),
  );
  await page.goto('/admin/dlp');
  const t = text().dlpAdmin;
  await page.getByLabel(t.addDomain).fill('Supplier.example, not a domain');
  await page.getByRole('button', { name: t.add, exact: true }).click();
  await expect(page.getByText(fill(t.domainInvalid, { value: ['not', 'a', 'domain'].join(text().common.listSeparator) }))).toBeVisible();
  await expect(page.getByRole('button', { name: fill(t.removeDomain, { domain: 'supplier.example' }) })).toBeVisible();
  await expectNoWcagViolations(page, 'DLP settings, domain added');

  await page.getByRole('button', { name: text().common.save }).click();
  const dialog = page.getByRole('dialog', { name: t.confirmSettings });
  await expect(dialog.getByText(fill(t.change.trust, { domains: 'supplier.example' }))).toBeVisible();
  await expectNoWcagViolations(page, 'DLP settings confirmation');
  await dialog.getByRole('button', { name: text().common.save }).click();
  await expect(dialog.getByRole('button', { name: t.reload })).toBeVisible();
  await expectNoWcagViolations(page, 'DLP settings conflict');
});

test('DLP rules: turn off and delete confirmations, by keyboard (#218)', async ({ page }) => {
  await page.goto('/admin/dlp/rules');
  const t = text().dlpAdmin;
  const turnOff = page.getByRole('button', { name: fill(t.turnOffNamed, { name: 'My Numbers' }), exact: true });
  await turnOff.focus();
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog', { name: t.confirmTurnOff });
  await expect(dialog.getByText(fill(t.change.turnOff, { name: 'My Numbers' }))).toBeVisible();
  await expectNoWcagViolations(page, 'turn off rule dialog');
  await page.keyboard.press('Escape');
  await expect(turnOff).toBeFocused();

  await page.getByRole('button', { name: fill(t.deleteNamed, { name: 'My Numbers' }), exact: true }).click();
  await expect(page.getByRole('dialog', { name: t.confirmDeleteRule })).toBeVisible();
  await expectNoWcagViolations(page, 'delete rule dialog');
});

test('DLP rule form: what is missing, then the confirmation (#218)', async ({ page }) => {
  await page.goto('/admin/dlp/rules/new');
  const t = text().dlpAdmin;
  await page.getByRole('button', { name: t.addRule }).click();
  await expect(page.getByText(t.ruleProblem.name)).toBeVisible();
  await expect(page.getByText(t.ruleProblem.detectors)).toBeVisible();
  await expectNoWcagViolations(page, 'new rule, problems');

  await page.getByLabel(text().common.name, { exact: true }).fill('Project names');
  await page.getByRole('checkbox', { name: 'Project names' }).check();
  await page.getByRole('radio', { name: new RegExp(escapeRegExp(text().dlpAction.require_approval)) }).check();
  await page.getByRole('button', { name: t.addRule }).click();
  const dialog = page.getByRole('dialog', { name: t.confirmAddRule });
  await expect(dialog.getByText(fill(t.change.addRule, { name: 'Project names' }))).toBeVisible();
  await expectNoWcagViolations(page, 'new rule confirmation');
});

test('DLP keyword lists: a list a rule uses can\'t be deleted (#218)', async ({ page }) => {
  await page.route(`**/v1/dlp/detectors/${keywordListPath}`, (route) =>
    route.request().method() === 'DELETE'
      ? route.fulfill({ status: 409, json: problemOf(409, 'detector_in_use') })
      : route.fulfill({ status: 200, json: keywordList }),
  );
  await page.goto('/admin/dlp/keywords');
  const t = text().dlpAdmin;
  await page.getByRole('button', { name: fill(t.deleteNamed, { name: 'Project names' }) }).click();
  const dialog = page.getByRole('dialog', { name: t.confirmDeleteKeywordList });
  await expectNoWcagViolations(page, 'delete keyword list dialog');
  await dialog.getByRole('button', { name: text().common.delete }).click();
  await expect(dialog.getByText(text().problems.detector_in_use)).toBeVisible();
  await expectNoWcagViolations(page, 'keyword list in use');
});

test('DLP keyword list form: a term too long, then the confirmation (#218)', async ({ page }) => {
  await page.goto(`/admin/dlp/keywords/${keywordListPath}`);
  const t = text().dlpAdmin;
  const terms = page.getByLabel(t.terms, { exact: true });
  await expect(terms).toHaveValue('Bluebird\nKingfisher\n青い鳥');
  await terms.fill(`Bluebird\n${'x'.repeat(101)}`);
  await page.getByRole('button', { name: text().common.save }).click();
  await expect(terms).toHaveAttribute('aria-invalid', 'true');
  await expectNoWcagViolations(page, 'keyword list, term too long');
  await terms.fill('Bluebird\nRedbird');
  await page.getByRole('button', { name: text().common.save }).click();
  await expect(page.getByRole('dialog', { name: t.confirmEditKeywordList })).toBeVisible();
  await expectNoWcagViolations(page, 'keyword list confirmation');
});

test('transfer warned: the confirm dialog, by keyboard (#219)', async ({ page }) => {
  await page.goto(`/transfers/${warnedId}`);
  const t = text().dlp;
  await expect(page.getByText('My Numbers').first()).toBeVisible();
  const send = page.getByRole('button', { name: t.confirm.warning.button });
  await send.focus();
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog', { name: t.confirm.warning.title });
  await expect(dialog.getByLabel(t.justificationOptional)).toBeFocused();
  await expectNoWcagViolations(page, 'confirm dialog');
  await page.keyboard.press('Escape');
  await expect(send).toBeFocused();
});

test('transfer needing approval: the request dialog asks for a reason (#220)', async ({ page }) => {
  await page.goto(`/transfers/${approvalNeededId}`);
  const t = text().dlp;
  await page.getByRole('button', { name: t.confirm.approval.button }).click();
  const dialog = page.getByRole('dialog', { name: t.confirm.approval.title });
  await dialog.getByRole('button', { name: t.confirm.approval.action }).click();
  await expect(dialog.getByLabel(t.justificationRequired)).toHaveAccessibleDescription(new RegExp(escapeRegExp(t.justificationProblem.required)));
  await expectNoWcagViolations(page, 'request approval dialog, reason missing');
});

test('transfer held by a DLP rule: the remove and cancel dialogs (#219)', async ({ page }) => {
  await page.goto(`/transfers/${blockedId}`);
  const t = text().dlp;
  await page.getByRole('button', { name: fill(t.removeFileNamed, { name: 'staff-list.xlsx' }) }).click();
  await expect(page.getByRole('dialog', { name: t.removeTitle })).toBeVisible();
  await expectNoWcagViolations(page, 'remove file dialog');
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: text().sender.cancelTransfer }).click();
  await expect(page.getByRole('dialog', { name: t.cancelTitle })).toBeVisible();
  await expectNoWcagViolations(page, 'cancel transfer dialog');
});

test('approval request: approve with a sign-in too old, and reject without a comment (#220)', async ({ page }) => {
  await page.route(`**/v1/dlp/approval-requests/${queueRequestId}/approve`, (route) =>
    route.fulfill({ status: 401, json: problemOf(401, 'reauthentication_required') }),
  );
  await page.goto(`/approvals/${queueRequestId}`);
  const t = text().approvals;
  await page.getByRole('button', { name: t.approve.button, exact: true }).click();
  const approve = page.getByRole('dialog', { name: t.approve.title });
  await expect(approve.getByText(t.approve.stepUp)).toBeVisible();
  await expectNoWcagViolations(page, 'approve dialog');
  await approve.getByRole('button', { name: t.approve.action }).click();
  // "Confirm it's you" asks first (#232); cancelling it (Escape closes only it) leaves the approve dialog explaining.
  const stepUp = page.getByRole('dialog', { name: text().stepUp.title });
  await expect(stepUp.getByRole('button', { name: text().stepUp.signIn })).toBeVisible();
  await expectNoWcagViolations(page, 'step-up dialog');
  await page.keyboard.press('Escape');
  await expect(stepUp).toBeHidden();
  await expect(approve.getByRole('button', { name: text().admin.signInAgain })).toBeVisible();
  await expectNoWcagViolations(page, 'approve dialog, sign in again');
  await page.keyboard.press('Escape');

  await page.getByRole('button', { name: t.reject.button, exact: true }).click();
  const reject = page.getByRole('dialog', { name: t.reject.title });
  await reject.getByRole('button', { name: t.reject.action }).click();
  await expect(reject.getByLabel(t.commentRequired)).toHaveAccessibleDescription(new RegExp(escapeRegExp(t.commentProblem.required)));
  await expectNoWcagViolations(page, 'reject dialog, comment missing');
});

// ---- DLP-6 and DLP-7 (#221, #222): monitor mode, rules for received files, patterns, tests, blocks and reports ----

test('DLP settings: switching to monitor mode warns and names the change; a policy in monitor mode says so (#221)', async ({ page }) => {
  await page.goto('/admin/dlp');
  const t = text().dlpAdmin;
  await page.getByRole('radio', { name: new RegExp(escapeRegExp(t.modes.monitor)) }).check();
  await expect(page.getByText(t.monitorWarning)).toBeVisible();
  await expectNoWcagViolations(page, 'DLP settings, monitor chosen');
  await page.getByRole('button', { name: text().common.save, exact: true }).click();
  const dialog = page.getByRole('dialog', { name: t.confirmSettings });
  await expect(dialog.getByText(fill(t.change.mode, { from: t.modes.enforce, to: t.modes.monitor }))).toBeVisible();
  await expect(dialog.getByRole('button', { name: t.switchToMonitor })).toBeVisible();
  await expectNoWcagViolations(page, 'DLP settings, monitor confirmation');

  await page.route('**/v1/dlp/policy', (route) => route.fulfill({ status: 200, json: dlpPolicyMonitor }));
  await page.goto('/admin/dlp');
  await expect(page.getByText(fill(t.currentMode, { mode: t.modes.monitor }))).toBeVisible();
  await expect(page.getByText(t.monitorWarning)).toBeVisible();
  await expectNoWcagViolations(page, 'DLP settings in monitor mode');
});

test('DLP rule form: a rule for received files, then two approvers and the 24-hour window (#221)', async ({ page }) => {
  await page.goto('/admin/dlp/rules/new');
  const t = text().dlpAdmin;
  await page.getByRole('radio', { name: new RegExp(escapeRegExp(t.direction.received)) }).check();
  await expect(page.getByRole('group', { name: t.recipients })).toHaveCount(0);
  await expect(page.getByRole('radio', { name: new RegExp(escapeRegExp(text().dlpAction.warn)) })).toHaveCount(0);
  await expect(page.getByText(t.include24h)).toHaveCount(0);
  await expectNoWcagViolations(page, 'new rule for received files');

  await page.getByRole('radio', { name: new RegExp(escapeRegExp(t.direction.sent)) }).check();
  await page.getByRole('checkbox', { name: new RegExp(escapeRegExp(t.include24h)) }).check();
  await page.getByRole('radio', { name: new RegExp(escapeRegExp(text().dlpAction.require_approval)) }).check();
  await page.getByRole('checkbox', { name: new RegExp(escapeRegExp(t.twoApproversOption)) }).check();
  await expect(page.getByText(fill(t.twoApproversNeed_other, { count: 2 }))).toBeVisible();
  await expectNoWcagViolations(page, 'new rule with two approvers and 24 hours');
});

test('DLP pattern: its budget stops, a test on sample text, then a refusal on its field (#221)', async ({ page }) => {
  await page.route('**/v1/dlp/detector-tests', (route) => route.fulfill({ status: 200, json: detectorTestResult }));
  await page.route(`**/v1/dlp/detectors/${patternPath}`, (route) =>
    route.request().method() === 'PATCH'
      ? route.fulfill({
          status: 422,
          json: problemOf(422, 'validation_failed', { errors: [{ detail: 'The pattern matches the empty string.', pointer: '#/pattern' }] }),
        })
      : route.fulfill({ status: 200, json: patternDetector }),
  );
  await page.goto(`/admin/dlp/patterns/${patternPath}`);
  const t = text().dlpAdmin;
  await expect(page.getByText(t.budgetAdvice)).toBeVisible();

  const sample = page.getByLabel(t.test.text);
  await sample.fill('Invoice\nINV-000012 is due.');
  await page.getByRole('button', { name: t.test.run, exact: true }).click();
  await expect(page.getByRole('table', { name: t.test.resultsCaption })).toBeVisible();
  await expect(page.getByText('INV-••••12')).toBeVisible();
  await expectNoWcagViolations(page, 'pattern test results');

  const expression = page.getByLabel(t.pattern, { exact: true });
  await expression.fill('(INV)?');
  await page.getByRole('button', { name: text().common.save, exact: true }).click();
  await page.getByRole('dialog', { name: t.confirmEditPattern }).getByRole('button', { name: text().common.save }).click();
  await expect(expression).toHaveAttribute('aria-invalid', 'true');
  await expect(expression).toBeFocused();
  await expectNoWcagViolations(page, 'pattern refused on its field');
});

test('DLP keyword list: a test past the rate limit says when to try again (#221)', async ({ page }) => {
  await page.route('**/v1/dlp/detector-tests', (route) =>
    route.fulfill({ status: 429, headers: { 'Retry-After': '20' }, json: problemOf(429, 'rate_limited') }),
  );
  await page.goto(`/admin/dlp/keywords/${keywordListPath}`);
  const t = text().dlpAdmin.test;
  await page.getByLabel(t.text).fill('Bluebird ships on Friday.');
  await page.getByRole('button', { name: t.run, exact: true }).click();
  await expect(page.getByText(t.rateLimited, { exact: false })).toBeVisible();
  await expectNoWcagViolations(page, 'keyword list test, rate limited');
});

test('message findings on the transfer and on its approval request (#221)', async ({ page }) => {
  await page.goto(`/transfers/${warnedId}`);
  await expect(page.getByRole('heading', { name: text().dlp.message })).toBeVisible();
  await expectNoWcagViolations(page, 'transfer with message findings');
  await page.goto(`/approvals/${queueRequestId}`);
  await expect(page.getByText(text().dlp.messageFindings)).toBeVisible();
  await expectNoWcagViolations(page, 'approval request with message findings');
});

test('upload request: a file the data policy blocked can\'t be downloaded (#221)', async ({ page }) => {
  await page.goto(`/upload-requests/${uploadRequestId}`);
  await expect(page.getByText(text().requests.dlpBlocked)).toBeVisible();
  await expect(page.getByRole('button', { name: fill(text().requests.downloadFile, { name: 'customers.csv' }) })).toHaveCount(0);
  await expect(page.locator(`#blocked-${dlpBlockedFileId}`)).toBeVisible();
  await expectNoWcagViolations(page, 'received file blocked by the data policy');
});

test('uploader: a file not accepted, with no reason and no Remove (#221)', async ({ page }) => {
  await answerLinks(page, {
    'POST /v1/links/resolve': { status: 200, json: uploaderResolution(language(), 'verified') },
    'GET /v1/session': { status: 200, json: uploaderSession(language()) },
    'GET /v1/session/files': { status: 200, json: uploaderFiles },
  });
  await page.goto(UPLOAD_LINK);
  await expect(page.getByText(text().uploader.status.notAccepted, { exact: true })).toBeVisible();
  await expect(page.getByText(text().uploader.notAcceptedHint)).toBeVisible();
  await expect(page.getByRole('button', { name: fill(text().uploader.removeFile, { name: 'customers.csv' }) })).toHaveCount(0);
  await expectNoWcagViolations(page, 'uploader file not accepted');
});

test('DLP reports: the charts as tables, the decisions list, and the export link (#222)', async ({ page }) => {
  await page.goto('/admin/dlp/reports');
  const t = text().dlpReports;
  await expect(page.getByRole('heading', { name: t.overTime })).toBeVisible();
  for (const button of await page.getByRole('button', { name: t.tableView }).all()) await button.click();
  await expect(page.getByRole('table', { name: t.overTimeCaption })).toBeVisible();
  await expect(page.getByRole('table', { name: t.decisionsCaption })).toBeVisible();
  await expect(page.getByText(t.recordedOnly)).toBeVisible();
  await expectNoWcagViolations(page, 'DLP reports as tables');

  await page.getByLabel(t.from, { exact: true }).fill('2020-01-01');
  await page.getByRole('button', { name: t.apply, exact: true }).click();
  await expect(page.getByText(fill(t.rangeProblem.tooLong, { max: 92 }))).toBeVisible();
  await expectNoWcagViolations(page, 'DLP reports, range too long');

  await page.getByRole('link', { name: t.export }).click();
  await expect(page).toHaveURL(/\/admin\/audit\?action=dlp\.decided&from=/);
  await expect(page.locator('main').getByRole('heading', { level: 1, name: text().audit.title })).toBeVisible();
  await expectNoWcagViolations(page, 'audit log filtered to DLP decisions');
});

test('single sign-on: a domain the DNS doesn\'t prove yet, and the remove dialog (#231)', async ({ page }) => {
  await page.route(`**/v1/tenant/sso/domains/${ssoDomainPendingId}/verify`, (route) =>
    route.fulfill({ status: 422, json: problemOf(422, 'validation_failed') }),
  );
  await page.goto('/admin/sso');
  const t = text().sso.domains;
  await page.getByRole('button', { name: t.verifyDomain.replace('{{domain}}', 'example.co.jp') }).click();
  await expect(page.getByText(t.verifyProblem.unverified)).toBeVisible();
  await expectNoWcagViolations(page, 'single sign-on, domain unverified');
  await page.getByRole('button', { name: t.removeDomain.replace('{{domain}}', 'example.co.jp') }).click();
  await expect(page.getByRole('dialog', { name: t.removeTitle })).toBeVisible();
  await expectNoWcagViolations(page, 'single sign-on, remove domain dialog');
});
