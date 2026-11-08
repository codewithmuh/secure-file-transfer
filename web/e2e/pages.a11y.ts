import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { resources, type Language } from '../src/lib/i18n';
import {
  draft,
  draftId,
  fakeAdmin,
  inspection,
  myNumberFileId,
  policy,
  transfer,
  transferId,
  transferPage,
  userPage,
} from './apiFixtures';

/**
 * axe on every page of the web app (NFR-22, #110), once per language project (playwright.config.ts). Any violation of
 * a WCAG 2.0, 2.1 or 2.2 A or AA rule fails the test, whatever axe's impact rating: NFR-22 asks for WCAG 2.2 AA, not
 * for "no serious ones". axe's best-practice rules, which no WCAG criterion requires, are printed to the console so
 * they show in the CI log, but don't fail. The API is answered from contract-typed fixtures (apiFixtures.ts), so the
 * live pages, their dialogs and menus are checked with real shapes and no backend is needed.
 */

// WCAG 2.0, 2.1 and 2.2, levels A and AA: what NFR-22 asks for.
const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

/** What the API answers, by path: contract-typed fixtures (apiFixtures.ts), so the live pages show real shapes. */
const answers: Record<string, unknown> = {
  '/v1/me': fakeAdmin,
  '/v1/tenant/policy': policy,
  '/v1/transfers': transferPage,
  [`/v1/transfers/${transferId}`]: transfer,
  [`/v1/transfers/${draftId}`]: draft,
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

type Violation = Awaited<ReturnType<AxeBuilder['analyze']>>['violations'][number];

const describe = (violation: Violation) =>
  `${violation.impact ?? 'unrated'} ${violation.id}: ${violation.help} (${violation.helpUrl})\n` +
  violation.nodes.map((node) => `    ${node.target.join(' ')}: ${node.failureSummary ?? ''}`).join('\n');

async function expectNoWcagViolations(page: Page, name: string): Promise<void> {
  const lang = language();
  // The page is in the language under test, so the Japanese run doesn't check English pages by mistake.
  await expect(page.locator('html')).toHaveAttribute('lang', lang);

  const results = await new AxeBuilder({ page }).withTags([...WCAG_TAGS, 'best-practice']).analyze();
  await test.info().attach(`axe-${name}.json`, { body: JSON.stringify(results.violations, null, 2), contentType: 'application/json' });

  const isWcag = (violation: Violation) => violation.tags.some((tag) => WCAG_TAGS.includes(tag));
  const bestPractice = results.violations.filter((violation) => !isWcag(violation));
  if (bestPractice.length > 0) {
    // The list reporter prints a test's console output, so these show in CI without failing it.
    console.log(`axe best-practice findings on ${name} (${lang}):\n${bestPractice.map(describe).join('\n')}`);
  }
  const failing = results.violations.filter(isWcag);
  expect(failing.map(describe), `WCAG A/AA axe violations on ${name} (${lang})`).toEqual([]);
}

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

// The recipient's link page: verification first, then, after a (mock) code, the download page. #198 makes it live.
test('recipient verification and download', async ({ page }) => {
  await page.goto('/t#fake-link-token');
  const code = page.getByRole('textbox');
  await expect(code).toBeVisible();
  await expectNoWcagViolations(page, 'recipient verification');

  await code.fill('12345678');
  await page.getByRole('button', { name: text().recipient.verifyButton, exact: true }).click();
  await expect(code).toBeHidden();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await expectNoWcagViolations(page, 'recipient download');
});

// The uploader's link page is M5's: NotAvailableYet in the public layout (#195).
test('uploader link (not available yet)', async ({ page }) => {
  await page.goto('/u#fake-link-token');
  await expect(page.getByRole('heading', { level: 1, name: text().notAvailable.title })).toBeVisible();
  await expectNoWcagViolations(page, 'uploader link');
});
