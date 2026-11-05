import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { resources, type Language } from '../src/lib/i18n';

/**
 * axe on every page of the web app (NFR-22, #110), once per language project (playwright.config.ts). Any violation of
 * a WCAG 2.0, 2.1 or 2.2 A or AA rule fails the test, whatever axe's impact rating: NFR-22 asks for WCAG 2.2 AA, not
 * for "no serious ones". axe's best-practice rules, which no WCAG criterion requires, are printed to the console so
 * they show in the CI log, but don't fail. The pages show the mock data they hold today, and the only API call,
 * `GET /me`, gets a fake member here, so no backend is needed.
 */

// WCAG 2.0, 2.1 and 2.2, levels A and AA: what NFR-22 asks for.
const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

// `CurrentMember` in the API contract. The CSRF token only has the contract's shape; nothing checks it here.
const fakeAdmin = {
  user: { id: '00000000-0000-4000-8000-000000000001', email: 'admin@example.com' },
  tenant: { id: '00000000-0000-4000-8000-000000000002', name: 'Example Corp' },
  session: { effective_role: 'admin' },
  csrf_token: `k1.${'A'.repeat(43)}`,
};

async function mockApi(page: Page): Promise<void> {
  // Anything else the app asks the API for is a test bug: answer 404 rather than reach a real server.
  await page.route('**/v1/**', (route) => route.fulfill({ status: 404, json: { code: 'not_found' } }));
  await page.route('**/v1/me', (route) => route.fulfill({ status: 200, json: fakeAdmin }));
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
  ['transfer detail', '/transfers/t-1'],
  ['upload request list', '/upload-requests'],
  ['new upload request', '/upload-requests/new'],
  ['admin users', '/admin/users'],
  ['admin tenant policy', '/admin/policy'],
  ['admin audit log', '/admin/audit'],
  ['admin API keys', '/admin/api-keys'],
] as const;

for (const [name, path] of memberPages) {
  test(name, async ({ page }) => {
    await page.goto(path);
    await expect(page.locator('main').getByRole('heading', { level: 1 })).toBeVisible();
    await expectNoWcagViolations(page, name);
  });
}

// The link pages: verification first, then, after a (mock) code, the download or upload page.
for (const [name, path, content] of [
  ['recipient', '/t', 'download'],
  ['uploader', '/u', 'upload'],
] as const) {
  test(`${name} verification and ${content}`, async ({ page }) => {
    await page.goto(`${path}#fake-link-token`);
    const code = page.getByRole('textbox');
    await expect(code).toBeVisible();
    await expectNoWcagViolations(page, `${name} verification`);

    await code.fill('12345678');
    const verify = resources[language()].translation.recipient.verifyButton;
    await page.getByRole('button', { name: verify, exact: true }).click();
    await expect(code).toBeHidden();
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expectNoWcagViolations(page, `${name} ${content}`);
  });
}
