import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * The one axe check (NFR-22, #110, #200), shared by the backend-free checks (pages.a11y.ts) and the browser journey
 * against the stack (journey.e2e.ts), so live pages, their dialogs and the link states are scanned the same way. Any
 * violation of a WCAG 2.0, 2.1 or 2.2 A or AA rule fails, whatever axe's impact rating: NFR-22 asks for WCAG 2.2 AA,
 * not for "no serious ones". axe's best-practice rules, which no WCAG criterion requires, are printed to the console
 * so they show in the CI log, but don't fail. Each scan's findings are attached to the test's report.
 */

// WCAG 2.0, 2.1 and 2.2, levels A and AA: what NFR-22 asks for.
export const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

type Violation = Awaited<ReturnType<AxeBuilder['analyze']>>['violations'][number];

const describe = (violation: Violation) =>
  `${violation.impact ?? 'unrated'} ${violation.id}: ${violation.help} (${violation.helpUrl})\n` +
  violation.nodes.map((node) => `    ${node.target.join(' ')}: ${node.failureSummary ?? ''}`).join('\n');

/** Fails on any WCAG A/AA violation on the page as it is now; `lang` is the language the page must be in. */
export async function checkAxe(page: Page, name: string, lang: string): Promise<void> {
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
