import { expect, type APIRequestContext, type Page } from '@playwright/test';

/**
 * Helpers for the browser flows against the local stack (playwright.e2e.config.ts). The seeded users and their
 * local-only, fake passwords are docs/local-development.md's, section 3; `make seed` writes them.
 */

const env = (globalThis as unknown as { process: { env: Record<string, string | undefined> } }).process.env;

export const USERS = {
  member: { email: env.E2E_MEMBER_EMAIL ?? 'dev.member@example.com', password: env.E2E_MEMBER_PASSWORD ?? 'local-only-member-password' },
  admin: { email: env.E2E_ADMIN_EMAIL ?? 'dev.admin@example.com', password: env.E2E_ADMIN_PASSWORD ?? 'local-only-admin-password' },
} as const;

export const MAILPIT = 'http://localhost:8025';
export const MIB = 1024 * 1024;

/** The Keycloak sign-in form, as a person fills it in. */
export async function fillKeycloak(page: Page, email: string, password: string): Promise<void> {
  await expect(page).toHaveURL(/^http:\/\/localhost:8180\/realms\/sft\//);
  await expect(page.locator('#password')).toBeVisible();
  // With a Keycloak session still open, `prompt=login` asks only for the password again, the user already named.
  if (await page.locator('#username').isVisible()) await page.locator('#username').fill(email);
  await page.locator('#password').fill(password);
  await page.locator('#kc-login').click();
}

/**
 * Signs in through the web app's sign-in page and Keycloak, starting from `path` (a deep link), and waits until the
 * app is back on that path with the member loaded (`GET /me`: their address in the header).
 */
export async function signIn(page: Page, who: keyof typeof USERS, path = '/'): Promise<void> {
  const { email, password } = USERS[who];
  await page.goto(path);
  await expect(page).toHaveURL(/\/sign-in$/);
  await page.getByRole('button', { name: 'Sign in with password or passkey' }).click();
  await fillKeycloak(page, email, password);
  await expect(page).toHaveURL(new RegExp(`^http://localhost:3000${path.replace(/[/?]/g, (c) => `\\${c}`)}$`));
  await expect(page.getByRole('banner').getByText(email)).toBeVisible();
}

const WORDS = ['report', 'review', 'quarterly', 'budget', 'meeting', 'draft', 'final', 'schedule', 'project', 'summary'];

/** `size` bytes of plain words that no detector matches, different on each run. */
export function wordsText(size: number, seed = Date.now()): string {
  let state = seed % 2147483647 || 1;
  const next = () => (state = (state * 48271) % 2147483647);
  const lines: string[] = [];
  let total = 0;
  while (total < size) {
    const line = `${Array.from({ length: 12 }, () => WORDS[next() % WORDS.length]).join(' ')}\n`;
    lines.push(line);
    total += line.length;
  }
  return lines.join('').slice(0, size);
}

/** A synthetic My Number with a valid check digit (the DLP corpus's rule, services/api/tests/dlp_corpus). */
export function myNumber(): string {
  const base = Array.from({ length: 11 }, () => Math.floor(Math.random() * 10)).join('');
  const weights = Array.from({ length: 11 }, (_, i) => (i + 1 <= 6 ? i + 2 : i - 4));
  const sum = weights.reduce((total, weight, i) => total + Number(base[base.length - 1 - i]) * weight, 0);
  const remainder = sum % 11;
  return base + String(remainder <= 1 ? 0 : 11 - remainder);
}

/** The EICAR test file, decoded at run time so no scanner on a laptop or in CI quarantines the repository. */
export function eicar(): string {
  return atob('WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=');
}

/** A file payload for `setInputFiles`. Node's Buffer, whose types this project doesn't load. */
export function payload(name: string, text: string) {
  const buffer = (globalThis as unknown as { Buffer: { from(text: string): never } }).Buffer.from(text);
  return { name, mimeType: 'text/plain', buffer };
}

export function unique(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
}

interface MailpitMessage {
  ID: string;
  Subject: string;
  To: { Address: string }[];
}

/** The newest message to `address` in Mailpit, waiting for it to arrive. */
export async function mailTo(request: APIRequestContext, address: string): Promise<{ subject: string; text: string }> {
  let found: MailpitMessage | undefined;
  await expect
    .poll(
      async () => {
        const response = await request.get(`${MAILPIT}/api/v1/search`, { params: { query: `to:"${address}"` } });
        const body = (await response.json()) as { messages: MailpitMessage[] };
        found = body.messages[0];
        return found?.ID ?? null;
      },
      { timeout: 60_000 },
    )
    .not.toBeNull();
  const message = await request.get(`${MAILPIT}/api/v1/message/${(found as MailpitMessage).ID}`);
  const body = (await message.json()) as { Subject: string; Text: string };
  return { subject: body.Subject, text: body.Text };
}
