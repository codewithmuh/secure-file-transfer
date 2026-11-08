import { expect, type APIRequestContext, type Page, type Route } from '@playwright/test';
import { resources, type Language } from '../../src/lib/i18n';

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

/** `value` as a regular expression that matches it literally, for names built from addresses and messages. */
export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

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
 * app is back on that path with the member loaded (`GET /me`: their address in the header). `lang` is the page's.
 */
export async function signIn(page: Page, who: keyof typeof USERS, path = '/', lang: Language = 'en'): Promise<void> {
  const { email, password } = USERS[who];
  await page.goto(path);
  await expect(page).toHaveURL(/\/sign-in$/);
  await page.getByRole('button', { name: resources[lang].translation.auth.signInWithPassword }).click();
  await fillKeycloak(page, email, password);
  await expect(page).toHaveURL(new RegExp(`^http://localhost:3000${escapeRegExp(path)}$`));
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

/** Every part PUT to the S3 stand-in, by object and part number: how many tries, and how many landed. */
export function watchParts(
  page: Page,
  decide: (part: string, attempt: number, route: Route) => Promise<boolean> = async () => false,
) {
  const tries = new Map<string, number>();
  const landed = new Map<string, number>();
  void page.route('http://localhost:9090/**', async (route) => {
    const request = route.request();
    if (request.method() !== 'PUT') return route.continue();
    const url = new URL(request.url());
    const part = `${url.pathname}#${url.searchParams.get('partNumber')}`;
    const attempt = (tries.get(part) ?? 0) + 1;
    tries.set(part, attempt);
    if (await decide(part, attempt, route)) return;
    const response = await route.fetch();
    if (response.ok()) landed.set(part, (landed.get(part) ?? 0) + 1);
    await route.fulfill({ response });
  });
  return { tries, landed };
}

/** Every message to `address` in Mailpit, newest first, with its text. */
export async function messagesTo(request: APIRequestContext, address: string): Promise<{ subject: string; text: string }[]> {
  const response = await request.get(`${MAILPIT}/api/v1/search`, { params: { query: `to:"${address}"`, limit: 50 } });
  const found = ((await response.json()) as { messages: MailpitMessage[] | null }).messages ?? [];
  return Promise.all(
    found.map(async (message) => {
      const body = (await (await request.get(`${MAILPIT}/api/v1/message/${message.ID}`)).json()) as { Subject: string; Text: string };
      return { subject: body.Subject, text: body.Text };
    }),
  );
}

const LINK_URL = /(http:\/\/localhost:3000\/t#[A-Za-z0-9_-]{22,128})/;

/** The newest link email to a recipient (`transfer_link`): its subject and the link, waiting for it to arrive. */
export async function linkEmail(
  request: APIRequestContext,
  address: string,
  { except }: { except?: string } = {},
): Promise<{ subject: string; url: string }> {
  let found: { subject: string; url: string } | undefined;
  await expect
    .poll(
      async () => {
        for (const message of await messagesTo(request, address)) {
          const url = LINK_URL.exec(message.text)?.[1];
          if (url && url !== except) {
            found = { subject: message.subject, url };
            return true;
          }
        }
        return false;
      },
      { timeout: 120_000, message: `a link email to ${address}` },
    )
    .toBe(true);
  return found as { subject: string; url: string };
}

/** Codes emailed to `address` (the verification emails, not the link's), newest first. */
export async function codesTo(request: APIRequestContext, address: string): Promise<string[]> {
  const codes: string[] = [];
  for (const message of await messagesTo(request, address)) {
    if (LINK_URL.test(message.text)) continue;
    const code = /(?<![0-9])([0-9]{6,10})(?![0-9])/.exec(message.text)?.[1];
    if (code) codes.push(code);
  }
  return codes;
}

/** The code that arrives after the `seen` codes already in the inbox. */
export async function newCode(request: APIRequestContext, address: string, seen: number): Promise<string> {
  let codes: string[] = [];
  await expect
    .poll(async () => (codes = await codesTo(request, address)).length, { timeout: 60_000, message: `a code email to ${address}` })
    .toBeGreaterThan(seen);
  return codes[0] as string;
}

interface NodeFs {
  writeFileSync(path: string, data: string): void;
  renameSync(from: string, to: string): void;
  existsSync(path: string): boolean;
  readFileSync(path: string, encoding: 'utf8'): string;
  readFileSync(path: string): Uint8Array;
}

/** Node's `fs`, which this project has no types for (it loads none of Node's). */
const fs = () =>
  (globalThis as unknown as { process: { getBuiltinModule(name: string): unknown } }).process.getBuiltinModule('node:fs') as NodeFs;

/**
 * Runs a lifecycle job (#181) with the clock's test hook moved `offsetSeconds` on (#182), as `make jobs` does. The
 * Playwright container has no Docker, so it asks `local/e2e-jobs.sh`, which `make web-e2e` runs on the host: a request
 * file in `E2E_JOBS_DIR`, answered with a `.done` or `.failed` file holding the job's output.
 */
export async function runJob(job: 'expiry' | 'deletion', offsetSeconds: number): Promise<void> {
  const dir = env.E2E_JOBS_DIR;
  if (!dir) throw new Error('E2E_JOBS_DIR is not set: run the browser journey with make web-e2e');
  const id = unique(job);
  const files = fs();
  files.writeFileSync(`${dir}/${id}.tmp`, `${job} ${offsetSeconds}\n`);
  files.renameSync(`${dir}/${id}.tmp`, `${dir}/${id}.request`);
  await expect
    .poll(() => files.existsSync(`${dir}/${id}.done`) || files.existsSync(`${dir}/${id}.failed`), {
      timeout: 300_000,
      intervals: [1000],
      message: `the ${job} job`,
    })
    .toBe(true);
  if (files.existsSync(`${dir}/${id}.failed`)) {
    throw new Error(`the ${job} job failed:\n${files.readFileSync(`${dir}/${id}.failed`, 'utf8').slice(-2000)}`);
  }
}

/** A file's bytes, such as a download Playwright saved. */
export function readBytes(path: string): Uint8Array {
  return fs().readFileSync(path);
}

/** SHA-256 of some bytes, as hex. */
export async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** The transfer's state on its detail page: the badge under "Status", not "Sent" as the label of the sent time. */
export function transferStatus(page: Page, state: keyof (typeof resources)['en']['translation']['transferState'], lang: Language = 'en') {
  const label = resources[lang].translation.transferState[state];
  return page.locator('dd').filter({ hasText: new RegExp(`^${escapeRegExp(label)}$`) });
}

/**
 * Waits on a transfer's page until it is sent, confirming a DLP warning on the way (#219): the default policy warns
 * about My Numbers and about a recipient domain the tenant hasn't sent to in 365 days, so a first send to a domain
 * waits for the sender's confirmation.
 */
export async function sendPastWarning(page: Page, lang: Language = 'en', justification?: string): Promise<void> {
  const t = resources[lang].translation;
  const sent = transferStatus(page, 'sent', lang);
  const waiting = transferStatus(page, 'awaiting_confirmation', lang);
  await expect(sent.or(waiting)).toBeVisible({ timeout: 180_000 });
  if (await waiting.isVisible()) {
    await page.getByRole('button', { name: t.dlp.confirm.warning.button }).click();
    const dialog = page.getByRole('dialog', { name: t.dlp.confirm.warning.title });
    if (justification) await dialog.getByLabel(t.dlp.justificationOptional).fill(justification);
    await dialog.getByRole('button', { name: t.dlp.confirm.warning.action, exact: true }).click();
    await expect(dialog).toBeHidden();
  }
  await expect(sent).toBeVisible({ timeout: 60_000 });
}
