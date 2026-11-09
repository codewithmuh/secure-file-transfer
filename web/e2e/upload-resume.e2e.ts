import { expect, test, type Page, type Request } from '@playwright/test';
import { MIB, signIn, unique } from './support/stack';

/**
 * NFR-3 (#251): a large file uploads over a throttled link, the connection drops halfway, comes back, and the upload
 * finishes without sending a completed part again, against `make up` and `make seed`.
 *
 * The network is Chromium's own emulation through the DevTools protocol (`Network.emulateNetworkConditions`): a fixed
 * upload and download rate for the page, then `offline` for the outage, which fails every request in flight and every
 * new one, as a dropped link does. Parts are watched passively (`request`, `requestfinished`, `requestfailed`), never
 * routed: a routed request is fetched by Playwright, outside the browser's network, so the throttle wouldn't apply.
 *
 * Opt-in (E2E_UPLOAD_RESUME=1), not part of CI's e2e run until #267 makes it reliable there: its 40 MiB of words
 * held the local stack's one small-pool scan worker for minutes, which starved the specs running beside it, and in CI
 * the outage cut no part in flight. Scaled down by default: 40 MiB (8 parts of 5 MiB) at 40 Mbit/s with a 5-second
 * outage. The full measure, a 5 GB file at 100 Mbit/s, uses the same spec (docs/operations/performance.md):
 *
 *   E2E_UPLOAD_RESUME=1 E2E_ARGS='e2e/upload-resume.e2e.ts' E2E_UPLOAD_MIB=4769 E2E_UPLOAD_MBITS=100 make web-e2e
 *
 * Time: the upload must finish within NFR-3's line rate plus 10 %, plus the outage and the engine's retry wait after it
 * (at most 8 s, then a fresh `listUploadedParts`), which the allowance below names.
 */

const env = (globalThis as unknown as { process: { env: Record<string, string | undefined> } }).process.env;
const SIZE = Number(env.E2E_UPLOAD_MIB ?? 40) * MIB;
const MBITS = Number(env.E2E_UPLOAD_MBITS ?? 40);
const OUTAGE_MS = Number(env.E2E_UPLOAD_OUTAGE_SECONDS ?? 5) * 1000;
const RETRY_ALLOWANCE_MS = 20_000;
const BYTES_PER_SECOND = (MBITS * 1_000_000) / 8;
const LINE_RATE_MS = (SIZE / BYTES_PER_SECOND) * 1000;

interface NodeFs {
  openSync(path: string, flags: string): number;
  writeSync(fd: number, data: string): number;
  closeSync(fd: number): void;
  rmSync(path: string, options: { force: boolean }): void;
}

const node = (name: string) =>
  (globalThis as unknown as { process: { getBuiltinModule(name: string): unknown } }).process.getBuiltinModule(name);

const WORDS = ['report', 'review', 'quarterly', 'budget', 'meeting', 'draft', 'final', 'schedule', 'project', 'summary'];

/** A file of plain words on disk, `size` bytes: setInputFiles takes a buffer only up to 50 MB, a path at any size. */
function wordsFile(size: number): string {
  const fs = node('node:fs') as NodeFs;
  const { tmpdir } = node('node:os') as { tmpdir(): string };
  const path = `${tmpdir()}/${unique('nfr3')}.txt`;
  let block = '';
  for (let i = 0; block.length < MIB; i += 1) block += `${WORDS[(i * 7) % WORDS.length]} ${i % 97}\n`;
  block = block.slice(0, MIB);
  const fd = fs.openSync(path, 'w');
  try {
    for (let written = 0; written < size; written += MIB) fs.writeSync(fd, block.slice(0, Math.min(MIB, size - written)));
  } finally {
    fs.closeSync(fd);
  }
  return path;
}

/** Every part PUT to the S3 stand-in, by part number: how many were sent, how many landed, and when. */
function watchPartPuts(page: Page) {
  const sent = new Map<number, number>();
  const landed = new Map<number, number>();
  const landedAt = new Map<number, number>();
  let failed = 0;
  let firstPut = 0;
  const partOf = (request: Request) => {
    if (request.method() !== 'PUT' || !request.url().startsWith('http://localhost:9090/')) return null;
    const n = Number(new URL(request.url()).searchParams.get('partNumber'));
    return Number.isInteger(n) && n > 0 ? n : null;
  };
  page.on('request', (request) => {
    const n = partOf(request);
    if (n === null) return;
    firstPut ||= Date.now();
    sent.set(n, (sent.get(n) ?? 0) + 1);
  });
  page.on('requestfinished', async (request) => {
    const n = partOf(request);
    if (n === null) return;
    if ((await request.response())?.status() === 200) {
      landed.set(n, (landed.get(n) ?? 0) + 1);
      if (!landedAt.has(n)) landedAt.set(n, Date.now());
    }
  });
  page.on('requestfailed', (request) => {
    if (partOf(request) !== null) failed += 1;
  });
  return { sent, landed, landedAt, failed: () => failed, firstPut: () => firstPut };
}

test.skip(env.E2E_UPLOAD_RESUME !== '1', 'opt-in: E2E_UPLOAD_RESUME=1 (#267)');

test('a throttled upload survives a dropped connection without sending a completed part again', async ({ page }) => {
  const parts = Math.ceil(SIZE / (5 * MIB));
  test.setTimeout(Math.round(LINE_RATE_MS * 1.5 + OUTAGE_MS + 240_000));
  const path = wordsFile(SIZE);
  try {
    await signIn(page, 'member', '/transfers/new');
    await page.getByLabel("Recipient's email address").fill(`${unique('nfr3')}@partner.example`);
    await page.getByRole('button', { name: 'Add recipient' }).click();
    await page.getByTestId('transfer-files').setInputFiles(path);

    const cdp = await page.context().newCDPSession(page);
    await cdp.send('Network.enable');
    const link = (offline: boolean) =>
      cdp.send('Network.emulateNetworkConditions', {
        offline,
        latency: 20,
        downloadThroughput: BYTES_PER_SECOND,
        uploadThroughput: BYTES_PER_SECOND,
      });
    await link(false);

    const puts = watchPartPuts(page);
    const completed = page.waitForResponse(
      (r) => /\/v1\/files\/[0-9a-f-]+\/complete$/.test(r.url()) && r.request().method() === 'POST',
      { timeout: Math.round(LINE_RATE_MS * 1.5 + OUTAGE_MS + 120_000) },
    );
    await page.getByRole('button', { name: 'Send transfer' }).click();

    // Halfway: half the parts have landed. Then the link drops, and comes back after the outage.
    await expect
      .poll(() => puts.landed.size, { timeout: Math.round(LINE_RATE_MS * 2 + 60_000), intervals: [250] })
      .toBeGreaterThanOrEqual(Math.max(1, Math.floor(parts / 2)));
    await link(true);
    const cutAt = Date.now();
    const landedBeforeCut = new Set(puts.landed.keys());
    await page.waitForTimeout(OUTAGE_MS);
    await link(false);

    expect((await completed).status(), 'completeUpload').toBe(200);
    const elapsed = Date.now() - puts.firstPut();
    await expect(page).toHaveURL(/\/transfers\/[0-9a-f-]{36}$/, { timeout: 60_000 });

    // The outage cut something in flight, or the test proved nothing.
    expect(puts.failed(), 'parts cut by the outage').toBeGreaterThan(0);
    expect(landedBeforeCut.size).toBeLessThan(parts);
    // Every part was sent and none landed twice (completeUpload's 200 says S3 holds them all: a part whose answer the
    // cut lost is found by `listUploadedParts`, not sent again), and no part that had landed before the cut was sent
    // again.
    expect([...puts.sent.keys()].sort((a, b) => a - b)).toEqual(Array.from({ length: parts }, (_, i) => i + 1));
    for (const [n, count] of puts.landed) expect(count, `part ${n} landed once`).toBe(1);
    for (const n of landedBeforeCut) expect(puts.sent.get(n), `part ${n}, landed before the cut, sent once`).toBe(1);
    for (const [n, at] of puts.landedAt) if (at < cutAt) expect(landedBeforeCut.has(n)).toBe(true);

    const budget = LINE_RATE_MS * 1.1 + OUTAGE_MS + RETRY_ALLOWANCE_MS;
    test.info().annotations.push({
      type: 'NFR-3',
      description: `${(SIZE / MIB).toFixed(0)} MiB at ${MBITS} Mbit/s: ${(elapsed / 1000).toFixed(1)} s with a ${OUTAGE_MS / 1000} s outage (line rate ${(LINE_RATE_MS / 1000).toFixed(1)} s, budget ${(budget / 1000).toFixed(1)} s)`,
    });
    expect(elapsed, 'line rate + 10 %, the outage and one retry wait').toBeLessThanOrEqual(budget);
  } finally {
    (node('node:fs') as NodeFs).rmSync(path, { force: true });
  }
});
