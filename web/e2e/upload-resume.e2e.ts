import { expect, test, type Request, type Route } from '@playwright/test';
import { MIB, signIn, unique } from './support/stack';

/**
 * NFR-3 (#251, #267): a large file uploads over a throttled link, the connection drops halfway, comes back, and the
 * upload finishes without sending a completed part again, against `make up` and `make seed`.
 *
 * **The link is the test's own** (#267). Chromium's network emulation throttled nothing on the part PUTs in CI, so
 * every part had landed before its `offline` cut, and the cut proved nothing. Here every request of the page goes
 * through `page.route`, and the part PUTs to the S3 stand-in go on through a small proxy in this file
 * (`ThrottledLink`): it sends each body to S3 at the line rate, shared by all parts in flight, as one link is, and
 * times each part. The outage fails every request of the page, and the proxy destroys each part in flight half sent,
 * so S3 never assembles it and the browser sees the connection drop. A part whose answer the cut lost had landed: the
 * upload engine finds it with `listUploadedParts` and doesn't send it again.
 *
 * **Cheap to scan** (#267). The file is bytes, not words: a PNG signature, which the DLP inspector names unsupported
 * without decoding (`sft.dlp.extract._sniff`), then pseudo-random bytes. 40 MiB of words held the stack's one
 * small-pool scan worker for 214 s and starved the specs beside it; this takes ClamAV and the inspector seconds.
 *
 * Scaled down by default: 40 MiB (8 parts of 5 MiB) at 40 Mbit/s with a 5-second outage. The full measure, a 5 GB file
 * at 100 Mbit/s, uses the same spec (docs/operations/performance.md):
 *
 *   E2E_ARGS='e2e/upload-resume.e2e.ts' E2E_UPLOAD_MIB=4769 E2E_UPLOAD_MBITS=100 make web-e2e
 *
 * Time: the upload must finish within NFR-3's line rate plus 10 %, plus the outage and the engine's retry wait after it
 * (at most 8 s, then a fresh `listUploadedParts`) and the bytes the cut threw away, which the allowance below names.
 */

const env = (globalThis as unknown as { process: { env: Record<string, string | undefined> } }).process.env;
const SIZE = Number(env.E2E_UPLOAD_MIB ?? 40) * MIB;
const MBITS = Number(env.E2E_UPLOAD_MBITS ?? 40);
const OUTAGE_MS = Number(env.E2E_UPLOAD_OUTAGE_SECONDS ?? 5) * 1000;
const RETRY_ALLOWANCE_MS = 20_000;
const BYTES_PER_SECOND = (MBITS * 1_000_000) / 8;
const LINE_RATE_MS = (SIZE / BYTES_PER_SECOND) * 1000;
/** What the proxy writes at once: about 25 ms of the link at the default rate. */
const SLICE = 128 * 1024;

interface NodeFs {
  openSync(path: string, flags: string): number;
  writeSync(fd: number, data: Uint8Array): number;
  closeSync(fd: number): void;
  rmSync(path: string, options: { force: boolean }): void;
}

interface ClientRequest {
  write(chunk: Uint8Array): boolean;
  end(): void;
  destroy(error?: Error): void;
  once(event: 'drain' | 'error', listener: (error?: Error) => void): void;
  on(event: 'error', listener: (error: Error) => void): void;
}

interface IncomingMessage {
  statusCode?: number;
  headers: Record<string, string | string[] | undefined>;
  on(event: 'data', listener: (chunk: Uint8Array) => void): void;
  on(event: 'end' | 'error', listener: (error?: Error) => void): void;
}

interface NodeHttp {
  request(
    options: { host: string; port: number; path: string; method: string; headers: Record<string, string> },
    answer: (response: IncomingMessage) => void,
  ): ClientRequest;
}

const node = (name: string) =>
  (globalThis as unknown as { process: { getBuiltinModule(name: string): unknown } }).process.getBuiltinModule(name);

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * The file on disk, `size` bytes: the PNG signature, then a megabyte of pseudo-random bytes repeated. setInputFiles
 * takes a buffer only up to 50 MB, a path at any size.
 */
function binaryFile(size: number): string {
  const fs = node('node:fs') as NodeFs;
  const { tmpdir } = node('node:os') as { tmpdir(): string };
  const path = `${tmpdir()}/${unique('nfr3')}.bin`;
  const block = new Uint8Array(MIB);
  let state = 2463534242;
  for (let i = 0; i < block.length; i += 1) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    block[i] = state & 0xff;
  }
  const fd = fs.openSync(path, 'w');
  try {
    for (let written = 0; written < size; written += MIB) {
      const chunk = block.subarray(0, Math.min(MIB, size - written));
      if (written === 0) chunk.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
      fs.writeSync(fd, chunk);
    }
  } finally {
    fs.closeSync(fd);
  }
  return path;
}

interface PartTry {
  part: number;
  bytes: number;
  started: number;
  ended?: number;
  /** Every byte went to S3. A try cut after that may still have landed: its answer was lost. */
  sentAll?: boolean;
  outcome?: 'landed' | 'cut' | 'unanswered' | 'refused';
}

/** The test's link: one line rate for every part PUT, an outage on demand, and a record of every part's try. */
class ThrottledLink {
  readonly tries: PartTry[] = [];
  private next = 0;
  private down = false;
  private readonly inFlight = new Set<() => void>();

  constructor(private readonly bytesPerSecond: number) {}

  /** Waits until the link has carried `bytes` more, at its rate, after whatever is queued ahead. */
  private async carry(bytes: number): Promise<void> {
    const now = Date.now();
    this.next = Math.max(this.next, now) + (bytes / this.bytesPerSecond) * 1000;
    await sleep(this.next - now);
  }

  /** Drops the connection: every request fails until `restore`, and every part in flight is cut where it is. */
  cut(): void {
    this.down = true;
    for (const destroy of this.inFlight) destroy();
    this.inFlight.clear();
  }

  restore(): void {
    this.down = false;
    this.next = Date.now();
  }

  /** The route handler for every request of the page. */
  async handle(route: Route): Promise<void> {
    if (this.down) return route.abort('internetdisconnected');
    const request = route.request();
    const part = partOf(request);
    if (part === null) return route.continue();
    const body = request.postDataBuffer();
    if (!body) throw new Error(`part ${part} has no body`);
    const attempt: PartTry = { part, bytes: body.length, started: Date.now() };
    this.tries.push(attempt);
    try {
      const answer = await this.forward(request, new Uint8Array(body), attempt);
      attempt.ended = Date.now();
      attempt.outcome = answer.status === 200 ? 'landed' : 'refused';
      // The answer is lost if the link dropped while it came back.
      if (this.down) return route.abort('internetdisconnected');
      await route.fulfill({ status: answer.status, headers: answer.headers, body: answer.body });
    } catch {
      attempt.ended = Date.now();
      attempt.outcome = attempt.sentAll ? 'unanswered' : 'cut';
      await route.abort('internetdisconnected');
    }
  }

  /** Sends the part to S3 at the link's rate, as the browser would, and reads S3's answer. */
  private forward(
    request: Request,
    body: Uint8Array,
    attempt: PartTry,
  ): Promise<{ status: number; headers: Record<string, string>; body: Uint8Array }> {
    const http = node('node:http') as NodeHttp;
    const url = new URL(request.url());
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(request.headers())) {
      if (!name.startsWith(':') && !['connection', 'content-length', 'host', 'transfer-encoding'].includes(name)) headers[name] = value;
    }
    headers.host = url.host;
    headers['content-length'] = String(body.length);
    return new Promise((resolve, reject) => {
      let cut = false;
      const out = http.request(
        { host: url.hostname, port: Number(url.port), path: `${url.pathname}${url.search}`, method: 'PUT', headers },
        (response) => {
          const chunks: Uint8Array[] = [];
          response.on('data', (chunk) => chunks.push(chunk));
          response.on('error', (error) => reject(error ?? new Error('S3 answer failed')));
          response.on('end', () => {
            const answerHeaders: Record<string, string> = {};
            for (const [name, value] of Object.entries(response.headers)) {
              if (value !== undefined) answerHeaders[name] = Array.isArray(value) ? value.join(', ') : value;
            }
            const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
            const joined = new Uint8Array(length);
            let at = 0;
            for (const chunk of chunks) {
              joined.set(chunk, at);
              at += chunk.length;
            }
            resolve({ status: response.statusCode ?? 0, headers: answerHeaders, body: joined });
          });
        },
      );
      out.on('error', (error) => reject(error));
      const destroy = () => {
        cut = true;
        out.destroy(new Error('the link dropped'));
        reject(new Error(`part ${attempt.part} cut in flight`));
      };
      this.inFlight.add(destroy);
      void (async () => {
        try {
          for (let offset = 0; offset < body.length && !cut; offset += SLICE) {
            const slice = body.subarray(offset, Math.min(body.length, offset + SLICE));
            await this.carry(slice.length);
            if (cut) return;
            if (!out.write(slice)) await new Promise<void>((done) => out.once('drain', () => done()));
          }
          if (!cut) {
            out.end();
            attempt.sentAll = true;
          }
        } finally {
          this.inFlight.delete(destroy);
        }
      })();
    });
  }
}

/** The part number of a part PUT to the S3 stand-in, else `null`. */
function partOf(request: Request): number | null {
  if (request.method() !== 'PUT' || !request.url().startsWith('http://localhost:9090/')) return null;
  const n = Number(new URL(request.url()).searchParams.get('partNumber'));
  return Number.isInteger(n) && n > 0 ? n : null;
}

test('a throttled upload survives a dropped connection without sending a completed part again', async ({ page }) => {
  const parts = Math.ceil(SIZE / (5 * MIB));
  test.setTimeout(Math.round(LINE_RATE_MS * 1.5 + OUTAGE_MS + 240_000));
  const path = binaryFile(SIZE);
  try {
    await signIn(page, 'member', '/transfers/new');
    await page.getByLabel("Recipient's email address").fill(`${unique('nfr3')}@partner.example`);
    await page.getByRole('button', { name: 'Add recipient' }).click();
    await page.getByTestId('transfer-files').setInputFiles(path);

    const link = new ThrottledLink(BYTES_PER_SECOND);
    await page.route('**/*', (route) => link.handle(route));
    const completed = page.waitForResponse(
      (r) => /\/v1\/files\/[0-9a-f-]+\/complete$/.test(r.url()) && r.request().method() === 'POST',
      { timeout: Math.round(LINE_RATE_MS * 1.5 + OUTAGE_MS + 120_000) },
    );
    await page.getByRole('button', { name: 'Send transfer' }).click();

    // Halfway: half the parts have landed. Then the link drops, and comes back after the outage.
    const landed = () => new Set(link.tries.filter((t) => t.outcome === 'landed').map((t) => t.part));
    await expect
      .poll(() => landed().size, { timeout: Math.round(LINE_RATE_MS * 2 + 60_000), intervals: [100] })
      .toBeGreaterThanOrEqual(Math.max(1, Math.floor(parts / 2)));
    const cutAt = Date.now();
    link.cut();
    const landedBeforeCut = landed();
    await page.waitForTimeout(OUTAGE_MS);
    link.restore();

    expect((await completed).status(), 'completeUpload').toBe(200);
    await expect(page).toHaveURL(/\/transfers\/[0-9a-f-]{36}$/, { timeout: 60_000 });
    await page.unrouteAll({ behavior: 'ignoreErrors' });
    const first = Math.min(...link.tries.map((t) => t.started));
    const last = Math.max(...link.tries.map((t) => t.ended ?? 0));
    const elapsed = last - first;

    // The throttle reached the part PUTs: no part landed faster than the line rate allows, and the link as a whole
    // carried no more than its rate (with 5 % for timer slack).
    const done = link.tries.filter((t) => t.outcome === 'landed');
    for (const t of done) {
      const floor = (t.bytes / BYTES_PER_SECOND) * 1000 * 0.95;
      expect((t.ended ?? 0) - t.started, `part ${t.part} took at least its line-rate time`).toBeGreaterThanOrEqual(floor);
    }
    const carried = link.tries.reduce((total, t) => total + (t.outcome === 'landed' ? t.bytes : 0), 0);
    expect(carried / ((elapsed - OUTAGE_MS) / 1000), 'bytes a second over the link').toBeLessThanOrEqual(BYTES_PER_SECOND * 1.05);

    // The outage cut a part in flight, or the test proved nothing.
    const cut = link.tries.filter((t) => t.outcome === 'cut');
    expect(cut.length, 'parts cut by the outage').toBeGreaterThan(0);
    expect(landedBeforeCut.size).toBeLessThan(parts);
    for (const t of cut) expect(landedBeforeCut.has(t.part), `part ${t.part} was cut before it landed`).toBe(false);

    // completeUpload's 200 says S3 holds every part. Each landed at most once, and no part that had landed was sent
    // again: not one that landed before the cut, not one whose answer the cut lost (`listUploadedParts` finds it).
    const delivered = new Set(link.tries.filter((t) => t.outcome === 'landed' || t.outcome === 'unanswered').map((t) => t.part));
    expect([...delivered].sort((a, b) => a - b)).toEqual(Array.from({ length: parts }, (_, i) => i + 1));
    for (let n = 1; n <= parts; n += 1) {
      const tries = link.tries.filter((t) => t.part === n);
      const landing = tries.findIndex((t) => t.outcome === 'landed');
      expect(tries.filter((t) => t.outcome === 'landed').length, `part ${n} landed at most once`).toBeLessThanOrEqual(1);
      if (landing >= 0) expect(tries.slice(landing + 1), `part ${n} not sent again after it landed`).toEqual([]);
    }
    for (const t of link.tries) if (t.outcome === 'landed' && (t.ended ?? 0) < cutAt) expect(landedBeforeCut.has(t.part)).toBe(true);

    const budget = LINE_RATE_MS * 1.1 + OUTAGE_MS + RETRY_ALLOWANCE_MS;
    test.info().annotations.push({
      type: 'NFR-3',
      description: `${(SIZE / MIB).toFixed(0)} MiB at ${MBITS} Mbit/s: ${(elapsed / 1000).toFixed(1)} s with a ${OUTAGE_MS / 1000} s outage and ${cut.length} parts cut in flight (line rate ${(LINE_RATE_MS / 1000).toFixed(1)} s, budget ${(budget / 1000).toFixed(1)} s)`,
    });
    expect(elapsed, 'line rate + 10 %, the outage and one retry wait').toBeLessThanOrEqual(budget);
  } finally {
    (node('node:fs') as NodeFs).rmSync(path, { force: true });
  }
});
