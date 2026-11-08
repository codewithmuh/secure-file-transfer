/**
 * The upload engine (#196; FR-2, architecture 4.1): one file, in parts, straight to object storage through the
 * pre-signed part URLs the API issues, then `completeUpload`.
 *
 * - **Order.** `listUploadedParts` first, so a resumed upload, after a reload or an outage, sends only the parts S3
 *   doesn't hold yet (FR-2: "completed parts are not sent again"). Then part URLs in batches of up to 100
 *   (`requestUploadPartUrls`), a `PUT` of each `Blob.slice` with the headers its `PartUrl` names, at most 4 at once,
 *   and `completeUpload` once every part is there.
 * - **Failures.** A failed part is tried again with a growing wait. A `403` from storage is an expired URL: the URL is
 *   dropped and a new one asked for. Before each retry the engine asks the API again which parts S3 holds, so a part
 *   that landed before its answer was lost isn't sent twice. When the tries run out the upload stops as `failed`;
 *   `resume` (the page calls it on "Retry" and when the browser comes back online) starts again from
 *   `listUploadedParts`.
 * - **No credentials to storage.** Parts go through their own axios instance: no base URL, `withCredentials: false`,
 *   no default `Content-Type`, and none of the app's interceptors, so no cookie, CSRF token or link session ever
 *   reaches S3.
 * - **Cancel.** `cancel` stops every part in flight and removes the file (`deleteFile`), when the caller can.
 *
 * The engine knows nothing of React: the page passes the API calls in and reads progress from `onChange`. A member's
 * transfer passes the member operations (`uploadApi`); an uploader's page passes the link session's (#213,
 * `sessionUploadApi`), whose completion answers a `SessionFile` and which has no delete.
 */
import axios, { type AxiosInstance } from 'axios';
import type { Schema } from '@/api';

export type PartUrl = Schema<'PartUrl'>;
export type UploadPlan = Schema<'UploadPlan'>;
export type UploadedParts = Schema<'UploadedParts'>;
export type ApiFile = Schema<'File'>;

/** At most this many parts in flight per file (#196). */
export const PART_CONCURRENCY = 4;
/** The contract's limit per `requestUploadPartUrls` call. */
export const URL_BATCH = 100;
/** Tries per part before the upload stops as `failed`, and the waits between them. */
export const PART_ATTEMPTS = 5;
export const FIRST_WAIT_MS = 1000;
export const MAX_WAIT_MS = 30_000;
/** A URL this close to its `expires_at` is asked for again rather than used. */
export const URL_MARGIN_MS = 30_000;

/**
 * The API calls the engine makes, for one file. `Completed` is what `completeUpload` answers: a `File` for a member,
 * a `SessionFile` for an uploader. `deleteFile` is left out where the caller can't delete (an uploader, #213).
 */
export interface UploadApi<Completed = ApiFile> {
  listUploadedParts(fileId: string): Promise<UploadedParts>;
  requestPartUrls(fileId: string, partNumbers: number[]): Promise<PartUrl[]>;
  completeUpload(fileId: string): Promise<Completed>;
  deleteFile?(fileId: string): Promise<void>;
}

export interface Part {
  number: number;
  start: number;
  end: number;
  size: number;
}

/** The parts of a file of `size` bytes under its plan: every part but the last is exactly `part_size` bytes. */
export function planParts(size: number, plan: Pick<UploadPlan, 'part_size' | 'part_count'>): Part[] {
  const parts: Part[] = [];
  for (let number = 1; number <= plan.part_count; number += 1) {
    const start = (number - 1) * plan.part_size;
    const end = number === plan.part_count ? size : Math.min(size, start + plan.part_size);
    parts.push({ number, start, end, size: end - start });
  }
  const fits = (part: Part) => part.size > 0 && part.size <= plan.part_size;
  if (parts.length === 0 || !parts.every(fits) || parts[parts.length - 1]?.end !== size) {
    throw new Error('the file does not match its upload plan');
  }
  return parts;
}

/** The wait before try `attempt` (1-based) of a part: 1 s, 2 s, 4 s, ... up to 30 s. */
export function backoff(attempt: number): number {
  return Math.min(MAX_WAIT_MS, FIRST_WAIT_MS * 2 ** Math.max(0, attempt - 1));
}

/**
 * The axios instance parts go through: nothing of the app's. No base URL (the URL is absolute), no cookies
 * (`withCredentials: false`), no default `Content-Type`, and no interceptors, so no CSRF token or link session is
 * ever added.
 */
export function createStorageClient(): AxiosInstance {
  const client = axios.create({ withCredentials: false, timeout: 0 });
  delete client.defaults.headers.common.Accept;
  for (const method of ['put', 'post', 'patch'] as const) {
    delete client.defaults.headers[method]['Content-Type'];
  }
  return client;
}

export type UploadStatus = 'pending' | 'uploading' | 'completing' | 'done' | 'failed' | 'cancelled';

export interface UploadProgress {
  status: UploadStatus;
  /** Bytes S3 holds or has received of this file so far. */
  sentBytes: number;
  totalBytes: number;
  /** Parts sent by this engine (not counting the ones S3 already held when it started). */
  partsSent: number[];
  /** Why a failed upload stopped: `network`, `expired` or the problem's status. */
  error: unknown;
}

export interface FileUploadOptions<Completed = ApiFile> {
  fileId: string;
  blob: Blob;
  api: UploadApi<Completed>;
  storage?: AxiosInstance;
  concurrency?: number;
  attempts?: number;
  /** For tests: the wait between tries, and the clock. */
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
  now?: () => number;
  onChange?: (progress: UploadProgress) => void;
}

class CancelledError extends Error {
  constructor() {
    super('cancelled');
  }
}

function defaultSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(new CancelledError());
    const timer = setTimeout(resolve, ms);
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        reject(new CancelledError());
      },
      { once: true },
    );
  });
}

function statusOf(error: unknown): number | null {
  return axios.isAxiosError(error) ? (error.response?.status ?? null) : null;
}

/** One file's upload. `start` runs it to `completeUpload`; `resume` runs it again after a failure; `cancel` ends it. */
export class FileUpload<Completed = ApiFile> {
  readonly fileId: string;
  private readonly blob: Blob;
  private readonly api: UploadApi<Completed>;
  private readonly storage: AxiosInstance;
  private readonly concurrency: number;
  private readonly attempts: number;
  private readonly sleep: (ms: number, signal: AbortSignal) => Promise<void>;
  private readonly now: () => number;
  private readonly onChange?: (progress: UploadProgress) => void;

  private controller = new AbortController();
  private running: Promise<Completed | null> | null = null;
  private held = new Set<number>();
  private inFlight = new Map<number, number>();
  private urls = new Map<number, PartUrl>();
  private urlRequest: Promise<void> | null = null;
  private parts: Part[] = [];
  private progress: UploadProgress;

  constructor(options: FileUploadOptions<Completed>) {
    this.fileId = options.fileId;
    this.blob = options.blob;
    this.api = options.api;
    this.storage = options.storage ?? createStorageClient();
    this.concurrency = options.concurrency ?? PART_CONCURRENCY;
    this.attempts = options.attempts ?? PART_ATTEMPTS;
    this.sleep = options.sleep ?? defaultSleep;
    this.now = options.now ?? Date.now;
    this.onChange = options.onChange;
    this.progress = { status: 'pending', sentBytes: 0, totalBytes: options.blob.size, partsSent: [], error: null };
  }

  get state(): UploadProgress {
    return this.progress;
  }

  /** Uploads every missing part and completes the file. Resolves with the completed file, or `null` if cancelled. */
  start(): Promise<Completed | null> {
    if (!this.running) {
      this.running = this.run().finally(() => {
        this.running = null;
      });
    }
    return this.running;
  }

  /** After a failure: start again from the parts S3 holds. */
  resume(): Promise<Completed | null> {
    if (this.progress.status === 'cancelled' || this.progress.status === 'done') return Promise.resolve(null);
    return this.start();
  }

  /**
   * Stops every part in flight and keeps the file: the page is closing, or the whole draft is being cancelled. What S3
   * holds stays, so `resume` (or the draft's detail page after a reload) carries on from there.
   */
  async pause(): Promise<void> {
    if (this.progress.status !== 'uploading' && this.progress.status !== 'pending') return;
    this.controller.abort();
    await this.running?.catch(() => null);
    this.controller = new AbortController();
    this.update({ status: 'failed', error: 'paused' });
  }

  /** Stops every part in flight and removes the file from its transfer (`deleteFile`), when the API offers that. */
  async cancel(): Promise<void> {
    if (this.progress.status === 'cancelled' || this.progress.status === 'done') return;
    this.controller.abort();
    this.update({ status: 'cancelled' });
    await this.running?.catch(() => null);
    await this.api.deleteFile?.(this.fileId);
  }

  private update(change: Partial<UploadProgress>): void {
    const inFlight = [...this.inFlight.values()].reduce((sum, bytes) => sum + bytes, 0);
    const heldBytes = this.parts.filter((part) => this.held.has(part.number)).reduce((sum, part) => sum + part.size, 0);
    this.progress = { ...this.progress, sentBytes: Math.min(this.blob.size, heldBytes + inFlight), ...change };
    this.onChange?.(this.progress);
  }

  private async run(): Promise<Completed | null> {
    if (this.controller.signal.aborted) return null;
    this.update({ status: 'uploading', error: null });
    try {
      await this.syncHeld();
      const queue = this.parts.filter((part) => !this.held.has(part.number));
      const workers = Array.from({ length: Math.min(this.concurrency, Math.max(queue.length, 1)) }, () =>
        this.worker(queue),
      );
      await Promise.all(workers);
      this.update({ status: 'completing' });
      const file = await this.api.completeUpload(this.fileId);
      this.update({ status: 'done', sentBytes: this.blob.size });
      return file;
    } catch (error) {
      if (error instanceof CancelledError || this.controller.signal.aborted) return null;
      this.update({ status: 'failed', error });
      throw error;
    }
  }

  /** Reads which parts S3 holds (`listUploadedParts`); its plan is the one the API keeps. */
  private async syncHeld(): Promise<void> {
    const uploaded = await this.api.listUploadedParts(this.fileId);
    this.parts = planParts(this.blob.size, uploaded);
    const sizes = new Map(this.parts.map((part) => [part.number, part.size]));
    this.held = new Set(uploaded.parts.filter((p) => sizes.get(p.part_number) === p.size).map((p) => p.part_number));
    this.update({});
  }

  private async worker(queue: Part[]): Promise<void> {
    for (let part = queue.shift(); part; part = queue.shift()) {
      if (this.held.has(part.number)) continue;
      await this.sendPart(part, queue);
    }
  }

  private async sendPart(part: Part, queue: Part[]): Promise<void> {
    for (let attempt = 1; ; attempt += 1) {
      if (this.controller.signal.aborted) throw new CancelledError();
      try {
        const url = await this.urlFor(part, queue);
        await this.storage.put(url.url, this.blob.slice(part.start, part.end), {
          // `false` keeps axios from adding a Content-Type of its own; S3 takes the part as it is.
          headers: { 'Content-Type': false, ...(url.headers ?? {}) },
          withCredentials: false,
          signal: this.controller.signal,
          onUploadProgress: (event) => {
            this.inFlight.set(part.number, Math.min(part.size, event.loaded));
            this.update({});
          },
        });
        this.inFlight.delete(part.number);
        this.held.add(part.number);
        this.update({ partsSent: [...this.progress.partsSent, part.number] });
        return;
      } catch (error) {
        this.inFlight.delete(part.number);
        if (this.controller.signal.aborted || axios.isCancel(error)) throw new CancelledError();
        // 403 from storage: the signature expired (or was refused). Ask for a new URL.
        if (statusOf(error) === 403) this.urls.delete(part.number);
        if (attempt >= this.attempts) throw error;
        await this.sleep(backoff(attempt), this.controller.signal);
        // The part may have landed before its answer was lost: ask S3 before sending it again.
        try {
          await this.syncHeld();
        } catch {
          // The API is out of reach too; the next try finds out again.
        }
        if (this.held.has(part.number)) return;
      }
    }
  }

  /**
   * A fresh URL for the part, asking for up to 100 at once: this part and the next ones in the queue. One request at a
   * time: a worker that needs a URL while another asks waits for that answer first.
   */
  private async urlFor(part: Part, queue: Part[]): Promise<PartUrl> {
    const fresh = (url: PartUrl | undefined): url is PartUrl =>
      url !== undefined && Date.parse(url.expires_at) - URL_MARGIN_MS > this.now();
    while (this.urlRequest) await this.urlRequest;
    const cached = this.urls.get(part.number);
    if (fresh(cached)) return cached;
    const wanted = [part, ...queue]
      .filter((p) => !this.held.has(p.number) && !fresh(this.urls.get(p.number)))
      .slice(0, URL_BATCH)
      .map((p) => p.number);
    this.urlRequest = this.api.requestPartUrls(this.fileId, wanted).then((issued) => {
      for (const url of issued) this.urls.set(url.part_number, url);
    });
    try {
      await this.urlRequest;
    } finally {
      this.urlRequest = null;
    }
    const url = this.urls.get(part.number);
    if (!url) throw new Error(`no URL issued for part ${part.number}`);
    return url;
  }
}
