import { AxiosError, AxiosHeaders, CanceledError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import { csrfToken, member } from '@/test/apiHarness';
import {
  backoff,
  createStorageClient,
  FileUpload,
  planParts,
  type ApiFile,
  type PartUrl,
  type UploadApi,
  type UploadedParts,
} from './upload';

const MIB = 1024 * 1024;
const FILE_ID = '0190c0de-0000-7000-8000-0000000000f1';
const NOW = Date.parse('2026-11-08T00:00:00Z');

/** A file of `parts` parts of 5 MiB, the last one `tail` bytes. */
function blobOf(parts: number, tail = 1000): { blob: Blob; plan: { part_size: number; part_count: number } } {
  const size = (parts - 1) * 5 * MIB + tail;
  return { blob: new Blob([new Uint8Array(size)]), plan: { part_size: 5 * MIB, part_count: parts } };
}

interface FakeApi extends UploadApi {
  calls: string[];
  held: number[];
  urlRequests: number[][];
}

/** The API, answering from memory: `held` is what S3 holds; part URLs live `urlSeconds`. */
function fakeApi(plan: { part_size: number; part_count: number }, size: number, held: number[] = [], urlSeconds = 900): FakeApi {
  const sizeOf = (n: number) => (n === plan.part_count ? size - (n - 1) * plan.part_size : plan.part_size);
  let issued = 0;
  const api: FakeApi = {
    calls: [],
    held: [...held],
    urlRequests: [],
    async listUploadedParts(): Promise<UploadedParts> {
      api.calls.push('listUploadedParts');
      return { ...plan, parts: api.held.map((n) => ({ part_number: n, size: sizeOf(n) })) };
    },
    async requestPartUrls(_fileId, numbers): Promise<PartUrl[]> {
      api.calls.push('requestPartUrls');
      api.urlRequests.push([...numbers]);
      issued += 1;
      return numbers.map((n) => ({
        part_number: n,
        size: sizeOf(n),
        method: 'PUT',
        url: `https://files.example/bucket/key?partNumber=${n}&issue=${issued}`,
        expires_at: new Date(NOW + urlSeconds * 1000).toISOString(),
      }));
    },
    async completeUpload(): Promise<ApiFile> {
      api.calls.push('completeUpload');
      return { id: FILE_ID, state: 'scanning' } as ApiFile;
    },
    async deleteFile(): Promise<void> {
      api.calls.push('deleteFile');
    },
  };
  return api;
}

type Reply = 'ok' | 'network' | number | (() => Promise<'ok'>);

/** Storage through the engine's own axios instance, with an adapter in place of the network. */
function fakeStorage(api: FakeApi, reply: (part: number, attempt: number) => Reply = () => 'ok') {
  const storage = createStorageClient();
  const sent: InternalAxiosRequestConfig[] = [];
  const attempts = new Map<number, number>();
  let inFlight = 0;
  let maxInFlight = 0;
  storage.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    const part = Number(new URL(config.url ?? '').searchParams.get('partNumber'));
    const attempt = (attempts.get(part) ?? 0) + 1;
    attempts.set(part, attempt);
    sent.push(config);
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    try {
      let answer = reply(part, attempt);
      if (typeof answer === 'function') {
        // As the browser's adapter does: an abort ends the request at once.
        const aborted = new Promise<never>((_, reject) =>
          config.signal?.addEventListener?.('abort', () => reject(new CanceledError())),
        );
        answer = await Promise.race([answer(), aborted]);
      }
      await new Promise((resolve) => setTimeout(resolve, 1));
      if (answer === 'network') throw new AxiosError('Network Error', 'ERR_NETWORK', config);
      if (typeof answer === 'number') {
        const response: AxiosResponse = { status: answer, statusText: '', data: '', headers: {}, config };
        throw new AxiosError(`status ${answer}`, 'ERR_BAD_REQUEST', config, null, response);
      }
      api.held.push(part);
      return { status: 200, statusText: 'OK', data: '', headers: {}, config };
    } finally {
      inFlight -= 1;
    }
  };
  return { storage, sent, parts: () => sent.map((c) => Number(new URL(c.url ?? '').searchParams.get('partNumber'))), maxInFlight: () => maxInFlight };
}

const noWait = vi.fn(async () => undefined);

function upload(blob: Blob, api: UploadApi, storage: ReturnType<typeof fakeStorage>['storage']) {
  return new FileUpload({ fileId: FILE_ID, blob, api, storage, sleep: noWait, now: () => NOW });
}

afterEach(() => {
  noWait.mockClear();
  useAuthStore.setState(useAuthStore.getInitialState(), true);
});

describe('planParts: slicing a file by its UploadPlan', () => {
  it('cuts every part but the last at part_size', () => {
    const { blob, plan } = blobOf(3, 1234);
    expect(planParts(blob.size, plan)).toEqual([
      { number: 1, start: 0, end: 5 * MIB, size: 5 * MIB },
      { number: 2, start: 5 * MIB, end: 10 * MIB, size: 5 * MIB },
      { number: 3, start: 10 * MIB, end: 10 * MIB + 1234, size: 1234 },
    ]);
    expect(planParts(10, { part_size: 5 * MIB, part_count: 1 })).toEqual([{ number: 1, start: 0, end: 10, size: 10 }]);
  });

  it('refuses a file that does not match the plan: another size than the one declared', () => {
    expect(() => planParts(5 * MIB, { part_size: 5 * MIB, part_count: 2 })).toThrow();
    expect(() => planParts(11 * MIB, { part_size: 5 * MIB, part_count: 2 })).toThrow();
  });

  it('waits longer after each failure, up to 30 s', () => {
    expect([1, 2, 3, 4, 5, 6, 7].map(backoff)).toEqual([1000, 2000, 4000, 8000, 16000, 30000, 30000]);
  });
});

describe('FileUpload (#196, FR-2)', () => {
  it('reads the parts S3 holds, sends the rest with their URLs, then completes', async () => {
    const { blob, plan } = blobOf(3);
    const api = fakeApi(plan, blob.size);
    const s3 = fakeStorage(api);
    const changes: string[] = [];
    const file = new FileUpload({
      fileId: FILE_ID,
      blob,
      api,
      storage: s3.storage,
      sleep: noWait,
      now: () => NOW,
      onChange: (p) => changes.push(p.status),
    });

    await expect(file.start()).resolves.toMatchObject({ id: FILE_ID });

    expect(api.calls[0]).toBe('listUploadedParts');
    expect(api.calls[api.calls.length - 1]).toBe('completeUpload');
    expect(api.urlRequests).toEqual([[1, 2, 3]]); // one batch for all three
    expect(s3.parts().sort()).toEqual([1, 2, 3]);
    expect(s3.sent.every((c) => c.method === 'put')).toBe(true);
    expect((s3.sent.find((c) => c.url?.includes('partNumber=3'))?.data as Blob).size).toBe(1000);
    expect(file.state).toMatchObject({ status: 'done', sentBytes: blob.size });
    expect(changes).toContain('completing');
  });

  it('asks for part URLs in batches of at most 100', async () => {
    const plan = { part_size: 1, part_count: 250 };
    const blob = new Blob([new Uint8Array(250)]);
    const api = fakeApi(plan, 250);
    const s3 = fakeStorage(api);
    await upload(blob, api, s3.storage).start();
    expect(api.urlRequests.map((batch) => batch.length).every((n) => n <= 100)).toBe(true);
    expect(new Set(api.urlRequests.flat()).size).toBe(250);
  });

  it('keeps at most 4 parts in flight', async () => {
    const { blob, plan } = blobOf(10);
    const api = fakeApi(plan, blob.size);
    const s3 = fakeStorage(api, () => () => new Promise((resolve) => setTimeout(() => resolve('ok'), 5)));
    await upload(blob, api, s3.storage).start();
    expect(s3.maxInFlight()).toBe(4);
    expect(s3.sent).toHaveLength(10);
  });

  it('tries a failed part again after a wait, without sending finished parts again', async () => {
    const { blob, plan } = blobOf(3);
    const api = fakeApi(plan, blob.size);
    const s3 = fakeStorage(api, (part, attempt) => (part === 2 && attempt === 1 ? 'network' : 'ok'));
    await upload(blob, api, s3.storage).start();
    expect(s3.parts().filter((p) => p === 2)).toHaveLength(2);
    expect(s3.parts().filter((p) => p !== 2).sort()).toEqual([1, 3]);
    expect(noWait).toHaveBeenCalledWith(1000, expect.anything());
    // Before the retry it asked S3 again which parts it holds.
    expect(api.calls.filter((c) => c === 'listUploadedParts').length).toBeGreaterThanOrEqual(2);
  });

  it('asks for a new URL when storage refuses an expired one (403)', async () => {
    const { blob, plan } = blobOf(2);
    const api = fakeApi(plan, blob.size);
    const s3 = fakeStorage(api, (part, attempt) => (part === 1 && attempt === 1 ? 403 : 'ok'));
    await upload(blob, api, s3.storage).start();
    expect(api.urlRequests).toEqual([[1, 2], [1]]);
    const urls = s3.sent.filter((c) => c.url?.includes('partNumber=1')).map((c) => c.url);
    expect(urls[0]).not.toBe(urls[1]);
  });

  it('asks for a new URL instead of using one that is about to expire', async () => {
    const { blob, plan } = blobOf(2);
    const api = fakeApi(plan, blob.size);
    let clock = NOW;
    // Part 1 takes 15 minutes to send: part 2's URL, issued with it, has expired by then.
    const s3 = fakeStorage(api, (part) => {
      if (part === 1) clock += 15 * 60 * 1000;
      return 'ok';
    });
    const file = new FileUpload({ fileId: FILE_ID, blob, api, storage: s3.storage, sleep: noWait, now: () => clock, concurrency: 1 });
    await file.start();
    expect(api.urlRequests).toEqual([[1, 2], [2]]);
  });

  it('resumes from listUploadedParts: only the missing parts are sent', async () => {
    const { blob, plan } = blobOf(4);
    const api = fakeApi(plan, blob.size, [1, 3]);
    const s3 = fakeStorage(api);
    await upload(blob, api, s3.storage).start();
    expect(s3.parts().sort()).toEqual([2, 4]);
    expect(api.urlRequests).toEqual([[2, 4]]);
  });

  it('stops as failed when the network stays down, then resume sends only what is still missing', async () => {
    const { blob, plan } = blobOf(3);
    const api = fakeApi(plan, blob.size);
    const s3 = fakeStorage(api, (part) => (part === 3 ? 'network' : 'ok'));
    const file = upload(blob, api, s3.storage);
    await expect(file.start()).rejects.toBeTruthy();
    expect(file.state.status).toBe('failed');
    expect(s3.parts().filter((p) => p === 3)).toHaveLength(5); // PART_ATTEMPTS
    expect(s3.parts().filter((p) => p !== 3).sort()).toEqual([1, 2]);

    // The network is back: the page resumes, and only part 3 goes again.
    const healed = fakeStorage(api);
    const resumed = new FileUpload({ fileId: FILE_ID, blob, api, storage: healed.storage, sleep: noWait, now: () => NOW });
    await resumed.start();
    expect(healed.parts()).toEqual([3]);
    expect(api.calls[api.calls.length - 1]).toBe('completeUpload');
  });

  it('cancelling stops the parts in flight and removes the file', async () => {
    const { blob, plan } = blobOf(6);
    const api = fakeApi(plan, blob.size);
    let release: () => void = () => undefined;
    const gate = new Promise<'ok'>((resolve) => {
      release = () => resolve('ok');
    });
    const s3 = fakeStorage(api, () => () => gate);
    const file = upload(blob, api, s3.storage);
    const running = file.start();
    await vi.waitFor(() => expect(s3.sent.length).toBe(4));

    await file.cancel();
    release();

    await expect(running).resolves.toBeNull();
    expect(api.calls).toContain('deleteFile');
    expect(api.calls).not.toContain('completeUpload');
    expect(file.state.status).toBe('cancelled');
    expect(s3.sent.every((c) => c.signal?.aborted)).toBe(true);
    expect(s3.sent).toHaveLength(4); // nothing more was sent
  });

  it('sends no cookie, CSRF token, link session or Content-Type of its own to storage', async () => {
    useAuthStore.getState().setAuth(member, csrfToken('member'));
    useAuthStore.getState().setLinkSession('ls-1', csrfToken('link'));
    const { blob, plan } = blobOf(1);
    const api = fakeApi(plan, blob.size);
    const s3 = fakeStorage(api);
    await upload(blob, api, s3.storage).start();

    const [put] = s3.sent;
    expect(put?.withCredentials).toBe(false);
    expect(put?.baseURL).toBeUndefined();
    // What goes on the wire: axios leaves out a header set to false.
    const headers = Object.keys(AxiosHeaders.from(put?.headers).toJSON()).map((name) => name.toLowerCase());
    for (const name of ['x-csrf-token', 'x-link-session', 'cookie', 'authorization', 'content-type']) {
      expect(headers, name).not.toContain(name);
    }
  });

  it('sends the headers a PartUrl names', async () => {
    const { blob, plan } = blobOf(1);
    const api = fakeApi(plan, blob.size);
    const issue = api.requestPartUrls.bind(api);
    api.requestPartUrls = async (id, numbers) =>
      (await issue(id, numbers)).map((url) => ({ ...url, headers: { 'x-amz-checksum-sha256': 'abc' } }));
    const s3 = fakeStorage(api);
    await upload(blob, api, s3.storage).start();
    expect(AxiosHeaders.from(s3.sent[0]?.headers).get('x-amz-checksum-sha256')).toBe('abc');
  });
});
