import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { InternalAxiosRequestConfig } from 'axios';
import { problem, setUpApi, type FakeReply } from '@/test/apiHarness';
import { createReceivedDownload, downloadReceivedFile, storedReceivedGrant } from './receivedDownload';

const fileId = '0190c0de-0000-7000-8000-0000000000f3';
const grantId = '0190c0de-0000-7000-8000-0000000000a3';
const fresh = '0190c0de-0000-7000-8000-0000000000a4';
const apiOrigin = 'https://api.example/v1';
const content = (grant: string) => `https://api.example/v1/files/${fileId}/downloads/${grant}/content`;

function access(id: string) {
  return {
    grant_id: id,
    method: 'GET',
    url: `/v1/files/${fileId}/downloads/${id}/content`,
    expires_at: '2026-11-09T00:00:00Z',
    byte_budget: 300,
    request_limit: 20,
    file: { id: fileId, display_name: 'invoice.pdf', content_type: 'application/pdf', size: 100 },
  };
}

/** A `sessionStorage` in memory: the tests run in Node, which has none. */
function memoryStorage(): Storage {
  const items = new Map<string, string>();
  return {
    get length() {
      return items.size;
    },
    clear: () => items.clear(),
    getItem: (key) => items.get(key) ?? null,
    key: (index) => [...items.keys()][index] ?? null,
    removeItem: (key) => void items.delete(key),
    setItem: (key, value) => void items.set(key, value),
  };
}

const bodyOf = (config: InternalAxiosRequestConfig | undefined): unknown =>
  typeof config?.data === 'string' ? JSON.parse(config.data) : config?.data;

const resumeOf = (config: InternalAxiosRequestConfig) => (bodyOf(config) as { resume_grant_id?: string }).resume_grant_id;

/** A document with one hidden link, enough for `startDownload`. */
function fakeDocument() {
  const link = { href: '', rel: '', hidden: false, click: vi.fn(), remove: vi.fn() };
  const doc = { createElement: () => link, body: { appendChild: vi.fn() } } as unknown as Document;
  return { doc, link };
}

const problemResponse = (status: number, code: string) =>
  new Response(JSON.stringify(problem(status, code).data), {
    status,
    headers: { 'content-type': 'application/problem+json' },
  });

/** The API's grants answer `grants`; the content check answers `replies` in turn, then 200. */
async function stack(grants: (config: InternalAxiosRequestConfig) => FakeReply, replies: Response[] = []) {
  const harness = await setUpApi(grants, '/upload-requests/x', { apiOrigin });
  const fetched = vi.fn(async (_url: string, _init?: RequestInit) => replies.shift() ?? new Response('bytes', { status: 200 }));
  vi.stubGlobal('fetch', fetched);
  return { ...harness, fetched };
}

beforeEach(() => {
  vi.stubGlobal('sessionStorage', memoryStorage());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the member\'s received-file download resumes under its grant (#229, FR-6)', () => {
  it('asks for a new grant first, then sends the kept one as resume_grant_id on the next click', async () => {
    const { sent } = await setUpApi(() => ({ status: 200, data: access(grantId) }));
    await createReceivedDownload(fileId);
    expect(sent[0]?.url).toBe(`/files/${fileId}/downloads`);
    expect(bodyOf(sent[0])).toEqual({});
    expect(storedReceivedGrant(fileId)).toBe(grantId);
    await createReceivedDownload(fileId);
    expect(bodyOf(sent[1])).toEqual({ resume_grant_id: grantId });
  });

  it('503 on the check: the interrupted start keeps its grant, and the next click resumes it', async () => {
    const { sent, fetched } = await stack(() => ({ status: 200, data: access(grantId) }), [problemResponse(503, 'service_unavailable')]);
    const { doc, link } = fakeDocument();
    await expect(downloadReceivedFile(fileId, doc)).rejects.toThrow();
    expect(storedReceivedGrant(fileId)).toBe(grantId);
    expect(link.click).not.toHaveBeenCalled();

    await downloadReceivedFile(fileId, doc);
    expect(sent.map(bodyOf)).toEqual([{}, { resume_grant_id: grantId }]);
    expect(fetched.mock.calls.map(([url]) => url)).toEqual([content(grantId), content(grantId)]);
    expect(link.href).toBe(content(grantId));
    expect(link.click).toHaveBeenCalledOnce();
    // The browser has the download: its download manager resumes it, so nothing is kept.
    expect(storedReceivedGrant(fileId)).toBeNull();
  });

  it('a kept grant of another member session (404) is dropped, and a new one asked for', async () => {
    sessionStorage.setItem(`sft.received-grant.${fileId}`, grantId);
    const { sent } = await setUpApi((config) =>
      resumeOf(config) ? problem(404, 'not_found') : { status: 200, data: access(fresh) },
    );
    expect((await createReceivedDownload(fileId)).grant_id).toBe(fresh);
    expect(sent.map(bodyOf)).toEqual([{ resume_grant_id: grantId }, {}]);
    expect(storedReceivedGrant(fileId)).toBe(fresh);
  });

  it('a used-up grant is dropped and the error passed on, so the next click asks for a new one', async () => {
    sessionStorage.setItem(`sft.received-grant.${fileId}`, grantId);
    await setUpApi(() => problem(403, 'download_grant_exhausted'));
    await expect(createReceivedDownload(fileId)).rejects.toThrow();
    expect(storedReceivedGrant(fileId)).toBeNull();
  });

  it('a check the grant can\'t pass (403 download_grant_exhausted) drops it and starts nothing', async () => {
    await stack(() => ({ status: 200, data: access(grantId) }), [problemResponse(403, 'download_grant_exhausted')]);
    const { doc, link } = fakeDocument();
    await expect(downloadReceivedFile(fileId, doc)).rejects.toThrow();
    expect(link.click).not.toHaveBeenCalled();
    expect(storedReceivedGrant(fileId)).toBeNull();
  });

  it('without sessionStorage, a download still works, with no resume', async () => {
    vi.stubGlobal('sessionStorage', undefined);
    const { sent } = await stack(() => ({ status: 200, data: access(grantId) }));
    const { doc, link } = fakeDocument();
    await downloadReceivedFile(fileId, doc);
    await downloadReceivedFile(fileId, doc);
    expect(sent.map(bodyOf)).toEqual([{}, {}]);
    expect(link.click).toHaveBeenCalledTimes(2);
  });
});
