import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { InternalAxiosRequestConfig } from 'axios';
import i18n, { resources } from '@/lib/i18n';
import { csrfToken, header, problem, setUpApi, type FakeReply } from '@/test/apiHarness';
import { useAuthStore } from '@/stores/authStore';
import {
  applyLinkLocale,
  contentUrl,
  createDownload,
  downloadFile,
  downloadsUsedUp,
  goneOf,
  linkProblemText,
  MalformedAnswer,
  RECIPIENT_PROBLEMS,
  resumeLinkSession,
  storedGrant,
  verifyCode,
} from './linkApi';

const sessionId = '0190c0de-0000-7000-8000-0000000000e1';
const fileId = '0190c0de-0000-7000-8000-0000000000f1';
const grantId = '0190c0de-0000-7000-8000-0000000000a1';
const token = 'A'.repeat(43);

const linkSession = {
  id: sessionId,
  csrf_token: csrfToken('link'),
  kind: 'transfer',
  email: 'tanaka@example.co.jp',
  locale: 'ja',
  expires_at: '2026-11-09T00:00:00Z',
  transfer: {
    tenant_name: 'Example KK',
    sender_email: 'aiko@example.co.jp',
    message: null,
    expires_at: '2026-11-14T00:00:00Z',
    download_limit: 2,
  },
};

function access(id: string) {
  return {
    grant_id: id,
    method: 'GET',
    url: `/v1/session/downloads/${id}/content`,
    expires_at: '2026-11-09T00:00:00Z',
    byte_budget: 300,
    request_limit: 20,
    file: { id: fileId, display_name: 'report.pdf', content_type: 'application/pdf', size: 100 },
    downloads_remaining: 1,
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

beforeEach(() => {
  vi.stubGlobal('sessionStorage', memoryStorage());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('applyLinkLocale (FR-33)', () => {
  it('switches the page to the link\'s language whatever the browser prefers, and <html lang> follows', async () => {
    const html = { lang: 'en' };
    vi.stubGlobal('document', { documentElement: html });
    await i18n.changeLanguage('en');
    applyLinkLocale('ja');
    await vi.waitFor(() => expect(i18n.language).toBe('ja'));
    expect(html.lang).toBe('ja');
    applyLinkLocale('fr'); // a locale the app doesn't have leaves the language as it is
    expect(i18n.language).toBe('ja');
    await i18n.changeLanguage('en');
  });
});

describe('contentUrl: a grant\'s url resolves against the API\'s origin (#198 decision)', () => {
  const path = `/v1/session/downloads/${grantId}/content`;

  it('behind the dev server\'s proxy (apiOrigin /v1) the API is on the page\'s origin', () => {
    expect(contentUrl(path, '/v1', 'http://localhost:5173')).toBe(`http://localhost:5173${path}`);
  });

  it('in the compose stack the API is on :8000, never the web app\'s :3000', () => {
    expect(contentUrl(path, 'http://localhost:8000/v1', 'http://localhost:3000')).toBe(`http://localhost:8000${path}`);
  });

  it('accepts an absolute URL only on the API\'s origin and under /v1/', () => {
    expect(contentUrl(`http://localhost:8000${path}`, 'http://localhost:8000/v1', 'http://localhost:3000')).toBe(
      `http://localhost:8000${path}`,
    );
    expect(() => contentUrl(`https://evil.example${path}`, 'http://localhost:8000/v1', 'http://localhost:3000')).toThrow();
    expect(() => contentUrl('http://localhost:8000/other', 'http://localhost:8000/v1', 'http://localhost:3000')).toThrow();
  });
});

describe('createDownload: the grant kept in sessionStorage resumes, uncounted (FR-6)', () => {
  async function withSession(handler: (config: InternalAxiosRequestConfig) => FakeReply) {
    const harness = await setUpApi(handler, '/t');
    useAuthStore.getState().setLinkSession(sessionId, csrfToken('link'));
    return harness;
  }

  it('sends the stored grant ID as resume_grant_id on the next click', async () => {
    const { sent } = await withSession(() => ({ status: 200, data: access(grantId) }));
    await createDownload(fileId);
    expect(bodyOf(sent[0])).toEqual({});
    expect(storedGrant(sessionId, fileId)).toBe(grantId);

    await createDownload(fileId);
    expect(bodyOf(sent[1])).toEqual({ resume_grant_id: grantId });
    expect(header(sent[1], 'X-Link-Session')).toBe(sessionId);
    expect(header(sent[1], 'X-CSRF-Token')).toBe(csrfToken('link'));
  });

  it('drops a grant the API no longer knows (404) and asks for a new download', async () => {
    sessionStorage.setItem(`sft.grant.${sessionId}.${fileId}`, grantId);
    const fresh = '0190c0de-0000-7000-8000-0000000000a2';
    const { sent } = await withSession((config) =>
      bodyOf(config) && (bodyOf(config) as { resume_grant_id?: string }).resume_grant_id
        ? problem(404, 'not_found')
        : { status: 200, data: access(fresh) },
    );
    expect((await createDownload(fileId)).grant_id).toBe(fresh);
    expect(sent.map(bodyOf)).toEqual([{ resume_grant_id: grantId }, {}]);
    expect(storedGrant(sessionId, fileId)).toBe(fresh);
  });

  it('drops a used-up grant and passes download_grant_exhausted on, so the next click counts a new one', async () => {
    sessionStorage.setItem(`sft.grant.${sessionId}.${fileId}`, grantId);
    await withSession(() => problem(403, 'download_grant_exhausted'));
    await expect(createDownload(fileId)).rejects.toThrow();
    expect(storedGrant(sessionId, fileId)).toBeNull();
  });
});

describe('a malformed link session answer leaves the page unverified (fail closed)', () => {
  it('verifyCode: a 201 without the contract\'s shape stores nothing', async () => {
    await setUpApi(() => ({ status: 201, data: { ...linkSession, csrf_token: 'not-a-token' } }), '/t');
    await expect(verifyCode(token, '123456')).rejects.toBeInstanceOf(MalformedAnswer);
    expect(useAuthStore.getState().linkSession).toBeNull();
  });

  it('verifyCode: a well-formed answer keeps only the ID and CSRF token, in memory', async () => {
    const { sent } = await setUpApi(() => ({ status: 201, data: linkSession }), '/t');
    const session = await verifyCode(token, '123456');
    expect(session.transfer?.tenant_name).toBe('Example KK');
    expect(useAuthStore.getState().linkSession).toEqual({ id: sessionId, csrfToken: csrfToken('link') });
    expect(bodyOf(sent[0])).toEqual({ token, code: '123456' });
    expect(sessionStorage.length).toBe(0);
  });

  it('resumeLinkSession: an answer naming another session stores nothing', async () => {
    const { sent } = await setUpApi(
      () => ({ status: 200, data: { ...linkSession, id: '0190c0de-0000-7000-8000-0000000000e2' } }),
      '/t',
    );
    await expect(resumeLinkSession(sessionId)).rejects.toBeInstanceOf(MalformedAnswer);
    expect(header(sent[0], 'X-Link-Session')).toBe(sessionId);
    expect(useAuthStore.getState().linkSession).toBeNull();
  });
});

describe('what a failed link call means', () => {
  it('maps the link codes to their pages, and leaves the rest to the step', async () => {
    await setUpApi(() => ({ status: 404 }), '/t');
    const failure = (status: number, code: string) => {
      const reply = problem(status, code);
      return { isAxiosError: true, response: { status: reply.status, data: reply.data, headers: {} } };
    };
    expect(goneOf(failure(404, 'link_not_found'))).toBe('not_found');
    expect(goneOf(failure(410, 'link_revoked'))).toBe('revoked');
    expect(goneOf(failure(410, 'link_expired'))).toBe('expired');
    expect(goneOf(failure(403, 'recipient_locked'))).toBe('locked');
    expect(goneOf(failure(422, 'code_invalid'))).toBeNull();
  });

  it('explains code_invalid with the attempts the code still allows', async () => {
    let reply: FakeReply = problem(422, 'code_invalid');
    reply = { ...reply, data: { ...(reply.data as object), attempts_remaining: 3 } };
    await setUpApi(() => reply, '/t');
    const error = await verifyCode(token, '123456').catch((caught: unknown) => caught);
    await i18n.changeLanguage('en');
    expect(linkProblemText(error, i18n.t)).toBe('That code isn\'t right. 3 more tries with this code.');
    await i18n.changeLanguage('ja');
    expect(linkProblemText(error, i18n.t)).toBe('コードが正しくありません。このコードであと3回試せます。');
    await i18n.changeLanguage('en');
  });

  it('has its own text for every code it explains, in both languages', () => {
    for (const language of ['en', 'ja'] as const) {
      const problems = resources[language].translation.recipient.problems as Record<string, string>;
      for (const code of RECIPIENT_PROBLEMS) {
        expect(problems[code] ?? problems[`${code}_other`], `${language}: recipient.problems.${code}`).toBeTruthy();
      }
    }
  });
});

describe('resumeLinkSession: opening transfer B\'s link after A resumes B\'s session (#198 review)', () => {
  const other = '0190c0de-0000-7000-8000-0000000000e2';

  it('sends the session it names, not the one the store holds, then holds that one', async () => {
    const { sent } = await setUpApi(() => ({ status: 200, data: { ...linkSession, id: other } }), '/t');
    useAuthStore.getState().setLinkSession(sessionId, csrfToken('link'));
    const session = await resumeLinkSession(other);
    expect(header(sent[0], 'X-Link-Session')).toBe(other);
    expect(session.id).toBe(other);
    expect(useAuthStore.getState().linkSession?.id).toBe(other);
  });
});

describe('downloadFile: a failed content request is explained in the app (#198 review)', () => {
  const apiOrigin = 'https://api.example/v1';
  const content = `https://api.example/v1/session/downloads/${grantId}/content`;

  /** A document with one hidden link, enough for `startDownload`. */
  function fakeDocument() {
    const link = { href: '', rel: '', hidden: false, click: vi.fn(), remove: vi.fn() };
    const doc = { createElement: () => link, body: { appendChild: vi.fn() } } as unknown as Document;
    return { doc, link };
  }

  /** The API: grants from `createSessionDownload`; the content check answers `reply`. */
  async function stack(reply: () => Response) {
    const harness = await setUpApi(() => ({ status: 200, data: access(grantId) }), '/t', { apiOrigin });
    useAuthStore.getState().setLinkSession(sessionId, csrfToken('link'));
    const fetched = vi.fn(async (_url: string, _init?: RequestInit) => reply());
    vi.stubGlobal('fetch', fetched);
    return { ...harness, fetched };
  }

  const problemResponse = (status: number, code: string) =>
    new Response(JSON.stringify(problem(status, code).data), {
      status,
      headers: { 'content-type': 'application/problem+json' },
    });

  it('checks the content with the cookie only, then hands it to the browser and forgets the grant', async () => {
    const { fetched } = await stack(() => new Response('bytes', { status: 200 }));
    const { doc, link } = fakeDocument();
    await downloadFile(fileId, doc);
    const [url, init] = fetched.mock.calls[0] ?? [];
    expect(url).toBe(content);
    expect(init?.credentials).toBe('include');
    expect(init?.headers).toBeUndefined(); // no X-Link-Session: the content request takes the cookie only
    expect(init?.signal?.aborted).toBe(true); // cancelled once the headers arrived
    expect(link.href).toBe(content);
    expect(link.click).toHaveBeenCalledOnce();
    expect(storedGrant(sessionId, fileId)).toBeNull();
  });

  it('410 link_revoked: the app shows its revoked page, and the browser never leaves it', async () => {
    await stack(() => problemResponse(410, 'link_revoked'));
    const { doc, link } = fakeDocument();
    const error = await downloadFile(fileId, doc).catch((caught: unknown) => caught);
    expect(goneOf(error)).toBe('revoked');
    expect(link.click).not.toHaveBeenCalled();
  });

  it('403 download_grant_exhausted: the app\'s own text, and the grant is dropped so the next click counts', async () => {
    await stack(() => problemResponse(403, 'download_grant_exhausted'));
    const { doc, link } = fakeDocument();
    const error = await downloadFile(fileId, doc).catch((caught: unknown) => caught);
    await i18n.changeLanguage('en');
    expect(linkProblemText(error, i18n.t)).toBe(resources.en.translation.recipient.problems.download_grant_exhausted);
    expect(link.click).not.toHaveBeenCalled();
    expect(storedGrant(sessionId, fileId)).toBeNull();
  });

  it('401: the link session ends in the store, so the page goes back to the code step', async () => {
    await stack(() => problemResponse(401, 'session_expired'));
    const { doc, link } = fakeDocument();
    await expect(downloadFile(fileId, doc)).rejects.toThrow();
    expect(link.click).not.toHaveBeenCalled();
    expect(useAuthStore.getState().linkSession).toBeNull();
    expect(useAuthStore.getState().linkSessionLapsed).toBe(true);
  });

  it('503: the interrupted start keeps its grant, and the next click resumes it uncounted', async () => {
    const replies = [problemResponse(503, 'service_unavailable'), new Response('bytes', { status: 200 })];
    const { sent } = await stack(() => replies.shift() ?? new Response('bytes', { status: 200 }));
    const { doc, link } = fakeDocument();
    await expect(downloadFile(fileId, doc)).rejects.toThrow();
    expect(storedGrant(sessionId, fileId)).toBe(grantId);
    expect(link.click).not.toHaveBeenCalled();

    await downloadFile(fileId, doc);
    expect(sent.map(bodyOf)).toEqual([{}, { resume_grant_id: grantId }]);
    expect(link.click).toHaveBeenCalledOnce();
    expect(storedGrant(sessionId, fileId)).toBeNull();
  });

  it('a network failure is explained too, and keeps the grant', async () => {
    await stack(() => {
      throw new TypeError('Failed to fetch');
    });
    const { doc } = fakeDocument();
    const error = await downloadFile(fileId, doc).catch((caught: unknown) => caught);
    await i18n.changeLanguage('en');
    expect(linkProblemText(error, i18n.t)).toBe(resources.en.translation.problems.network);
    expect(storedGrant(sessionId, fileId)).toBe(grantId);
  });
});

describe('a finished download is not resumed: Download is off once the limit is used (#198 review)', () => {
  const file = { download_limit: 2, downloads_used: 2 };

  it('is off at the limit with no interrupted grant, on with one, and never off without a limit', () => {
    expect(downloadsUsedUp(file, null)).toBe(true);
    expect(downloadsUsedUp(file, grantId)).toBe(false);
    expect(downloadsUsedUp({ download_limit: 2, downloads_used: 1 }, null)).toBe(false);
    expect(downloadsUsedUp({ download_limit: null, downloads_used: 9 }, null)).toBe(false);
  });

  it('after the last counted download reaches the browser, nothing is kept to resume, so Download is off', async () => {
    await setUpApi(() => ({ status: 200, data: access(grantId) }), '/t', { apiOrigin: 'https://api.example/v1' });
    useAuthStore.getState().setLinkSession(sessionId, csrfToken('link'));
    vi.stubGlobal('fetch', vi.fn(async () => new Response('bytes', { status: 200 })));
    const link = { href: '', rel: '', hidden: false, click: vi.fn(), remove: vi.fn() };
    await downloadFile(fileId, { createElement: () => link, body: { appendChild: vi.fn() } } as unknown as Document);
    expect(downloadsUsedUp(file, storedGrant(sessionId, fileId))).toBe(true);
  });
});
