// The public API as the load test calls it: a tenant's API key on the member side, a recipient's or uploader's link
// cookie, X-Link-Session, the web app's Origin and the session's CSRF token on the link side, as the web app sends them
// (authn-authz 3.4). Every request is tagged with its operation ID as `name` and a `kind`: `api` for the calls NFR-2
// measures, `bytes` for part uploads and download streams, whose time is file bytes moving, `mail` for the mailbox.
// The thresholds read those tags (design-load.js). No URL is ever a tag (`systemTags` there): part URLs are signed.
import http from 'k6/http';
import { check, fail, sleep } from 'k6';

export const cfg = {
  api: (__ENV.API_URL || 'http://localhost:8000').replace(/\/$/, ''),
  webOrigin: __ENV.WEB_ORIGIN || 'http://localhost:3000',
  // Part URLs name the S3 stand-in as a browser on the host reaches it; a load generator elsewhere rewrites them.
  partHost: __ENV.PART_HOST || '',
};

const JSON_HEADERS = { 'content-type': 'application/json' };

function expect(res, op, status) {
  const ok = check(res, { [`${op} ${status}`]: (r) => r.status === status });
  if (!ok) {
    // The status and the problem's code only: never a body, which might quote an address.
    let code = '';
    try {
      code = res.json('code') || '';
    } catch (_) {
      code = '';
    }
    fail(`${op} answered ${res.status} ${code}`.trim());
  }
  return res;
}

/** A call as a tenant's API key (FR-32). */
export function member(key, method, path, op, status, body) {
  const params = {
    headers: { authorization: `Bearer ${key}`, ...JSON_HEADERS },
    tags: { name: op, kind: 'api' },
  };
  const payload = body === undefined ? (method === 'GET' ? null : '{}') : JSON.stringify(body);
  return expect(http.request(method, `${cfg.api}${path}`, payload, params), op, status);
}

/** A recipient's or uploader's browser: its cookies and, once verified, its link session. */
export class LinkBrowser {
  constructor() {
    this.cookies = {};
    this.session = null;
  }

  headers(method, withSession) {
    const headers = { ...JSON_HEADERS };
    const jar = Object.entries(this.cookies)
      .filter(([, v]) => v)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    if (jar) headers.cookie = jar;
    if (withSession && this.session) headers['x-link-session'] = this.session.id;
    if (method !== 'GET') {
      headers.origin = cfg.webOrigin;
      if (this.session) headers['x-csrf-token'] = this.session.csrf_token;
    }
    return headers;
  }

  keep(res) {
    // k6's jar drops `Secure` cookies over http://localhost, as httpx does; keep them as a browser would.
    for (const name of Object.keys(res.cookies || {})) {
      const values = res.cookies[name];
      if (values.length) this.cookies[name] = values[values.length - 1].value;
    }
  }

  call(method, path, op, status, body, { withSession = true } = {}) {
    const payload = method === 'GET' ? null : JSON.stringify(body || {});
    const res = http.request(method, `${cfg.api}${path}`, payload, {
      headers: this.headers(method, withSession),
      tags: { name: op, kind: 'api' },
      jar: new http.CookieJar(), // an empty jar: the cookies are the ones `headers` sends, as kept above
    });
    this.keep(res);
    return expect(res, op, status);
  }

  /** resolveLink, requestVerificationCode, the code from the mailbox, createLinkSession. */
  verify(token, mailbox, address) {
    this.call('POST', '/v1/links/resolve', 'resolveLink', 200, { token }, { withSession: false });
    const seen = mailbox.codes(address).length;
    this.call('POST', '/v1/links/codes', 'requestVerificationCode', 202, { token }, { withSession: false });
    const code = mailbox.newCode(address, seen);
    const session = this.call('POST', '/v1/links/sessions', 'createLinkSession', 201, { token, code }, { withSession: false });
    this.session = session.json();
  }

  /** A download grant, then the stream, whose body k6 discards. The wait for the first byte is NFR-4's. */
  download(fileId) {
    const grant = this.call('POST', `/v1/session/files/${fileId}/downloads`, 'createSessionDownload', 200, {});
    const url = grant.json('url');
    const res = http.get(url.startsWith('http') ? url : `${cfg.api}${url}`, {
      headers: this.headers('GET', false),
      tags: { name: 'getSessionDownloadContent', kind: 'bytes' },
      responseType: 'none',
      jar: new http.CookieJar(),
      timeout: '600s',
    });
    return expect(res, 'getSessionDownloadContent', 200);
  }
}

function partUrl(url) {
  if (!cfg.partHost) return url;
  const match = /^https?:\/\/[^/]+(\/.*)$/.exec(url);
  return match ? `${cfg.partHost}${match[1]}` : url;
}

/**
 * One file's upload, as the web app's engine does it (#196): part URLs in batches of up to 100, then at most 4 PUTs at
 * once; the caller completes. `callPartUrls(numbers)` asks for URLs as a member's key or an uploader's session;
 * `body(n)` gives part n's bytes.
 */
export function uploadParts(callPartUrls, plan, body) {
  const numbers = Array.from({ length: plan.part_count }, (_, i) => i + 1);
  for (let start = 0; start < numbers.length; start += 100) {
    const parts = callPartUrls(numbers.slice(start, start + 100)).json('parts');
    for (let i = 0; i < parts.length; i += 4) {
      const batch = parts.slice(i, i + 4).map((p) => ({
        method: 'PUT',
        url: partUrl(p.url),
        body: body(p.part_number),
        params: { headers: p.headers || {}, tags: { name: 'putPart', kind: 'bytes' }, timeout: '600s' },
      }));
      for (const res of http.batch(batch)) expect(res, 'putPart', 200);
    }
  }
}

/** Polls `probe` every `every` seconds until it returns something, or fails after `seconds`. */
export function waitFor(what, probe, seconds, every = 2) {
  const deadline = Date.now() + seconds * 1000;
  for (;;) {
    const found = probe();
    if (found !== null && found !== undefined) return found;
    if (Date.now() > deadline) fail(`timed out waiting for ${what}`);
    sleep(every);
  }
}
