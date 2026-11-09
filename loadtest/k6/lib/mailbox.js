// The recipients' and uploaders' inbox: Mailpit's search API. Locally that is the stack's Mailpit; in staging it is
// loadtest/mailbox_bridge.py, which serves the same two calls from the SES receipt rule's bucket. The link token after
// `/t#` (a transfer) or `/u#` (an upload request) and the verification code are all that is read; neither is logged.
import http from 'k6/http';
import { fail, sleep } from 'k6';

const LINK = /\/[tu]#([A-Za-z0-9_-]{22,128})/;
// A run of 6 to 10 digits on its own; no lookbehind, which not every JavaScript engine k6 has used supports.
const CODE = /(^|[^0-9])([0-9]{6,10})($|[^0-9])/;

export class Mailbox {
  // `hostHeader`: Mailpit refuses Host headers it doesn't list (MP_ALLOWED_HOSTS), so a k6 container that reaches the
  // laptop's Mailpit as host.docker.internal names it as the stack does, localhost:8025.
  constructor(baseUrl, hostHeader = '') {
    this.base = baseUrl.replace(/\/$/, '');
    this.headers = hostHeader ? { Host: hostHeader } : {};
  }

  texts(address) {
    const params = { headers: this.headers, tags: { name: 'mailSearch', kind: 'mail' } };
    const found = http.get(`${this.base}/api/v1/search?limit=50&query=${encodeURIComponent(`to:"${address}"`)}`, params);
    if (found.status !== 200) return [];
    const messages = found.json('messages') || [];
    // Oldest first.
    return messages.reverse().map((m) => {
      const one = http.get(`${this.base}/api/v1/message/${m.ID}`, {
        headers: this.headers,
        tags: { name: 'mailMessage', kind: 'mail' },
      });
      return one.status === 200 ? one.json('Text') || '' : '';
    });
  }

  codes(address) {
    return this.texts(address)
      .filter((text) => !LINK.test(text))
      .map((text) => (CODE.exec(text) || [])[2])
      .filter(Boolean);
  }

  /** The link in the first email to `address` that has one, waiting up to `seconds`. */
  linkToken(address, seconds = 300) {
    const deadline = Date.now() + seconds * 1000;
    for (;;) {
      for (const text of this.texts(address)) {
        const found = LINK.exec(text);
        if (found) return found[1];
      }
      if (Date.now() > deadline) fail('timed out waiting for a link email');
      sleep(2);
    }
  }

  /** The code that arrives after the `seen` codes already there. */
  newCode(address, seen, seconds = 120) {
    const deadline = Date.now() + seconds * 1000;
    for (;;) {
      const codes = this.codes(address);
      if (codes.length > seen) return codes[codes.length - 1];
      if (Date.now() > deadline) fail('timed out waiting for a code email');
      sleep(2);
    }
  }
}
