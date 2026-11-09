// The design-load test (#249; NFR-2, NFR-5, NFR-16; [PRD] 6.1, [CAP] 3, A42): docs/operations/performance.md.
//
// The peak hour of the design load, times the profile's `factor` (1 and 2 in staging, a small share on a laptop):
//
//   | Scenario        | Peak-hour rate at 1x | One iteration                                                           |
//   |-----------------|----------------------|-------------------------------------------------------------------------|
//   | transfers       | 1,000 an hour        | create to 2 recipients, 1 to 5 files of the mix uploaded in parts,      |
//   |                 |                      | send, wait until sent (time to shareable), then each recipient reads    |
//   |                 |                      | the link email, verifies with a code and downloads about 83 % of files  |
//   | upload_requests | 250 an hour          | create, the uploader verifies and uploads 1 to 5 files, the member      |
//   |                 |                      | waits until every file is available                                     |
//   | api_reads       | 138 a second         | one read a member's web app or integration makes: lists and details     |
//
// That is about 150 API calls a second in all, 5,000 downloads and about 2,250 verifications an hour at 1x ([CAP] 3.1).
// Every transfer's DLP decision is made; the load-test tenants' policies are in monitor mode, since an API key can't
// confirm a warning (confirmTransfer), so a decision never stops a send.
//
// Thresholds (the test fails if one is missed):
// - NFR-2: API calls, file bytes excluded: p95 <= 300 ms and p99 <= 1 s.
// - NFR-5: time to shareable, from the last upload's completion to `sent`: p95 <= 2 minutes for transfers whose largest
//   file is up to 100 MB, p95 <= 15 minutes otherwise; for an upload request, per file, to available to the member.
// - NFR-4: a download's first byte, p95 <= 1 s.
// - NFR-1's budget for the run: under 0.1 % of API calls fail, and every journey finishes.
// The server-side histograms (time_to_shareable_seconds, http_request_duration_seconds) are the record; these are the
// client's view of the same, so a run fails here before anyone opens a dashboard.
import exec from 'k6/execution';
import { group } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import { LinkBrowser, member, uploadParts, waitFor } from './lib/api.js';
import { drawFile } from './lib/corpus.js';
import { Mailbox } from './lib/mailbox.js';

const profile = JSON.parse(open(__ENV.PROFILE || '../profiles/local.json'));
// [{ "tenant": "<id>", "key": "<API key>" }, ...]: made by loadtest/setup_local.py locally, read from Secrets
// Manager in staging. A file, never an environment variable on the command line, so no key is in a process list.
const keys = JSON.parse(open(__ENV.KEYS_FILE));
const mailbox = new Mailbox(__ENV.MAILPIT_URL || 'http://127.0.0.1:8025', __ENV.MAILPIT_HOST_HEADER || '');
const mailDomain = __ENV.MAIL_DOMAIN || 'loadtest.sft.localhost';
const shard = __ENV.SHARD || '0';

const PEAK = { transfers: 1000 / 3600, uploadRequests: 250 / 3600, reads: 138 };
const STOPPED = ['held', 'cancelled', 'revoked', 'expired', 'awaiting_confirmation', 'pending_approval'];
const DOWNLOAD_SHARE = 0.83; // 5,000 downloads an hour over 1,000 transfers x 2 recipients x 3 files

const timeToShareable = new Trend('time_to_shareable', true);
const journeys = new Rate('journeys_completed');
const journeyFailures = new Counter('journey_failures');

function rate(perSecond) {
  // constant-arrival-rate takes a whole number per time unit: per hour keeps the small rates exact.
  return { rate: Math.max(1, Math.round(perSecond * profile.factor * 3600)), timeUnit: '1h' };
}

function scenario(fn, perSecond, vus) {
  return {
    executor: 'constant-arrival-rate',
    exec: fn,
    ...rate(perSecond),
    duration: profile.duration,
    preAllocatedVUs: vus[0],
    maxVUs: vus[1],
    gracefulStop: profile.gracefulStop || '10m',
  };
}

export const options = {
  scenarios: {
    transfers: scenario('transfers', PEAK.transfers, profile.vus.transfers),
    upload_requests: scenario('uploadRequests', PEAK.uploadRequests, profile.vus.uploadRequests),
    api_reads: scenario('reads', PEAK.reads, profile.vus.reads),
  },
  thresholds: {
    'http_req_duration{kind:api}': ['p(95)<=300', 'p(99)<=1000'],
    'http_req_failed{kind:api}': ['rate<0.001'],
    'http_req_waiting{name:getSessionDownloadContent}': ['p(95)<=1000'],
    'time_to_shareable{kind:transfer,size_class:small}': ['p(95)<=120000'],
    'time_to_shareable{kind:transfer,size_class:large}': ['p(95)<=900000'],
    'time_to_shareable{kind:request_file,size_class:small}': ['p(95)<=120000'],
    'time_to_shareable{kind:request_file,size_class:large}': ['p(95)<=900000'],
    journeys_completed: ['rate>=0.999'],
  },
  // Never the URL: a part URL carries its signature, and IDs add nothing to a percentile.
  systemTags: ['status', 'method', 'name', 'group', 'check', 'error', 'error_code', 'scenario', 'expected_response'],
  summaryTrendStats: ['avg', 'p(50)', 'p(95)', 'p(99)', 'max', 'count'],
  discardResponseBodies: false,
};

function key() {
  return keys[exec.scenario.iterationInTest % keys.length].key;
}

function address(kind) {
  // A fresh address every time, so no per-address cap of NFR-14 binds (abuse 2.2, A and G).
  return `lt-${kind}-${shard}-${exec.vu.idInTest}-${exec.scenario.iterationInTest}-${Date.now().toString(36)}@${mailDomain}`;
}

function files() {
  const count = 1 + Math.floor(Math.random() * 5); // 1 to 5: 3 on average ([PRD] 6.1)
  return Array.from({ length: count }, () => drawFile(profile));
}

function journey(name, body) {
  try {
    group(name, body);
    journeys.add(1);
  } catch (error) {
    journeys.add(0);
    journeyFailures.add(1, { journey: name });
    console.warn(`${name}: ${error.message || error}`); // the step and status only (lib/api.js)
  }
}

// ---- scenarios ----

export function transfers() {
  journey('transfer', () => {
    const k = key();
    const recipients = [address('r'), address('r')];
    const transfer = member(k, 'POST', '/v1/transfers', 'createTransfer', 201, {
      recipients: recipients.map((email) => ({ email })),
      expires_in: 'PT1H',
    }).json();
    const mix = files();
    const ids = [];
    for (const file of mix) {
      const declared = member(k, 'POST', `/v1/transfers/${transfer.id}/files`, 'addTransferFile', 201, {
        display_name: file.name,
        size: file.size,
        content_type: file.contentType,
      }).json();
      const plan = declared.upload;
      uploadParts(
        (numbers) => member(k, 'POST', `/v1/files/${declared.id}/parts`, 'requestUploadPartUrls', 200, { part_numbers: numbers }),
        plan,
        (n) => file.body(n, plan.part_size),
      );
      member(k, 'POST', `/v1/files/${declared.id}/complete`, 'completeUpload', 200);
      ids.push(declared.id);
    }
    const completed = Date.now();
    member(k, 'POST', `/v1/transfers/${transfer.id}/send`, 'sendTransfer', 200);
    const sizeClass = mix.some((f) => f.sizeClass === 'large') ? 'large' : 'small';
    waitFor(
      'the transfer to be sent',
      () => {
        const state = member(k, 'GET', `/v1/transfers/${transfer.id}`, 'getTransfer', 200).json('state');
        if (STOPPED.includes(state)) throw new Error(`the transfer became ${state}`);
        return state === 'sent' ? true : null;
      },
      sizeClass === 'small' ? 600 : 1800,
      3,
    );
    timeToShareable.add(Date.now() - completed, { kind: 'transfer', size_class: sizeClass });

    for (const recipient of recipients) {
      const browser = new LinkBrowser();
      browser.verify(mailbox.linkToken(recipient), mailbox, recipient);
      browser.call('GET', '/v1/session/files', 'listSessionFiles', 200);
      for (const id of ids) if (Math.random() < DOWNLOAD_SHARE) browser.download(id);
    }
  });
}

export function uploadRequests() {
  journey('upload_request', () => {
    const k = key();
    const uploader = address('u');
    const request = member(k, 'POST', '/v1/upload-requests', 'createUploadRequest', 201, {
      uploader_email: uploader,
    }).json();
    const browser = new LinkBrowser();
    browser.verify(mailbox.linkToken(uploader), mailbox, uploader);
    const mix = files();
    const completed = {};
    for (const file of mix) {
      const declared = browser
        .call('POST', '/v1/session/files', 'addSessionUploadFile', 201, {
          display_name: file.name,
          size: file.size,
          content_type: file.contentType,
        })
        .json();
      const plan = declared.upload;
      uploadParts(
        (numbers) =>
          browser.call('POST', `/v1/session/files/${declared.id}/parts`, 'requestSessionUploadPartUrls', 200, {
            part_numbers: numbers,
          }),
        plan,
        (n) => file.body(n, plan.part_size),
      );
      browser.call('POST', `/v1/session/files/${declared.id}/complete`, 'completeSessionUpload', 200);
      completed[declared.id] = { at: Date.now(), sizeClass: file.sizeClass };
    }
    // Each file, from its upload completing to available to the member ([PRD] NFR-5).
    const pending = new Set(Object.keys(completed));
    const largest = mix.some((f) => f.sizeClass === 'large') ? 1800 : 600;
    waitFor(
      'the received files to be available',
      () => {
        const items = member(k, 'GET', `/v1/upload-requests/${request.id}/files`, 'listUploadRequestFiles', 200).json('items');
        for (const item of items) {
          if (!pending.has(item.id)) continue;
          if (item.shareable) {
            const done = completed[item.id];
            timeToShareable.add(Date.now() - done.at, { kind: 'request_file', size_class: done.sizeClass });
            pending.delete(item.id);
          } else if (['infected', 'unscannable', 'scan_failed', 'rejected'].includes(item.state)) {
            throw new Error(`a received file became ${item.state}`);
          }
        }
        return pending.size === 0 ? true : null;
      },
      largest,
      3,
    );
  });
}

const READS = [
  ['listTransfers', '/v1/transfers?limit=20', 0.4],
  ['listTransfers', '/v1/transfers?scope=tenant&limit=50', 0.15],
  ['listUploadRequests', '/v1/upload-requests?limit=20', 0.2],
  ['getTenantPolicy', '/v1/tenant/policy', 0.25],
];

export function reads() {
  let roll = Math.random();
  for (const [op, path, share] of READS) {
    if (roll < share) {
      try {
        member(key(), 'GET', path, op, 200);
      } catch (error) {
        console.warn(`${op}: ${error.message || error}`);
      }
      return;
    }
    roll -= share;
  }
}

export function handleSummary(data) {
  const out = __ENV.SUMMARY_FILE || 'summary.json';
  return { [out]: JSON.stringify(data, null, 2), stdout: textSummary(data) };
}

function textSummary(data) {
  const lines = [`design load x${profile.factor} (${profile.name}), ${profile.duration}`];
  for (const [name, metric] of Object.entries(data.metrics)) {
    if (!metric.thresholds) continue;
    for (const [rule, result] of Object.entries(metric.thresholds)) {
      lines.push(`${result.ok ? 'PASS' : 'FAIL'}  ${name}  ${rule}`);
    }
  }
  return `${lines.join('\n')}\n`;
}
