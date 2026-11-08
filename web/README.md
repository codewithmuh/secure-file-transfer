# Web app

React + TypeScript web app for **secure-file-transfer** (FR-30). It serves members and admins in the
authenticated dashboard, and recipients and uploaders on the public verification and download/upload pages.

## Tech stack

| Concern | Choice |
|---|---|
| Build | Vite 8, Vitest 5 |
| Framework | React 18, TypeScript (strict) |
| Styling | Tailwind CSS 4, configured in `src/styles/index.css` (no `tailwind.config`) |
| Routing | React Router 7 (the `react-router` package) |
| Client state | Zustand |
| Server state | TanStack Query |
| HTTP | Axios, typed by the client generated from the API contract (below) |
| Validation | Zod 4 |
| i18n | react-i18next (EN + JA, FR-33) |

## Quick start

The local stack serves the built app at **http://localhost:3000** (always `localhost`, never `127.0.0.1`), on its own
origin as in AWS, beside the API, Keycloak and Mailpit:

```bash
make up && make seed   # from the repository root; then sign in as dev.member@example.com (docs/local-development.md 3)
```

For hot reload, run the dev server on the same address instead:

```bash
docker compose stop web
cd web
npm install
npm run dev     # http://localhost:3000, proxies /v1 to localhost:8000 (public/config.json: apiOrigin /v1)
npm run build   # production bundle in dist/
npm test        # unit tests (Vitest, *.test.ts next to the code)
npm run check   # type check, eslint, the routed-page mock check and unit tests; `make web-check` adds a clean install, the build and the client check, as CI
npm run gen:api # regenerate src/api/schema.ts from docs/api/openapi.yaml
make -C .. web-a11y  # axe on every page in English and Japanese, in the pinned Playwright image (needs Docker)
make -C .. web-e2e   # the browser flows against the running stack (needs make up and make seed, and Docker)
```

`make up` starts the built app again. [docs/local-development.md](../docs/local-development.md), section 8, says how to
test every flow by hand.

## Accessibility and translations

- **axe (NFR-22).** `e2e/pages.a11y.ts` runs axe (WCAG 2.0 to 2.2, A and AA) on every page in the table below, once
  in English and once in Japanese (`playwright.config.ts`), against the built app served by `vite preview`. The API
  is answered from contract-typed fixtures (`e2e/apiFixtures.ts`), so the live pages, the users page's action menu and
  its dialogs, the findings table, the upload request's revoke, unlock and delete dialogs, the extend expiry dialog
  and the uploader's code and upload steps are checked with real shapes and no backend. Any violation of a WCAG 2.0, 2.1 or 2.2 A or AA
  rule fails CI's `web-a11y` job, a required check, whatever impact axe gives it. Findings of axe's best-practice
  rules, which no WCAG criterion requires, are printed in the test output and don't fail it. axe needs a real browser
  for checks such as colour contrast, which jsdom can't compute, so this runs in Chromium through Playwright.
  `make web-a11y` runs it all in the Playwright image pinned in the Makefile, the same way locally and in CI, on a copy
  of `web/` inside the container, so no browser is installed on the host and nothing is written to it. When you bump
  `@playwright/test`, bump `PLAYWRIGHT_VERSION` and the image digest with it.
- **Translations (FR-33).** `src/lib/i18n.test.ts`, part of `npm test`, fails when English and Japanese don't have the
  same keys, a value is empty, or a key names different `{{placeholders}}` in the two. Plural forms (`_one`, `_other`)
  count as one key, since Japanese has only `_other`.
- **Language.** The app starts in the first of the browser's languages it has (English or Japanese), else English, and
  keeps `<html lang>` in step so screen readers read it in the right voice (WCAG 3.1.1). Every string a page shows or
  announces, `aria-label`s included, comes from `src/lib/i18n.ts`, so no English is read in a Japanese voice
  (WCAG 3.1.2). Names, emails and file names in the fixtures are data, not text to translate. The recipient and
  uploader pages switch to the link's `locale` (FR-33).

## Dependencies

- **Tailwind CSS 4** is configured in CSS (`src/styles/index.css`): `@theme` holds the brand colours, the font and
  the Tailwind 3 values of the colour families the pages use, so the upgrade (#134) changed no pixel. A short
  `@layer base` block keeps the Tailwind 3 defaults the pages rely on (border and placeholder colours, form field
  backgrounds, the pointer on buttons). `tailwind-merge` 3 is the version that knows Tailwind 4's class names.
- **`overrides` in `package.json`** lifts `minimatch` 10, which ESLint and typescript-eslint pull in, to 11 for
  GHSA-g3hv-75wg-m249. Both only call `new Minimatch(...).match()` and `minimatch()`, which 11 keeps. Drop the
  override once they depend on minimatch 11 themselves.
- **ESLint 10** keeps the lint rules of ESLint 9 plus what `@eslint/js` 10 added to `recommended`. Only the two
  classic React hooks rules are on (`rules-of-hooks`, `exhaustive-deps`); the React Compiler rules that
  `eslint-plugin-react-hooks` 7 recommends are not adopted yet.
- New and upgraded packages are at least 7 days old when they are added (threat model T-68):
  `npm install --before=<today minus 7 days>` resolves the whole tree as it was then.

## Structure

```
src/
├── api/           # Typed API client; schema.ts is generated from the contract
├── app/           # App-level setup: providers, router, entry
├── features/      # Feature modules (auth, sender, recipient, uploader, admin, audit)
├── components/
│   ├── ui/        # Shared primitives (Button, Input, Card, Badge, Table, Toast, …)
│   └── layout/    # AppLayout, PublicLayout, Header, Sidebar, PageShell
├── hooks/         # TanStack Query hooks over the typed client: transfers, files, users, the tenant policy
├── lib/           # Axios instance and its interceptors, config loader, i18n, formatting, cn()
├── stores/        # Zustand stores (auth, UI)
└── styles/        # Tailwind entry: theme, sources, component classes
```

## API client

Every call the web app makes goes through the API (FR-31), and its types come from the contract,
[`docs/api/openapi.yaml`](../docs/api/openapi.yaml), never from hand-written copies.

- `src/api/schema.ts` is generated by [openapi-typescript](https://openapi-ts.dev) (MIT, pinned in
  `package.json`): `npm run gen:api`. Don't edit it. It runs with `--default-non-nullable=false`, so a property with a
  `default` stays optional, as `required` says: a client may leave it out.
- `src/api/client.ts` is a small typed layer over the one axios instance in `src/lib/api.ts`:
  `api.get('/transfers/{transfer_id}', { path: { transfer_id } })` only accepts contract paths, needs the path
  parameters, query, headers and body the operation declares, and resolves to a response typed from the contract.
  Path parameters are percent-encoded, and an empty or `.`/`..` value is refused. The `/operator` paths are left out:
  only the operator API serves them (authn-authz 8.2).
- `src/api/index.ts` names the schemas the pages use (`Transfer`, `User`, `AuditEvent`, ...).
- Axios still does the sending, so its interceptors still choose the credential (the member CSRF token, or the link
  session ID and its token, authn-authz 1) and handle a `401` (#73). Uploads to presigned URLs keep axios's progress
  events.
- Answers the web app relies on for security, such as `GET /me`, are still checked at run time with Zod (fail closed),
  and those Zod schemas are typed against the generated types.

**When the contract changes**, run `npm run gen:api` and commit `schema.ts` with it. CI regenerates it in the `web`
job and fails on any difference, and the job runs when `docs/api/openapi.yaml` changes, not only `web/`. If the type
check then fails, the web app relied on something the contract no longer says.

## Pages

| Route | Page | Role |
|---|---|---|
| `/sign-in` | Sign-in: the password sign-in, and SSO once `config.ssoSignIn` is on (M6) | Public |
| `/auth/callback` | The web app's landing page after the API's own callback (`completeSignIn`): loads the session, then goes to the checked return path | Public |
| `/` | Dashboard: the five newest transfers and the five newest upload requests (`listTransfers`, `listUploadRequests`) | Member |
| `/transfers` | Transfer list, with a state filter and "load more"; an admin's "every transfer in the organization" switch (`scope=tenant`, #217) adds the owner and revoke | Member |
| `/transfers/new` | Create, upload and send a transfer; "email me on the first download" (`notify_on_first_download`, #214) | Member |
| `/transfers/:id` | Transfer detail: scan and DLP status, findings on demand, each recipient's delivery, verification and downloads, unlock, revoke, extend expiry (`extendTransferExpiry`, #214); a draft's upload resumes here. A DLP decision shows its matched rules, flagged recipients and findings, with confirm, request approval, remove file and cancel (#219, #220) | Member |
| `/upload-requests` | Upload requests (`listUploadRequests`, `scope=own`): state, link email and the uploader's access as badges with text, a state filter and "load more" (#212); an admin's "every request in the organization" switch (`scope=tenant`, #217) adds the owner and revoke | Member |
| `/upload-requests/new` | Ask someone for files (`createUploadRequest`): address, language, how long it stays open, message (#212) | Member |
| `/upload-requests/:id` | One request (`getUploadRequest`): state, expiry, link email, verified or locked, unlock (`unlockUploader`), revoke (`revokeUploadRequest`); the received files (`listUploadRequestFiles`) with findings on demand (`getFileInspection`), download (`createReceivedFileDownload`) and delete (`deleteFile`) (#212, #213) | Member (an admin sees another member's as metadata) |
| `/approvals`, `/approvals/:id` | DLP approvals (#220): an approver's queue and every request for an admin; a request's page with approve and reject. The sender may open their own request | Approver, admin |
| `/t` | The recipient's link page (#198): the link's state, the code, then each file's download, in the link's language | Public (link) |
| `/u` | The uploader's link page (#212, #213): the same link states and code step as `/t`, then the request and the uploads, in the link's language | Public (link) |
| `/admin/users` | Members and admins: invite, role, DLP approver, sign out everywhere, reset sign-in, deactivate | Admin |
| `/admin/policy` | Tenant policy, with the allowed and blocked recipient domains (#217), and a form that clears a suppressed email address (`clearEmailSuppression`, #217) | Admin |
| `/admin/audit` | Audit log (#216): filters in the POST body only (T-47), cursor paging, an event's details, CSV and JSON export | Admin |
| `/admin/api-keys` | API keys (#215): list, create (the secret shown once), revoke | Admin |
| `/admin/dlp` | DLP policy (#218): settings (mode, trusted domains, approval timeout), rules, keyword lists; every write confirmed | Admin |

Every M5 page is routed: upload requests and the uploader (#212, #213), the audit log and API keys (#215, #216), the
DLP policy and approvals (#218, #220). `npm run check:mocks` (part of `npm run check`) walks the imports from
`src/main.tsx` and fails on mock data or a simulated delay in any page the app can reach; none is pending since #198.

**The recipient's link page** (`/t`, #198, `features/recipient/`). `captureLinkToken` reads the token from the
fragment and removes it in `main.tsx`, before the config loads or React renders. `LinkGate` resolves the link, switches
the page to the link's `locale` (FR-33), gives `404 link_not_found`, `410 link_revoked`, `410 link_expired` and a
locked link a page each, resumes a session this browser already holds (`resolveLink` says `verified`) without a new
code, and otherwise asks for one (`VerificationPage`). `RecipientDownloadPage` shows the sender, message and expiry
only then (FR-14) and each file on its own (FR-6, FR-18). "Download" asks for a grant, checks its `url` from the app
(`checkContent`: a `GET` cancelled once the headers arrive, since `HEAD` isn't offered), so a `410`, `403` or `401` is
explained on the page instead of the browser showing the API's JSON, then navigates a hidden link to it, resolved
against the API's origin (`contentUrl`), so the browser's download manager saves and resumes it. The grant ID is kept
per session and file in `sessionStorage` only until the download is handed to the browser: a click after an
interrupted start (a `503`, or the page closed in between) resumes it uncounted, and a click after a hand-off counts a
new download, since the page can't see whether the browser finished. `LinkGate` is shared with `/u`.

**Upload requests** (#212, #213, `features/sender/`). The create form turns the chosen duration into the
`expires_at` the contract takes (now plus the duration and two minutes, never past the tenant's cap:
`uploadRequests.ts`), and keeps that body for the attempt, so "Try again" sends the same body with the same
`Idempotency-Key` and the API replays its answer instead of creating a second request. Revoking works as for a
transfer: a `503` is shown as done and retried in the background (`revocation.ts`). Unlocking always emails a new link.
The received files table polls while a file is scanned; findings are fetched only on demand, as counts per detector.
"Download" gets a grant (`createReceivedFileDownload`), checks it in the app and hands it to the browser's download
manager by navigation, as the recipient's page does (`checkContent`, `startDownload`, `contentUrl`); an unscannable
file shows the FR-18 warning. Only the request's owner downloads or deletes; an admin sees the metadata.

**The uploader's page** (`/u`, #212, #213, `features/uploader/`). `LinkGate` resolves the link (a transfer's link on
`/u` is "not found"), switches to its `locale`, verifies, then `UploaderUploadPage` shows who asks, the message, the
expiry and the limits (`LinkSession.upload_request`). Picked files are checked against those limits, declared with
`addSessionUploadFile` (with an `Idempotency-Key`) and uploaded by the M3 engine (`upload.ts`) over the session's
operations (`sessionUploadApi`: `listSessionUploadedParts`, `requestSessionUploadPartUrls`, `completeSessionUpload`),
which the API client sends with `X-Link-Session` and the session's CSRF token. A dropped connection resumes by itself
when the browser is back online; after a reload a file still `uploading` is picked again (matched on name and size)
and only its missing parts go. Each file's state comes from `listSessionFiles`, in the uploader's words: a blocked
file says only "blocked by the company's policy" or "couldn't be scanned" (FR-12). The list is polled, so a revocation
or an expiry ends the page within 15 seconds.

**Extend expiry and the first-download email** (#214, `features/sender/`). `/transfers/new` sends
`notify_on_first_download`. On `/transfers/:id` the owner of a submitted, not ended transfer gets "Extend expiry": the
dialog offers 1, 3, 7 and 14 days after the current expiry and the latest allowed, at most 30 days, or the tenant's
`max_expiry` if shorter, after `submitted_at` (`extension.ts`), and sends `extendTransferExpiry` with an
`Idempotency-Key`. When nothing later is allowed, the page says so instead.

## Browser journey

`web/e2e/journey.e2e.ts` (#200) is M3's exit test: #182's M2 journey, steps 1 to 9, through the browser, in English
and in Japanese (`playwright.e2e.config.ts`'s `en` and `ja` projects, browser locales `en-US` and `ja-JP`). It runs
with `make web-e2e`, after `make up` and `make seed`, with the other browser flows (`*.e2e.ts`, English only), and in
CI's Local stack job on every pull request. It uses only the browser, Mailpit's API, the seed, and the lifecycle jobs
with the clock's test hook: the container has no Docker, so `local/e2e-jobs.sh` runs the jobs on the host for it. Each
step runs the same axe check as `make web-a11y` (`e2e/support/axe.ts`) on the live page. A failure names its step and
keeps the trace and screenshots of every browser in `web/test-results/` (CI keeps them as the `web-e2e-results`
artifact).

**Browsers (NFR-22).** Chromium, in both languages, on every pull request. Firefox isn't run yet: the journey's time in
CI is to be measured first, and Firefox joins the PR run if it fits the job's budget, else a nightly run. WebKit
follows #195's open point: Safari doesn't keep `Secure` cookies on `http://localhost`, so it is checked in dev behind
real TLS (M4).

#199's lockout test (`e2e/recipients.e2e.ts`) drives the 20 failed attempts through `createLinkSession`, which count
against the per-IP quota of 30 failed codes an hour: one `make web-e2e` run an hour fits; `make down` and `make up`
clear the counters (Valkey keeps no volume).

## Security notes

- Link tokens travel in the URL fragment (`/t#token`, `/u#token`), removed with `history.replaceState` before
  anything else runs (architecture 4.2), and kept in memory only; they go only in request bodies. The link session's
  ID and CSRF token, checked with Zod, are kept in memory too. A download's grant ID is kept in `sessionStorage`: it
  is not a credential, since the content needs the `__Host-sft_link` cookie of the session that made it.
- CSRF tokens from `GET /me` are sent in `X-CSRF-Token` on every unsafe request.
- Part uploads go straight to object storage through their own axios instance (`features/sender/upload.ts`): no base
  URL, no cookies, no default `Content-Type` and none of the app's interceptors, so no CSRF token or link session ever
  reaches S3.
- Sign-out follows the API's logout URL only when it is on `config.signInOrigin` (Keycloak locally, managed login in
  AWS); any other origin or scheme, `javascript:` included, goes to `/sign-in` instead.
- Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`.
- No third-party scripts. CSP: `script-src 'self'` (ADR-0008).
- `config.json` is loaded at runtime, never baked into the build (one bundle for every environment), and checked with
  Zod: `apiOrigin` (`/v1` behind the dev server's proxy, or the API's absolute origin with `/v1`), `uploadOrigin`,
  `signInOrigin` and `ssoSignIn`.

## Data layer

Pages read the API through TanStack Query hooks in `src/hooks/` (`transfers.ts`, `uploadRequests.ts`, `users.ts`), over the typed `api`
client, never through `api` directly. Failures go through `src/lib/problems.ts`: `problemMessage` gives each problem
code the pages handle its own English and Japanese text and any other code the text of its HTTP status, and shows a
`Retry-After` on `429` and `503` as a wait. Calls that create something send an `Idempotency-Key` kept for the
attempt (`src/lib/idempotency.ts`), so "Try again" after a lost answer replays it. The transfer detail page polls
while the transfer is `submitted` or a file is uploading, completing or scanning (`features/sender/polling.ts`), and
findings are fetched only on demand, since each response with details is audited. A transfer waiting for an approver
is polled every 15 seconds; one waiting for its sender's confirmation or held isn't, and its DLP view
(`getTransferDlp`) is fetched again only when the transfer's state or decision changes (`dlpSignature`). Each recipient's delivery is polled
every 10 seconds while the transfer is `sent`. A revocation answered `503` stands but isn't confirmed: the page says
so, retries in the background and offers "Confirm now" (`features/sender/revocation.ts`).

## Status

Members create, upload and send transfers and watch their scan and DLP status (#196); admins manage members and the
tenant policy (#197). Recipients verify and download in their link's language (#198); members see each recipient's
delivery, unlock recipients and revoke transfers (#199); the M3 browser journey runs in English and Japanese (#200).
Members ask outsiders for files, and uploaders verify and upload on `/u` (#212, #213); members extend a transfer's
expiry and choose a first-download email (#214).
Admins manage the DLP policy, rules and keyword lists (#218); senders confirm warnings, clear blocks and request
approval, and approvers decide requests (#219, #220); `e2e/dlp.e2e.ts` runs those flows in English and Japanese.
