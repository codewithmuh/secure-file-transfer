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
  its dialogs, and the findings table are checked with real shapes and no backend. Any violation of a WCAG 2.0, 2.1 or 2.2 A or AA
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
  (WCAG 3.1.2). Names, emails and file names in the mock data are data, not text to translate. The recipient and
  uploader pages will switch to the link's `locale` once they call the API (FR-33).

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
| `/` | Dashboard: the five newest transfers | Member |
| `/transfers` | Transfer list, with a state filter and "load more" | Member |
| `/transfers/new` | Create, upload and send a transfer | Member |
| `/transfers/:id` | Transfer detail: scan and DLP status, findings on demand; a draft's upload resumes here | Member |
| `/t` | Recipient verification + download (live with #198) | Public (link) |
| `/admin/users` | Members and admins: invite, role, DLP approver, sign out everywhere, reset sign-in, deactivate | Admin |
| `/admin/policy` | Tenant policy | Admin |
| `/upload-requests`, `/u`, `/admin/audit`, `/admin/api-keys`, `/admin/dlp` | Not available yet (M5): no navigation entry; the URL shows `NotAvailableYet` | — |

M5's pages stay in the repository unrouted (`UploadRequestListPage`, `CreateUploadRequestPage`, `UploaderPage`,
`AuditLogPage`, `ApiKeysPage`): nothing imports them, so the bundle leaves them and their mock data out, and M5 routes
each again as its operations land. `npm run check:mocks` (part of `npm run check`) walks the imports from
`src/main.tsx` and fails on mock data or a simulated delay in any page the app can reach; the recipient pages are listed
there as pending #198.

## Security notes

- Link tokens travel in the URL fragment (`/t#token`), removed with `history.replaceState` before
  anything else runs (architecture 4.2).
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

Pages read the API through TanStack Query hooks in `src/hooks/` (`transfers.ts`, `users.ts`), over the typed `api`
client, never through `api` directly. Failures go through `src/lib/problems.ts`: `problemMessage` gives each problem
code the pages handle its own English and Japanese text and any other code the text of its HTTP status, and shows a
`Retry-After` on `429` and `503` as a wait. Calls that create something send an `Idempotency-Key` kept for the
attempt (`src/lib/idempotency.ts`), so "Try again" after a lost answer replays it. The transfer detail page polls
while the transfer is `submitted` or a file is uploading, completing or scanning (`features/sender/polling.ts`), and
findings are fetched only on demand, since each response with details is audited.

## Status

Members create, upload and send transfers and watch their scan and DLP status (#196); admins manage members and the
tenant policy (#197). The recipient pages become live with #198, the delivery table, unlock and revoke with #199, and
the M3 browser journey in English and Japanese with #200.
