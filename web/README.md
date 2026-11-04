# Web app

React + TypeScript web app for **secure-file-transfer** (FR-30). It serves members and admins in the
authenticated dashboard, and recipients and uploaders on the public verification and download/upload pages.

## Tech stack

| Concern | Choice |
|---|---|
| Build | Vite |
| Framework | React 18, TypeScript (strict) |
| Styling | TailwindCSS |
| Routing | React Router v6 |
| Client state | Zustand |
| Server state | TanStack Query |
| HTTP | Axios |
| Validation | Zod |
| i18n | react-i18next (EN + JA, FR-33) |

## Quick start

```bash
cd web
npm install
npm run dev     # http://localhost:3000, proxies /v1 to localhost:8000
npm run build   # production bundle in dist/
npm run check   # tsc --noEmit + eslint
```

## Structure

```
src/
├── app/           # App-level setup: providers, router, entry
├── features/      # Feature modules (auth, sender, recipient, uploader, admin, audit)
├── components/
│   ├── ui/        # Shared primitives (Button, Input, Card, Badge, Table, Toast, …)
│   └── layout/    # AppLayout, PublicLayout, Header, Sidebar, PageShell
├── hooks/         # Shared hooks (empty, ready for TanStack Query hooks)
├── lib/           # API client, config loader, i18n, formatting, cn()
├── stores/        # Zustand stores (auth, UI)
├── types/         # Domain types matching the OpenAPI contract
└── styles/        # Tailwind entry + component classes
```

## Pages

| Route | Page | Role |
|---|---|---|
| `/sign-in` | SSO + local sign-in | Public |
| `/auth/callback` | Cognito redirect handler | Public |
| `/` | Dashboard | Member |
| `/transfers` | Transfer list | Member |
| `/transfers/new` | Create transfer wizard | Member |
| `/transfers/:id` | Transfer detail | Member |
| `/upload-requests` | Upload request list | Member |
| `/upload-requests/new` | Create upload request | Member |
| `/t` | Recipient verification + download | Public (link) |
| `/u` | Uploader verification + upload | Public (link) |
| `/admin/users` | User management | Admin |
| `/admin/policy` | Tenant policy | Admin |
| `/admin/audit` | Audit log search + export | Admin |
| `/admin/api-keys` | API key management | Admin |

## Security notes

- Link tokens travel in the URL fragment (`/t#token`), removed with `history.replaceState` before
  anything else runs (architecture 4.2).
- CSRF tokens from `GET /me` are sent in `X-CSRF-Token` on every unsafe request.
- Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`.
- No third-party scripts. CSP: `script-src 'self'` (ADR-0008).
- `config.json` is loaded at runtime, never baked into the build (one bundle for every environment).

## Status

This is the UI foundation with mock data. API integration happens when the backend endpoints exist
(the `apiClient` and TanStack Query are ready). The pages match the OpenAPI contract in
`docs/api/openapi.yaml`.
