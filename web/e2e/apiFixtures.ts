import type { Schema, Transfer, TransferSummary, User } from '../src/api';

/**
 * Contract-typed answers for the axe checks (#196, #197): what the live pages show, without a backend. Typed with the
 * generated contract types, so a contract change that breaks them fails the type check.
 */

const tenantId = '00000000-0000-4000-8000-000000000002';
const memberId = '00000000-0000-4000-8000-000000000001';
export const transferId = '0190c0de-0000-7000-8000-000000000010';
export const draftId = '0190c0de-0000-7000-8000-000000000011';
export const myNumberFileId = '0190c0de-0000-7000-8000-000000000021';

/** `CurrentMember`. The CSRF token only has the contract's shape; nothing checks it here. */
export const fakeAdmin: Schema<'CurrentMember'> = {
  user: {
    id: memberId,
    email: 'admin@example.com',
    role: 'admin',
    status: 'active',
    sso_fallback: false,
    dlp_approver: false,
    created_at: '2026-10-01T00:00:00Z',
  },
  tenant: { id: tenantId, name: 'Example Corp', status: 'active', created_at: '2026-01-01T00:00:00Z' },
  session: {
    auth_method: 'passkey',
    auth_time: '2026-11-08T00:00:00Z',
    effective_role: 'admin',
    expires_at: '2026-11-08T12:00:00Z',
  },
  csrf_token: `k1.${'A'.repeat(43)}`,
};

export const policy: Schema<'TenantPolicy'> = {
  max_expiry: 'P30D',
  unscannable_policy: 'block',
  received_file_retention_days: 30,
  allowed_domains: [],
  blocked_domains: [],
  default_locale: 'en',
  updated_at: '2026-11-01T00:00:00Z',
};

const summary = (id: string, state: TransferSummary['state'], days: number): TransferSummary => ({
  id,
  state,
  created_by: memberId,
  created_at: `2026-11-0${days}T05:00:00Z`,
  expires_at: state === 'draft' ? null : '2026-11-15T05:00:00Z',
  sent_at: state === 'sent' ? `2026-11-0${days}T05:10:00Z` : null,
  revoked_at: null,
  file_count: 2,
  recipient_count: 2,
  total_size: 15_000_000,
});

export const transferPage: Schema<'TransferPage'> = {
  items: [
    summary(transferId, 'sent', 7),
    summary(draftId, 'draft', 6),
    summary('0190c0de-0000-7000-8000-000000000012', 'held', 5),
    summary('0190c0de-0000-7000-8000-000000000013', 'submitted', 4),
    summary('0190c0de-0000-7000-8000-000000000014', 'expired', 3),
  ],
  next_cursor: 'next-page',
};

type ApiFile = Schema<'File'>;

const file = (id: string, name: string, state: ApiFile['state'], extra: Partial<ApiFile> = {}): ApiFile => ({
  id,
  transfer_id: transferId,
  upload_request_id: null,
  display_name: name,
  content_type: 'application/octet-stream',
  declared_size: 10_485_760,
  actual_size: state === 'uploading' ? null : 10_485_760,
  state,
  shareable: state === 'clean',
  inspection: { state: 'inspected', reasons: [], dlp_blocked: false, detectors: [] },
  scanned_at: state === 'clean' ? '2026-11-07T05:05:00Z' : null,
  scan_detail: null,
  created_at: '2026-11-07T05:00:00Z',
  ...extra,
});

const recipients: Transfer['recipients'] = [
  { id: '0190c0de-0000-7000-8000-000000000031', email: 'alice@example.com', locale: 'en', access_state: 'verified' },
  { id: '0190c0de-0000-7000-8000-000000000032', email: 'tanaka@example.co.jp', locale: 'ja', access_state: 'invited' },
];

/** A sent transfer: a clean file, a file with a My Number finding, an encrypted one and one over 2 GB. */
export const transfer: Transfer = {
  id: transferId,
  state: 'held',
  created_by: memberId,
  created_at: '2026-11-07T05:00:00Z',
  expires_in: 'P7D',
  expires_at: '2026-11-14T05:10:00Z',
  message: 'Q4 reports',
  download_limit: 5,
  notify_on_first_download: false,
  submitted_at: '2026-11-07T05:10:00Z',
  sent_at: null,
  revoked_at: null,
  revoked_by: null,
  total_size: 41_943_040,
  hold_reason: 'file_blocked',
  dlp: null,
  files: [
    file('0190c0de-0000-7000-8000-000000000020', 'report.pdf', 'clean'),
    file(myNumberFileId, 'staff-list.txt', 'clean', {
      inspection: { state: 'inspected', reasons: [], dlp_blocked: false, detectors: ['jp_my_number', 'custom:0190c0de'] },
    }),
    file('0190c0de-0000-7000-8000-000000000022', 'archive.zip', 'unscannable', {
      scan_detail: 'encrypted',
      inspection: { state: 'not_inspected', reasons: ['encrypted'], dlp_blocked: false, detectors: [] },
    }),
    file('0190c0de-0000-7000-8000-000000000023', 'eicar.com', 'infected', {
      inspection: { state: 'skipped', reasons: [], dlp_blocked: false, detectors: [] },
    }),
  ],
  recipients,
};

/** A draft whose upload stopped: the detail page asks to pick the file again. */
export const draft: Transfer = {
  ...transfer,
  id: draftId,
  state: 'draft',
  expires_at: null,
  submitted_at: null,
  hold_reason: null,
  files: [
    file('0190c0de-0000-7000-8000-000000000024', 'big.iso', 'uploading', {
      transfer_id: draftId,
      upload: { part_size: 5_242_880, part_count: 2 },
      inspection: { state: 'pending', reasons: [], dlp_blocked: false, detectors: [] },
    }),
  ],
};

export const inspection: Schema<'FileInspection'> = {
  file_id: myNumberFileId,
  state: 'inspected',
  reasons: [],
  dlp_blocked: false,
  engine_version: '1.0.0',
  policy_version: 1,
  inspected_at: '2026-11-07T05:05:00Z',
  findings: [
    {
      detector: 'jp_my_number',
      detector_name: 'My Number (Individual Number)',
      count_low: 0,
      count_medium: 1,
      count_high: 2,
      details_visible: true,
      locations: [{ line: 3 }, { line: 7 }],
      previews: [],
    },
    {
      detector: 'custom:0190c0de',
      detector_name: 'Project code',
      count_low: 1,
      count_medium: 0,
      count_high: 0,
      details_visible: false,
    },
  ],
};

const user = (id: string, email: string, role: User['role'], status: User['status'], dlp = false): User => ({
  id,
  email,
  role,
  status,
  sso_fallback: false,
  dlp_approver: dlp,
  created_at: '2026-10-15T00:00:00Z',
});

export const userPage: Schema<'UserPage'> = {
  items: [
    user(memberId, 'admin@example.com', 'admin', 'active', true),
    user('00000000-0000-4000-8000-000000000003', 'member@example.com', 'member', 'active'),
    user('00000000-0000-4000-8000-000000000004', 'new@example.com', 'member', 'invited'),
    user('00000000-0000-4000-8000-000000000005', 'left@example.com', 'member', 'deactivated'),
  ],
  next_cursor: null,
};

/** An expired transfer: read-only on its detail page (#199). */
export const expiredId = '0190c0de-0000-7000-8000-000000000014';
export const expired: Transfer = {
  ...transfer,
  id: expiredId,
  state: 'expired',
  hold_reason: null,
  sent_at: '2026-11-07T05:10:00Z',
  files: transfer.files.map((f) => ({ ...f, state: 'deleted', shareable: false })),
};

const recipientStatus = (
  id: string,
  email: string,
  extra: Partial<Schema<'RecipientStatus'>> = {},
): Schema<'RecipientStatus'> => ({
  id,
  email,
  locale: 'en',
  access_state: 'invited',
  delivery_state: 'sent',
  notified_at: '2026-11-07T05:11:00Z',
  first_verified_at: null,
  last_verified_at: null,
  failed_attempts: 0,
  locked_at: null,
  downloads: [],
  ...extra,
});

/** Every delivery and access state the table shows (#199): verified with downloads, locked, bounced, suppressed. */
export const recipientStatuses: Schema<'RecipientStatusList'> = {
  items: [
    recipientStatus('0190c0de-0000-7000-8000-000000000031', 'alice@example.com', {
      access_state: 'verified',
      first_verified_at: '2026-11-07T06:00:00Z',
      last_verified_at: '2026-11-07T08:00:00Z',
      downloads: [
        {
          file_id: '0190c0de-0000-7000-8000-000000000020',
          count: 1,
          first_downloaded_at: '2026-11-07T06:01:00Z',
          last_downloaded_at: '2026-11-07T06:01:00Z',
        },
      ],
    }),
    recipientStatus('0190c0de-0000-7000-8000-000000000032', 'tanaka@example.co.jp', {
      locale: 'ja',
      access_state: 'locked',
      failed_attempts: 20,
      locked_at: '2026-11-07T07:00:00Z',
    }),
    recipientStatus('0190c0de-0000-7000-8000-000000000033', 'gone@example.org', {
      delivery_state: 'bounced',
      failed_attempts: 2,
    }),
    recipientStatus('0190c0de-0000-7000-8000-000000000034', 'blocked@example.org', {
      delivery_state: 'suppressed',
      notified_at: null,
    }),
    recipientStatus('0190c0de-0000-7000-8000-000000000035', 'later@example.org', {
      delivery_state: 'queued',
      notified_at: null,
    }),
  ],
};

// ---- the recipient's link page (#198) ----

export const linkSessionId = '0190c0de-0000-7000-8000-0000000000e1';

/** A problem document, as the API answers an error. */
export function problemOf(status: number, code: Schema<'ProblemCode'>, extra: Partial<Schema<'Problem'>> = {}): Schema<'Problem'> {
  return { type: `https://secure-file-transfer.example/problems/${code}`, title: code, status, code, ...extra };
}

export const resolution = (locale: Schema<'Locale'>, access: Schema<'LinkResolution'>['access_state'] = 'verification_required') =>
  ({
    kind: 'transfer',
    access_state: access,
    locale,
    ...(access === 'verified' ? { link_session_id: linkSessionId } : {}),
  }) satisfies Schema<'LinkResolution'>;

export const codeRequested: Schema<'VerificationCodeRequested'> = { code_valid_for_seconds: 600, max_attempts: 5 };

export const linkSession = (locale: Schema<'Locale'>): Schema<'LinkSession'> => ({
  id: linkSessionId,
  csrf_token: `k1.${'B'.repeat(43)}`,
  kind: 'transfer',
  email: 'tanaka@example.co.jp',
  locale,
  expires_at: '2026-11-09T05:00:00Z',
  transfer: {
    tenant_name: 'Example Corp',
    sender_email: 'admin@example.com',
    message: 'Q4 reports, as discussed.',
    expires_at: '2026-11-14T05:10:00Z',
    download_limit: 2,
  },
});

/** A clean file, one whose downloads are used up, and an unscannable one allowed by policy, with its warning. */
export const sessionFiles: Schema<'SessionFileList'> = {
  items: [
    {
      id: '0190c0de-0000-7000-8000-000000000020',
      display_name: 'report.pdf',
      content_type: 'application/pdf',
      size: 10_485_760,
      state: 'clean',
      download_limit: 2,
      downloads_used: 1,
    },
    {
      id: '0190c0de-0000-7000-8000-000000000025',
      display_name: 'budget.xlsx',
      content_type: 'application/vnd.ms-excel',
      size: 2_048_000,
      state: 'clean',
      download_limit: 2,
      downloads_used: 2,
    },
    {
      id: '0190c0de-0000-7000-8000-000000000022',
      display_name: 'archive.zip',
      content_type: 'application/zip',
      size: 4_096_000,
      state: 'unscannable',
      warning: 'unscannable',
      download_limit: 2,
      downloads_used: 0,
    },
  ],
};
