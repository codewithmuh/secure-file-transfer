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
    // An approver too, so the sidebar shows Approvals with its badge, and the queue is the approver's (#220).
    dlp_approver: true,
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

// ---- upload requests: the member's pages (#212, #213) ----

export const uploadRequestId = '0190c0de-0000-7000-8000-0000000000b1';
export const receivedFindingsFileId = '0190c0de-0000-7000-8000-0000000000c2';

const uploadRequest = (id: string, extra: Partial<Schema<'UploadRequest'>> = {}): Schema<'UploadRequest'> => ({
  id,
  state: 'open',
  created_by: memberId,
  created_at: '2026-11-06T05:00:00Z',
  uploader_email: 'supplier@example.com',
  locale: 'ja',
  message: 'Please upload the signed contract and the invoice.',
  expires_at: '2026-11-13T05:00:00Z',
  revoked_at: null,
  revoked_by: null,
  uploader_access_state: 'invited',
  delivery_state: 'sent',
  notified_at: '2026-11-06T05:00:05Z',
  failed_attempts: 0,
  locked_at: null,
  file_count: 0,
  total_size: 0,
  ...extra,
});

/** An open request whose uploader is locked (the unlock dialog), with files received. */
export const openRequest = uploadRequest(uploadRequestId, {
  uploader_access_state: 'locked',
  failed_attempts: 20,
  locked_at: '2026-11-07T01:00:00Z',
  file_count: 4,
  total_size: 25_165_824,
});

/** Every state, link email and access state the list shows. */
export const uploadRequestPage: Schema<'UploadRequestPage'> = {
  items: [
    openRequest,
    uploadRequest('0190c0de-0000-7000-8000-0000000000b2', {
      uploader_email: 'accountant@example.co.jp',
      uploader_access_state: 'verified',
      file_count: 2,
      total_size: 8_000_000,
    }),
    uploadRequest('0190c0de-0000-7000-8000-0000000000b3', { delivery_state: 'queued', notified_at: null, locale: 'en' }),
    uploadRequest('0190c0de-0000-7000-8000-0000000000b4', { state: 'revoked', revoked_at: '2026-11-05T00:00:00Z', revoked_by: memberId }),
    uploadRequest('0190c0de-0000-7000-8000-0000000000b5', { state: 'expired', delivery_state: 'bounced' }),
  ],
  next_cursor: null,
};

// ---- M5 administration (#215, #216, #217) ----

const otherAdminId = '00000000-0000-4000-8000-000000000006';

const apiKey = (id: string, name: string, extra: Partial<Schema<'ApiKey'>> = {}): Schema<'ApiKey'> => ({
  id,
  name,
  key_prefix: 'sft_dev_Ab3dE6gH',
  scopes: ['transfers:read', 'transfers:write'],
  created_by: memberId,
  created_at: '2026-10-01T00:00:00Z',
  expires_at: '2027-01-01T00:00:00Z',
  last_used_at: '2026-11-07T04:00:00Z',
  revoked_at: null,
  ...extra,
});

/** An active key of the signed-in admin, one of another admin, an expired one and a revoked one. */
export const apiKeyPage: Schema<'ApiKeyPage'> = {
  items: [
    apiKey('0190c0de-0000-7000-8000-0000000000a1', 'CI pipeline'),
    apiKey('0190c0de-0000-7000-8000-0000000000a2', 'Audit export', {
      scopes: ['audit:read'],
      created_by: otherAdminId,
      key_prefix: 'sft_dev_Zy9xW8vU',
      last_used_at: null,
    }),
    apiKey('0190c0de-0000-7000-8000-0000000000a3', 'Old sync', { expires_at: '2026-11-01T00:00:00Z' }),
    apiKey('0190c0de-0000-7000-8000-0000000000a4', 'Retired', { revoked_at: '2026-10-20T00:00:00Z' }),
  ],
  next_cursor: null,
};

const received = (id: string, name: string, state: ApiFile['state'], extra: Partial<ApiFile> = {}): ApiFile =>
  file(id, name, state, {
    transfer_id: null,
    upload_request_id: uploadRequestId,
    retention_until: '2026-12-07T05:00:00Z',
    ...extra,
  });

/** What arrived: a clean file with findings, one allowed though unscannable (FR-18), one infected, one still scanning. */
export const receivedFiles: Schema<'FileList'> = {
  items: [
    received('0190c0de-0000-7000-8000-0000000000c1', 'contract.pdf', 'clean'),
    received(receivedFindingsFileId, 'staff-list.xlsx', 'clean', {
      inspection: { state: 'inspected', reasons: [], dlp_blocked: false, detectors: ['jp_my_number'] },
    }),
    received('0190c0de-0000-7000-8000-0000000000c3', 'invoice.zip', 'unscannable', {
      shareable: true,
      scan_detail: 'encrypted',
      inspection: { state: 'not_inspected', reasons: ['encrypted'], dlp_blocked: false, detectors: [] },
    }),
    received('0190c0de-0000-7000-8000-0000000000c4', 'setup.exe', 'infected', {
      inspection: { state: 'skipped', reasons: [], dlp_blocked: false, detectors: [] },
    }),
    received('0190c0de-0000-7000-8000-0000000000c5', 'photos.zip', 'scanning', {
      retention_until: null,
      inspection: { state: 'pending', reasons: [], dlp_blocked: false, detectors: [] },
    }),
  ],
};

export const receivedInspection: Schema<'FileInspection'> = { ...inspection, file_id: receivedFindingsFileId };

// ---- the uploader's link page (#212, #213) ----

export const uploaderResolution = (locale: Schema<'Locale'>, access: Schema<'LinkResolution'>['access_state'] = 'verification_required') =>
  ({ ...resolution(locale, access), kind: 'upload_request' }) satisfies Schema<'LinkResolution'>;

export const uploaderSession = (locale: Schema<'Locale'>): Schema<'LinkSession'> => ({
  id: linkSessionId,
  csrf_token: `k1.${'C'.repeat(43)}`,
  kind: 'upload_request',
  email: 'supplier@example.com',
  locale,
  expires_at: '2026-11-09T05:00:00Z',
  upload_request: {
    tenant_name: 'Example Corp',
    requester_email: 'admin@example.com',
    message: 'Please upload the signed contract and the invoice.',
    expires_at: '2026-11-13T05:00:00Z',
    max_files: 50,
    max_file_size: 5_000_000_000,
    max_total_size: 20_000_000_000,
    files_received: 3,
    bytes_received: 16_777_216,
  },
});

/** The uploader's files: received, blocked, unscannable and one left uploading by an earlier visit. */
export const uploaderFiles: Schema<'SessionFileList'> = {
  items: [
    { id: '0190c0de-0000-7000-8000-0000000000c1', display_name: 'contract.pdf', content_type: 'application/pdf', size: 10_485_760, state: 'clean' },
    { id: '0190c0de-0000-7000-8000-0000000000c4', display_name: 'setup.exe', content_type: 'application/octet-stream', size: 2_097_152, state: 'infected' },
    { id: '0190c0de-0000-7000-8000-0000000000c3', display_name: 'invoice.zip', content_type: 'application/zip', size: 4_194_304, state: 'scan_failed' },
    {
      id: '0190c0de-0000-7000-8000-0000000000c6',
      display_name: 'large.mov',
      content_type: 'video/quicktime',
      size: 10_485_760,
      state: 'uploading',
      upload: { part_size: 5_242_880, part_count: 2 },
    },
  ],
};

// ---- extend expiry (#214) ----

/** A sent transfer the member can extend: its times are relative to now, so the dialog has choices on any day. */
export function extendableTransfer(now = Date.now()): Transfer {
  const day = 86_400_000;
  const submitted = new Date(now - 2 * day).toISOString();
  return {
    ...transfer,
    state: 'sent',
    hold_reason: null,
    notify_on_first_download: true,
    submitted_at: submitted,
    sent_at: submitted,
    expires_at: new Date(now + 5 * day).toISOString(),
  };
}

/**
 * `createApiKey`'s answer. The secret has the contract's shape but is built here at run time, so no key-shaped string
 * sits in the repository for a secret scanner to find; it is fake either way.
 */
export function apiKeyCreated(): Schema<'ApiKeyCreated'> {
  const secret = ['sft', 'dev', 'F'.repeat(43), 'A'.repeat(6)].join('_');
  return { ...apiKey('0190c0de-0000-7000-8000-0000000000a5', 'New integration', { last_used_at: null }), secret };
}

const auditEvent = (n: number, extra: Partial<Schema<'AuditEvent'>> = {}): Schema<'AuditEvent'> => ({
  id: `0190c0de-0000-7000-8000-0000000001${String(n).padStart(2, '0')}`,
  occurred_at: `2026-11-07T0${n % 10}:00:00Z`,
  actor_type: 'member',
  actor_id: memberId,
  actor_email: 'admin@example.com',
  action: 'transfer.created',
  target_type: 'transfer',
  target_id: transferId,
  source_ip: '203.0.113.1',
  user_agent: 'Mozilla/5.0',
  request_id: `req-${n}`,
  security_critical: false,
  details: {},
  ...extra,
});

/** UC-4's answer: who downloaded the transfer, from which IP, plus a revocation and a key's use. */
export const auditPage: Schema<'AuditEventPage'> = {
  items: [
    auditEvent(9, {
      actor_type: 'recipient',
      actor_id: '0190c0de-0000-7000-8000-000000000031',
      actor_email: 'alice@example.com',
      action: 'download.granted',
      target_type: 'file',
      target_id: '0190c0de-0000-7000-8000-000000000020',
      source_ip: '198.51.100.5',
      details: { transfer_id: transferId, recipient_id: '0190c0de-0000-7000-8000-000000000031', count: 1 },
    }),
    auditEvent(8, { action: 'transfer.revoked', security_critical: true, details: { reason: 'admin' } }),
    auditEvent(7, {
      actor_type: 'api_key',
      actor_id: '0190c0de-0000-7000-8000-0000000000a1',
      actor_email: null,
      action: 'api_key.used',
      target_type: null,
      target_id: null,
      details: { operation: 'listTransfers', status: 200, owner_id: memberId },
    }),
    auditEvent(6),
  ],
  next_cursor: 'older-page',
};

/** Another member's open upload request, for the admin's tenant-wide list (#217). */
export const tenantUploadRequestPage: Schema<'UploadRequestPage'> = {
  items: [
    uploadRequest('0190c0de-0000-7000-8000-0000000000b6', { created_by: '00000000-0000-4000-8000-000000000003' }),
    ...uploadRequestPage.items,
  ],
  next_cursor: null,
};

/** Another member's sent transfer, for the admin's tenant-wide list. */
export const tenantTransferPage: Schema<'TransferPage'> = {
  items: [
    { ...summary('0190c0de-0000-7000-8000-000000000015', 'sent', 8), created_by: '00000000-0000-4000-8000-000000000003' },
    ...transferPage.items,
  ],
  next_cursor: null,
};

// ---- DLP (#218 to #220): the policy, rules and keyword lists; a transfer in each DLP state; approval requests ----

const otherMemberId = '00000000-0000-4000-8000-000000000003';
export const keywordListId = 'custom:0190c0de-0000-7000-8000-0000000000c1';
/** The keyword list's address on the admin page: `custom:<id>`, its colon encoded as the app encodes it. */
export const keywordListPath = encodeURIComponent(keywordListId);

export const dlpPolicy: Schema<'DlpPolicy'> = {
  mode: 'enforce',
  version: 12,
  trusted_domains: ['partner.example', 'example.co.jp'],
  approval_timeout: 'PT72H',
  active_approvers: 2,
  updated_at: '2026-11-07T00:00:00Z',
  updated_by: memberId,
};

const builtIn = (id: string, name: string, description: string): Schema<'DlpDetector'> => ({
  id,
  kind: 'built_in',
  name,
  description,
  enabled: true,
});

export const keywordList: Schema<'DlpDetector'> = {
  id: keywordListId,
  kind: 'keywords',
  name: 'Project names',
  enabled: true,
  revision: 2,
  keywords: ['Bluebird', 'Kingfisher', '青い鳥'],
  created_at: '2026-11-05T00:00:00Z',
};

export const dlpDetectors: Schema<'DlpDetectorList'> = {
  engine_version: '1.0.0',
  items: [
    builtIn('jp_my_number', 'My Number (Individual Number)', 'Twelve digits with a valid check digit.'),
    builtIn('payment_card', 'Payment card number', 'Card numbers that pass the Luhn check.'),
    builtIn('cloud_credential', 'Cloud credential', 'Access keys of the major cloud providers.'),
    keywordList,
  ],
};

const rule = (id: string, name: string, extra: Partial<Schema<'DlpRule'>>): Schema<'DlpRule'> => ({
  id,
  revision: 1,
  name,
  enabled: true,
  direction: 'sent',
  condition: 'content',
  detectors: [],
  min_confidence: 'medium',
  threshold: 1,
  reasons: [],
  include_sender_24h: false,
  recipient_scope: 'any',
  action: 'warn',
  approvals_required: 1,
  created_by: memberId,
  created_at: '2026-11-01T00:00:00Z',
  ...extra,
});

export const myNumberRuleId = '0190c0de-0000-7000-8000-0000000000d1';

export const dlpRules: Schema<'DlpRuleList'> = {
  policy_version: 12,
  items: [
    rule(myNumberRuleId, 'My Numbers', { detectors: ['jp_my_number'], min_confidence: 'high' }),
    rule('0190c0de-0000-7000-8000-0000000000d2', 'Project names to outsiders', {
      detectors: [keywordListId],
      recipient_scope: 'untrusted',
      action: 'require_approval',
    }),
    rule('0190c0de-0000-7000-8000-0000000000d3', 'Files that couldn\'t be fully inspected', {
      condition: 'not_inspected',
      reasons: ['encrypted', 'too_large', 'limit_exceeded', 'parse_error'],
    }),
    rule('0190c0de-0000-7000-8000-0000000000d4', 'Credentials', { detectors: ['cloud_credential'], action: 'block', enabled: false }),
    rule('0190c0de-0000-7000-8000-0000000000d5', 'New recipient domain', { condition: 'new_domain' }),
  ],
};

const matchedRule = (index: number, action: Schema<'DlpAction'>, condition: Schema<'DlpRuleCondition'> = 'content') => ({
  rule_id: dlpRules.items[index]?.id ?? myNumberRuleId,
  revision: 1,
  name: dlpRules.items[index]?.name ?? 'My Numbers',
  condition,
  action,
  matched_count: condition === 'new_domain' ? 1 : 3,
  threshold: condition === 'content' ? 1 : null,
});

export const warnedId = '0190c0de-0000-7000-8000-000000000041';
export const approvalNeededId = '0190c0de-0000-7000-8000-000000000042';
export const pendingId = '0190c0de-0000-7000-8000-000000000043';
export const blockedId = '0190c0de-0000-7000-8000-000000000044';
export const rejectedId = '0190c0de-0000-7000-8000-000000000045';
export const pendingRequestId = '0190c0de-0000-7000-8000-000000000051';
export const rejectedRequestId = '0190c0de-0000-7000-8000-000000000052';
/** A request from another member, which the signed-in approver can decide. */
export const queueRequestId = '0190c0de-0000-7000-8000-000000000053';

const dlpTransfer = (
  id: string,
  state: Transfer['state'],
  outcome: Schema<'DlpOutcome'>,
  extra: Partial<Transfer> = {},
): Transfer => ({
  ...transfer,
  id,
  state,
  hold_reason: null,
  sent_at: null,
  dlp: { outcome, mode: 'enforce', enforced: true, approval_request_id: null },
  files: [
    file('0190c0de-0000-7000-8000-000000000061', 'report.pdf', 'clean', { transfer_id: id }),
    file('0190c0de-0000-7000-8000-000000000062', 'staff-list.xlsx', 'clean', {
      transfer_id: id,
      inspection: { state: 'inspected', reasons: [], dlp_blocked: false, detectors: ['jp_my_number', keywordListId] },
    }),
  ],
  recipients: [
    { id: '0190c0de-0000-7000-8000-000000000071', email: 'alice@partner.example', locale: 'en', access_state: 'invited' },
    { id: '0190c0de-0000-7000-8000-000000000072', email: 'kim@newcorp.example', locale: 'en', access_state: 'invited' },
  ],
  ...extra,
});

export const warned = dlpTransfer(warnedId, 'awaiting_confirmation', 'warn');
export const approvalNeeded = dlpTransfer(approvalNeededId, 'awaiting_confirmation', 'require_approval');
export const pending = dlpTransfer(pendingId, 'pending_approval', 'require_approval', {
  dlp: { outcome: 'require_approval', mode: 'enforce', enforced: true, approval_request_id: pendingRequestId },
});
export const blocked = dlpTransfer(blockedId, 'held', 'block', { hold_reason: 'dlp_blocked' });
export const rejected = dlpTransfer(rejectedId, 'held', 'require_approval', {
  hold_reason: 'approval_rejected',
  dlp: { outcome: 'require_approval', mode: 'enforce', enforced: true, approval_request_id: rejectedRequestId },
});

const findings = (): Schema<'DlpFinding'>[] => [
  { detector: 'jp_my_number', detector_name: 'My Number (Individual Number)', count_low: 0, count_medium: 1, count_high: 2, details_visible: false },
  { detector: keywordListId, detector_name: 'Project names', count_low: 0, count_medium: 0, count_high: 4, details_visible: false },
];

const recipientChecks: Schema<'DlpRecipientCheck'>[] = [
  { recipient_id: '0190c0de-0000-7000-8000-000000000071', email: 'alice@partner.example', trusted: true, new_domain: false },
  { recipient_id: '0190c0de-0000-7000-8000-000000000072', email: 'kim@newcorp.example', trusted: false, new_domain: true },
];

const requestSummary = (
  id: string,
  state: Schema<'ApprovalState'>,
  transferId: string,
  requestedBy = memberId,
): Schema<'ApprovalRequestSummary'> => ({
  id,
  transfer_id: transferId,
  state,
  requested_by: requestedBy,
  requested_at: '2026-11-08T01:00:00Z',
  expires_at: '2026-11-11T01:00:00Z',
  approvals_required: 1,
  approvals: 0,
  rule_names: ['Project names to outsiders'],
});

const transferDlp = (
  of: Transfer,
  outcome: Schema<'DlpOutcome'>,
  rules: ReturnType<typeof matchedRule>[],
  request: Schema<'ApprovalRequestSummary'> | null = null,
): Schema<'TransferDlp'> => ({
  transfer_id: of.id,
  state: of.state,
  decision: {
    id: `0190c0de-0000-7000-8000-0000000009${of.id.slice(-2)}`,
    transfer_id: of.id,
    file_id: null,
    policy_version: 12,
    mode: 'enforce',
    outcome,
    enforced: true,
    untrusted_recipients: 1,
    new_domains: 1,
    matched_rules: rules,
    decided_at: '2026-11-08T00:30:00Z',
  },
  recipients: recipientChecks,
  files: of.files.map((f) => ({
    file_id: f.id,
    display_name: f.display_name,
    inspection: f.inspection,
    findings: f.inspection.detectors.length > 0 ? findings() : [],
  })),
  message_findings: [],
  approval_request: request,
});

export const warnedDlp = transferDlp(warned, 'warn', [matchedRule(0, 'warn'), matchedRule(4, 'warn', 'new_domain')]);
export const approvalNeededDlp = transferDlp(approvalNeeded, 'require_approval', [matchedRule(1, 'require_approval'), matchedRule(0, 'warn')]);
export const pendingDlp = transferDlp(pending, 'require_approval', [matchedRule(1, 'require_approval')], requestSummary(pendingRequestId, 'pending', pendingId));
export const blockedDlp = transferDlp(blocked, 'block', [matchedRule(3, 'block'), matchedRule(0, 'warn')]);
export const rejectedDlp = transferDlp(
  rejected,
  'require_approval',
  [matchedRule(1, 'require_approval')],
  requestSummary(rejectedRequestId, 'rejected', rejectedId),
);

/** Before sending: no recipient was emailed yet. */
export const unsentRecipients: Schema<'RecipientStatusList'> = {
  items: recipientChecks.map((check) => ({
    id: check.recipient_id,
    email: check.email,
    locale: 'en',
    access_state: 'invited',
    delivery_state: 'pending',
    notified_at: null,
    first_verified_at: null,
    last_verified_at: null,
    failed_attempts: 0,
    locked_at: null,
    downloads: [],
  })),
};

const approvalRequest = (
  summary: Schema<'ApprovalRequestSummary'>,
  of: Transfer,
  extra: Partial<Schema<'ApprovalRequest'>> = {},
): Schema<'ApprovalRequest'> => ({
  ...summary,
  justification: 'The client asked for the staff list for the audit. Agreed with legal.',
  matched_rules: [matchedRule(1, 'require_approval')],
  transfer: {
    created_by: summary.requested_by,
    message: of.message,
    expires_at: of.expires_at,
    recipients: recipientChecks,
    files: of.files.map((f) => ({ id: f.id, display_name: f.display_name, size: f.declared_size, inspection: f.inspection })),
  },
  decisions: [],
  can_decide: false,
  ...extra,
});

export const pendingRequest = approvalRequest(requestSummary(pendingRequestId, 'pending', pendingId), pending);
export const rejectedRequest = approvalRequest(requestSummary(rejectedRequestId, 'rejected', rejectedId), rejected, {
  decisions: [
    {
      approver_id: otherMemberId,
      decision: 'reject',
      comment: 'The staff list can only go to the auditor\'s own portal. Send a summary instead.',
      decided_at: '2026-11-08T02:00:00Z',
    },
  ],
});
/** Another member's transfer, waiting in the signed-in approver's queue. */
export const queueRequest = approvalRequest(requestSummary(queueRequestId, 'pending', pendingId, otherMemberId), pending, {
  can_decide: true,
});

export const approvalQueue: Schema<'ApprovalRequestPage'> = {
  items: [
    requestSummary(queueRequestId, 'pending', pendingId, otherMemberId),
    { ...requestSummary('0190c0de-0000-7000-8000-000000000054', 'pending', blockedId, otherMemberId), rule_names: ['My Numbers'] },
  ],
  next_cursor: null,
};
