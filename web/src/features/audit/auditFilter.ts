import type { ActorType, Schema } from '@/api';

/**
 * The audit log's filter form (#216; FR-28, UC-4) as the contract's `AuditFilter`, and the export's file name. Email
 * addresses and IP addresses go only in a POST body, never in the page's address or a query string (T-47), so the
 * form's state lives in the page, not in the URL.
 */

export type AuditFilter = Schema<'AuditFilter'>;

export const ACTOR_TYPES: readonly ActorType[] = ['member', 'admin', 'recipient', 'uploader', 'api_key', 'operator', 'system'];

/**
 * The actions the multi-select offers, grouped as the audit log names them (data model 5). The filter takes any
 * dotted code, so an action missing here can't be picked but still shows in the results.
 */
export const KNOWN_ACTIONS = {
  transfer: [
    'transfer.created',
    'transfer.submitted',
    'transfer.sent',
    'transfer.cancelled',
    'transfer.revoked',
    'transfer.expired',
  ],
  file: ['file.added', 'file.uploaded', 'file.scanned', 'file.rejected', 'file.deleted'],
  download: ['download.granted', 'download.completed', 'download.refused'],
  recipient: [
    'recipient.link_issued',
    'verification.code_requested',
    'verification.attempted',
    'link_session.started',
    'link_session.ended',
    'recipient.locked',
    'recipient.unlocked',
  ],
  email: ['email.sent', 'email.bounced', 'email.suppressed', 'email_suppression.cleared'],
  member: [
    'member.signed_in',
    'member.sign_in_refused',
    'member.signed_out',
    'user.invited',
    'user.activated',
    'user.role_changed',
    'user.dlp_approver_changed',
    'user.deactivated',
  ],
  admin: [
    'tenant_policy.updated',
    'api_key.created',
    'api_key.revoked',
    'api_key.used',
    'audit.searched',
    'audit.exported',
  ],
} as const satisfies Record<string, readonly string[]>;

export type ActionGroup = keyof typeof KNOWN_ACTIONS;

/** The contract's limit on `actions`. */
export const MAX_ACTIONS = 20;

/** The form as the page holds it: every field a string, as the inputs give them. */
export interface FilterForm {
  /** `datetime-local` values, in the browser's time zone. */
  from: string;
  to: string;
  actorType: ActorType | '';
  actorId: string;
  email: string;
  actions: string[];
  targetType: string;
  targetId: string;
  sourceIp: string;
}

export const EMPTY_FILTER: FilterForm = {
  from: '',
  to: '',
  actorType: '',
  actorId: '',
  email: '',
  actions: [],
  targetType: '',
  targetId: '',
  sourceIp: '',
};

export type FilterField = 'from' | 'to' | 'actorId' | 'email' | 'actions' | 'targetType' | 'targetId' | 'sourceIp';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const TARGET_TYPE = /^[a-z_]{1,64}$/;

/** An IPv4 or IPv6 address, as the contract's `source_ip` takes it. */
export function isIpAddress(value: string): boolean {
  if (IPV4.test(value)) return true;
  if (!value.includes(':') || value.length > 45) return false;
  try {
    // The URL parser checks and normalises IPv6; anything else throws.
    return new URL(`http://[${value}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

/** A `datetime-local` value as an RFC 3339 timestamp, or `null` when it isn't one. */
export function localToIso(value: string): string | null {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(value)) return null;
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? null : new Date(time).toISOString();
}

/** What is wrong with the form, by field; empty when it can be sent. */
export function filterProblems(form: FilterForm): FilterField[] {
  const problems: FilterField[] = [];
  const from = form.from ? localToIso(form.from) : null;
  const to = form.to ? localToIso(form.to) : null;
  if (form.from && from === null) problems.push('from');
  if (form.to && (to === null || (from !== null && to <= from))) problems.push('to');
  if (form.actorId.trim() && !UUID.test(form.actorId.trim())) problems.push('actorId');
  if (form.email.trim() && !EMAIL.test(form.email.trim())) problems.push('email');
  if (form.actions.length > MAX_ACTIONS) problems.push('actions');
  if (form.targetType.trim() && !TARGET_TYPE.test(form.targetType.trim())) problems.push('targetType');
  if (form.targetId.trim() && !UUID.test(form.targetId.trim())) problems.push('targetId');
  if (form.sourceIp.trim() && !isIpAddress(form.sourceIp.trim())) problems.push('sourceIp');
  return problems;
}

/** The contract's `AuditFilter`: only the fields filled in, trimmed; `undefined` when nothing is. */
export function filterBody(form: FilterForm): AuditFilter | undefined {
  const filter: AuditFilter = {};
  const from = form.from ? localToIso(form.from) : null;
  const to = form.to ? localToIso(form.to) : null;
  if (from) filter.occurred_after = from;
  if (to) filter.occurred_before = to;
  if (form.actorType) filter.actor_type = form.actorType;
  if (form.actorId.trim()) filter.actor_id = form.actorId.trim().toLowerCase();
  if (form.email.trim()) filter.email = form.email.trim();
  if (form.actions.length > 0) filter.actions = [...new Set(form.actions)];
  if (form.targetType.trim()) filter.target_type = form.targetType.trim();
  if (form.targetId.trim()) filter.target_id = form.targetId.trim().toLowerCase();
  if (form.sourceIp.trim()) filter.source_ip = form.sourceIp.trim();
  return Object.keys(filter).length > 0 ? filter : undefined;
}

export function toggleAction(actions: readonly string[], action: string): string[] {
  return actions.includes(action) ? actions.filter((a) => a !== action) : [...actions, action];
}

export type ExportFormat = 'csv' | 'json';

/** A safe file name: no path, no control or quote characters. */
function safeName(name: string): string | null {
  const base = name.split(/[\\/]/).pop()?.trim() ?? '';
  // eslint-disable-next-line no-control-regex
  const clean = base.replace(/[\u0000-\u001f\u007f"<>:|?*]/g, '');
  return clean && clean !== '.' && clean !== '..' ? clean : null;
}

/**
 * The file name a `Content-Disposition` header gives (RFC 6266): `filename*` (RFC 5987, UTF-8) wins over `filename`.
 * Falls back to `audit-events-<date>.<format>` when there is none, or it isn't safe.
 */
export function exportFileName(header: string | null | undefined, format: ExportFormat, now: Date = new Date()): string {
  const fallback = `audit-events-${now.toISOString().slice(0, 10)}.${format}`;
  if (!header) return fallback;
  const extended = /filename\*\s*=\s*([^']*)'[^']*'([^;]+)/i.exec(header);
  if (extended?.[2]) {
    try {
      const name = safeName(decodeURIComponent(extended[2].trim()));
      if (name) return name;
    } catch {
      // A malformed escape: try the plain parameter.
    }
  }
  const plain = /filename\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;\s]+))/i.exec(header);
  const value = plain?.[1]?.replace(/\\(.)/g, '$1') ?? plain?.[2];
  return (value && safeName(value)) || fallback;
}

/** An event's `details` as key and value rows for the drawer, nested values as JSON. */
export function detailRows(details: Record<string, unknown>): [string, string][] {
  return Object.entries(details)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => [key, typeof value === 'string' ? value : JSON.stringify(value)]);
}
