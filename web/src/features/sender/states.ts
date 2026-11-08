import type { FileState, Schema, TransferState } from '@/api';

/**
 * How the member's pages show each state (#196): a badge colour and a translated label. Every state is shown as text,
 * never by colour alone (WCAG 1.4.1).
 */
export type BadgeVariant = 'default' | 'success' | 'warning' | 'danger' | 'info';

export const TRANSFER_STATES: readonly TransferState[] = [
  'draft',
  'submitted',
  'awaiting_confirmation',
  'pending_approval',
  'sent',
  'held',
  'revoked',
  'expired',
  'cancelled',
];

export const transferStateVariant: Record<TransferState, BadgeVariant> = {
  draft: 'default',
  submitted: 'info',
  awaiting_confirmation: 'warning',
  pending_approval: 'warning',
  sent: 'success',
  held: 'warning',
  revoked: 'danger',
  expired: 'default',
  cancelled: 'default',
};

export const fileStateVariant: Record<FileState, BadgeVariant> = {
  uploading: 'info',
  completing: 'info',
  scanning: 'info',
  clean: 'success',
  infected: 'danger',
  unscannable: 'warning',
  scan_failed: 'warning',
  rejected: 'danger',
  deleted: 'default',
};

export const inspectionStateVariant: Record<Schema<'InspectionState'>, BadgeVariant> = {
  pending: 'info',
  inspected: 'success',
  partial: 'warning',
  not_inspected: 'warning',
  failed: 'danger',
  skipped: 'default',
};

/** The M5 states: DLP confirmation and approval can't happen before DLP-4, and their actions are hidden (#195). */
export const NOT_AVAILABLE_STATES: readonly TransferState[] = ['awaiting_confirmation', 'pending_approval'];

/** Built-in detectors with a name in i18n.ts (`detectors.<id>`); a tenant's own (`custom:`) show `detector_name`. */
export const BUILTIN_DETECTORS = [
  'jp_my_number',
  'jp_corporate_number',
  'payment_card',
  'jp_bank_account',
  'iban',
  'phone_number',
  'email_address',
  'jp_passport',
  'passport_mrz',
  'jp_drivers_licence',
  'cloud_credential',
  'private_key',
  'confidentiality_label',
] as const;

export function isBuiltinDetector(id: string): id is (typeof BUILTIN_DETECTORS)[number] {
  return (BUILTIN_DETECTORS as readonly string[]).includes(id);
}
