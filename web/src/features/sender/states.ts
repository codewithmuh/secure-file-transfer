import type { FileState, Schema, TransferState } from '@/api';

export type DeliveryState = Schema<'DeliveryState'>;
export type AccessState = Schema<'AccessState'>;

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

/** Where a recipient's link email stands (#199, FR-7). `queued` never says why (NFR-12). */
export const deliveryStateVariant: Record<DeliveryState, BadgeVariant> = {
  pending: 'default',
  queued: 'info',
  sent: 'success',
  bounced: 'danger',
  suppressed: 'warning',
};

/** The delivery states that need a word of explanation (`deliveryExplain.<state>` in i18n.ts): no email arrived. */
export const EXPLAINED_DELIVERY_STATES: readonly DeliveryState[] = ['bounced', 'suppressed'];

/** Where a recipient stands (#199): `locked` after 20 failed attempts until a member unlocks them (NFR-14). */
export const accessStateVariant: Record<AccessState, BadgeVariant> = {
  invited: 'default',
  verified: 'success',
  locked: 'danger',
};

/**
 * The states `revokeTransfer` takes (#199, FR-20): the contract's list. `awaiting_confirmation` and
 * `pending_approval` can't happen before M5's DLP-4, so in M3 that is `submitted`, `held` and `sent`.
 */
export const REVOCABLE_STATES: readonly TransferState[] = [
  'submitted',
  'awaiting_confirmation',
  'pending_approval',
  'held',
  'sent',
];

/** The states in which a locked recipient can be unlocked: the transfer still shares its files (`409` otherwise). */
export const UNLOCKABLE_STATES: readonly TransferState[] = REVOCABLE_STATES;

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
