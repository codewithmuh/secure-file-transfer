import type { DlpFinding, DlpLocation, DlpRecipientCheck, Transfer, TransferDlp, TransferState } from '@/api';

/**
 * What the sender's transfer page shows of a DLP decision (#219, #220; FR-41 to FR-43, FR-45, FR-46):
 * - `checking`: the transfer waits for its decision (`decision` is `null` until every file is shareable);
 * - `confirm`: a rule warns; the sender confirms, with an optional justification;
 * - `approval`: a rule requires approval; the sender requests it, with a justification;
 * - `pending`: an approval request waits for an approver;
 * - `blocked`: a rule blocked the transfer (`held`, `dlp_blocked`); the sender removes the files or cancels;
 * - `rejected`: an approver rejected it (`held`, `approval_rejected`).
 */
export type DlpStage = 'checking' | 'confirm' | 'approval' | 'pending' | 'blocked' | 'rejected';

/** Whether the transfer's page shows its DLP decision: the states the decision holds it in. */
export function showsDlp(transfer: Pick<Transfer, 'state' | 'hold_reason'>): boolean {
  if (transfer.state === 'awaiting_confirmation' || transfer.state === 'pending_approval') return true;
  return transfer.state === 'held' && (transfer.hold_reason === 'dlp_blocked' || transfer.hold_reason === 'approval_rejected');
}

export function dlpStage(transfer: Pick<Transfer, 'state' | 'hold_reason'>, dlp: Pick<TransferDlp, 'decision'> | undefined): DlpStage | null {
  if (!showsDlp(transfer)) return null;
  if (transfer.state === 'pending_approval') return 'pending';
  if (transfer.state === 'held') return transfer.hold_reason === 'dlp_blocked' ? 'blocked' : 'rejected';
  const decision = dlp?.decision;
  if (!decision) return 'checking';
  return decision.outcome === 'require_approval' ? 'approval' : 'confirm';
}

/** The states in which a file can be removed and the transfer cancelled (`deleteFile`, `cancelTransfer`). */
export const CHANGEABLE_STATES: readonly TransferState[] = ['awaiting_confirmation', 'pending_approval', 'held'];

export const JUSTIFICATION_MAX = 1000;
export const COMMENT_MAX = 1000;

export type TextProblem = 'required' | 'tooLong';

/** A justification or comment: required or not, at most 1,000 characters once trimmed. */
export function textProblem(text: string, required: boolean, max = JUSTIFICATION_MAX): TextProblem | null {
  const trimmed = text.trim();
  if (required && trimmed.length === 0) return 'required';
  if ([...trimmed].length > max) return 'tooLong';
  return null;
}

/** Recipients the decision flagged: outside the trusted domains, or in a domain new to the tenant. */
export function flaggedRecipients(recipients: readonly DlpRecipientCheck[]): DlpRecipientCheck[] {
  return recipients.filter((recipient) => !recipient.trusted || recipient.new_domain);
}

/** Every match a finding counts, at any confidence. */
export function findingTotal(finding: Pick<DlpFinding, 'count_low' | 'count_medium' | 'count_high'>): number {
  return finding.count_low + finding.count_medium + finding.count_high;
}

/**
 * The files to remove for a blocked transfer: those a content rule could have counted (they have findings) and, if a
 * not-inspected rule blocked it, those not fully inspected. The sender doesn't see the rules' detectors (they are the
 * admin's), so this is every file that could have matched.
 */
export function filesToRemove(dlp: Pick<TransferDlp, 'decision' | 'files'>): string[] {
  const blocking = (dlp.decision?.matched_rules ?? []).filter((rule) => rule.action === 'block');
  const content = blocking.some((rule) => rule.condition === 'content');
  const notInspected = blocking.some((rule) => rule.condition === 'not_inspected');
  return dlp.files
    .filter(
      (file) =>
        (content && file.findings.length > 0) ||
        (notInspected && file.inspection.state !== 'inspected' && file.inspection.state !== 'pending'),
    )
    .map((file) => file.file_id);
}

/** The parts of a location hint (#233), in reading order, each as an i18n key and its values: an archive member,
 * then its page, sheet and row, slide, line or paragraph, then the part of the document. */
export function locationParts(location: DlpLocation): { key: string; values: Record<string, string | number> }[] {
  const parts: { key: string; values: Record<string, string | number> }[] = [];
  if (location.member) parts.push({ key: 'dlp.location.member', values: { member: location.member } });
  if (location.page) parts.push({ key: 'dlp.location.page', values: { n: location.page } });
  if (location.sheet !== undefined) parts.push({ key: 'dlp.location.sheet', values: { sheet: location.sheet } });
  if (location.row) parts.push({ key: 'dlp.location.row', values: { n: location.row } });
  if (location.slide) parts.push({ key: 'dlp.location.slide', values: { n: location.slide } });
  if (location.line) parts.push({ key: 'dlp.location.line', values: { n: location.line } });
  if (location.paragraph) parts.push({ key: 'dlp.location.paragraph', values: { n: location.paragraph } });
  if (location.part) parts.push({ key: `dlp.location.part.${location.part}`, values: {} });
  return parts;
}
