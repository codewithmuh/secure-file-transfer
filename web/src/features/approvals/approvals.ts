import type { ApprovalRequest, ApprovalState } from '@/api';
import type { ApprovalScope } from '@/hooks/dlp';
import type { BadgeVariant } from '@/features/sender/states';
import type { Member } from '@/stores/authStore';

/**
 * DLP approvals (#220; FR-43, T-100): who sees which queue, why someone can't decide a request, and how a person the
 * API names by ID is shown.
 */

export const approvalStateVariant: Record<ApprovalState, BadgeVariant> = {
  pending: 'warning',
  approved: 'success',
  rejected: 'danger',
  expired: 'default',
  withdrawn: 'default',
};

/** Who sees the approvals page and its sidebar entry: approvers and admins. */
export function seesApprovals(member: Pick<Member, 'role' | 'dlpApprover'> | null | undefined): boolean {
  return Boolean(member && (member.dlpApprover || member.role === 'admin'));
}

/**
 * The lists a member can open: an approver's queue (pending requests they may decide), and every request in the
 * tenant for an admin. A member who is neither gets `403` for both, so none.
 */
export function approvalScopes(member: Pick<Member, 'role' | 'dlpApprover'> | null | undefined): ApprovalScope[] {
  if (!member) return [];
  const scopes: ApprovalScope[] = [];
  if (member.dlpApprover) scopes.push('queue');
  if (member.role === 'admin') scopes.push('tenant');
  return scopes;
}

/** Why the signed-in person can't approve or reject a request now; `null` when they can (`can_decide`). */
export type CannotDecide = 'own' | 'decided' | 'not_pending' | 'not_approver';

export function cannotDecide(
  request: Pick<ApprovalRequest, 'can_decide' | 'state' | 'requested_by' | 'decisions' | 'transfer'>,
  me: Pick<Member, 'id' | 'dlpApprover'> | null | undefined,
): CannotDecide | null {
  if (request.can_decide) return null;
  if (request.state !== 'pending') return 'not_pending';
  if (me && (request.requested_by === me.id || request.transfer.created_by === me.id)) return 'own';
  if (me && request.decisions.some((decision) => decision.approver_id === me.id)) return 'decided';
  if (me && !me.dlpApprover) return 'not_approver';
  // The API knows something the page doesn't (an approver taken away meanwhile): the request isn't theirs to decide.
  return 'not_approver';
}

/**
 * The contract names people in approvals by user ID only, and members can't list users. The page shows "you" for
 * the signed-in person and the end of the ID for anyone else, so two people can be told apart.
 */
export function shortId(id: string): string {
  return id.replace(/-/g, '').slice(-8);
}
