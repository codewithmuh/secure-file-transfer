import { describe, expect, it } from 'vitest';
import type { ApprovalRequest } from '@/api';
import { approvalScopes, cannotDecide, seesApprovals, shortId } from './approvals';

const me = { id: 'u-approver', role: 'member' as const, dlpApprover: true };

const request = (extra: Partial<ApprovalRequest> = {}) =>
  ({
    can_decide: false,
    state: 'pending',
    requested_by: 'u-sender',
    decisions: [],
    transfer: { created_by: 'u-sender', message: null, expires_at: null, recipients: [], files: [] },
    ...extra,
  }) as Pick<ApprovalRequest, 'can_decide' | 'state' | 'requested_by' | 'decisions' | 'transfer'>;

describe('who sees approvals (#220)', () => {
  it('shows the page to approvers and admins only', () => {
    expect(seesApprovals(me)).toBe(true);
    expect(seesApprovals({ role: 'admin', dlpApprover: false })).toBe(true);
    expect(seesApprovals({ role: 'member', dlpApprover: false })).toBe(false);
    expect(seesApprovals(null)).toBe(false);
  });

  it('gives an approver the queue and an admin every request too', () => {
    expect(approvalScopes(me)).toEqual(['queue']);
    expect(approvalScopes({ role: 'admin', dlpApprover: true })).toEqual(['queue', 'tenant']);
    expect(approvalScopes({ role: 'admin', dlpApprover: false })).toEqual(['tenant']);
    expect(approvalScopes({ role: 'member', dlpApprover: false })).toEqual([]);
  });
});

describe('why someone can\'t decide (#220, T-100)', () => {
  it('says nothing when the API says they can', () => {
    expect(cannotDecide(request({ can_decide: true }), me)).toBeNull();
  });

  it('names an own transfer, also one an API key of theirs created', () => {
    expect(cannotDecide(request({ requested_by: me.id }), me)).toBe('own');
    expect(cannotDecide(request({ transfer: { ...request().transfer, created_by: me.id } }), me)).toBe('own');
  });

  it('names a request already decided by them, or no longer pending', () => {
    const decided = [{ approver_id: me.id, decision: 'approve' as const, comment: null, decided_at: '2026-11-08T00:00:00Z' }];
    expect(cannotDecide(request({ decisions: decided }), me)).toBe('decided');
    expect(cannotDecide(request({ state: 'approved' }), me)).toBe('not_pending');
    expect(cannotDecide(request(), { id: 'u-other', dlpApprover: false })).toBe('not_approver');
  });

  it('tells two people apart by the end of their IDs', () => {
    expect(shortId('0190c0de-0000-7000-8000-0000000000a1')).toBe('000000a1');
  });
});
