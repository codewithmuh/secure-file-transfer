/**
 * The DLP hooks and calls over the typed `api` client: the tenant's policy, rules and keyword lists for admins (#218),
 * a transfer's decision and its confirmation for the sender (#219), and approval requests for approvers (#220).
 * Pages read through these, never through `api` directly.
 */
import { useInfiniteQuery, useQuery, type QueryClient } from '@tanstack/react-query';
import {
  api,
  type ApprovalRequest,
  type ApprovalState,
  type DlpDetector,
  type DlpPolicy,
  type DlpRule,
  type Schema,
  type Transfer,
  type TransferDlp,
} from '@/api';

export type DlpPolicyUpdate = Schema<'DlpPolicyUpdate'>;
export type DlpRuleCreate = Schema<'DlpRuleCreate'>;
export type DlpRuleUpdate = Schema<'DlpRuleUpdate'>;
export type DlpDetectorCreate = Schema<'DlpDetectorCreate'>;
export type DlpDetectorUpdate = Schema<'DlpDetectorUpdate'>;
export type ApprovalScope = 'queue' | 'own' | 'tenant';

export const dlpKeys = {
  all: ['dlp'] as const,
  policy: ['dlp', 'policy'] as const,
  rules: ['dlp', 'rules'] as const,
  detectors: ['dlp', 'detectors'] as const,
  detector: (id: string) => ['dlp', 'detectors', id] as const,
  approvals: ['approvals'] as const,
  approvalList: (scope: ApprovalScope, state: ApprovalState | null) => ['approvals', 'list', scope, state ?? 'all'] as const,
  pendingCount: ['approvals', 'pending-count'] as const,
  approval: (id: string) => ['approvals', 'detail', id] as const,
  /**
   * Under the transfer's own key, so `invalidateTransfers` refreshes it too. `signature` is what the transfer says
   * about its decision, so a new state or decision fetches the view again without polling it.
   */
  transferDlp: (transferId: string, signature: string) => ['transfers', 'detail', transferId, 'dlp', signature] as const,
};

// ---- the tenant's policy (#218): admins only ----

/**
 * Loaded afresh when a section opens, but not again on window focus: a newer version would start a half-made edit
 * over without a word. A write from another admin meanwhile gets `409 dlp_policy_conflict` instead, and the page
 * offers to load the policy again.
 */
const policyQuery = { staleTime: 0, refetchOnWindowFocus: false } as const;

export function useDlpPolicy() {
  return useQuery({
    queryKey: dlpKeys.policy,
    queryFn: async ({ signal }) => (await api.get('/dlp/policy', { signal })).data,
    ...policyQuery,
  });
}

export function useDlpRules() {
  return useQuery({
    queryKey: dlpKeys.rules,
    queryFn: async ({ signal }) => (await api.get('/dlp/rules', { signal })).data,
    ...policyQuery,
  });
}

/** The built-in detectors, in the caller's language, and the tenant's own keyword lists with their terms. */
export function useDlpDetectors() {
  return useQuery({
    queryKey: dlpKeys.detectors,
    queryFn: async ({ signal }) => (await api.get('/dlp/detectors', { signal })).data,
    ...policyQuery,
  });
}

export function useDlpDetector(id: string | undefined) {
  return useQuery({
    queryKey: dlpKeys.detector(id ?? ''),
    queryFn: async ({ signal }) => (await api.get('/dlp/detectors/{detector_id}', { path: { detector_id: id ?? '' }, signal })).data,
    enabled: Boolean(id),
    ...policyQuery,
  });
}

export async function updateDlpPolicy(body: DlpPolicyUpdate): Promise<DlpPolicy> {
  return (await api.patch('/dlp/policy', { body })).data;
}

export async function createDlpRule(body: DlpRuleCreate, idempotencyKey: string): Promise<DlpRule> {
  return (await api.post('/dlp/rules', { body, headers: { 'Idempotency-Key': idempotencyKey } })).data;
}

export async function updateDlpRule(ruleId: string, body: DlpRuleUpdate): Promise<DlpRule> {
  return (await api.patch('/dlp/rules/{rule_id}', { path: { rule_id: ruleId }, body })).data;
}

export async function deleteDlpRule(ruleId: string): Promise<void> {
  await api.delete('/dlp/rules/{rule_id}', { path: { rule_id: ruleId } });
}

export async function createDlpDetector(body: DlpDetectorCreate, idempotencyKey: string): Promise<DlpDetector> {
  return (await api.post('/dlp/detectors', { body, headers: { 'Idempotency-Key': idempotencyKey } })).data;
}

export async function updateDlpDetector(detectorId: string, body: DlpDetectorUpdate): Promise<DlpDetector> {
  return (await api.patch('/dlp/detectors/{detector_id}', { path: { detector_id: detectorId }, body })).data;
}

export async function deleteDlpDetector(detectorId: string): Promise<void> {
  await api.delete('/dlp/detectors/{detector_id}', { path: { detector_id: detectorId } });
}

/** After any policy, rule or detector write: every DLP view loads again, with the new policy version. */
export function invalidateDlp(client: QueryClient): Promise<void> {
  return client.invalidateQueries({ queryKey: dlpKeys.all });
}

// ---- a transfer's decision (#219, #220): the sender, and approvers of its request ----

/** What a transfer says about its decision: a change fetches the DLP view again. */
export function dlpSignature(transfer: Pick<Transfer, 'state' | 'hold_reason' | 'dlp'>): string {
  const dlp = transfer.dlp;
  return [transfer.state, transfer.hold_reason ?? '', dlp?.outcome ?? '', dlp?.approval_request_id ?? ''].join('|');
}

/**
 * The transfer's decision, findings and approval request (`getTransferDlp`). Not polled: the transfer is, and a change
 * in its state or decision changes the key (`dlpSignature`). Each response with details is audited, so it is never
 * fetched more often than the transfer changes.
 */
export function useTransferDlp(transferId: string, signature: string | null) {
  return useQuery({
    queryKey: dlpKeys.transferDlp(transferId, signature ?? ''),
    queryFn: async ({ signal }) =>
      (await api.get('/transfers/{transfer_id}/dlp', { path: { transfer_id: transferId }, signal })).data,
    enabled: signature !== null && transferId !== '',
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    retry: false,
  });
}

/** `confirmTransfer`: sends a warned transfer, or asks for approval with the justification. */
export async function confirmTransfer(transferId: string, decisionId: string, justification: string): Promise<Transfer> {
  const text = justification.trim();
  return (
    await api.post('/transfers/{transfer_id}/confirm', {
      path: { transfer_id: transferId },
      body: { decision_id: decisionId, ...(text ? { justification: text } : {}) },
    })
  ).data;
}

export type { TransferDlp };

// ---- approval requests (#220) ----

export function useApprovalRequests(scope: ApprovalScope, state: ApprovalState | null, enabled = true, limit = 25) {
  return useInfiniteQuery({
    queryKey: dlpKeys.approvalList(scope, state),
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam, signal }) =>
      (
        await api.get('/dlp/approval-requests', {
          query: { scope, limit, ...(state ? { state: [state] } : {}), ...(pageParam ? { cursor: pageParam } : {}) },
          signal,
        })
      ).data,
    getNextPageParam: (page) => page.next_cursor ?? null,
    enabled,
  });
}

/** How often the sidebar asks for the approver's pending count. */
export const PENDING_COUNT_INTERVAL_MS = 60_000;

/** The pending requests the approver may decide, for the sidebar's badge: up to 100, then "100+". */
export function usePendingApprovalCount(enabled: boolean) {
  return useQuery({
    queryKey: dlpKeys.pendingCount,
    queryFn: async ({ signal }) => {
      const page = (await api.get('/dlp/approval-requests', { query: { scope: 'queue', state: ['pending'], limit: 100 }, signal }))
        .data;
      return { count: page.items.length, more: page.next_cursor !== null };
    },
    enabled,
    refetchInterval: enabled ? PENDING_COUNT_INTERVAL_MS : false,
    retry: false,
  });
}

export function useApprovalRequest(id: string | undefined) {
  return useQuery({
    queryKey: dlpKeys.approval(id ?? ''),
    queryFn: async ({ signal }) =>
      (await api.get('/dlp/approval-requests/{approval_request_id}', { path: { approval_request_id: id ?? '' }, signal })).data,
    enabled: Boolean(id),
    staleTime: 0,
  });
}

export async function approveTransfer(requestId: string, comment: string): Promise<ApprovalRequest> {
  const text = comment.trim();
  return (
    await api.post('/dlp/approval-requests/{approval_request_id}/approve', {
      path: { approval_request_id: requestId },
      body: text ? { comment: text } : {},
    })
  ).data;
}

export async function rejectTransfer(requestId: string, comment: string): Promise<ApprovalRequest> {
  return (
    await api.post('/dlp/approval-requests/{approval_request_id}/reject', {
      path: { approval_request_id: requestId },
      body: { comment: comment.trim() },
    })
  ).data;
}

/** After an approval decision: the queue, the badge and the request load again. */
export function invalidateApprovals(client: QueryClient): Promise<void> {
  return client.invalidateQueries({ queryKey: dlpKeys.approvals });
}
