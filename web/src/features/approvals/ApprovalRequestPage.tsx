import { useState } from 'react';
import { Link, useParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, FileIcon } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Alert, Badge, Button, Card, CardTitle, Spinner, toast } from '@/components/ui';
import type { ApprovalRequest, TransferDlp } from '@/api';
import { approveTransfer, invalidateApprovals, rejectTransfer, useApprovalRequest, useTransferDlp } from '@/hooks/dlp';
import { invalidateTransfers } from '@/hooks/transfers';
import { formatDate, formatFileSize } from '@/lib/formatters';
import { errorMessage, problemCode } from '@/lib/problems';
import { useAuthStore } from '@/stores/authStore';
import { InspectionStateBadge } from '@/features/sender/StateBadges';
import { FindingLine, MessageFindings } from '@/features/sender/TransferDlpPanel';
import { dlpActionVariant, isBuiltinDetector } from '@/features/sender/states';
import { approvalStateVariant, cannotDecide, seesApprovals, shortId } from './approvals';
import { ApproveDialog, RejectDialog } from './DecisionDialogs';

/**
 * An approval request (#220; FR-43, UC-7 steps 3 to 5): everything `getApprovalRequest` returns (the recipients with
 * their trust and new-domain flags, each file's name, size and inspection, the message, the matched rules, the
 * sender's justification and the decisions so far) and each file's and the message's findings as detector names and
 * counts (`getTransferDlp`; the message's since #221, FR-50). There is never a way to download the files. Approve and reject when `can_decide`; otherwise
 * the page says why not.
 */
export function ApprovalRequestPage() {
  const { id = '' } = useParams<{ id: string }>();
  const { t } = useTranslation();
  const me = useAuthStore((state) => state.user);
  const request = useApprovalRequest(id);
  const back = seesApprovals(me) ? '/approvals' : request.data ? `/transfers/${request.data.transfer_id}` : '/transfers';

  return (
    <PageShell
      title={t('approvals.requestTitle')}
      actions={
        <Link to={back} className="btn-secondary">
          <ArrowLeft className="mr-2 h-4 w-4" aria-hidden="true" />
          {seesApprovals(me) ? t('approvals.backToQueue') : t('approvals.backToTransfer')}
        </Link>
      }
    >
      {request.isPending ? (
        <div className="flex justify-center py-12">
          <Spinner />
          <span className="sr-only">{t('common.loading')}</span>
        </div>
      ) : request.isError ? (
        <Alert>{problemCode(request.error) === 'not_found' ? t('approvals.notFound') : errorMessage(request.error, t)}</Alert>
      ) : (
        <RequestView request={request.data} />
      )}
    </PageShell>
  );
}

function RequestView({ request }: { request: ApprovalRequest }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const me = useAuthStore((state) => state.user);
  const dlp = useTransferDlp(request.transfer_id, `${request.state}|${request.approvals}|${request.decisions.length}`);
  const [dialog, setDialog] = useState<'approve' | 'reject' | null>(null);
  const date = (value: string) => formatDate(value, i18n.language);
  const person = (id: string) => (id === me?.id ? t('approvals.you') : t('approvals.person', { id: shortId(id) }));
  const reason = cannotDecide(request, me);

  const decide = (kind: 'approve' | 'reject') => async (comment: string) => {
    if (kind === 'approve') await approveTransfer(request.id, comment);
    else await rejectTransfer(request.id, comment);
    setDialog(null);
    toast('success', t(`approvals.${kind}.done`));
    await Promise.all([invalidateApprovals(queryClient), invalidateTransfers(queryClient)]);
  };

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
      <div className="space-y-6 lg:col-span-2">
        <Card>
          <CardTitle>{t('approvals.whyTitle')}</CardTitle>
          <ul className="mt-3 space-y-2">
            {request.matched_rules.map((rule) => (
              <li key={`${rule.rule_id}:${rule.revision}`} className="flex flex-wrap items-center gap-2 text-sm text-gray-900">
                <span className="font-medium">{rule.name}</span>
                <Badge variant={dlpActionVariant[rule.action]}>{t(`dlpAction.${rule.action}`)}</Badge>
                {rule.condition === 'content' && rule.threshold !== null && (
                  <span className="text-gray-600">{t('dlp.matchedCount', { count: rule.matched_count, threshold: rule.threshold })}</span>
                )}
              </li>
            ))}
          </ul>
          <h3 className="mt-5 text-sm font-semibold text-gray-900">{t('approvals.justification')}</h3>
          <p className="mt-1 whitespace-pre-wrap break-words text-sm text-gray-700">{request.justification}</p>
          <h3 className="mt-5 text-sm font-semibold text-gray-900">{t('sender.messageColumn')}</h3>
          <p className="mt-1 whitespace-pre-wrap break-words text-sm text-gray-700">{request.transfer.message ?? t('approvals.noMessage')}</p>
          {dlp.data && (request.transfer.message || dlp.data.message_findings.length > 0) && (
            <div className="mt-2">
              <p className="text-sm font-medium text-gray-900">{t('dlp.messageFindings')}</p>
              <div className="mt-1">
                <MessageFindings findings={dlp.data.message_findings} />
              </div>
            </div>
          )}
        </Card>

        <Card>
          <CardTitle>{t('dlp.recipients')}</CardTitle>
          <ul className="mt-3 space-y-2">
            {request.transfer.recipients.map((recipient) => (
              <li key={recipient.recipient_id} className="flex flex-wrap items-center gap-2 text-sm text-gray-900">
                <span className="break-all">{recipient.email}</span>
                <Badge variant={recipient.trusted ? 'success' : 'warning'}>{t(recipient.trusted ? 'dlp.trusted' : 'dlp.untrusted')}</Badge>
                {recipient.new_domain && <Badge variant="info">{t('dlp.newDomain')}</Badge>}
              </li>
            ))}
          </ul>
        </Card>

        <Card>
          <CardTitle>{t('sender.files')}</CardTitle>
          <p className="mt-1 text-sm text-gray-600">{t('approvals.noDownload')}</p>
          <ul className="mt-3 space-y-3">
            {request.transfer.files.map((file) => (
              <li key={file.id} className="rounded-lg bg-gray-50 p-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <FileIcon className="h-5 w-5 shrink-0 text-gray-500" aria-hidden="true" />
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-gray-900">{file.display_name}</p>
                      <p className="text-xs text-gray-500">{formatFileSize(file.size)}</p>
                    </div>
                  </div>
                  <InspectionStateBadge state={file.inspection.state} />
                </div>
                {file.inspection.reasons.length > 0 && (
                  <p className="mt-2 text-sm text-gray-700">
                    {t('sender.notInspectedBecause')}{' '}
                    {file.inspection.reasons.map((value) => t(`inspectionReason.${value}`)).join(t('common.listSeparator'))}
                  </p>
                )}
                <FileFindings fileId={file.id} detectors={file.inspection.detectors} dlp={dlp.data} />
              </li>
            ))}
          </ul>
          {/* Once decided, the request's approvers may no longer read the transfer's findings: the detectors stay. */}
          {dlp.isError && request.state === 'pending' && <Alert className="mt-3">{errorMessage(dlp.error, t)}</Alert>}
        </Card>
      </div>

      <div className="space-y-6">
        <Card>
          <CardTitle>{t('common.details')}</CardTitle>
          <dl className="mt-3 space-y-3 text-sm">
            <div>
              <dt className="text-gray-500">{t('common.status')}</dt>
              <dd className="mt-0.5">
                <Badge variant={approvalStateVariant[request.state]}>{t(`approvalState.${request.state}`)}</Badge>
              </dd>
            </div>
            <div>
              <dt className="text-gray-500">{t('approvals.sender')}</dt>
              <dd className="mt-0.5 font-medium">{person(request.requested_by)}</dd>
            </div>
            <div>
              <dt className="text-gray-500">{t('approvals.requestedAt')}</dt>
              <dd className="mt-0.5 font-medium">{date(request.requested_at)}</dd>
            </div>
            <div>
              <dt className="text-gray-500">{t(request.state === 'pending' ? 'approvals.expiresAt' : 'approvals.expiredAt')}</dt>
              <dd className="mt-0.5 font-medium">{date(request.expires_at)}</dd>
            </div>
            <div>
              <dt className="text-gray-500">{t('approvals.approvals')}</dt>
              <dd className="mt-0.5 font-medium">
                {t('approvals.approvalsOf', { approvals: request.approvals, required: request.approvals_required })}
              </dd>
            </div>
            {request.transfer.expires_at && (
              <div>
                <dt className="text-gray-500">{t('approvals.transferExpires')}</dt>
                <dd className="mt-0.5 font-medium">{date(request.transfer.expires_at)}</dd>
              </div>
            )}
          </dl>

          <div className="mt-4 border-t border-gray-100 pt-4">
            {reason === null ? (
              <div className="flex flex-wrap gap-3">
                <Button onClick={() => setDialog('approve')}>{t('approvals.approve.button')}</Button>
                <Button variant="danger" onClick={() => setDialog('reject')}>
                  {t('approvals.reject.button')}
                </Button>
              </div>
            ) : (
              <p className="text-sm text-gray-700" role="status">
                {t(`approvals.cannotDecide.${reason}`, { state: t(`approvalState.${request.state}`) })}
              </p>
            )}
          </div>
        </Card>

        <Card>
          <CardTitle>{t('approvals.decisions')}</CardTitle>
          {request.decisions.length === 0 ? (
            <p className="mt-3 text-sm text-gray-600">{t('approvals.noDecisions')}</p>
          ) : (
            <ul className="mt-3 space-y-3 text-sm">
              {request.decisions.map((decision) => (
                <li key={`${decision.approver_id}:${decision.decided_at}`}>
                  <p className="font-medium text-gray-900">
                    {t(`approvals.decision.${decision.decision}`, { who: person(decision.approver_id), date: date(decision.decided_at) })}
                  </p>
                  {decision.comment && <p className="mt-0.5 whitespace-pre-wrap break-words text-gray-700">{decision.comment}</p>}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <ApproveDialog open={dialog === 'approve'} onDecide={decide('approve')} onClose={() => setDialog(null)} />
      <RejectDialog open={dialog === 'reject'} onDecide={decide('reject')} onClose={() => setDialog(null)} />
    </div>
  );
}

/** A file's findings from the transfer's DLP view: detector names and counts; the detectors alone until it loads. */
function FileFindings({ fileId, detectors, dlp }: { fileId: string; detectors: readonly string[]; dlp: TransferDlp | undefined }) {
  const { t } = useTranslation();
  const findings = dlp?.files.find((file) => file.file_id === fileId)?.findings;
  if (findings) {
    if (findings.length === 0) return <p className="mt-2 text-sm text-gray-600">{t('dlp.nothingFound')}</p>;
    return (
      <ul className="mt-2 space-y-1 text-sm text-gray-700">
        {findings.map((finding) => (
          <FindingLine key={finding.detector} finding={finding} />
        ))}
      </ul>
    );
  }
  if (detectors.length === 0) return null;
  return (
    <p className="mt-2 text-sm text-gray-700">
      {t('sender.detectorsFound')}{' '}
      {detectors.map((id) => (isBuiltinDetector(id) ? t(`detectors.${id}`) : id)).join(t('common.listSeparator'))}
    </p>
  );
}
