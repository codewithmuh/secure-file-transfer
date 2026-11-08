import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { FileIcon } from 'lucide-react';
import { Alert, Badge, Button, Card, CardTitle, Dialog, Spinner, toast } from '@/components/ui';
import type { ApprovalRequestSummary, DlpFinding, DlpMatchedRule, Transfer, TransferDlp } from '@/api';
import { confirmTransfer, dlpSignature, useApprovalRequest, useTransferDlp } from '@/hooks/dlp';
import { cancelTransfer, invalidateTransfers, uploadApi } from '@/hooks/transfers';
import { errorMessage, problemCode } from '@/lib/problems';
import { formatDate } from '@/lib/formatters';
import { useAuthStore } from '@/stores/authStore';
import { approvalStateVariant, shortId } from '@/features/approvals/approvals';
import { InspectionStateBadge } from './StateBadges';
import { CHANGEABLE_STATES, dlpStage, filesToRemove, findingTotal, flaggedRecipients, JUSTIFICATION_MAX, textProblem, type DlpStage } from './dlpView';
import { dlpActionVariant, isBuiltinDetector } from './states';

/**
 * The transfer's DLP decision on its page (#219, #220, #221; FR-41 to FR-43, FR-45, FR-46, FR-48, FR-50, UC-7): the
 * rules that matched and their actions, the recipients flagged untrusted or new, what each file's inspection found and
 * what the message holds (detector names and counts). The sender confirms a warning, requests approval with a
 * justification, removes a file (the transfer is checked again) or cancels. A pending request shows its expiry and
 * the approvals so far; a rejection shows the approver's comment.
 */
export function TransferDlpPanel({ transfer }: { transfer: Transfer }) {
  const { t } = useTranslation();
  const dlp = useTransferDlp(transfer.id, dlpSignature(transfer));
  const [changed, setChanged] = useState(false);

  if (dlp.isPending) {
    return (
      <Card>
        <CardTitle>{t('dlp.title')}</CardTitle>
        <div className="mt-3 flex justify-center py-4">
          <Spinner />
          <span className="sr-only">{t('common.loading')}</span>
        </div>
      </Card>
    );
  }
  if (dlp.isError) {
    return (
      <Card>
        <CardTitle>{t('dlp.title')}</CardTitle>
        <Alert className="mt-3">{errorMessage(dlp.error, t)}</Alert>
      </Card>
    );
  }
  const stage = dlpStage(transfer, dlp.data);
  if (!stage) return null;
  return <DlpView transfer={transfer} dlp={dlp.data} stage={stage} changed={changed} onChanged={() => setChanged(true)} />;
}

function DlpView({
  transfer,
  dlp,
  stage,
  changed,
  onChanged,
}: {
  transfer: Transfer;
  dlp: TransferDlp;
  stage: DlpStage;
  changed: boolean;
  onChanged: () => void;
}) {
  const { t, i18n } = useTranslation();
  const date = (value: string) => formatDate(value, i18n.language);
  const rules = dlp.decision?.matched_rules ?? [];
  const flagged = flaggedRecipients(dlp.recipients);
  const changeable = CHANGEABLE_STATES.includes(transfer.state);
  const toRemove = stage === 'blocked' ? filesToRemove(dlp) : [];
  const request = dlp.approval_request;

  return (
    <Card>
      <CardTitle>{t('dlp.title')}</CardTitle>
      <p className="mt-2 text-sm text-gray-700">{t(`dlp.intro.${stage}`)}</p>
      {changed && (
        <Alert variant="warning" role="status" className="mt-3">
          {t('dlp.decisionChanged')}
        </Alert>
      )}

      {stage === 'approval' && request && request.state !== 'pending' && (
        <Alert variant="info" role="status" className="mt-3">
          {t(`dlp.previousRequest.${request.state}`, { date: date(request.expires_at) })}
        </Alert>
      )}
      {(stage === 'pending' || stage === 'rejected') && request && <RequestStatus request={request} />}

      {rules.length > 0 && (
        <div className="mt-5">
          <h3 id="dlp-rules" className="text-sm font-semibold text-gray-900">
            {t('dlp.matchedRules')}
          </h3>
          <ul className="mt-2 space-y-2">
            {rules.map((rule) => (
              <MatchedRule key={`${rule.rule_id}:${rule.revision}`} rule={rule} />
            ))}
          </ul>
        </div>
      )}

      <div className="mt-5">
        <h3 id="dlp-recipients" className="text-sm font-semibold text-gray-900">
          {t('dlp.recipients')}
        </h3>
        {flagged.length === 0 ? (
          <p className="mt-2 text-sm text-gray-600">{t('dlp.noFlaggedRecipients')}</p>
        ) : (
          <ul className="mt-2 space-y-2">
            {flagged.map((recipient) => (
              <li key={recipient.recipient_id} className="flex flex-wrap items-center gap-2 text-sm text-gray-900">
                <span className="break-all">{recipient.email}</span>
                {!recipient.trusted && <Badge variant="warning">{t('dlp.untrusted')}</Badge>}
                {recipient.new_domain && <Badge variant="info">{t('dlp.newDomain')}</Badge>}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="mt-5">
        <h3 id="dlp-files" className="text-sm font-semibold text-gray-900">
          {t('dlp.files')}
        </h3>
        {stage === 'blocked' && toRemove.length > 0 && <p className="mt-1 text-sm text-gray-700">{t('dlp.removeToSend')}</p>}
        <ul className="mt-2 space-y-3">
          {dlp.files.map((file) => (
            <li
              key={file.file_id}
              className={toRemove.includes(file.file_id) ? 'rounded-lg bg-red-50 p-3 ring-1 ring-red-200' : 'rounded-lg bg-gray-50 p-3'}
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-3">
                  <FileIcon className="h-5 w-5 shrink-0 text-gray-500" aria-hidden="true" />
                  <p className="truncate text-sm font-medium text-gray-900">{file.display_name}</p>
                  <InspectionStateBadge state={file.inspection.state} />
                  {toRemove.includes(file.file_id) && <Badge variant="danger">{t('dlp.blockedFile')}</Badge>}
                </div>
                {changeable && <RemoveFile fileId={file.file_id} name={file.display_name} />}
              </div>
              {file.inspection.reasons.length > 0 && (
                <p className="mt-2 text-sm text-gray-700">
                  {t('sender.notInspectedBecause')}{' '}
                  {file.inspection.reasons.map((reason) => t(`inspectionReason.${reason}`)).join(t('common.listSeparator'))}
                </p>
              )}
              {file.findings.length === 0 ? (
                <p className="mt-2 text-sm text-gray-600">{t('dlp.nothingFound')}</p>
              ) : (
                <ul className="mt-2 space-y-1 text-sm text-gray-700">
                  {file.findings.map((finding) => (
                    <FindingLine key={finding.detector} finding={finding} />
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
      </div>

      {(transfer.message || dlp.message_findings.length > 0) && (
        <div className="mt-5">
          <h3 id="dlp-message" className="text-sm font-semibold text-gray-900">
            {t('dlp.message')}
          </h3>
          <div
            className={
              dlp.message_findings.length > 0 && stage === 'blocked'
                ? 'mt-2 rounded-lg bg-red-50 p-3 ring-1 ring-red-200'
                : 'mt-2 rounded-lg bg-gray-50 p-3'
            }
          >
            <MessageFindings findings={dlp.message_findings} />
            {dlp.message_findings.length > 0 && changeable && <p className="mt-2 text-sm text-gray-700">{t('dlp.messageFixed')}</p>}
          </div>
        </div>
      )}

      {changeable && (
        <div className="mt-6 flex flex-wrap gap-3 border-t border-gray-100 pt-4">
          {(stage === 'confirm' || stage === 'approval') && dlp.decision && (
            <ConfirmSend transferId={transfer.id} decisionId={dlp.decision.id} approval={stage === 'approval'} rules={rules} onChanged={onChanged} />
          )}
          <CancelTransfer transferId={transfer.id} />
        </div>
      )}
    </Card>
  );
}

function MatchedRule({ rule }: { rule: DlpMatchedRule }) {
  const { t } = useTranslation();
  return (
    <li className="flex flex-wrap items-center gap-2 text-sm text-gray-900">
      <span className="font-medium">{rule.name}</span>
      <Badge variant={dlpActionVariant[rule.action]}>{t(`dlpAction.${rule.action}`)}</Badge>
      {rule.condition === 'content' && rule.threshold !== null && (
        <span className="text-gray-600">{t('dlp.matchedCount', { count: rule.matched_count, threshold: rule.threshold })}</span>
      )}
      {rule.condition === 'not_inspected' && <span className="text-gray-600">{t('dlp.notInspectedFiles', { count: rule.matched_count })}</span>}
      {rule.condition === 'new_domain' && <span className="text-gray-600">{t('dlp.newDomains', { count: rule.matched_count })}</span>}
    </li>
  );
}

export function FindingLine({ finding }: { finding: DlpFinding }) {
  const { t } = useTranslation();
  // The API names built-in detectors in the caller's language; the app's own names stand in if it sent none.
  const name = finding.detector_name || (isBuiltinDetector(finding.detector) ? t(`detectors.${finding.detector}`) : finding.detector);
  return (
    <li>
      <span className="font-medium text-gray-900">{name}</span>
      {': '}
      {t('dlp.findingCounts', {
        count: findingTotal(finding),
        high: finding.count_high,
        medium: finding.count_medium,
        low: finding.count_low,
      })}
    </li>
  );
}

/** What the transfer's message holds (FR-50): detector names and counts, as for a file. */
export function MessageFindings({ findings }: { findings: readonly DlpFinding[] }) {
  const { t } = useTranslation();
  if (findings.length === 0) return <p className="text-sm text-gray-600">{t('dlp.nothingFound')}</p>;
  return (
    <ul className="space-y-1 text-sm text-gray-700">
      {findings.map((finding) => (
        <FindingLine key={finding.detector} finding={finding} />
      ))}
    </ul>
  );
}

/** The approval request in brief: its state, approvals so far, expiry, the rules that asked for it, and decisions. */
function RequestStatus({ request }: { request: ApprovalRequestSummary }) {
  const { t, i18n } = useTranslation();
  const me = useAuthStore((state) => state.user);
  const full = useApprovalRequest(request.id);
  const date = (value: string) => formatDate(value, i18n.language);
  return (
    <div className="mt-4 rounded-lg bg-gray-50 p-3">
      <h3 id="dlp-request" className="flex flex-wrap items-center gap-2 text-sm font-semibold text-gray-900">
        {t('dlp.request')}
        <Badge variant={approvalStateVariant[request.state]}>{t(`approvalState.${request.state}`)}</Badge>
      </h3>
      <dl className="mt-2 grid gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
        <div>
          <dt className="inline text-gray-600">{t('approvals.requestedAt')}: </dt>
          <dd className="inline text-gray-900">{date(request.requested_at)}</dd>
        </div>
        <div>
          <dt className="inline text-gray-600">{t(request.state === 'pending' ? 'approvals.expiresAt' : 'approvals.expiredAt')}: </dt>
          <dd className="inline text-gray-900">{date(request.expires_at)}</dd>
        </div>
        <div>
          <dt className="inline text-gray-600">{t('approvals.approvals')}: </dt>
          <dd className="inline text-gray-900">{t('approvals.approvalsOf', { approvals: request.approvals, required: request.approvals_required })}</dd>
        </div>
        {request.rule_names.length > 0 && (
          <div>
            <dt className="inline text-gray-600">{t('approvals.rules')}: </dt>
            <dd className="inline text-gray-900">{request.rule_names.join(t('common.listSeparator'))}</dd>
          </div>
        )}
      </dl>
      {full.data && (
        <>
          <p className="mt-2 text-sm text-gray-700">
            <span className="text-gray-600">{t('dlp.yourJustification')}: </span>
            <span className="whitespace-pre-wrap break-words">{full.data.justification}</span>
          </p>
          {full.data.decisions.length > 0 && (
            <ul className="mt-2 space-y-2 text-sm">
              {full.data.decisions.map((decision) => (
                <li key={`${decision.approver_id}:${decision.decided_at}`} className="text-gray-900">
                  <span className="font-medium">
                    {t(`approvals.decision.${decision.decision}`, {
                      who: me?.id === decision.approver_id ? t('approvals.you') : t('approvals.person', { id: shortId(decision.approver_id) }),
                      date: date(decision.decided_at),
                    })}
                  </span>
                  {decision.comment && <p className="mt-0.5 whitespace-pre-wrap break-words text-gray-700">{decision.comment}</p>}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      {full.isError && <Alert className="mt-2">{errorMessage(full.error, t)}</Alert>}
      <p className="mt-2">
        <RequestLink id={request.id} />
      </p>
    </div>
  );
}

/**
 * "Send anyway" for a warning, or "Request approval" when a rule requires it (`confirmTransfer`). The dialog names
 * the rules again; the justification is optional for a warning and required for approval, at most 1,000 characters.
 * A newer decision (`409 dlp_decision_changed`, a file removed in another tab) closes it and loads the view again.
 */
export function ConfirmSend({
  transferId,
  decisionId,
  approval,
  rules,
  onChanged,
  initiallyOpen = false,
}: {
  transferId: string;
  decisionId: string;
  approval: boolean;
  rules: readonly DlpMatchedRule[];
  onChanged: () => void;
  initiallyOpen?: boolean;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(initiallyOpen);
  const [justification, setJustification] = useState('');
  const [shown, setShown] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const problem = textProblem(justification, approval);
  const kind = approval ? 'approval' : 'warning';

  const close = () => {
    setOpen(false);
    setError(null);
    setShown(false);
  };

  const submit = async () => {
    setShown(true);
    if (problem) return;
    setBusy(true);
    setError(null);
    try {
      await confirmTransfer(transferId, decisionId, justification);
      toast('success', t(`dlp.confirm.${kind}.done`));
      close();
      setJustification('');
      await invalidateTransfers(queryClient);
    } catch (failure) {
      if (problemCode(failure) === 'dlp_decision_changed') {
        close();
        onChanged();
        await invalidateTransfers(queryClient);
      } else {
        setError(failure);
      }
    } finally {
      setBusy(false);
    }
  };

  const fieldError = shown && problem ? t(`dlp.justificationProblem.${problem}`, { max: JUSTIFICATION_MAX }) : undefined;

  return (
    <>
      <Button onClick={() => setOpen(true)}>{t(`dlp.confirm.${kind}.button`)}</Button>
      <Dialog open={open} onClose={close} title={t(`dlp.confirm.${kind}.title`)}>
        <form
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            void submit();
          }}
        >
          <p className="text-sm text-gray-700">{t(`dlp.confirm.${kind}.body`)}</p>
          {rules.length > 0 && (
            <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-gray-900">
              {rules.map((rule) => (
                <li key={`${rule.rule_id}:${rule.revision}`}>
                  {rule.name} ({t(`dlpAction.${rule.action}`)})
                </li>
              ))}
            </ul>
          )}
          <div className="mt-4 space-y-1.5">
            <label htmlFor="dlp-justification" className="block text-sm font-medium text-gray-700">
              {t(approval ? 'dlp.justificationRequired' : 'dlp.justificationOptional')}
            </label>
            <textarea
              id="dlp-justification"
              className="input-field min-h-[100px] resize-y"
              value={justification}
              maxLength={JUSTIFICATION_MAX}
              required={approval}
              aria-invalid={fieldError ? true : undefined}
              aria-describedby={fieldError ? 'dlp-justification-error dlp-justification-count' : 'dlp-justification-count'}
              onChange={(event) => setJustification(event.target.value)}
            />
            {fieldError && (
              <p id="dlp-justification-error" className="text-sm text-red-600">
                {fieldError}
              </p>
            )}
            <p id="dlp-justification-count" className="text-right text-xs text-gray-500">
              {t('sender.messageCount', { count: justification.length, max: JUSTIFICATION_MAX })}
            </p>
            <p className="text-sm text-gray-600">{t(`dlp.confirm.${kind}.note`)}</p>
          </div>
          {error !== null && <Alert className="mt-4">{errorMessage(error, t)}</Alert>}
          <div className="mt-6 flex justify-end gap-3">
            <Button type="button" variant="secondary" onClick={close} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={busy}>
              {t(`dlp.confirm.${kind}.action`)}
            </Button>
          </div>
        </form>
      </Dialog>
    </>
  );
}

/** "Remove": the file leaves the transfer, which is checked again without it (`deleteFile`; UC-1). */
function RemoveFile({ fileId, name }: { fileId: string; name: string }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const remove = async () => {
    setBusy(true);
    setError(null);
    try {
      await uploadApi.deleteFile(fileId);
      toast('success', t('dlp.removed', { name }));
      setOpen(false);
      await invalidateTransfers(queryClient);
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Button size="sm" variant="secondary" aria-label={t('dlp.removeFileNamed', { name })} onClick={() => setOpen(true)}>
        {t('dlp.removeFile')}
      </Button>
      <Dialog
        open={open}
        onClose={() => {
          setOpen(false);
          setError(null);
        }}
        title={t('dlp.removeTitle')}
      >
        <p className="break-words text-sm text-gray-700">{t('dlp.removeBody', { name })}</p>
        {error !== null && <Alert className="mt-4">{errorMessage(error, t)}</Alert>}
        <div className="mt-6 flex justify-end gap-3">
          <Button variant="secondary" onClick={() => setOpen(false)} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="danger" loading={busy} onClick={() => void remove()}>
            {t('dlp.removeFile')}
          </Button>
        </div>
      </Dialog>
    </>
  );
}

/** "Cancel transfer": nobody is notified, and a pending request is withdrawn (`cancelTransfer`). */
function CancelTransfer({ transferId }: { transferId: string }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const cancel = async () => {
    setBusy(true);
    setError(null);
    try {
      await cancelTransfer(transferId);
      toast('success', t('dlp.cancelled'));
      setOpen(false);
      await invalidateTransfers(queryClient);
      navigate('/transfers');
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Button variant="secondary" onClick={() => setOpen(true)}>
        {t('sender.cancelTransfer')}
      </Button>
      <Dialog
        open={open}
        onClose={() => {
          setOpen(false);
          setError(null);
        }}
        title={t('dlp.cancelTitle')}
      >
        <p className="text-sm text-gray-700">{t('dlp.cancelBody')}</p>
        {error !== null && <Alert className="mt-4">{errorMessage(error, t)}</Alert>}
        <div className="mt-6 flex justify-end gap-3">
          <Button variant="secondary" onClick={() => setOpen(false)} disabled={busy}>
            {t('dlp.keepTransfer')}
          </Button>
          <Button variant="danger" loading={busy} onClick={() => void cancel()}>
            {t('sender.cancelTransfer')}
          </Button>
        </div>
      </Dialog>
    </>
  );
}

/** A link to the approval request's own page, which the sender may read too. */
function RequestLink({ id }: { id: string }) {
  const { t } = useTranslation();
  return (
    <Link to={`/approvals/${id}`} className="text-sm font-semibold text-brand-700 underline hover:text-brand-800">
      {t('dlp.openRequest')}
    </Link>
  );
}
