import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Dialog } from '@/components/ui';
import { AdminAccessNote } from '@/features/admin/AdminAccessNote';
import { COMMENT_MAX, textProblem } from '@/features/sender/dlpView';
import { errorMessage, isAccessProblem } from '@/lib/problems';

export interface DecisionDialogProps {
  open: boolean;
  /** Approve or reject, with the comment; throws the API's error. */
  onDecide: (comment: string) => Promise<void>;
  onClose: () => void;
}

/**
 * "Approve" (#220; FR-43): an optional comment, and the step-up rule said up front: approving needs a sign-in in the
 * last 15 minutes (`401 reauthentication_required`), which the dialog explains with a way to sign in again.
 */
export function ApproveDialog(props: DecisionDialogProps) {
  return <DecisionDialog kind="approve" {...props} />;
}

/** "Reject" (#220): a comment is required, since the sender reads it. Rejecting only stops sharing: no step-up. */
export function RejectDialog(props: DecisionDialogProps) {
  return <DecisionDialog kind="reject" {...props} />;
}

function DecisionDialog({ kind, open, onDecide, onClose }: DecisionDialogProps & { kind: 'approve' | 'reject' }) {
  const { t } = useTranslation();
  const [comment, setComment] = useState('');
  const [shown, setShown] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const problem = textProblem(comment, kind === 'reject', COMMENT_MAX);
  const fieldError = shown && problem ? t(`approvals.commentProblem.${problem}`, { max: COMMENT_MAX }) : undefined;
  const id = `${kind}-comment`;

  const close = () => {
    setError(null);
    setShown(false);
    onClose();
  };

  const submit = async () => {
    setShown(true);
    if (problem) return;
    setBusy(true);
    setError(null);
    try {
      await onDecide(comment);
      setComment('');
      setShown(false);
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={close} title={t(`approvals.${kind}.title`)}>
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <p className="text-sm text-gray-700">{t(`approvals.${kind}.body`)}</p>
        {kind === 'approve' && (
          <p className="mt-3 rounded-lg bg-yellow-50 p-3 text-sm text-yellow-800">{t('approvals.approve.stepUp')}</p>
        )}
        <div className="mt-4 space-y-1.5">
          <label htmlFor={id} className="block text-sm font-medium text-gray-700">
            {t(kind === 'reject' ? 'approvals.commentRequired' : 'approvals.commentOptional')}
          </label>
          <textarea
            id={id}
            className="input-field min-h-[100px] resize-y"
            value={comment}
            maxLength={COMMENT_MAX}
            required={kind === 'reject'}
            aria-invalid={fieldError ? true : undefined}
            aria-describedby={fieldError ? `${id}-error ${id}-hint` : `${id}-hint`}
            onChange={(event) => setComment(event.target.value)}
          />
          {fieldError && (
            <p id={`${id}-error`} className="text-sm text-red-600">
              {fieldError}
            </p>
          )}
          <p id={`${id}-hint`} className="text-sm text-gray-600">
            {t(`approvals.${kind}.commentHint`)}
          </p>
        </div>
        {error !== null && (
          <div className="mt-4">
            {isAccessProblem(error) ? <AdminAccessNote error={error} /> : <Alert>{errorMessage(error, t)}</Alert>}
          </div>
        )}
        <div className="mt-6 flex justify-end gap-3">
          <Button type="button" variant="secondary" onClick={close} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant={kind === 'reject' ? 'danger' : 'primary'} loading={busy}>
            {t(`approvals.${kind}.action`)}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
