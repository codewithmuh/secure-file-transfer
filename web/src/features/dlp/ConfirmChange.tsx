import { useTranslation } from 'react-i18next';
import { Alert, Button, Dialog } from '@/components/ui';
import { AdminAccessNote } from '@/features/admin/AdminAccessNote';
import { errorMessage, isAccessProblem, problemCode } from '@/lib/problems';

export interface ConfirmChangeProps {
  open: boolean;
  title: string;
  /** What the change does, one line each, named: "Trust partner.example", "Action: Warn → Block". */
  lines: readonly string[];
  action: string;
  danger?: boolean;
  busy: boolean;
  error: unknown;
  onConfirm: () => void;
  onClose: () => void;
  /** After `409 dlp_policy_conflict`: load the policy again (the form starts over from it). */
  onReload?: () => void;
}

/**
 * The confirmation every DLP policy write asks for (#218): it names what changes before anything is sent. A write
 * needs a recent sign-in, and a passkey for a local admin (`AdminAccessNote`); a stale policy version gets
 * `409 dlp_policy_conflict`, and the dialog offers to load the policy again.
 */
export function ConfirmChange({ open, title, lines, action, danger, busy, error, onConfirm, onClose, onReload }: ConfirmChangeProps) {
  const { t } = useTranslation();
  const conflict = problemCode(error) === 'dlp_policy_conflict';
  return (
    <Dialog open={open} onClose={onClose} title={title}>
      <ul className="list-disc space-y-1 pl-5 text-sm text-gray-700">
        {lines.map((line, index) => (
          <li key={index} className="break-words">
            {line}
          </li>
        ))}
      </ul>
      <p className="mt-3 text-sm text-gray-600">{t('dlpAdmin.confirmNote')}</p>
      {error !== null && error !== undefined && (
        <div className="mt-4">
          {isAccessProblem(error) ? (
            <AdminAccessNote error={error} />
          ) : (
            <Alert>
              <p>{errorMessage(error, t)}</p>
              {conflict && onReload && (
                <Button size="sm" variant="secondary" className="mt-2" onClick={onReload}>
                  {t('dlpAdmin.reload')}
                </Button>
              )}
            </Alert>
          )}
        </div>
      )}
      <div className="mt-6 flex justify-end gap-3">
        <Button variant="secondary" onClick={onClose} disabled={busy}>
          {t('common.cancel')}
        </Button>
        <Button variant={danger ? 'danger' : 'primary'} loading={busy} disabled={conflict} onClick={onConfirm}>
          {action}
        </Button>
      </div>
    </Dialog>
  );
}
