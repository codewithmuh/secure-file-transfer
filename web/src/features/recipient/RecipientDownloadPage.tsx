import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Download, FileIcon } from 'lucide-react';
import { Alert, Button, Card, CardTitle, Spinner } from '@/components/ui';
import { formatDate, formatFileSize } from '@/lib/formatters';
import {
  downloadFile,
  downloadsUsedUp,
  endLinkSession,
  goneOf,
  linkProblemText,
  listSessionFiles,
  storedGrant,
  type SessionFile,
  type VerifiedSession,
} from './linkApi';
import type { GateActions } from './LinkGate';
import { StepHeading } from './StepHeading';

/**
 * The verified recipient's page (#198): who sent the files, their message and the expiry, shown only now (FR-14), then
 * each file on its own with its size, its downloads of the limit and the unscannable warning (FR-6, FR-18). "Download"
 * asks for a grant, checks it in the app and lets the browser's download manager fetch it (`downloadFile`); "Done"
 * ends the link session.
 */
export function RecipientDownloadPage({ session, actions }: { session: VerifiedSession; actions: GateActions }) {
  const { t, i18n } = useTranslation();
  const files = useQuery({
    queryKey: ['link-session', session.id, 'files'],
    queryFn: ({ signal }) => listSessionFiles(signal),
    retry: false,
    staleTime: 0,
  });
  const [ending, setEnding] = useState(false);

  // A `410` on the list: the link was revoked or has expired since (a 401 goes back to the code step on its own).
  const listGone = files.isError ? goneOf(files.error) : null;
  useEffect(() => {
    if (listGone) actions.gone(listGone);
  }, [listGone, actions]);

  const done = async () => {
    setEnding(true);
    try {
      await endLinkSession();
    } catch {
      // The store forgot the session either way; the API ends it at its idle timeout.
    }
    actions.done();
  };

  const transfer = session.transfer;
  return (
    <div className="space-y-6">
      <Card>
        <StepHeading>{t('recipient.filesTitle')}</StepHeading>
        {transfer && (
          <dl className="mt-4 grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-gray-600">{t('recipient.organization')}</dt>
              <dd className="mt-0.5 font-medium text-gray-900">{transfer.tenant_name}</dd>
            </div>
            <div>
              <dt className="text-gray-600">{t('recipient.sentBy')}</dt>
              <dd className="mt-0.5 break-all font-medium text-gray-900">{transfer.sender_email}</dd>
            </div>
            <div>
              <dt className="text-gray-600">{t('recipient.availableUntil')}</dt>
              <dd className="mt-0.5 font-medium text-gray-900">{formatDate(transfer.expires_at, i18n.language)}</dd>
            </div>
            <div>
              <dt className="text-gray-600">{t('recipient.verifiedAs')}</dt>
              <dd className="mt-0.5 break-all font-medium text-gray-900">{session.email}</dd>
            </div>
            {transfer.message && (
              <div className="sm:col-span-2">
                <dt className="text-gray-600">{t('recipient.message')}</dt>
                <dd className="mt-0.5 whitespace-pre-wrap break-words text-gray-900">{transfer.message}</dd>
              </div>
            )}
          </dl>
        )}
      </Card>

      <Card>
        <CardTitle>{t('sender.files')}</CardTitle>
        {files.isPending ? (
          <div className="flex justify-center py-6">
            <Spinner />
            <span className="sr-only">{t('common.loading')}</span>
          </div>
        ) : files.isError ? (
          listGone ? null : <Alert className="mt-3">{linkProblemText(files.error, t)}</Alert>
        ) : files.data.length === 0 ? (
          <p className="mt-3 text-sm text-gray-600">{t('recipient.noFiles')}</p>
        ) : (
          <ul className="mt-3 space-y-3">
            {files.data.map((file) => (
              <FileRow
                key={file.id}
                file={file}
                sessionId={session.id}
                onGone={actions.gone}
                onCounted={() => void files.refetch()}
              />
            ))}
          </ul>
        )}
      </Card>

      <div className="flex justify-end">
        <Button variant="secondary" onClick={() => void done()} loading={ending}>
          {t('recipient.done')}
        </Button>
      </div>
    </div>
  );
}

function FileRow({
  file,
  sessionId,
  onGone,
  onCounted,
}: {
  file: SessionFile;
  sessionId: string;
  onGone: GateActions['gone'];
  onCounted: () => void;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const used = file.downloads_used ?? 0;
  const limit = file.download_limit ?? null;
  // Once the counted downloads are used up, only a download whose start was interrupted can carry on: its grant is
  // counted already and still kept. A grant handed to the browser is forgotten (`downloadFile`).
  const usedUp = downloadsUsedUp(file, storedGrant(sessionId, file.id));
  const warningId = `warning-${file.id}`;

  const download = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await downloadFile(file.id);
      setNotice(t('recipient.downloadStarted', { name: file.display_name }));
      onCounted();
    } catch (failure) {
      const gone = goneOf(failure);
      if (gone) return onGone(gone);
      setError(linkProblemText(failure, t));
      onCounted();
    } finally {
      setBusy(false);
    }
  };

  return (
    <li className="rounded-lg border border-gray-200 p-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 items-start gap-3">
          <FileIcon className="mt-0.5 h-5 w-5 shrink-0 text-gray-500" aria-hidden="true" />
          <div className="min-w-0">
            <p className="break-all text-sm font-medium text-gray-900">{file.display_name}</p>
            <p className="text-xs text-gray-600">
              {formatFileSize(file.size)}
              {' · '}
              {limit === null ? t('recipient.downloadsNoLimit', { used }) : t('recipient.downloadsUsed', { used, limit })}
            </p>
          </div>
        </div>
        <Button
          size="sm"
          className="shrink-0"
          onClick={() => void download()}
          loading={busy}
          disabled={usedUp}
          aria-label={t('recipient.downloadFile', { name: file.display_name })}
          aria-describedby={file.warning === 'unscannable' ? warningId : undefined}
        >
          <Download className="mr-1 h-4 w-4" aria-hidden="true" />
          {t('recipient.download')}
        </Button>
      </div>
      {file.warning === 'unscannable' && (
        <div className="mt-3 flex items-start gap-2 rounded-lg bg-yellow-50 p-2">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-yellow-700" aria-hidden="true" />
          <p id={warningId} className="text-xs text-yellow-900">
            {t('recipient.unscannableWarning')}
          </p>
        </div>
      )}
      {usedUp && <p className="mt-2 text-sm text-gray-700">{t('recipient.limitReached')}</p>}
      <div role="status" className="mt-2 text-sm text-gray-700 empty:hidden">
        {notice}
      </div>
      {error && <Alert className="mt-2">{error}</Alert>}
    </li>
  );
}
