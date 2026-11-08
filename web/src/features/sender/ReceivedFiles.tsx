import { Fragment, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, Download, Trash2 } from 'lucide-react';
import {
  Alert,
  Button,
  Card,
  CardTitle,
  Dialog,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  toast,
} from '@/components/ui';
import type { Schema, UploadRequest } from '@/api';
import {
  createReceivedFileDownload,
  deleteReceivedFile,
  invalidateUploadRequests,
  useReceivedFiles,
} from '@/hooks/uploadRequests';
import { checkContent, contentUrl, startDownload } from '@/features/recipient/linkApi';
import { formatDate, formatFileSize } from '@/lib/formatters';
import { errorMessage } from '@/lib/problems';
import { FileStateBadge, InspectionStateBadge } from './StateBadges';
import { DetectorName, Findings } from './TransferDetailPage';
import { receivedFileActions } from './uploadRequests';

type ApiFile = Schema<'File'>;

/**
 * The files received through a request (#213; FR-12, FR-13, FR-16, FR-18): `listUploadRequestFiles`, each with its
 * scan state, size, the day it is deleted (`retention_until`), its inspection in brief and, on demand, its findings as
 * counts (`getFileInspection`, audited, so never polled). The request's owner downloads a shareable file by a grant
 * (`createReceivedFileDownload`), checked in the app and then handed to the browser's download manager by navigation,
 * with a warning for a file that couldn't be scanned (FR-18), and can delete one before its retention ends.
 */
export function ReceivedFiles({ request, isOwner }: { request: UploadRequest; isOwner: boolean }) {
  const { t } = useTranslation();
  const query = useReceivedFiles(request.id, request.state);
  const [deleting, setDeleting] = useState<ApiFile | null>(null);
  const files = query.data?.filter((file) => file.state !== 'deleted') ?? [];

  return (
    <Card>
      <CardTitle>{t('requests.received')}</CardTitle>
      {query.isPending ? (
        <div className="flex justify-center py-6">
          <Spinner />
          <span className="sr-only">{t('common.loading')}</span>
        </div>
      ) : query.isError ? (
        <Alert className="mt-3">{errorMessage(query.error, t)}</Alert>
      ) : files.length === 0 ? (
        <p className="mt-3 text-sm text-gray-600">{t('requests.noFiles')}</p>
      ) : (
        <Table label={t('requests.received')} caption={t('requests.receivedCaption')} className="mt-3">
          <TableHead>
            <tr>
              <TableHeader>{t('requests.file')}</TableHeader>
              <TableHeader>{t('common.status')}</TableHeader>
              <TableHeader>{t('common.size')}</TableHeader>
              <TableHeader>{t('requests.keptUntil')}</TableHeader>
              <TableHeader>{t('common.actions')}</TableHeader>
            </tr>
          </TableHead>
          <TableBody>
            {files.map((file) => (
              <ReceivedFileRow key={file.id} file={file} isOwner={isOwner} onDelete={() => setDeleting(file)} />
            ))}
          </TableBody>
        </Table>
      )}
      <DeleteFileDialog file={deleting} onClose={() => setDeleting(null)} />
    </Card>
  );
}

function ReceivedFileRow({ file, isOwner, onDelete }: { file: ApiFile; isOwner: boolean; onDelete: () => void }) {
  const { t, i18n } = useTranslation();
  const [showFindings, setShowFindings] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const actions = receivedFileActions(file, isOwner);
  const inspection = file.inspection;
  const findingsId = `findings-${file.id}`;
  const warningId = `warning-${file.id}`;
  const unscannable = file.state === 'unscannable';
  const canHaveFindings = (inspection.state === 'inspected' || inspection.state === 'partial') && inspection.detectors.length > 0;

  const download = async () => {
    setBusy(true);
    setNotice(null);
    setError(null);
    try {
      const access = await createReceivedFileDownload(file.id);
      const href = contentUrl(access.url);
      // As on the recipient's page: a refused grant is explained here, not by the browser showing the API's JSON.
      await checkContent(href);
      startDownload(href);
      setNotice(t('requests.downloadStarted', { name: file.display_name }));
    } catch (failure) {
      setError(errorMessage(failure, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Fragment>
      <TableRow>
        <th scope="row" className="px-4 py-3 text-left align-top text-sm font-medium break-all text-gray-900">
          {file.display_name}
        </th>
        <TableCell className="whitespace-normal align-top">
          <div className="flex flex-wrap items-center gap-2">
            <FileStateBadge state={file.state} />
            {file.state !== 'uploading' && file.state !== 'completing' && <InspectionStateBadge state={inspection.state} />}
          </div>
          {file.scan_detail && <p className="mt-1 max-w-xs text-xs text-gray-700">{t(`scanDetail.${file.scan_detail}`)}</p>}
          {inspection.reasons.length > 0 && (
            <p className="mt-1 max-w-xs text-xs text-gray-700">
              {t('sender.notInspectedBecause')}{' '}
              {inspection.reasons.map((reason) => t(`inspectionReason.${reason}`)).join(t('common.listSeparator'))}
            </p>
          )}
          {inspection.detectors.length > 0 && (
            <p className="mt-1 max-w-xs text-xs text-gray-700">
              {t('sender.detectorsFound')}{' '}
              {inspection.detectors.map((detector, index) => (
                <Fragment key={detector}>
                  <DetectorName id={detector} />
                  {index < inspection.detectors.length - 1 ? t('common.listSeparator') : ''}
                </Fragment>
              ))}
            </p>
          )}
          {canHaveFindings && (
            <button
              type="button"
              className="mt-1 text-xs font-semibold text-brand-700 underline hover:text-brand-800"
              aria-expanded={showFindings}
              aria-controls={showFindings ? findingsId : undefined}
              onClick={() => setShowFindings((shown) => !shown)}
            >
              {showFindings ? t('sender.hideFindings') : t('sender.showFindings', { name: file.display_name })}
            </button>
          )}
          {actions.download && unscannable && (
            <p id={warningId} className="mt-2 flex max-w-xs items-start gap-1 rounded bg-yellow-50 p-1.5 text-xs text-yellow-900">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-yellow-700" aria-hidden="true" />
              {t('recipient.unscannableWarning')}
            </p>
          )}
        </TableCell>
        <TableCell className="align-top">{formatFileSize(file.actual_size ?? file.declared_size)}</TableCell>
        <TableCell className="align-top">{file.retention_until ? formatDate(file.retention_until, i18n.language) : '—'}</TableCell>
        <TableCell className="whitespace-normal align-top">
          <div className="flex flex-wrap gap-2">
            {actions.download && (
              <Button
                size="sm"
                onClick={() => void download()}
                loading={busy}
                aria-label={t('requests.downloadFile', { name: file.display_name })}
                aria-describedby={unscannable ? warningId : undefined}
              >
                <Download className="mr-1 h-4 w-4" aria-hidden="true" />
                {t('requests.download')}
              </Button>
            )}
            {actions.remove && (
              <Button
                size="sm"
                variant="secondary"
                onClick={onDelete}
                aria-label={t('requests.deleteFile', { name: file.display_name })}
              >
                <Trash2 className="mr-1 h-4 w-4" aria-hidden="true" />
                {t('common.delete')}
              </Button>
            )}
          </div>
          <div role="status" className="mt-1 max-w-xs text-xs text-gray-700 empty:hidden">
            {notice}
          </div>
          {error && <Alert className="mt-2">{error}</Alert>}
        </TableCell>
      </TableRow>
      {canHaveFindings && showFindings && (
        <tr>
          <td colSpan={5} className="px-4 pb-3" id={findingsId}>
            <Findings fileId={file.id} />
          </td>
        </tr>
      )}
    </Fragment>
  );
}

/** Delete a received file before its retention ends (FR-13, `deleteFile`), after a confirmation. */
function DeleteFileDialog({ file, onClose }: { file: ApiFile | null; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const close = () => {
    setError(null);
    onClose();
  };

  const remove = async (target: ApiFile) => {
    setBusy(true);
    setError(null);
    try {
      await deleteReceivedFile(target.id);
      toast('success', t('requests.deleted', { name: target.display_name }));
      await invalidateUploadRequests(queryClient);
      close();
    } catch (failure) {
      setError(errorMessage(failure, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={file !== null} onClose={close} title={t('requests.deleteTitle')}>
      {file && (
        <div className="space-y-4">
          <p className="text-sm text-gray-700">{t('requests.deleteBody', { name: file.display_name })}</p>
          {error && <Alert>{error}</Alert>}
          <div className="flex justify-end gap-3">
            <Button variant="secondary" onClick={close} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button variant="danger" onClick={() => void remove(file)} loading={busy}>
              {t('common.delete')}
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}
