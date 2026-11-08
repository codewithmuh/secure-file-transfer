import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, FileIcon, Mail } from 'lucide-react';
import { PageShell } from '@/components/layout';
import {
  Alert,
  Badge,
  Button,
  Card,
  CardTitle,
  ProgressBar,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  toast,
} from '@/components/ui';
import type { Schema, Transfer } from '@/api';
import {
  cancelTransfer,
  invalidateTransfers,
  queryKeys,
  sendTransfer,
  uploadApi,
  useFileInspection,
  useTransfer,
} from '@/hooks/transfers';
import { errorMessage, problemCode } from '@/lib/problems';
import { formatDate, formatFileSize } from '@/lib/formatters';
import { useDurationLabel } from '@/lib/useDurationLabel';
import { FileStateBadge, InspectionStateBadge, TransferStateBadge } from './StateBadges';
import { isBuiltinDetector, NOT_AVAILABLE_STATES } from './states';
import { useActiveUploads } from './polling';
import { FileUpload, type UploadProgress } from './upload';

type ApiFile = Schema<'File'>;

/** File states past `completing`: the upload is over, whatever its result. */
const UPLOAD_OVER = new Set<ApiFile['state']>(['scanning', 'clean', 'infected', 'unscannable', 'scan_failed', 'rejected']);

/**
 * The sender's view of a transfer (#196): its state and expiry, each file's scan state and inspection, findings on
 * demand, and its recipients. Polled while something still moves (`useTransfer`). For a draft whose upload stopped (a
 * reload, a closed tab), the member picks each file again and its upload carries on from the parts S3 holds; then
 * the draft can be sent. The delivery table, unlock and revoke come with #199.
 */
export function TransferDetailPage() {
  const { id = '' } = useParams<{ id: string }>();
  const { t, i18n } = useTranslation();
  const query = useTransfer(id);
  const transfer = query.data;
  const announcement = useStateAnnouncement(transfer);

  return (
    <PageShell
      title={t('sender.transfer')}
      description={transfer ? t('sender.createdOn', { date: formatDate(transfer.created_at, i18n.language) }) : undefined}
      actions={
        <Link to="/transfers" className="btn-secondary">
          <ArrowLeft className="mr-2 h-4 w-4" aria-hidden="true" />
          {t('sender.backToTransfers')}
        </Link>
      }
    >
      <div className="sr-only" role="status" aria-live="polite">
        {announcement}
      </div>
      {query.isPending ? (
        <div className="flex justify-center py-12">
          <Spinner />
          <span className="sr-only">{t('common.loading')}</span>
        </div>
      ) : query.isError ? (
        <Alert>{problemCode(query.error) === 'not_found' ? t('sender.transferNotFound') : errorMessage(query.error, t)}</Alert>
      ) : transfer ? (
        <TransferView transfer={transfer} />
      ) : null}
    </PageShell>
  );
}

/** One polite announcement of what changed between two polls, for every file at once (one live region). */
function useStateAnnouncement(transfer: Transfer | undefined): string {
  const { t } = useTranslation();
  const previous = useRef<Map<string, string> | null>(null);
  const [text, setText] = useState('');
  useEffect(() => {
    if (!transfer) return;
    const now = new Map<string, string>([['transfer', transfer.state], ...transfer.files.map((f) => [f.id, f.state] as [string, string])]);
    const before = previous.current;
    previous.current = now;
    if (!before) return;
    const changes: string[] = [];
    if (before.get('transfer') !== transfer.state) {
      changes.push(t('sender.announceTransfer', { state: t(`transferState.${transfer.state}`) }));
    }
    for (const file of transfer.files) {
      if (before.has(file.id) && before.get(file.id) !== file.state) {
        changes.push(t('sender.announceFile', { name: file.display_name, state: t(`fileState.${file.state}`) }));
      }
    }
    if (changes.length > 0) setText(changes.join(' '));
  }, [transfer, t]);
  return text;
}

function TransferView({ transfer }: { transfer: Transfer }) {
  const { t, i18n } = useTranslation();
  const durationLabel = useDurationLabel();
  const isDraft = transfer.state === 'draft';
  const files = transfer.files.filter((file) => file.state !== 'deleted');

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
      <div className="space-y-6 lg:col-span-2">
        {transfer.state === 'held' && transfer.hold_reason && (
          <Alert variant="warning" role="status">
            {t(`holdReason.${transfer.hold_reason}`)}
          </Alert>
        )}
        {NOT_AVAILABLE_STATES.includes(transfer.state) && (
          <Alert variant="info" role="status">
            {t('sender.dlpNotAvailable')}
          </Alert>
        )}
        {isDraft && <DraftActions transfer={transfer} />}

        <Card>
          <CardTitle>{t('sender.files')}</CardTitle>
          {files.length === 0 ? (
            <p className="mt-3 text-sm text-gray-500">{t('sender.noFiles')}</p>
          ) : (
            <ul className="mt-3 space-y-3">
              {files.map((file) => (
                <FileRow key={file.id} file={file} />
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardTitle>{t('sender.recipients')}</CardTitle>
          <Table label={t('sender.recipients')}>
            <TableHead>
              <tr>
                <TableHeader>{t('common.email')}</TableHeader>
                <TableHeader>{t('sender.language')}</TableHeader>
                <TableHeader>{t('common.status')}</TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {transfer.recipients.map((recipient) => (
                <TableRow key={recipient.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Mail className="h-4 w-4 text-gray-500" aria-hidden="true" />
                      <span className="font-medium">{recipient.email}</span>
                    </div>
                  </TableCell>
                  <TableCell>{t(`locales.${recipient.locale}`)}</TableCell>
                  <TableCell>
                    <Badge variant={recipient.access_state === 'locked' ? 'danger' : recipient.access_state === 'verified' ? 'success' : 'default'}>
                      {t(`accessState.${recipient.access_state}`)}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      </div>

      <div>
        <Card>
          <CardTitle>{t('common.details')}</CardTitle>
          <dl className="mt-3 space-y-3 text-sm">
            <div>
              <dt className="text-gray-500">{t('common.status')}</dt>
              <dd className="mt-0.5">
                <TransferStateBadge state={transfer.state} />
              </dd>
            </div>
            <div>
              <dt className="text-gray-500">{t('common.expiresAt')}</dt>
              <dd className="mt-0.5 font-medium">
                {transfer.expires_at
                  ? formatDate(transfer.expires_at, i18n.language)
                  : t('sender.expiresAfterSending', { duration: durationLabel(transfer.expires_in) })}
              </dd>
            </div>
            <div>
              <dt className="text-gray-500">{t('sender.downloadLimit')}</dt>
              <dd className="mt-0.5 font-medium">{transfer.download_limit ?? t('common.noLimit')}</dd>
            </div>
            <div>
              <dt className="text-gray-500">{t('common.totalSize')}</dt>
              <dd className="mt-0.5 font-medium">{formatFileSize(transfer.total_size)}</dd>
            </div>
            <div>
              <dt className="text-gray-500">{t('sender.sentAt')}</dt>
              <dd className="mt-0.5 font-medium">{transfer.sent_at ? formatDate(transfer.sent_at, i18n.language) : '—'}</dd>
            </div>
            {transfer.message && (
              <div>
                <dt className="text-gray-500">{t('sender.messageColumn')}</dt>
                <dd className="mt-0.5 whitespace-pre-wrap break-words">{transfer.message}</dd>
              </div>
            )}
          </dl>
        </Card>
      </div>
    </div>
  );
}

function FileRow({ file }: { file: ApiFile }) {
  const { t } = useTranslation();
  const [showFindings, setShowFindings] = useState(false);
  const inspection = file.inspection;
  const findingsId = `findings-${file.id}`;
  const canHaveFindings = inspection.state === 'inspected' || inspection.state === 'partial';

  return (
    <li className="rounded-lg bg-gray-50 p-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <FileIcon className="h-5 w-5 shrink-0 text-gray-500" aria-hidden="true" />
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-gray-900">{file.display_name}</p>
            <p className="text-xs text-gray-500">{formatFileSize(file.actual_size ?? file.declared_size)}</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <FileStateBadge state={file.state} />
          {file.state !== 'uploading' && file.state !== 'completing' && <InspectionStateBadge state={inspection.state} />}
        </div>
      </div>
      {file.scan_detail && <p className="mt-2 text-sm text-gray-700">{t(`scanDetail.${file.scan_detail}`)}</p>}
      {inspection.reasons.length > 0 && (
        <p className="mt-2 text-sm text-gray-700">
          {t('sender.notInspectedBecause')} {inspection.reasons.map((reason) => t(`inspectionReason.${reason}`)).join(t('common.listSeparator'))}
        </p>
      )}
      {inspection.detectors.length > 0 && (
        <div className="mt-2 text-sm text-gray-700">
          <span>{t('sender.detectorsFound')} </span>
          <ul className="inline">
            {inspection.detectors.map((detector, index) => (
              <li key={detector} className="inline">
                <DetectorName id={detector} />
                {index < inspection.detectors.length - 1 ? t('common.listSeparator') : ''}
              </li>
            ))}
          </ul>
        </div>
      )}
      {canHaveFindings && inspection.detectors.length > 0 && (
        <div className="mt-2">
          <button
            type="button"
            className="text-sm font-semibold text-brand-700 underline hover:text-brand-800"
            aria-expanded={showFindings}
            aria-controls={findingsId}
            onClick={() => setShowFindings((shown) => !shown)}
          >
            {showFindings ? t('sender.hideFindings') : t('sender.showFindings', { name: file.display_name })}
          </button>
          <div id={findingsId}>{showFindings && <Findings fileId={file.id} />}</div>
        </div>
      )}
    </li>
  );
}

function DetectorName({ id, fallback }: { id: string; fallback?: string }) {
  const { t } = useTranslation();
  return <>{isBuiltinDetector(id) ? t(`detectors.${id}`) : (fallback ?? id)}</>;
}

/** A file's findings, fetched once when shown (`getFileInspection`); each response with details is audited. */
function Findings({ fileId }: { fileId: string }) {
  const { t } = useTranslation();
  const inspection = useFileInspection(fileId, true);
  if (inspection.isPending) return <Spinner size="sm" className="mt-2" />;
  if (inspection.isError) return <Alert className="mt-2">{errorMessage(inspection.error, t)}</Alert>;
  const findings = inspection.data.findings;
  if (findings.length === 0) return <p className="mt-2 text-sm text-gray-500">{t('sender.noFindings')}</p>;
  return (
    <Table label={t('sender.findings')} className="mt-2">
      <TableHead>
        <tr>
          <TableHeader>{t('sender.detector')}</TableHeader>
          <TableHeader>{t('sender.confidenceHigh')}</TableHeader>
          <TableHeader>{t('sender.confidenceMedium')}</TableHeader>
          <TableHeader>{t('sender.confidenceLow')}</TableHeader>
          <TableHeader>{t('sender.where')}</TableHeader>
        </tr>
      </TableHead>
      <TableBody>
        {findings.map((finding) => (
          <TableRow key={finding.detector}>
            <TableCell>
              <DetectorName id={finding.detector} fallback={finding.detector_name} />
            </TableCell>
            <TableCell>{finding.count_high}</TableCell>
            <TableCell>{finding.count_medium}</TableCell>
            <TableCell>{finding.count_low}</TableCell>
            <TableCell className="whitespace-normal">
              {finding.details_visible ? <Locations finding={finding} /> : t('sender.countsOnly')}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function Locations({ finding }: { finding: Schema<'DlpFinding'> }) {
  const { t } = useTranslation();
  const places = (finding.locations ?? []).map((location) =>
    (['member', 'page', 'sheet', 'row', 'slide', 'line', 'paragraph', 'part'] as const)
      .filter((key) => location[key] !== undefined)
      .map((key) => t(`location.${key}`, { value: key === 'part' ? t(`documentPart.${location.part}`) : location[key] }))
      .join(', '),
  );
  const previews = finding.previews ?? [];
  if (places.length === 0 && previews.length === 0) return <>—</>;
  return (
    <div>
      {places.length > 0 && <p>{places.join('; ')}</p>}
      {previews.length > 0 && <p className="font-mono text-xs">{previews.join(', ')}</p>}
    </div>
  );
}

/**
 * A draft's actions: resume the files still uploading (the member picks each again: matched on name and size), send
 * once every file is past completing, or cancel the draft.
 */
function DraftActions({ transfer }: { transfer: Transfer }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const files = transfer.files.filter((file) => file.state !== 'deleted');
  const unfinished = files.filter((file) => file.state === 'uploading');
  const ready = files.length > 0 && files.every((file) => UPLOAD_OVER.has(file.state));

  const act = async (action: () => Promise<Transfer>, done: (result: Transfer) => void) => {
    setBusy(true);
    setError(null);
    try {
      done(await action());
      await invalidateTransfers(queryClient);
    } catch (failure) {
      setError(errorMessage(failure, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardTitle>{t('sender.draftTitle')}</CardTitle>
      <p className="mt-2 text-sm text-gray-600">{unfinished.length > 0 ? t('sender.draftResumeHint') : t('sender.draftHint')}</p>
      {unfinished.length > 0 && (
        <ul className="mt-3 space-y-3">
          {unfinished.map((file) => (
            <ResumeFile key={file.id} file={file} />
          ))}
        </ul>
      )}
      {error && <Alert className="mt-3">{error}</Alert>}
      <div className="mt-4 flex flex-wrap gap-3">
        <Button
          disabled={!ready || busy}
          loading={busy}
          onClick={() =>
            void act(
              () => sendTransfer(transfer.id),
              () => toast('success', t('sender.transferSent')),
            )
          }
        >
          {t('sender.send')}
        </Button>
        <Button
          variant="secondary"
          disabled={busy}
          onClick={() =>
            void act(
              () => cancelTransfer(transfer.id),
              () => navigate('/transfers'),
            )
          }
        >
          {t('sender.cancelTransfer')}
        </Button>
      </div>
    </Card>
  );
}

function ResumeFile({ file }: { file: ApiFile }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const input = useRef<HTMLInputElement>(null);
  const [progress, setProgress] = useState<UploadProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const engine = useRef<FileUpload | null>(null);

  useEffect(() => () => void engine.current?.pause(), []);

  const pick = async (picked: File | undefined) => {
    if (input.current) input.current.value = '';
    if (!picked) return;
    if (picked.name !== file.display_name || picked.size !== file.declared_size) {
      setError(t('sender.resumeMismatch', { name: file.display_name }));
      return;
    }
    setError(null);
    const upload = new FileUpload({ fileId: file.id, blob: picked, api: uploadApi, onChange: setProgress });
    engine.current = upload;
    const active = useActiveUploads.getState();
    active.start(file.id); // the detail page polls while this tab uploads the file
    try {
      await upload.start();
    } catch (failure) {
      setError(errorMessage(failure, t));
    } finally {
      active.stop(file.id);
      await queryClient.invalidateQueries({ queryKey: queryKeys.transfer(file.transfer_id ?? '') });
    }
  };

  const running = progress?.status === 'uploading' || progress?.status === 'completing';
  return (
    <li className="rounded-lg bg-gray-50 p-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm font-medium text-gray-900">
          {file.display_name} <span className="text-xs text-gray-500">({formatFileSize(file.declared_size)})</span>
        </p>
        <Button size="sm" variant="secondary" disabled={running} onClick={() => input.current?.click()}>
          {t('sender.pickAgain')}
        </Button>
        <input
          ref={input}
          type="file"
          hidden
          aria-label={t('sender.pickAgainFor', { name: file.display_name })}
          data-testid={`resume-${file.id}`}
          onChange={(event) => void pick(event.target.files?.[0])}
        />
      </div>
      {progress && (
        <ProgressBar
          className="mt-2"
          label={t('sender.uploadProgress', { name: file.display_name })}
          value={progress.sentBytes}
          max={progress.totalBytes}
          valueText={t('sender.uploadedOf', { sent: formatFileSize(progress.sentBytes), total: formatFileSize(progress.totalBytes) })}
        />
      )}
      {error && <p className="mt-1 text-sm text-red-700">{error}</p>}
    </li>
  );
}
