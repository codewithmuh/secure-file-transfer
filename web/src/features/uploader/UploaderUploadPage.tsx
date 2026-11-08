import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { FileIcon, Upload, X } from 'lucide-react';
import { Alert, Badge, Button, Card, CardTitle, ProgressBar, Spinner } from '@/components/ui';
import { endLinkSession, goneOf, type VerifiedSession } from '@/features/recipient/linkApi';
import type { GateActions } from '@/features/recipient/LinkGate';
import { StepHeading } from '@/features/recipient/StepHeading';
import { MAX_FILE_BYTES, MAX_FILES, MAX_TOTAL_BYTES } from '@/features/sender/limits';
import { FileUpload, type UploadProgress } from '@/features/sender/upload';
import { formatDate, formatFileSize } from '@/lib/formatters';
import { IdempotencyKeys } from '@/lib/idempotency';
import {
  addSessionUploadFile,
  countedFiles,
  deleteSessionUploadFile,
  limitsOf,
  listUploadedFiles,
  resumableMatch,
  sessionUploadApi,
  uploaderFileProblem,
  uploaderFileStatus,
  uploaderMayRemove,
  uploaderProblemText,
  uploaderStatusVariant,
  uploadsPollInterval,
  type SessionFile,
  type UploaderFileProblem,
  type UploaderFileStatus,
  type UploadLimits,
} from './uploaderApi';

/** A file picked in this tab: its server file once declared, and its upload's progress. */
interface LocalEntry {
  key: string;
  file: File;
  fileId?: string;
  progress?: UploadProgress;
  error?: string;
}

type Phase = 'idle' | 'uploading' | 'failed';

/** States past the upload: the file reached the service, whatever the scan said. */
const ARRIVED = new Set<SessionFile['state']>(['scanning', 'clean', 'infected', 'unscannable', 'scan_failed']);

/**
 * The verified uploader's page on `/u` (#212, #213; FR-11, FR-12, FR-14): who asks for files, their message, until
 * when and within which limits, shown only now (FR-14); then the uploader picks files and uploads them with the M3
 * upload engine over the link session's operations (`sessionUploadApi`), up to 4 parts at a time, and sees each file's
 * state from `listSessionFiles`, in their own words (`uploaderFileStatus`: a blocked file says only "blocked by the
 * company's policy" or "couldn't be scanned").
 *
 * **Resuming (FR-11, NFR-3).** A dropped connection stops the upload; it carries on by itself when the browser is
 * back online, or on "Try again", from the parts storage already holds. After a reload (the link opened again, the
 * session resumed), a file still `uploading` on the service is picked again, matched on its name and size, and carries
 * on where it stopped. A revoked or expired request ends the page (`410`, the gate's own page).
 *
 * **Taking a file back (#229).** While nothing uploads, each file but a blocked one has "Remove", which asks first,
 * then removes it on the service (`deleteSessionUploadFile`): it stops counting toward the limits and the company
 * never gets it. An unscannable file the company's policy accepts reads as accepted, with a word on why.
 */
export function UploaderUploadPage({ session, actions }: { session: VerifiedSession; actions: GateActions }) {
  const { t, i18n } = useTranslation();
  const request = session.upload_request;
  const limits: UploadLimits = request
    ? limitsOf(request)
    : { maxFiles: MAX_FILES, maxFileSize: MAX_FILE_BYTES, maxTotalSize: MAX_TOTAL_BYTES };
  const fileInput = useRef<HTMLInputElement>(null);
  const keys = useRef(new IdempotencyKeys());
  const engines = useRef(new Map<string, FileUpload<SessionFile>>());
  const entriesNow = useRef<LocalEntry[]>([]);
  const mounted = useRef(true);
  const phaseNow = useRef<Phase>('idle');

  const [entries, setEntries] = useState<LocalEntry[]>([]);
  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<string | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const [ending, setEnding] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);

  entriesNow.current = entries;
  phaseNow.current = phase;

  const files = useQuery({
    queryKey: ['link-session', session.id, 'uploads'],
    queryFn: ({ signal }) => listUploadedFiles(signal),
    retry: false,
    staleTime: 0,
    refetchInterval: (query) => uploadsPollInterval(query.state.data, phaseNow.current === 'uploading'),
  });
  const refetchFiles = files.refetch;

  // A `410` on the list: the request was revoked or has expired since (a 401 goes back to the code step on its own).
  const listGone = files.isError ? goneOf(files.error) : null;
  useEffect(() => {
    if (listGone) actions.gone(listGone);
  }, [listGone, actions]);

  // Leaving the page stops the uploads; what storage holds stays, and picking the file again carries on.
  useEffect(() => {
    const running = engines.current;
    mounted.current = true;
    return () => {
      mounted.current = false;
      for (const engine of running.values()) {
        if (engine.state.status === 'uploading') void engine.pause();
      }
    };
  }, []);

  const updateEntry = useCallback((key: string, change: Partial<LocalEntry>) => {
    setEntries((previous) => previous.map((entry) => (entry.key === key ? { ...entry, ...change } : entry)));
  }, []);

  const serverFiles = (files.data ?? []).filter((file) => file.state !== 'deleted');

  /** Adds picked files: one that continues a file still `uploading` is matched to it; a new one is checked first. */
  const addFiles = (picked: readonly File[]): LocalEntry[] => {
    const taken = new Set(entriesNow.current.flatMap((entry) => (entry.fileId ? [entry.fileId] : [])));
    const sizes = [
      ...countedFiles(serverFiles).map((file) => file.size),
      ...entriesNow.current.filter((entry) => !entry.fileId).map((entry) => entry.file.size),
    ];
    const added: LocalEntry[] = [];
    let problem: UploaderFileProblem | null = null;
    for (const file of picked) {
      const match = resumableMatch(file, serverFiles, taken);
      if (match) {
        taken.add(match.id);
        added.push({ key: crypto.randomUUID(), file, fileId: match.id });
        continue;
      }
      problem = uploaderFileProblem(file.size, sizes, limits);
      if (problem) break;
      sizes.push(file.size);
      added.push({ key: crypto.randomUUID(), file });
    }
    setEntries((previous) => [...previous, ...added]);
    setFileError(
      problem
        ? t(`uploader.fileProblem.${problem}`, {
            size: formatFileSize(problem === 'too_large' ? limits.maxFileSize : limits.maxTotalSize),
            files: limits.maxFiles,
          })
        : null,
    );
    if (fileInput.current) fileInput.current.value = '';
    entriesNow.current = [...entriesNow.current, ...added];
    return added;
  };

  const run = async () => {
    setError(null);
    setPhase('uploading');
    phaseNow.current = 'uploading';
    try {
      // One file at a time, each with up to 4 parts in flight; the list is read as it is now.
      for (const entry of [...entriesNow.current]) {
        if (!mounted.current) return;
        let engine = engines.current.get(entry.key);
        if (!engine) {
          let fileId = entry.fileId;
          if (!fileId) {
            const name = `addSessionUploadFile:${entry.key}`;
            const body = {
              display_name: entry.file.name,
              size: entry.file.size,
              ...(entry.file.type ? { content_type: entry.file.type } : {}),
            };
            const added = await addSessionUploadFile(body, keys.current.keyForBody(name, body));
            keys.current.done(name);
            fileId = added.id;
          }
          engine = new FileUpload<SessionFile>({
            fileId,
            blob: entry.file,
            api: sessionUploadApi,
            onChange: (progress) => updateEntry(entry.key, { progress }),
          });
          engines.current.set(entry.key, engine);
          updateEntry(entry.key, { fileId, error: undefined });
          entriesNow.current = entriesNow.current.map((other) => (other.key === entry.key ? { ...other, fileId } : other));
          void refetchFiles();
        }
        if (engine.state.status === 'done') continue;
        try {
          const completed = await engine.start();
          if (completed === null) return; // paused: the page is closing
          setAnnouncement(t('sender.fileUploaded', { name: entry.file.name }));
          void refetchFiles();
        } catch (failure) {
          updateEntry(entry.key, { error: uploaderProblemText(failure, t) });
          throw failure;
        }
      }
      if (!mounted.current) return;
      setPhase('idle');
      setAnnouncement(t('uploader.allUploaded'));
      void refetchFiles();
    } catch (failure) {
      const gone = goneOf(failure);
      if (gone) return actions.gone(gone);
      setError(uploaderProblemText(failure, t));
      setPhase('failed');
      setAnnouncement(t('sender.uploadStopped'));
    }
  };

  const pickAndRun = (picked: FileList | null) => {
    if (!picked || phaseNow.current === 'uploading') return;
    if (addFiles(Array.from(picked)).length > 0) void run();
  };

  // When the browser comes back online, a stopped upload carries on by itself.
  useEffect(() => {
    if (phase !== 'failed') return;
    const onOnline = () => void run();
    window.addEventListener('online', onOnline);
    return () => window.removeEventListener('online', onOnline);
  });

  /** Takes one of the uploader's files back, then forgets this tab's upload of it (#229). */
  const takeBack = async (file: SessionFile) => {
    setRemoving(file.id);
    setError(null);
    try {
      await deleteSessionUploadFile(file.id);
      for (const entry of entriesNow.current.filter((other) => other.fileId === file.id)) engines.current.delete(entry.key);
      setEntries((previous) => previous.filter((entry) => entry.fileId !== file.id));
      entriesNow.current = entriesNow.current.filter((entry) => entry.fileId !== file.id);
      setAnnouncement(t('uploader.removed', { name: file.display_name }));
      await refetchFiles();
    } catch (failure) {
      const gone = goneOf(failure);
      if (gone) return actions.gone(gone);
      setError(uploaderProblemText(failure, t));
    } finally {
      if (mounted.current) setRemoving(null);
    }
  };

  const done = async () => {
    setEnding(true);
    try {
      await endLinkSession();
    } catch {
      // The store forgot the session either way; the API ends it at its idle timeout.
    }
    actions.done();
  };

  const byFileId = new Map(entries.flatMap((entry) => (entry.fileId ? [[entry.fileId, entry] as const] : [])));
  const listed = new Set(serverFiles.map((file) => file.id));
  const localOnly = entries.filter((entry) => !entry.fileId || !listed.has(entry.fileId));
  const unfinished = entries.some((entry) => entry.progress?.status !== 'done');
  const arrived = serverFiles.filter((file) => ARRIVED.has(file.state));
  const received = files.data
    ? { count: arrived.length, bytes: arrived.reduce((sum, file) => sum + file.size, 0) }
    : { count: request?.files_received ?? 0, bytes: request?.bytes_received ?? 0 };
  const date = (value: string) => formatDate(value, i18n.language);

  return (
    <div className="space-y-6">
      <div className="sr-only" role="status" aria-live="polite">
        {announcement}
      </div>
      <Card>
        <StepHeading>{t('uploader.title')}</StepHeading>
        {request && (
          <dl className="mt-4 grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-gray-600">{t('recipient.organization')}</dt>
              <dd className="mt-0.5 font-medium text-gray-900">{request.tenant_name}</dd>
            </div>
            <div>
              <dt className="text-gray-600">{t('uploader.requestedBy')}</dt>
              <dd className="mt-0.5 break-all font-medium text-gray-900">{request.requester_email}</dd>
            </div>
            <div>
              <dt className="text-gray-600">{t('uploader.openUntil')}</dt>
              <dd className="mt-0.5 font-medium text-gray-900">{date(request.expires_at)}</dd>
            </div>
            <div>
              <dt className="text-gray-600">{t('recipient.verifiedAs')}</dt>
              <dd className="mt-0.5 break-all font-medium text-gray-900">{session.email}</dd>
            </div>
            <div>
              <dt className="text-gray-600">{t('uploader.limitsTitle')}</dt>
              <dd className="mt-0.5 text-gray-900">
                {t('uploader.limits', {
                  files: limits.maxFiles,
                  size: formatFileSize(limits.maxFileSize),
                  total: formatFileSize(limits.maxTotalSize),
                })}
              </dd>
            </div>
            <div>
              <dt className="text-gray-600">{t('uploader.receivedTitle')}</dt>
              <dd className="mt-0.5 text-gray-900">
                {t('uploader.receivedSoFar', { count: received.count, size: formatFileSize(received.bytes) })}
              </dd>
            </div>
            {request.message && (
              <div className="sm:col-span-2">
                <dt className="text-gray-600">{t('recipient.message')}</dt>
                <dd className="mt-0.5 whitespace-pre-wrap break-words text-gray-900">{request.message}</dd>
              </div>
            )}
          </dl>
        )}
      </Card>

      <Card>
        <CardTitle>{t('uploader.uploadFiles')}</CardTitle>
        <div
          onDrop={(event) => {
            event.preventDefault();
            pickAndRun(event.dataTransfer.files);
          }}
          onDragOver={(event) => event.preventDefault()}
          className="mt-3 flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-gray-300 p-8 text-center"
        >
          <Upload className="mb-3 h-10 w-10 text-gray-500" aria-hidden="true" />
          <p className="text-sm font-medium text-gray-700">{t('sender.dragDrop')}</p>
          <Button
            type="button"
            variant="secondary"
            className="mt-4"
            disabled={phase === 'uploading'}
            onClick={() => fileInput.current?.click()}
          >
            {t('sender.chooseFiles')}
          </Button>
          <input
            ref={fileInput}
            type="file"
            multiple
            hidden
            aria-label={t('sender.chooseFiles')}
            data-testid="uploader-files"
            onChange={(event) => pickAndRun(event.target.files)}
          />
        </div>
        {fileError && <Alert className="mt-3">{fileError}</Alert>}
        {error && (
          <Alert className="mt-3">
            <p>{error}</p>
            {unfinished && (
              <Button size="sm" variant="secondary" className="mt-2" onClick={() => void run()}>
                {t('common.tryAgain')}
              </Button>
            )}
          </Alert>
        )}
      </Card>

      <Card>
        <CardTitle>{t('uploader.yourFiles')}</CardTitle>
        {files.isPending ? (
          <div className="flex justify-center py-6">
            <Spinner />
            <span className="sr-only">{t('common.loading')}</span>
          </div>
        ) : files.isError && !listGone ? (
          <Alert className="mt-3">{uploaderProblemText(files.error, t)}</Alert>
        ) : serverFiles.length === 0 && localOnly.length === 0 ? (
          <p className="mt-3 text-sm text-gray-600">{t('uploader.noFilesYet')}</p>
        ) : (
          <ul className="mt-3 space-y-3">
            {serverFiles.map((file) => (
              <FileRow
                key={file.id}
                name={file.display_name}
                size={file.size}
                status={uploaderFileStatus(file.state, file.warning, file.blocked)}
                entry={byFileId.get(file.id)}
                resumable={file.state === 'uploading' && !byFileId.has(file.id) && phase !== 'uploading'}
                onPick={(picked) => pickAndRun(picked)}
                onTakeBack={uploaderMayRemove(file) && phase !== 'uploading' ? () => takeBack(file) : undefined}
                takingBack={removing === file.id}
              />
            ))}
            {localOnly.map((entry) => (
              <FileRow
                key={entry.key}
                name={entry.file.name}
                size={entry.file.size}
                status={null}
                entry={entry}
                onRemove={
                  !entry.fileId && phase !== 'uploading'
                    ? () => setEntries((previous) => previous.filter((other) => other.key !== entry.key))
                    : undefined
                }
              />
            ))}
          </ul>
        )}
      </Card>

      <div className="flex justify-end">
        <Button variant="secondary" onClick={() => void done()} loading={ending} disabled={phase === 'uploading'}>
          {t('recipient.done')}
        </Button>
      </div>
    </div>
  );
}

/**
 * One file: its name, size and state as words with a badge (never colour alone), its upload's progress while this tab
 * sends it, and, for a file left `uploading` by an earlier visit, a way to pick it again so it carries on. A file on
 * the service that the uploader may take back has "Remove", which asks before it removes (#229).
 */
function FileRow({
  name,
  size,
  status,
  entry,
  resumable = false,
  onPick,
  onRemove,
  onTakeBack,
  takingBack = false,
}: {
  name: string;
  size: number;
  /** The service's state in the uploader's words, or null for a file not declared yet. */
  status: UploaderFileStatus | null;
  entry?: LocalEntry;
  resumable?: boolean;
  onPick?: (picked: FileList | null) => void;
  onRemove?: () => void;
  /** Removes the file on the service, after the uploader confirmed (#229). */
  onTakeBack?: () => Promise<void>;
  takingBack?: boolean;
}) {
  const { t } = useTranslation();
  const input = useRef<HTMLInputElement>(null);
  const keep = useRef<HTMLButtonElement>(null);
  const removeButton = useRef<HTMLButtonElement>(null);
  const [mismatch, setMismatch] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const confirmId = useId();

  // Asking moves focus to the safe answer; keeping the file returns it to "Remove".
  useEffect(() => {
    if (confirming) keep.current?.focus();
  }, [confirming]);
  const cancel = () => {
    setConfirming(false);
    requestAnimationFrame(() => removeButton.current?.focus());
  };
  const progress = entry?.progress;
  const sending = progress && progress.status !== 'done';
  const shown: UploaderFileStatus | 'waiting' = sending ? 'uploading' : (status ?? (progress ? 'uploading' : 'waiting'));
  const variant = shown === 'waiting' ? 'default' : uploaderStatusVariant[shown];

  return (
    <li className="rounded-lg bg-gray-50 p-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <FileIcon className="h-5 w-5 shrink-0 text-gray-500" aria-hidden="true" />
          <div className="min-w-0">
            <p className="break-all text-sm font-medium text-gray-900">{name}</p>
            <p className="text-xs text-gray-600">{formatFileSize(size)}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={variant}>{t(`uploader.status.${shown}`)}</Badge>
          {onTakeBack && !confirming && (
            <Button
              ref={removeButton}
              size="sm"
              variant="secondary"
              aria-label={t('uploader.removeFile', { name })}
              onClick={() => setConfirming(true)}
            >
              {t('uploader.remove')}
            </Button>
          )}
          {onRemove && (
            <button
              type="button"
              onClick={onRemove}
              aria-label={t('sender.removeFile', { name })}
              className="rounded-sm p-1 text-gray-500 hover:bg-gray-200 hover:text-gray-600"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>
      {sending && progress && (
        <ProgressBar
          className="mt-2"
          label={t('sender.uploadProgress', { name })}
          value={progress.sentBytes}
          max={progress.totalBytes}
          valueText={t('sender.uploadedOf', { sent: formatFileSize(progress.sentBytes), total: formatFileSize(progress.totalBytes) })}
        />
      )}
      {resumable && (
        <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
          <p className="text-sm text-gray-700">{t('uploader.resumeHint')}</p>
          <Button size="sm" variant="secondary" onClick={() => input.current?.click()}>
            {t('sender.pickAgain')}
          </Button>
          <input
            ref={input}
            type="file"
            hidden
            aria-label={t('sender.pickAgainFor', { name })}
            onChange={(event) => {
              const picked = event.target.files;
              const file = picked?.[0];
              const differs = file !== undefined && (file.name !== name || file.size !== size);
              setMismatch(differs);
              if (!differs) onPick?.(picked ?? null);
              event.target.value = '';
            }}
          />
        </div>
      )}
      {status === 'accepted' && <p className="mt-1 text-xs text-gray-700">{t('uploader.acceptedHint')}</p>}
      {status === 'notAccepted' && <p className="mt-1 text-xs text-gray-700">{t('uploader.notAcceptedHint')}</p>}
      {onTakeBack && confirming && (
        <div role="group" aria-labelledby={confirmId} className="mt-2 flex flex-wrap items-center justify-between gap-2">
          <p id={confirmId} className="text-sm text-gray-700">
            {t('uploader.removeConfirm', { name })}
          </p>
          <div className="flex gap-2">
            <Button ref={keep} size="sm" variant="secondary" onClick={cancel} disabled={takingBack}>
              {t('uploader.removeKeep')}
            </Button>
            <Button size="sm" variant="danger" loading={takingBack} onClick={() => void onTakeBack().finally(() => setConfirming(false))}>
              {t('uploader.removeYes')}
            </Button>
          </div>
        </div>
      )}
      {resumable && mismatch && <p className="mt-1 text-sm text-red-700">{t('sender.resumeMismatch', { name })}</p>}
      {entry?.error && <p className="mt-1 text-sm text-red-700">{entry.error}</p>}
    </li>
  );
}
