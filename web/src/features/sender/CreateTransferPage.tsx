import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { Send, Upload, X, Plus, FileIcon } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Alert, Button, Input, Card, CardTitle, ProgressBar, Select, toast } from '@/components/ui';
import type { Schema } from '@/api';
import {
  addTransferFile,
  cancelTransfer,
  createTransfer,
  invalidateTransfers,
  sendTransfer,
  uploadApi,
  useTenantPolicy,
} from '@/hooks/transfers';
import { defaultExpiry, expiryOptions } from '@/lib/durations';
import { errorMessage, failureOf, fieldErrors } from '@/lib/problems';
import { formatFileSize } from '@/lib/formatters';
import { IdempotencyKeys } from '@/lib/idempotency';
import { useDurationLabel } from '@/lib/useDurationLabel';
import { downloadLimitOf, fileProblem, MAX_MESSAGE, recipientProblem, type FileProblem } from './limits';
import { FileUpload, type UploadProgress } from './upload';

type Locale = Schema<'Locale'>;

interface RecipientEntry {
  key: string;
  email: string;
  locale: Locale;
}

interface FileEntry {
  key: string;
  file: File;
  fileId?: string;
  progress?: UploadProgress;
  error?: string;
}

type Phase = 'form' | 'uploading' | 'sending' | 'failed';

const LOCALES: readonly Locale[] = ['en', 'ja'];

/**
 * Create, upload and send a transfer (#196; FR-1 to FR-5). The member fills in the recipients (each with the language
 * of their emails and pages), the expiry within the tenant's `max_expiry`, an optional download limit and message,
 * and picks files. "Send" then creates the draft (`createTransfer`), adds each file (`addTransferFile`), uploads its
 * parts (`FileUpload`) and sends it (`sendTransfer`) once every file is complete, then opens the transfer. Each create
 * call has an `Idempotency-Key` kept for its attempt, so "Try again" after a lost answer replays it. If the page is
 * reloaded mid-upload, the draft's detail page picks the upload up again.
 */
export function CreateTransferPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const durationLabel = useDurationLabel();
  const policy = useTenantPolicy();
  const fileInput = useRef<HTMLInputElement>(null);
  const keys = useRef(new IdempotencyKeys());
  const engines = useRef(new Map<string, FileUpload>());
  const filesNow = useRef<FileEntry[]>([]);
  const mounted = useRef(true);

  const [recipients, setRecipients] = useState<RecipientEntry[]>([]);
  const [recipientInput, setRecipientInput] = useState('');
  const [newLocale, setNewLocale] = useState<Locale | null>(null);
  const [recipientError, setRecipientError] = useState<string | null>(null);
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [fileError, setFileError] = useState<string | null>(null);
  const [message, setMessage] = useState('');
  const [expiresIn, setExpiresIn] = useState<string | null>(null);
  const [downloadLimit, setDownloadLimit] = useState('');
  const [phase, setPhase] = useState<Phase>('form');
  const [transferId, setTransferId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fields, setFields] = useState<Record<string, string>>({});
  const [announcement, setAnnouncement] = useState('');

  const maxExpiry = policy.data?.max_expiry;
  const options = useMemo(() => expiryOptions(maxExpiry), [maxExpiry]);
  const expiry = expiresIn !== null && options.includes(expiresIn) ? expiresIn : defaultExpiry(maxExpiry);
  const locale: Locale = newLocale ?? policy.data?.default_locale ?? 'en';
  const busy = phase === 'uploading' || phase === 'sending';
  const locked = transferId !== null;
  const limit = downloadLimitOf(downloadLimit);

  filesNow.current = files;

  // Leaving the page stops the uploads; the draft stays, and its detail page resumes them.
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

  const updateFile = useCallback((key: string, change: Partial<FileEntry>) => {
    setFiles((previous) => previous.map((entry) => (entry.key === key ? { ...entry, ...change } : entry)));
  }, []);

  const addRecipient = () => {
    const problem = recipientProblem(
      recipientInput,
      recipients.map((r) => r.email),
    );
    if (problem) {
      setRecipientError(t(`sender.recipientProblem.${problem}`));
      return;
    }
    setRecipients((previous) => [...previous, { key: crypto.randomUUID(), email: recipientInput.trim(), locale }]);
    setRecipientInput('');
    setRecipientError(null);
  };

  const addFiles = (picked: FileList | null) => {
    if (!picked) return;
    const sizes = files.map((entry) => entry.file.size);
    const added: FileEntry[] = [];
    let problem: FileProblem | null = null;
    for (const file of Array.from(picked)) {
      problem = fileProblem(file.size, sizes);
      if (problem) break;
      sizes.push(file.size);
      added.push({ key: crypto.randomUUID(), file });
    }
    setFiles((previous) => [...previous, ...added]);
    setFileError(problem ? t(`sender.fileProblem.${problem}`) : null);
    if (fileInput.current) fileInput.current.value = '';
  };

  const removeFile = async (entry: FileEntry) => {
    const engine = engines.current.get(entry.key);
    if (engine) {
      try {
        // Stops its parts and removes the file (deleteFile); a file already uploaded is removed the same way.
        if (engine.state.status === 'done') await uploadApi.deleteFile(engine.fileId);
        else await engine.cancel();
      } catch (failure) {
        toast('error', errorMessage(failure, t));
        return;
      }
      engines.current.delete(entry.key);
    }
    setFiles((previous) => previous.filter((other) => other.key !== entry.key));
  };

  const cancelAll = async () => {
    for (const engine of engines.current.values()) await engine.pause();
    if (transferId) {
      try {
        await cancelTransfer(transferId);
      } catch (failure) {
        setError(errorMessage(failure, t));
        return;
      }
      await invalidateTransfers(queryClient);
    }
    navigate('/transfers');
  };

  const run = async () => {
    setError(null);
    setFields({});
    if (recipients.length === 0 || files.length === 0 || limit === undefined || message.length > MAX_MESSAGE) return;
    setPhase('uploading');
    let id = transferId;
    try {
      if (!id) {
        const body = {
          recipients: recipients.map(({ email, locale: recipientLocale }) => ({ email, locale: recipientLocale })),
          expires_in: expiry,
          download_limit: limit,
          ...(message.trim() ? { message } : {}),
        };
        // An unchanged retry replays its key; an edited form is a new attempt with a new key.
        const transfer = await createTransfer(body, keys.current.keyForBody('createTransfer', body));
        keys.current.done('createTransfer');
        id = transfer.id;
        setTransferId(id);
        void invalidateTransfers(queryClient);
      }
      // One file at a time, each with up to 4 parts in flight. The list is read as it is now: a file the member
      // removed meanwhile is skipped.
      for (const entry of [...filesNow.current]) {
        if (!mounted.current) return;
        if (!filesNow.current.some((other) => other.key === entry.key)) continue;
        let engine = engines.current.get(entry.key);
        if (!engine) {
          const name = `addTransferFile:${entry.key}`;
          const fileBody = {
            display_name: entry.file.name,
            size: entry.file.size,
            ...(entry.file.type ? { content_type: entry.file.type } : {}),
          };
          const added = await addTransferFile(id, fileBody, keys.current.keyForBody(name, fileBody));
          keys.current.done(name);
          engine = new FileUpload({
            fileId: added.id,
            blob: entry.file,
            api: uploadApi,
            onChange: (progress) => updateFile(entry.key, { progress }),
          });
          engines.current.set(entry.key, engine);
          updateFile(entry.key, { fileId: added.id, error: undefined });
        }
        if (engine.state.status === 'done') continue;
        try {
          const completed = await engine.start();
          if (completed === null) {
            if (engine.state.status === 'cancelled') continue; // the member removed it
            return; // paused: the page is closing or the draft is being cancelled
          }
          setAnnouncement(t('sender.fileUploaded', { name: entry.file.name }));
        } catch (failure) {
          updateFile(entry.key, { error: errorMessage(failure, t) });
          throw failure;
        }
      }
      if (!mounted.current || filesNow.current.length === 0) return;
      setPhase('sending');
      await sendTransfer(id);
      await invalidateTransfers(queryClient);
      toast('success', t('sender.transferSent'));
      navigate(`/transfers/${id}`);
    } catch (failure) {
      const details = failureOf(failure);
      setFields(fieldErrors(details));
      setError(errorMessage(failure, t));
      setPhase('failed');
      setAnnouncement(t('sender.uploadStopped'));
    }
  };

  // When the browser comes back online, a stopped upload carries on by itself.
  useEffect(() => {
    if (phase !== 'failed' || !transferId) return;
    const onOnline = () => void run();
    window.addEventListener('online', onOnline);
    return () => window.removeEventListener('online', onOnline);
  });

  const totalSize = files.reduce((sum, entry) => sum + entry.file.size, 0);
  const totalSent = files.reduce((sum, entry) => sum + (entry.progress?.sentBytes ?? 0), 0);
  const fieldError = (name: string) => (fields[name] ? t('problems.fieldInvalid') : undefined);
  const recipientFieldError = recipients.some((_, index) => fields[`recipients/${index}/email`] || fields[`recipients/${index}`]);
  const canSend = recipients.length > 0 && files.length > 0 && limit !== undefined && !busy;

  return (
    <PageShell title={t('sender.transferTitle')}>
      <div className="sr-only" role="status" aria-live="polite">
        {announcement}
      </div>
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card>
            <CardTitle>{t('sender.recipients')}</CardTitle>
            <fieldset disabled={locked} className="mt-3 space-y-3">
              <legend className="sr-only">{t('sender.recipients')}</legend>
              {recipients.length > 0 && (
                <ul className="space-y-2">
                  {recipients.map((recipient, index) => (
                    <li key={recipient.key} className="flex flex-wrap items-end gap-2 rounded-lg bg-gray-50 p-2">
                      <span className="min-w-0 flex-1 truncate py-2 text-sm font-medium text-gray-900">{recipient.email}</span>
                      <div className="w-40">
                        <Select
                          label={t('sender.recipientLocale', { email: recipient.email })}
                          className="py-1.5"
                          value={recipient.locale}
                          onChange={(event) =>
                            setRecipients((previous) =>
                              previous.map((r) => (r.key === recipient.key ? { ...r, locale: event.target.value as Locale } : r)),
                            )
                          }
                          options={LOCALES.map((value) => ({ value, label: t(`locales.${value}`) }))}
                          error={fields[`recipients/${index}/email`] ? t('problems.recipientRefused') : undefined}
                        />
                      </div>
                      <button
                        type="button"
                        onClick={() => setRecipients((previous) => previous.filter((r) => r.key !== recipient.key))}
                        aria-label={t('sender.removeRecipient', { email: recipient.email })}
                        className="mb-1 rounded-full p-2 text-gray-500 hover:bg-gray-200"
                      >
                        <X className="h-4 w-4" aria-hidden="true" />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              <div className="flex flex-wrap items-end gap-2">
                <div className="min-w-56 flex-1">
                  <Input
                    id="recipient-email"
                    label={t('sender.recipientEmail')}
                    type="email"
                    autoComplete="off"
                    placeholder={t('auth.emailPlaceholder')}
                    value={recipientInput}
                    error={recipientError ?? undefined}
                    onChange={(event) => {
                      setRecipientInput(event.target.value);
                      setRecipientError(null);
                    }}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter') {
                        event.preventDefault();
                        addRecipient();
                      }
                    }}
                  />
                </div>
                <div className="w-40">
                  <Select
                    label={t('sender.newRecipientLocale')}
                    value={locale}
                    onChange={(event) => setNewLocale(event.target.value as Locale)}
                    options={LOCALES.map((value) => ({ value, label: t(`locales.${value}`) }))}
                  />
                </div>
                <Button variant="secondary" type="button" onClick={addRecipient}>
                  <Plus className="mr-1 h-4 w-4" aria-hidden="true" />
                  {t('sender.addRecipient')}
                </Button>
              </div>
              {recipientFieldError && <Alert>{t('problems.recipientRefused')}</Alert>}
            </fieldset>
          </Card>

          <Card>
            <CardTitle>{t('sender.files')}</CardTitle>
            <div
              onDrop={(event) => {
                event.preventDefault();
                if (!locked) addFiles(event.dataTransfer.files);
              }}
              onDragOver={(event) => event.preventDefault()}
              className="mt-3 flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-gray-300 p-8 text-center"
            >
              <Upload className="mb-3 h-10 w-10 text-gray-500" aria-hidden="true" />
              <p className="text-sm font-medium text-gray-700">{t('sender.dragDrop')}</p>
              <p className="mt-1 text-xs text-gray-500">{t('sender.maxFileSize')}</p>
              <Button type="button" variant="secondary" className="mt-4" disabled={locked} onClick={() => fileInput.current?.click()}>
                {t('sender.chooseFiles')}
              </Button>
              <input
                ref={fileInput}
                type="file"
                multiple
                hidden
                aria-label={t('sender.chooseFiles')}
                data-testid="transfer-files"
                onChange={(event) => addFiles(event.target.files)}
              />
            </div>
            {fileError && <Alert className="mt-3">{fileError}</Alert>}
            {files.length > 0 && (
              <ul className="mt-4 space-y-2">
                {files.map((entry) => {
                  const progress = entry.progress;
                  return (
                    <li key={entry.key} className="rounded-lg bg-gray-50 p-3">
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex min-w-0 items-center gap-3">
                          <FileIcon className="h-5 w-5 shrink-0 text-gray-500" aria-hidden="true" />
                          <div className="min-w-0">
                            <p className="truncate text-sm font-medium text-gray-900">{entry.file.name}</p>
                            <p className="text-xs text-gray-500">
                              {formatFileSize(entry.file.size)}
                              {progress ? ` · ${t(`uploadStatus.${progress.status}`)}` : ''}
                            </p>
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => void removeFile(entry)}
                          disabled={phase === 'sending'}
                          aria-label={t('sender.removeFile', { name: entry.file.name })}
                          className="rounded-sm p-1 text-gray-500 hover:bg-gray-200 hover:text-gray-600"
                        >
                          <X className="h-4 w-4" aria-hidden="true" />
                        </button>
                      </div>
                      {progress && (
                        <ProgressBar
                          className="mt-2"
                          label={t('sender.uploadProgress', { name: entry.file.name })}
                          value={progress.sentBytes}
                          max={progress.totalBytes}
                          valueText={t('sender.uploadedOf', {
                            sent: formatFileSize(progress.sentBytes),
                            total: formatFileSize(progress.totalBytes),
                          })}
                        />
                      )}
                      {entry.error && <p className="mt-1 text-sm text-red-700">{entry.error}</p>}
                    </li>
                  );
                })}
              </ul>
            )}
          </Card>

          <Card>
            <CardTitle>{t('sender.messageTitle')}</CardTitle>
            <label htmlFor="transfer-message" className="sr-only">
              {t('sender.message')}
            </label>
            <textarea
              id="transfer-message"
              className="input-field mt-3 min-h-[100px] resize-y"
              placeholder={t('sender.messagePlaceholder')}
              value={message}
              disabled={locked}
              aria-describedby="transfer-message-count"
              onChange={(event) => setMessage(event.target.value)}
              maxLength={MAX_MESSAGE}
            />
            <p id="transfer-message-count" className="mt-1 text-right text-xs text-gray-500">
              {t('sender.messageCount', { count: message.length, max: MAX_MESSAGE })}
            </p>
          </Card>
        </div>

        <div className="space-y-6">
          <Card>
            <CardTitle>{t('common.settings')}</CardTitle>
            <fieldset disabled={locked} className="mt-3 space-y-4">
              <legend className="sr-only">{t('common.settings')}</legend>
              <Select
                label={t('sender.expiry')}
                value={expiry}
                onChange={(event) => setExpiresIn(event.target.value)}
                options={options.map((value) => ({ value, label: durationLabel(value) }))}
                hint={maxExpiry ? t('sender.expiryCap', { duration: durationLabel(maxExpiry) }) : undefined}
                error={fieldError('expires_in')}
              />
              <Input
                id="download-limit"
                label={t('sender.downloadLimit')}
                inputMode="numeric"
                placeholder={t('common.noLimit')}
                value={downloadLimit}
                onChange={(event) => setDownloadLimit(event.target.value)}
                error={limit === undefined ? t('sender.downloadLimitInvalid') : fieldError('download_limit')}
                helperText={t('sender.downloadLimitHint')}
              />
            </fieldset>
          </Card>

          <Card>
            <CardTitle>{t('common.summary')}</CardTitle>
            <dl className="mt-3 space-y-2 text-sm">
              <div className="flex justify-between">
                <dt className="text-gray-500">{t('sender.recipients')}</dt>
                <dd className="font-medium">{recipients.length}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-500">{t('sender.files')}</dt>
                <dd className="font-medium">{files.length}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-500">{t('common.totalSize')}</dt>
                <dd className="font-medium">{formatFileSize(totalSize)}</dd>
              </div>
            </dl>
            {phase !== 'form' && totalSize > 0 && (
              <ProgressBar
                className="mt-3"
                label={t('sender.totalProgress')}
                value={totalSent}
                max={totalSize}
                valueText={t('sender.uploadedOf', { sent: formatFileSize(totalSent), total: formatFileSize(totalSize) })}
              />
            )}
          </Card>

          {error && <Alert>{error}</Alert>}

          <Button onClick={() => void run()} className="w-full" loading={busy} disabled={!canSend}>
            <Send className="mr-2 h-4 w-4" aria-hidden="true" />
            {phase === 'failed' ? t('common.tryAgain') : busy ? t(`sender.phase.${phase}`) : t('sender.send')}
          </Button>
          {locked && (
            <Button variant="ghost" className="w-full" onClick={() => void cancelAll()} disabled={phase === 'sending'}>
              {t('sender.cancelTransfer')}
            </Button>
          )}
        </div>
      </div>
    </PageShell>
  );
}
