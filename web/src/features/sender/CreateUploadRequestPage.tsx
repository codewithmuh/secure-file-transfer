import { useMemo, useRef, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { Inbox } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Alert, Button, Card, Input, Select, toast } from '@/components/ui';
import { useTenantPolicy } from '@/hooks/transfers';
import { createUploadRequest, invalidateUploadRequests } from '@/hooks/uploadRequests';
import { defaultExpiry, expiryOptions } from '@/lib/durations';
import { IdempotencyKeys, mayHaveHappened } from '@/lib/idempotency';
import { errorMessage, failureOf, fieldErrors } from '@/lib/problems';
import { useDurationLabel } from '@/lib/useDurationLabel';
import { isPlainAddress, MAX_MESSAGE } from './limits';
import { RequestAttempt, type Locale } from './uploadRequests';

const LOCALES: readonly Locale[] = ['en', 'ja'];

/**
 * Ask someone outside the company for files (#212; UC-2, FR-10, FR-3, FR-33). The member gives the uploader's address,
 * the language of their emails and pages (the tenant's by default), how long the request stays open (the tenant's
 * `max_expiry` caps the choices, as on the create-transfer form) and an optional message of up to 2,000 characters.
 * `createUploadRequest` gets an `Idempotency-Key` kept for the attempt, with the same body (`RequestAttempt`), so "Try
 * again" after a lost answer replays it rather than creating a second request. Then the request's page opens.
 */
export function CreateUploadRequestPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const durationLabel = useDurationLabel();
  const policy = useTenantPolicy();
  const keys = useRef(new IdempotencyKeys());
  const attempt = useRef(new RequestAttempt());
  const emailInput = useRef<HTMLInputElement>(null);

  const [email, setEmail] = useState('');
  const [emailError, setEmailError] = useState<string | null>(null);
  const [chosenLocale, setChosenLocale] = useState<Locale | null>(null);
  const [expiresIn, setExpiresIn] = useState<string | null>(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fields, setFields] = useState<Record<string, string>>({});

  const maxExpiry = policy.data?.max_expiry;
  const options = useMemo(() => expiryOptions(maxExpiry), [maxExpiry]);
  const expiry = expiresIn !== null && options.includes(expiresIn) ? expiresIn : defaultExpiry(maxExpiry);
  const locale: Locale = chosenLocale ?? policy.data?.default_locale ?? 'en';
  const fieldError = (name: string) => (fields[name] ? t('problems.fieldInvalid') : undefined);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setFields({});
    if (!isPlainAddress(email.trim())) {
      setEmailError(t('sender.recipientProblem.invalid'));
      emailInput.current?.focus();
      return;
    }
    if (message.length > MAX_MESSAGE) return;
    setBusy(true);
    const body = attempt.current.bodyFor({ email, locale, expiresIn: expiry, message }, maxExpiry, Date.now());
    try {
      const created = await createUploadRequest(body, keys.current.keyForBody('createUploadRequest', body));
      keys.current.done('createUploadRequest');
      attempt.current.done();
      await invalidateUploadRequests(queryClient);
      toast('success', t('requests.created', { email: created.uploader_email }));
      navigate(`/upload-requests/${created.id}`);
    } catch (failure) {
      // A definite refusal: the member changes the form, and the next try is a new attempt with a new time and key.
      if (!mayHaveHappened(failure)) {
        attempt.current.done();
        keys.current.done('createUploadRequest');
      }
      setFields(fieldErrors(failureOf(failure)));
      setError(errorMessage(failure, t));
      setBusy(false);
    }
  };

  return (
    <PageShell title={t('sender.newUploadRequest')} description={t('requests.createIntro')}>
      <form className="mx-auto max-w-2xl space-y-6" onSubmit={(event) => void submit(event)} noValidate>
        <Card>
          <div className="space-y-4">
            <Input
              ref={emailInput}
              id="uploader-email"
              label={t('requests.uploaderEmail')}
              type="email"
              autoComplete="off"
              placeholder={t('auth.emailPlaceholder')}
              value={email}
              onChange={(event) => {
                setEmail(event.target.value);
                setEmailError(null);
              }}
              error={emailError ?? fieldError('uploader_email')}
              required
            />
            <Select
              label={t('requests.uploaderLocale')}
              value={locale}
              onChange={(event) => setChosenLocale(event.target.value as Locale)}
              options={LOCALES.map((value) => ({ value, label: t(`locales.${value}`) }))}
              hint={t('requests.uploaderLocaleHint')}
              error={fieldError('locale')}
            />
            <Select
              label={t('requests.expiry')}
              value={expiry}
              onChange={(event) => setExpiresIn(event.target.value)}
              options={options.map((value) => ({ value, label: durationLabel(value) }))}
              hint={maxExpiry ? t('requests.expiryHint', { duration: durationLabel(maxExpiry) }) : undefined}
              error={fieldError('expires_at')}
            />
          </div>
        </Card>

        <Card>
          <label htmlFor="request-message" className="block text-sm font-medium text-gray-700">
            {t('requests.messageLabel')}
          </label>
          <textarea
            id="request-message"
            className="input-field mt-1.5 min-h-[100px] resize-y"
            placeholder={t('requests.messagePlaceholder')}
            value={message}
            aria-describedby="request-message-hint request-message-count"
            aria-invalid={fields.message ? true : undefined}
            onChange={(event) => setMessage(event.target.value)}
            maxLength={MAX_MESSAGE}
          />
          <div className="mt-1 flex flex-wrap justify-between gap-2 text-xs text-gray-500">
            <p id="request-message-hint">{t('requests.messageHint')}</p>
            <p id="request-message-count">{t('sender.messageCount', { count: message.length, max: MAX_MESSAGE })}</p>
          </div>
        </Card>

        {error && <Alert>{error}</Alert>}

        <Button type="submit" className="w-full" loading={busy}>
          <Inbox className="mr-2 h-4 w-4" aria-hidden="true" />
          {error ? t('common.tryAgain') : t('requests.create')}
        </Button>
      </form>
    </PageShell>
  );
}
