import { useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Mail } from 'lucide-react';
import { Alert, Button, Card } from '@/components/ui';
import { failureOf } from '@/lib/problems';
import type { LinkMode } from '@/stores/authStore';
import {
  goneOf,
  linkProblemText,
  RESEND_WAIT_SECONDS,
  requestCode,
  verifyCode,
  type LinkGone,
  type VerificationCodeRequested,
  type VerifiedSession,
} from './linkApi';
import { StepHeading } from './StepHeading';

const CODE = /^[0-9]{6,10}$/;

interface VerificationPageProps {
  mode: LinkMode;
  /** The link token, from memory only; it goes only in request bodies. */
  token: string;
  /** The API ended the session: say so above the code step. */
  lapsed: boolean;
  onVerified: (session: VerifiedSession) => void;
  onGone: (gone: LinkGone) => void;
}

/**
 * The code step (#198): `requestVerificationCode`, then `createLinkSession` with the code. The page says where the
 * code went only as the API does ("the address this link was sent to"); the resend wait and a `429 Retry-After` show
 * as a countdown. Each error is explained by the code input, tied to it with `aria-describedby`.
 */
export function VerificationPage({ mode, token, lapsed, onVerified, onGone }: VerificationPageProps) {
  const { t } = useTranslation();
  const inputId = useId();
  const hintId = `${inputId}-hint`;
  const errorId = `${inputId}-error`;
  const input = useRef<HTMLInputElement>(null);

  const [sent, setSent] = useState<VerificationCodeRequested | null>(null);
  const [waitUntil, setWaitUntil] = useState<number | null>(null);
  const secondsLeft = useCountdown(waitUntil);
  const [requesting, setRequesting] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);

  const ask = async () => {
    setRequesting(true);
    setRequestError(null);
    try {
      setSent(await requestCode(token));
      setWaitUntil(Date.now() + RESEND_WAIT_SECONDS * 1000);
    } catch (error) {
      const gone = goneOf(error);
      if (gone) return onGone(gone);
      const { retryAfter } = failureOf(error);
      if (retryAfter !== null) setWaitUntil(Date.now() + retryAfter * 1000);
      setRequestError(linkProblemText(error, t));
    } finally {
      setRequesting(false);
    }
  };

  const verify = async (event: FormEvent) => {
    event.preventDefault();
    const value = code.replace(/\s+/g, '');
    if (!CODE.test(value)) {
      setCodeError(t('recipient.codeRequired'));
      input.current?.focus();
      return;
    }
    setVerifying(true);
    setCodeError(null);
    try {
      onVerified(await verifyCode(token, value));
    } catch (error) {
      const gone = goneOf(error);
      if (gone) return onGone(gone);
      setCodeError(linkProblemText(error, t));
      input.current?.focus();
    } finally {
      setVerifying(false);
    }
  };

  const describedBy = [hintId, codeError ? errorId : null].filter(Boolean).join(' ');

  return (
    <div className="space-y-6">
      <Card>
        <div className="text-center">
          <Mail className="mx-auto h-10 w-10 text-brand-600" aria-hidden="true" />
          <StepHeading>{t('recipient.verifyTitle')}</StepHeading>
          <p className="mt-1 text-sm text-gray-600">
            {mode === 'recipient' ? t('recipient.subtitle') : t('uploader.verifySubtitle')}
          </p>
        </div>

        {lapsed && (
          <Alert variant="warning" role="status" className="mt-4">
            {t('recipient.sessionEnded')}
          </Alert>
        )}

        <p className="mt-4 text-sm text-gray-700">{t(mode === 'recipient' ? 'recipient.verifyIntro' : 'uploader.verifyIntro')}</p>
        <div className="mt-3 space-y-2">
          <Button
            variant={sent ? 'secondary' : 'primary'}
            className="w-full"
            onClick={() => void ask()}
            loading={requesting}
            disabled={secondsLeft > 0}
          >
            {sent ? t('recipient.sendAgain') : t('recipient.sendCode')}
          </Button>
          <div role="status" className="text-sm text-gray-700">
            {sent && !requestError && t('recipient.codeSent', { minutes: Math.ceil(sent.code_valid_for_seconds / 60) })}
          </div>
          {secondsLeft > 0 && <p className="text-sm text-gray-600">{t('recipient.resendIn', { count: secondsLeft })}</p>}
          {requestError && <Alert>{requestError}</Alert>}
        </div>

        <form className="mt-6 space-y-3" onSubmit={(event) => void verify(event)} noValidate>
          <div className="space-y-1.5">
            <label htmlFor={inputId} className="block text-sm font-medium text-gray-700">
              {t('recipient.codeLabel')}
            </label>
            <input
              ref={input}
              id={inputId}
              name="code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={12}
              value={code}
              onChange={(event) => {
                setCode(event.target.value);
                setCodeError(null);
              }}
              aria-invalid={codeError ? true : undefined}
              aria-describedby={describedBy}
              className="input-field text-center text-lg tracking-widest"
            />
            <p id={hintId} className="text-sm text-gray-600">
              {t('recipient.codeHint')}
            </p>
            {codeError && (
              <p id={errorId} className="text-sm text-red-700">
                {codeError}
              </p>
            )}
          </div>
          <Button type="submit" className="w-full" loading={verifying}>
            {t('recipient.verifyButton')}
          </Button>
        </form>
      </Card>
    </div>
  );
}

/** Whole seconds until `until` (a `Date.now()` time), ticking once a second; 0 when it has passed or is null. */
function useCountdown(until: number | null): number {
  const left = () => (until === null ? 0 : Math.max(0, Math.ceil((until - Date.now()) / 1000)));
  const [seconds, setSeconds] = useState(left);
  useEffect(() => {
    setSeconds(left());
    if (until === null) return;
    const timer = setInterval(() => {
      const now = left();
      setSeconds(now);
      if (now === 0) clearInterval(timer);
    }, 1000);
    return () => clearInterval(timer);
    // `left` reads only `until`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [until]);
  return seconds;
}
