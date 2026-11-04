import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Shield, Mail, ArrowRight, AlertCircle } from 'lucide-react';
import { Button, Input, Card } from '@/components/ui';
import { useAuthStore, type LinkMode } from '@/stores/authStore';

interface VerificationPageProps {
  mode: LinkMode;
}

/** Verifies the recipient or uploader. The parent page shows its content once the store holds a link session. */
export function VerificationPage({ mode }: VerificationPageProps) {
  const { t } = useTranslation();
  const setLinkToken = useAuthStore((s) => s.setLinkToken);
  const setLinkSession = useAuthStore((s) => s.setLinkSession);
  const sessionLapsed = useAuthStore((s) => s.linkSessionLapsed);

  const [step, setStep] = useState<'resolve' | 'code'>('resolve');
  const [token, setToken] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [linkStatus, setLinkStatus] = useState<'valid' | 'revoked' | 'expired' | null>(null);

  useEffect(() => {
    const fragment = window.location.hash.slice(1);
    let linkToken: string | null = null;
    if (fragment) {
      window.history.replaceState(null, '', window.location.pathname);
      setLinkToken(mode, fragment);
      linkToken = fragment;
    } else {
      // Back here after the link session lapsed: the fragment is gone, so use the token kept in memory.
      const kept = useAuthStore.getState().linkToken;
      if (kept?.mode === mode) linkToken = kept.value;
    }
    if (linkToken) {
      setToken(linkToken);
      resolveLink(linkToken);
    }
  }, []);

  const resolveLink = async (_linkToken: string) => {
    setLoading(true);
    try {
      await new Promise((resolve) => setTimeout(resolve, 500));
      setLinkStatus('valid');
      setEmail('user@example.com');
      setStep('code');
    } catch {
      setLinkStatus('expired');
      setError(t('recipient.linkExpired'));
    } finally {
      setLoading(false);
    }
  };

  const requestCode = async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      await new Promise((resolve) => setTimeout(resolve, 500));
      setStep('code');
    } catch {
      setError(t('auth.signInError'));
    } finally {
      setLoading(false);
    }
  };

  const verifyCode = async () => {
    if (!token || !code) return;
    setLoading(true);
    setError(null);
    try {
      await new Promise((resolve) => setTimeout(resolve, 800));
      const mockSessionId = crypto.randomUUID();
      const mockCsrfToken = crypto.randomUUID();
      setLinkSession(mockSessionId, mockCsrfToken);
    } catch {
      setError(t('recipient.codeExpired'));
    } finally {
      setLoading(false);
    }
  };

  if (linkStatus === 'revoked') {
    return (
      <Card className="text-center">
        <AlertCircle className="mx-auto h-12 w-12 text-red-500" />
        <h2 className="mt-4 text-lg font-semibold text-gray-900">{t('recipient.linkRevoked')}</h2>
      </Card>
    );
  }

  if (linkStatus === 'expired') {
    return (
      <Card className="text-center">
        <AlertCircle className="mx-auto h-12 w-12 text-yellow-500" />
        <h2 className="mt-4 text-lg font-semibold text-gray-900">{t('recipient.linkExpired')}</h2>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="text-center">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-600">
          <Shield className="h-8 w-8 text-white" />
        </div>
        <h1 className="mt-4 text-xl font-bold text-gray-900">
          {mode === 'recipient' ? t('recipient.title') : t('uploader.title')}
        </h1>
        <p className="mt-1 text-sm text-gray-500">
          {mode === 'recipient' ? t('recipient.subtitle') : t('uploader.subtitle', { name: 'Someone' })}
        </p>
      </div>

      <Card>
        {step === 'resolve' && !token && (
          <div className="py-8 text-center">
            <p className="text-sm text-gray-500">Invalid or missing link.</p>
          </div>
        )}

        {step === 'code' && (
          <div className="space-y-4">
            <div className="text-center">
              <Mail className="mx-auto h-10 w-10 text-brand-600" />
              <h2 className="mt-3 text-lg font-semibold text-gray-900">{t('recipient.verifyTitle')}</h2>
              <p className="mt-1 text-sm text-gray-500">{t('recipient.verifySubtitle')}</p>
              {email && <p className="mt-2 text-sm font-medium text-brand-600">{email}</p>}
              {sessionLapsed && <p className="mt-2 text-sm text-yellow-700">{t('recipient.sessionEnded')}</p>}
            </div>

            <Button variant="secondary" onClick={requestCode} loading={loading} className="w-full">
              {t('recipient.sendCode')}
            </Button>

            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-200" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="bg-white px-4 text-gray-400">then</span>
              </div>
            </div>

            <Input
              placeholder={t('recipient.codePlaceholder')}
              value={code}
              onChange={(e) => { setCode(e.target.value); setError(null); }}
              error={error ?? undefined}
              maxLength={8}
              className="text-center text-lg tracking-widest"
            />

            <Button onClick={verifyCode} className="w-full" loading={loading} disabled={code.length < 6}>
              {t('recipient.verifyButton')}
              <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </div>
        )}
      </Card>
    </div>
  );
}
