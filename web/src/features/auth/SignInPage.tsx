import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Shield, ArrowRight } from 'lucide-react';
import { Button, Input, Card } from '@/components/ui';

export function SignInPage() {
  const { t } = useTranslation();
  const [email, setEmail] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const domain = email.split('@')[1] ?? '';

  const handleSsoSignIn = () => {
    if (!domain) {
      setError(t('auth.signInError'));
      return;
    }
    setLoading(true);
    // In production, this navigates to /v1/auth/sign-in?method=sso&sso_domain=<domain>
    window.location.href = `/v1/auth/sign-in?method=sso&sso_domain=${encodeURIComponent(domain)}&return_path=/`;
  };

  const handleLocalSignIn = () => {
    setLoading(true);
    // In production, navigates to /v1/auth/sign-in?method=local&return_path=/
    window.location.href = `/v1/auth/sign-in?method=local&return_path=/`;
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-gray-50 px-4">
      <div className="mb-8 flex flex-col items-center">
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-600">
          <Shield className="h-8 w-8 text-white" />
        </div>
        <h1 className="mt-4 text-2xl font-bold text-gray-900">{t('auth.signInTitle')}</h1>
        <p className="mt-1 text-sm text-gray-500">{t('auth.signInSubtitle')}</p>
      </div>

      <Card className="w-full max-w-sm">
        <div className="space-y-4">
          <Input
            label={t('auth.emailLabel')}
            type="email"
            placeholder={t('auth.emailPlaceholder')}
            value={email}
            onChange={(e) => {
              setEmail(e.target.value);
              setError(null);
            }}
            error={error ?? undefined}
            autoFocus
          />

          <Button
            onClick={handleSsoSignIn}
            className="w-full"
            loading={loading}
            disabled={!email}
          >
            {t('auth.continueWithSso')}
            <ArrowRight className="ml-2 h-4 w-4" />
          </Button>

          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-gray-200" />
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="bg-white px-4 text-gray-400">or</span>
            </div>
          </div>

          <Button
            variant="secondary"
            onClick={handleLocalSignIn}
            className="w-full"
            loading={loading}
          >
            {t('auth.signInWithPassword')}
          </Button>
        </div>
      </Card>
    </div>
  );
}
