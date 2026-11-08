import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useLocation, useSearchParams } from 'react-router';
import { Shield, ArrowRight } from 'lucide-react';
import { Button, Input, Card } from '@/components/ui';
import { getConfig } from '@/lib/config';
import { signInUrl } from './memberSession';
import { returnPathOf } from './returnPath';

/**
 * The sign-in page. It navigates the browser to `startSignIn` on the API, which sends it on to the user pool; the
 * path to come back to travels as `return_to` and is checked by both sides. SSO is offered only when the config turns
 * it on (M6); until then the password sign-in is the one way in.
 */
export function SignInPage() {
  const { t } = useTranslation();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { ssoSignIn } = getConfig();
  const [email, setEmail] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const failed = searchParams.get('error') === 'sign_in_failed';
  const returnTo = returnPathOf(location.state);

  const domain = email.split('@')[1] ?? '';

  const handleSsoSignIn = () => {
    if (!domain) {
      setError(t('auth.signInError'));
      return;
    }
    setLoading(true);
    window.location.assign(signInUrl('sso', returnTo, domain));
  };

  const handleLocalSignIn = () => {
    setLoading(true);
    window.location.assign(signInUrl('local', returnTo));
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-gray-50 px-4">
      <div className="mb-8 flex flex-col items-center">
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-600">
          <Shield className="h-8 w-8 text-white" aria-hidden="true" />
        </div>
        <h1 className="mt-4 text-2xl font-bold text-gray-900">{t('auth.signInTitle')}</h1>
        <p className="mt-1 text-sm text-gray-500">{t('auth.signInSubtitle')}</p>
      </div>

      <Card className="w-full max-w-sm">
        <div className="space-y-4">
          {failed && (
            <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-700">
              {t('auth.signInFailed')}
            </p>
          )}

          {ssoSignIn && (
            <>
              <Input
                id="sign-in-email"
                label={t('auth.emailLabel')}
                type="email"
                placeholder={t('auth.emailPlaceholder')}
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  setError(null);
                }}
                error={error ?? undefined}
                autoComplete="email"
              />

              <Button onClick={handleSsoSignIn} className="w-full" loading={loading} disabled={!email}>
                {t('auth.continueWithSso')}
                <ArrowRight className="ml-2 h-4 w-4" aria-hidden="true" />
              </Button>

              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-gray-200" />
                </div>
                <div className="relative flex justify-center text-sm">
                  <span className="bg-white px-4 text-gray-500">{t('common.or')}</span>
                </div>
              </div>
            </>
          )}

          <Button
            variant={ssoSignIn ? 'secondary' : 'primary'}
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
