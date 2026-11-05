import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { RouterProvider } from 'react-router/dom';
import { Providers } from './providers';
import { router } from './router';
import { loadConfig } from '@/lib/config';
import { FullPageSpinner } from '@/components/ui';

export function App() {
  const { t } = useTranslation();
  const [ready, setReady] = useState(false);
  const [error, setError] = useState(false);

  useEffect(() => {
    loadConfig()
      .then(() => setReady(true))
      .catch(() => setError(true));
  }, []);

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-red-600">{t('common.configError')}</p>
      </div>
    );
  }

  if (!ready) return <FullPageSpinner />;

  return (
    <Providers>
      <RouterProvider router={router} />
    </Providers>
  );
}
