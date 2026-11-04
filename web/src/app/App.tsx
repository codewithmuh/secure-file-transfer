import { useEffect, useState } from 'react';
import { RouterProvider } from 'react-router-dom';
import { Providers } from './providers';
import { router } from './router';
import { loadConfig } from '@/lib/config';
import { FullPageSpinner } from '@/components/ui';

export function App() {
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadConfig()
      .then(() => setReady(true))
      .catch(() => setError('Failed to load application configuration.'));
  }, []);

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-red-600">{error}</p>
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
