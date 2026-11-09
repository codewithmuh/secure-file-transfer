import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { Spinner } from '@/components/ui';
import { STEP_UP_MESSAGE } from './stepUp';

/**
 * Where a step-up sign-in ends, in the popup the "Confirm it's you" dialog opened (#232). `/auth/callback` has loaded
 * the new session and sent the browser here. The page tells the window that opened it, on this app's own origin only,
 * and closes. Opened any other way (no opener), it goes to the dashboard.
 */
export function StepUpCompletePage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [stayed, setStayed] = useState(false);

  useEffect(() => {
    const opener = window.opener as Window | null;
    if (!opener || opener === window) {
      navigate('/', { replace: true });
      return;
    }
    try {
      opener.postMessage(STEP_UP_MESSAGE, window.location.origin);
    } catch {
      // The opener has gone; nothing waits for this message.
    }
    window.close();
    // A browser that won't close the window leaves it open: say it can be closed.
    setStayed(true);
  }, [navigate]);

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-6 text-center">
      {stayed ? <p className="text-sm text-gray-700" role="status">{t('stepUp.complete')}</p> : <Spinner size="lg" />}
    </div>
  );
}
