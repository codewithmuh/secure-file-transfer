import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { FullPageSpinner } from '@/components/ui';
import { finishSignIn } from './memberSession';

export function SignInCallbackPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  useEffect(() => {
    // After the API's callback sets the session cookie, load the member and go to a checked return path.
    void finishSignIn(searchParams).then((destination) => navigate(destination, { replace: true }));
  }, [navigate, searchParams]);

  return <FullPageSpinner />;
}
