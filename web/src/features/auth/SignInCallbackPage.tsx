import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuthStore } from '@/stores/authStore';
import { FullPageSpinner } from '@/components/ui';
import { apiClient } from '@/lib/api';

export function SignInCallbackPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { setAuth } = useAuthStore();

  useEffect(() => {
    const error = searchParams.get('error');
    if (error) {
      navigate('/sign-in?error=sign_in_failed', { replace: true });
      return;
    }

    // After Cognito redirects back, fetch the current member to get session info.
    apiClient
      .get('/me')
      .then((response) => {
        const { user, csrf_token } = response.data;
        setAuth(
          {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.effective_role,
            tenantId: user.tenant_id,
            tenantName: user.tenant_name,
          },
          csrf_token,
        );
        navigate(searchParams.get('return_path') ?? '/', { replace: true });
      })
      .catch(() => {
        navigate('/sign-in?error=sign_in_failed', { replace: true });
      });
  }, [navigate, searchParams, setAuth]);

  return <FullPageSpinner />;
}
