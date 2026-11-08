import { useTranslation } from 'react-i18next';
import { useLocation } from 'react-router';
import { Alert, Button } from '@/components/ui';
import { signInUrl } from '@/features/auth/memberSession';
import { problemCode } from '@/lib/problems';

/**
 * What an admin page says when the API wants a stronger sign-in (authn-authz 3.3): `401 reauthentication_required`
 * (a step-up operation needs a sign-in in the last 15 minutes: sign in again and come back here), or `403
 * passkey_required` (a local admin acts as admin only after a passkey sign-in, which M6 offers; locally the rule is
 * off). Nothing for any other error.
 */
export function AdminAccessNote({ error }: { error: unknown }) {
  const { t } = useTranslation();
  const location = useLocation();
  const code = problemCode(error);
  if (code === 'reauthentication_required') {
    return (
      <Alert variant="warning" role="status">
        <p>{t('admin.reauthenticate')}</p>
        <Button
          size="sm"
          className="mt-2"
          onClick={() => window.location.assign(signInUrl('local', `${location.pathname}${location.search}`))}
        >
          {t('admin.signInAgain')}
        </Button>
      </Alert>
    );
  }
  if (code === 'passkey_required') {
    return (
      <Alert variant="warning" role="status">
        {t('admin.passkeyRequired')}
      </Alert>
    );
  }
  return null;
}
