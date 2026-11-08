import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Card, CardTitle, Input } from '@/components/ui';
import { clearEmailSuppression } from '@/hooks/admin';
import { isPlainAddress } from '@/features/sender/limits';
import { errorMessage, isAccessProblem } from '@/lib/problems';
import { AdminAccessNote } from './AdminAccessNote';

/**
 * Clearing a suppressed address (#217; FR-7, abuse 7.4): after a hard bounce or a complaint the tenant stops emailing
 * an address until an admin clears it here. The service answers `204` whether or not the address was suppressed, so
 * the page says the same neutral thing either way and reveals nothing about the address. The address goes in the
 * POST body only.
 */
export function SuppressionClearForm() {
  const { t } = useTranslation();
  const [email, setEmail] = useState('');
  const [invalid, setInvalid] = useState(false);
  const [busy, setBusy] = useState(false);
  const [cleared, setCleared] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  const submit = async () => {
    const address = email.trim();
    setCleared(null);
    setError(null);
    if (!isPlainAddress(address)) {
      setInvalid(true);
      return;
    }
    setBusy(true);
    try {
      await clearEmailSuppression(address);
      setCleared(address);
      setEmail('');
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardTitle>{t('suppression.title')}</CardTitle>
      <p className="mt-2 text-sm text-gray-600">{t('suppression.intro')}</p>
      <form
        className="mt-4 space-y-4"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <Input
          id="suppression-email"
          type="email"
          autoComplete="off"
          label={t('suppression.email')}
          value={email}
          error={invalid ? t('sender.recipientProblem.invalid') : undefined}
          onChange={(event) => {
            setEmail(event.target.value);
            setInvalid(false);
          }}
        />
        {cleared !== null && (
          <Alert variant="info" role="status">
            {t('suppression.done', { email: cleared })}
          </Alert>
        )}
        {error !== null && (isAccessProblem(error) ? <AdminAccessNote error={error} /> : <Alert>{errorMessage(error, t)}</Alert>)}
        <Button type="submit" variant="secondary" loading={busy} disabled={!email.trim()}>
          {t('suppression.action')}
        </Button>
      </form>
    </Card>
  );
}
