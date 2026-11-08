import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Dialog } from '@/components/ui';
import type { Transfer } from '@/api';
import { errorMessage } from '@/lib/problems';
import type { useRevocation } from './revocation';

type Revocation = ReturnType<typeof useRevocation>;

/**
 * "Revoke transfer" and its confirmation (#199, FR-20, NFR-6), for a transfer in `REVOCABLE_STATES`. The dialog says
 * what revoking does; the revocation itself and its retries live in `useRevocation`, on the detail page, so the
 * unconfirmed banner (`RevocationBanner`) stays after the transfer shows `revoked`.
 */
export function RevokeTransfer({ revocation }: { revocation: Revocation }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);

  const close = () => {
    if (revocation.status === 'failed') revocation.reset();
    setOpen(false);
  };

  const confirm = async () => {
    const outcome = await revocation.revoke();
    if (outcome !== 'failed') setOpen(false);
  };

  return (
    <>
      <Button variant="danger" onClick={() => setOpen(true)}>
        {t('delivery.revoke')}
      </Button>
      <Dialog open={open} onClose={close} title={t('delivery.revokeTitle')}>
        <div className="space-y-4">
          <p className="text-sm text-gray-700">{t('delivery.revokeBody')}</p>
          {revocation.status === 'failed' && <Alert>{errorMessage(revocation.error, t)}</Alert>}
          <div className="flex justify-end gap-3">
            <Button variant="secondary" onClick={close} disabled={revocation.busy}>
              {t('common.cancel')}
            </Button>
            <Button variant="danger" onClick={() => void confirm()} loading={revocation.busy}>
              {t('delivery.revokeConfirm')}
            </Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}

/** What the page says about the transfer's end: revoked (confirmed or not, with a retry), or expired and read-only. */
export function TransferEndBanner({
  transfer,
  revocation,
  date,
}: {
  transfer: Transfer;
  revocation: Revocation;
  date: (value: string) => string;
}) {
  const { t } = useTranslation();
  if (revocation.status === 'unconfirmed') {
    return (
      <Alert variant="warning" role="status">
        <p>{t('delivery.revokeUnconfirmed')}</p>
        <Button size="sm" variant="secondary" className="mt-2" onClick={() => void revocation.revoke()} loading={revocation.busy}>
          {t('delivery.revokeRetry')}
        </Button>
      </Alert>
    );
  }
  if (transfer.state === 'revoked' || revocation.status === 'revoked') {
    return (
      <Alert variant="info" role="status">
        {t('delivery.revoked')} {transfer.revoked_at ? t('delivery.revokedOn', { date: date(transfer.revoked_at) }) : ''}
      </Alert>
    );
  }
  if (transfer.state === 'expired') {
    return (
      <Alert variant="info" role="status">
        {t('delivery.expiredReadOnly')}
      </Alert>
    );
  }
  return null;
}
