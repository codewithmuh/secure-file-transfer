import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { Mail } from 'lucide-react';
import {
  Alert,
  Badge,
  Button,
  Card,
  CardTitle,
  Dialog,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  toast,
} from '@/components/ui';
import type { Transfer } from '@/api';
import { queryKeys, unlockRecipient, useTransferRecipients, type RecipientStatus } from '@/hooks/transfers';
import { formatDate } from '@/lib/formatters';
import { errorMessage } from '@/lib/problems';
import { accessStateVariant, deliveryStateVariant, EXPLAINED_DELIVERY_STATES, UNLOCKABLE_STATES } from './states';

/**
 * Each recipient's link email, verification and downloads (#199, FR-7), from `listTransferRecipients`, polled while
 * the transfer is `sent`. A locked recipient (NFR-14) can be unlocked from here: that always emails a new link, and
 * the old one stops working (authn-authz 4.4), which the confirmation says.
 */
export function RecipientDelivery({ transfer }: { transfer: Transfer }) {
  const { t, i18n } = useTranslation();
  const query = useTransferRecipients(transfer.id, transfer.state);
  const [unlocking, setUnlocking] = useState<RecipientStatus | null>(null);
  const canUnlock = UNLOCKABLE_STATES.includes(transfer.state);
  const fileName = new Map(transfer.files.map((file) => [file.id, file.display_name]));
  const date = (value: string) => formatDate(value, i18n.language);

  return (
    <Card>
      <CardTitle>{t('sender.recipients')}</CardTitle>
      {query.isPending ? (
        <div className="flex justify-center py-6">
          <Spinner />
          <span className="sr-only">{t('common.loading')}</span>
        </div>
      ) : query.isError ? (
        <Alert className="mt-3">{errorMessage(query.error, t)}</Alert>
      ) : (
        <Table label={t('sender.recipients')} caption={t('delivery.caption')} className="mt-3">
          <TableHead>
            <tr>
              <TableHeader>{t('delivery.recipient')}</TableHeader>
              <TableHeader>{t('delivery.email')}</TableHeader>
              <TableHeader>{t('delivery.access')}</TableHeader>
              <TableHeader>{t('delivery.verified')}</TableHeader>
              <TableHeader>{t('delivery.downloads')}</TableHeader>
            </tr>
          </TableHead>
          <TableBody>
            {query.data.map((recipient) => (
              <TableRow key={recipient.id}>
                <th scope="row" className="px-4 py-3 text-left align-top text-sm font-normal text-gray-700">
                  <div className="flex items-center gap-2">
                    <Mail className="h-4 w-4 shrink-0 text-gray-500" aria-hidden="true" />
                    <span className="font-medium">{recipient.email}</span>
                  </div>
                  <div className="mt-0.5 text-xs text-gray-600">{t(`locales.${recipient.locale}`)}</div>
                </th>
                <TableCell className="whitespace-normal align-top">
                  <Badge variant={deliveryStateVariant[recipient.delivery_state]}>
                    {t(`deliveryState.${recipient.delivery_state}`)}
                  </Badge>
                  {recipient.notified_at && (
                    <div className="mt-1 text-xs text-gray-600">{t('delivery.notifiedAt', { date: date(recipient.notified_at) })}</div>
                  )}
                  {EXPLAINED_DELIVERY_STATES.includes(recipient.delivery_state) && (
                    <p className="mt-1 max-w-xs text-xs text-gray-700">{t(`deliveryExplain.${recipient.delivery_state}`)}</p>
                  )}
                </TableCell>
                <TableCell className="whitespace-normal align-top">
                  <Badge variant={accessStateVariant[recipient.access_state]}>{t(`accessState.${recipient.access_state}`)}</Badge>
                  {recipient.failed_attempts > 0 && recipient.access_state !== 'locked' && (
                    <div className="mt-1 text-xs text-gray-600">{t('delivery.failedAttempts', { count: recipient.failed_attempts })}</div>
                  )}
                  {recipient.access_state === 'locked' && (
                    <>
                      <p className="mt-1 text-xs text-gray-700">{t('delivery.lockedExplain')}</p>
                      {canUnlock && (
                        <Button
                          size="sm"
                          variant="secondary"
                          className="mt-2"
                          aria-label={t('delivery.unlockFor', { email: recipient.email })}
                          onClick={() => setUnlocking(recipient)}
                        >
                          {t('delivery.unlock')}
                        </Button>
                      )}
                    </>
                  )}
                </TableCell>
                <TableCell className="align-top text-xs">
                  {recipient.first_verified_at ? (
                    <>
                      <div>{t('delivery.firstVerified', { date: date(recipient.first_verified_at) })}</div>
                      {recipient.last_verified_at && recipient.last_verified_at !== recipient.first_verified_at && (
                        <div>{t('delivery.lastVerified', { date: date(recipient.last_verified_at) })}</div>
                      )}
                    </>
                  ) : (
                    t('delivery.none')
                  )}
                </TableCell>
                <TableCell className="whitespace-normal align-top text-xs">
                  {recipient.downloads.length === 0 ? (
                    t('delivery.none')
                  ) : (
                    <ul className="space-y-1">
                      {recipient.downloads.map((download) => (
                        <li key={download.file_id}>
                          <div className="font-medium">
                            {t('delivery.downloadCount', {
                              name: fileName.get(download.file_id) ?? t('delivery.unknownFile'),
                              count: download.count,
                            })}
                          </div>
                          <div className="text-gray-600">
                            {t('delivery.downloadTimes', {
                              first: date(download.first_downloaded_at),
                              last: date(download.last_downloaded_at),
                            })}
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <UnlockDialog transfer={transfer} recipient={unlocking} onClose={() => setUnlocking(null)} />
    </Card>
  );
}

function UnlockDialog({
  transfer,
  recipient,
  onClose,
}: {
  transfer: Transfer;
  recipient: RecipientStatus | null;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const close = () => {
    setError(null);
    onClose();
  };

  const unlock = async (target: RecipientStatus) => {
    setBusy(true);
    setError(null);
    try {
      // A `503` unlocked too: only its audit record is pending (`unlockRecipient`).
      const outcome = await unlockRecipient(transfer.id, target.id);
      const text = outcome === 'unlocked' ? 'delivery.unlocked' : 'delivery.unlockedUnconfirmed';
      toast('success', t(text, { email: target.email }));
      await queryClient.invalidateQueries({ queryKey: queryKeys.recipients(transfer.id) });
      close();
    } catch (failure) {
      // `403 passkey_required` has its own text (problems.ts).
      setError(errorMessage(failure, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={recipient !== null} onClose={close} title={t('delivery.unlockTitle')}>
      {recipient && (
        <div className="space-y-4">
          <p className="text-sm text-gray-700">{t('delivery.unlockBody', { email: recipient.email })}</p>
          {error && <Alert>{error}</Alert>}
          <div className="flex justify-end gap-3">
            <Button variant="secondary" onClick={close} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button onClick={() => void unlock(recipient)} loading={busy}>
              {t('delivery.unlockConfirm')}
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}
