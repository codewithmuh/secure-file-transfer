import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Dialog, Select, toast } from '@/components/ui';
import type { Transfer } from '@/api';
import { extendTransferExpiry, invalidateTransfers, queryKeys, useTenantPolicy } from '@/hooks/transfers';
import { formatDate } from '@/lib/formatters';
import { IdempotencyKeys, mayHaveHappened } from '@/lib/idempotency';
import { errorMessage } from '@/lib/problems';
import { useDurationLabel } from '@/lib/useDurationLabel';
import { EXTENDABLE_STATES, extensionChoices, extensionLimit, type ExtensionChoice } from './extension';
import { expiryCapSeconds } from './uploadRequests';
import { formatDuration } from '@/lib/durations';

/**
 * "Extend expiry" on the transfer's page (#214, FR-9), for its owner while the transfer is submitted and hasn't ended.
 * The dialog offers the times the lifetime allows (`extensionChoices`: steps after the current expiry, and the latest
 * allowed, at most 30 days or the tenant's `max_expiry` after `submitted_at`), says the limit, and sends
 * `extendTransferExpiry` with an `Idempotency-Key` kept for the attempt. When nothing later is allowed, it says so
 * instead of offering the button.
 */
export function ExtendExpiry({ transfer }: { transfer: Transfer }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const durationLabel = useDurationLabel();
  const policy = useTenantPolicy();
  const keys = useRef(new IdempotencyKeys());
  const [open, setOpen] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [chosen, setChosen] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!EXTENDABLE_STATES.includes(transfer.state) || !transfer.expires_at || !policy.data) return null;
  const maxExpiry = policy.data.max_expiry;
  const choices = extensionChoices(transfer, maxExpiry, now);
  const limit = extensionLimit(transfer, maxExpiry);
  const date = (value: string | number) => formatDate(new Date(value).toISOString(), i18n.language);

  if (choices.length === 0) {
    return <p className="mt-1 text-xs text-gray-600">{t('extend.atLimit')}</p>;
  }

  const selected = choices.find((choice) => choice.expiresAt === chosen) ?? (choices[0] as ExtensionChoice);
  const label = (choice: ExtensionChoice) =>
    choice.kind === 'latest'
      ? t('extend.latest', { date: date(choice.expiresAt) })
      : t('extend.step', { duration: durationLabel(choice.step), date: date(choice.expiresAt) });

  const close = () => {
    setOpen(false);
    setError(null);
  };

  const extend = async () => {
    setBusy(true);
    setError(null);
    const body = { expires_at: selected.expiresAt };
    try {
      const extended = await extendTransferExpiry(transfer.id, body, keys.current.keyForBody('extend', body));
      keys.current.done('extend');
      queryClient.setQueryData(queryKeys.transfer(transfer.id), extended);
      void invalidateTransfers(queryClient);
      toast('success', t('extend.extended', { date: date(extended.expires_at ?? selected.expiresAt) }));
      close();
    } catch (failure) {
      if (!mayHaveHappened(failure)) keys.current.done('extend');
      setError(errorMessage(failure, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Button
        size="sm"
        variant="secondary"
        className="mt-2"
        onClick={() => {
          setNow(Date.now());
          setChosen(null);
          setOpen(true);
        }}
      >
        {t('extend.button')}
      </Button>
      <Dialog open={open} onClose={close} title={t('extend.title')}>
        <div className="space-y-4">
          <p className="text-sm text-gray-700">
            {t('extend.current', { date: date(transfer.expires_at) })} {t('extend.body')}
          </p>
          {limit !== null && (
            <p className="text-sm text-gray-700">
              {t('extend.limit', { duration: durationLabel(formatDuration(expiryCapSeconds(maxExpiry))), date: date(limit) })}
            </p>
          )}
          <Select
            label={t('extend.newExpiry')}
            value={selected.expiresAt}
            onChange={(event) => setChosen(event.target.value)}
            options={choices.map((choice) => ({ value: choice.expiresAt, label: label(choice) }))}
          />
          {error && <Alert>{error}</Alert>}
          <div className="flex justify-end gap-3">
            <Button variant="secondary" onClick={close} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button onClick={() => void extend()} loading={busy}>
              {t('extend.confirm')}
            </Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}
