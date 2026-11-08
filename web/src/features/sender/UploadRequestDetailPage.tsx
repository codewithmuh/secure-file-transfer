import { useCallback, useState } from 'react';
import { Link, useParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowLeft } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Alert, Button, Card, CardTitle, Dialog, Spinner, toast } from '@/components/ui';
import type { UploadRequest } from '@/api';
import { queryKeys } from '@/hooks/transfers';
import { invalidateUploadRequests, revokeUploadRequest, unlockUploader, useUploadRequest } from '@/hooks/uploadRequests';
import { formatDate } from '@/lib/formatters';
import { errorMessage, problemCode } from '@/lib/problems';
import { useAuthStore } from '@/stores/authStore';
import { ReceivedFiles } from './ReceivedFiles';
import { useRevocation } from './revocation';
import { AccessStateBadge, DeliveryStateBadge, UploadRequestStateBadge } from './StateBadges';
import { EXPLAINED_DELIVERY_STATES } from './states';
import { isOpen } from './uploadRequests';

type Revocation = ReturnType<typeof useRevocation>;

/**
 * One upload request (#212, #213; UC-2, FR-10 to FR-13, FR-20, NFR-14): its state and expiry, where the uploader's
 * link email stands (`bounced` too when SES reports a bounce of any of the request's emails, #228), whether the
 * uploader verified or is locked, and the files received. Polled while open. The
 * member who created it can revoke it (shown as done and retried in the background on `503`, as revoking a transfer
 * is: `revocation.ts`), unlock a locked uploader (a new link is emailed), and download or delete what arrived. A tenant
 * admin sees another member's request as metadata only.
 */
export function UploadRequestDetailPage() {
  const { id = '' } = useParams<{ id: string }>();
  const { t, i18n } = useTranslation();
  const query = useUploadRequest(id);
  const request = query.data;

  return (
    <PageShell
      title={t('requests.request')}
      description={request ? t('sender.createdOn', { date: formatDate(request.created_at, i18n.language) }) : undefined}
      actions={
        <Link to="/upload-requests" className="btn-secondary">
          <ArrowLeft className="mr-2 h-4 w-4" aria-hidden="true" />
          {t('requests.backToList')}
        </Link>
      }
    >
      {query.isPending ? (
        <div className="flex justify-center py-12">
          <Spinner />
          <span className="sr-only">{t('common.loading')}</span>
        </div>
      ) : query.isError ? (
        <Alert>{problemCode(query.error) === 'not_found' ? t('requests.notFound') : errorMessage(query.error, t)}</Alert>
      ) : request ? (
        // Keyed by ID: another request gets its own view and revocation, never the last one's pending retry.
        <RequestView key={request.id} request={request} />
      ) : null}
    </PageShell>
  );
}

function RequestView({ request }: { request: UploadRequest }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const isOwner = useAuthStore((s) => s.user?.id === request.created_by);
  const [unlocking, setUnlocking] = useState(false);
  const revocation = useRevocation(
    request.id,
    revokeUploadRequest,
    useCallback(() => void invalidateUploadRequests(queryClient), [queryClient]),
  );
  const open = isOpen(request);
  const revocable = open && revocation.status !== 'revoked' && revocation.status !== 'unconfirmed';
  const date = (value: string) => formatDate(value, i18n.language);

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
      <div className="space-y-6 lg:col-span-2">
        <RequestEndBanner request={request} revocation={revocation} date={date} />
        {!isOwner && (
          <Alert variant="info" role="status">
            {t('requests.adminView')}
          </Alert>
        )}
        <ReceivedFiles request={request} isOwner={isOwner} />
      </div>

      <div>
        <Card>
          <CardTitle>{t('common.details')}</CardTitle>
          <dl className="mt-3 space-y-3 text-sm">
            <div>
              <dt className="text-gray-500">{t('common.status')}</dt>
              <dd className="mt-0.5">
                <UploadRequestStateBadge state={request.state} />
              </dd>
            </div>
            <div>
              <dt className="text-gray-500">{t('requests.openUntil')}</dt>
              <dd className="mt-0.5 font-medium">{date(request.expires_at)}</dd>
            </div>
            <div>
              <dt className="text-gray-500">{t('requests.uploader')}</dt>
              <dd className="mt-0.5 break-all font-medium">{request.uploader_email}</dd>
              <dd className="text-xs text-gray-600">{t(`locales.${request.locale}`)}</dd>
            </div>
            <div>
              <dt className="text-gray-500">{t('requests.linkEmail')}</dt>
              <dd className="mt-0.5">
                <UploaderDelivery request={request} date={date} />
              </dd>
            </div>
            <div>
              <dt className="text-gray-500">{t('requests.access')}</dt>
              <dd className="mt-0.5">
                <AccessStateBadge state={request.uploader_access_state} />
                {request.failed_attempts > 0 && request.uploader_access_state !== 'locked' && (
                  <div className="mt-1 text-xs text-gray-600">{t('delivery.failedAttempts', { count: request.failed_attempts })}</div>
                )}
                {request.uploader_access_state === 'locked' && (
                  <>
                    <p className="mt-1 text-xs text-gray-700">
                      {t('requests.lockedExplain')}
                      {request.locked_at ? ` ${date(request.locked_at)}` : ''}
                    </p>
                    {open && isOwner && (
                      <Button
                        size="sm"
                        variant="secondary"
                        className="mt-2"
                        aria-label={t('requests.unlockFor', { email: request.uploader_email })}
                        onClick={() => setUnlocking(true)}
                      >
                        {t('delivery.unlock')}
                      </Button>
                    )}
                  </>
                )}
              </dd>
            </div>
            <div>
              <dt className="text-gray-500">{t('sender.files')}</dt>
              <dd className="mt-0.5 font-medium">{t('common.fileCount', { count: request.file_count })}</dd>
            </div>
            {request.message && (
              <div>
                <dt className="text-gray-500">{t('requests.messageTitle')}</dt>
                <dd className="mt-0.5 whitespace-pre-wrap break-words">{request.message}</dd>
              </div>
            )}
          </dl>
          {revocable && (
            <div className="mt-4 border-t border-gray-100 pt-4">
              <RevokeUploadRequest revocation={revocation} />
            </div>
          )}
        </Card>
      </div>
      <UnlockUploaderDialog request={request} open={unlocking} onClose={() => setUnlocking(false)} />
    </div>
  );
}

/**
 * "Revoke upload request" and its confirmation (#212, FR-20, NFR-6). The revocation and its background retries live
 * in `useRevocation` on the page, as for a transfer, so the unconfirmed banner stays after the request shows `revoked`.
 */
function RevokeUploadRequest({ revocation }: { revocation: Revocation }) {
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
        {t('requests.revoke')}
      </Button>
      <Dialog open={open} onClose={close} title={t('requests.revokeTitle')}>
        <div className="space-y-4">
          <p className="text-sm text-gray-700">{t('requests.revokeBody')}</p>
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

/** What the page says about the request's end: revoked (confirmed or not, with a retry), or expired. */
/**
 * Where the uploader's emails stand (FR-7): the link email's delivery state, when it went out, and, for a bounce or a
 * suppressed address, what it means in the uploader's words (#228): any email of the request may have bounced, the
 * link, a code or the blocked-file notice, so the address is the thing to check.
 */
export function UploaderDelivery({
  request,
  date,
}: {
  request: Pick<UploadRequest, 'delivery_state' | 'notified_at'>;
  date: (value: string) => string;
}) {
  const { t } = useTranslation();
  return (
    <>
      <DeliveryStateBadge state={request.delivery_state} />
      {request.notified_at && (
        <div className="mt-1 text-xs text-gray-600">{t('delivery.notifiedAt', { date: date(request.notified_at) })}</div>
      )}
      {EXPLAINED_DELIVERY_STATES.includes(request.delivery_state) && (
        <p className="mt-1 text-xs text-gray-700">{t(`requests.deliveryExplain.${request.delivery_state}`)}</p>
      )}
    </>
  );
}

export function RequestEndBanner({
  request,
  revocation,
  date,
}: {
  request: Pick<UploadRequest, 'state' | 'revoked_at'>;
  revocation: Pick<Revocation, 'status' | 'busy' | 'revoke'>;
  date: (value: string) => string;
}) {
  const { t } = useTranslation();
  if (revocation.status === 'unconfirmed') {
    return (
      <Alert variant="warning" role="status">
        <p>{t('requests.revokeUnconfirmed')}</p>
        <Button size="sm" variant="secondary" className="mt-2" onClick={() => void revocation.revoke()} loading={revocation.busy}>
          {t('delivery.revokeRetry')}
        </Button>
      </Alert>
    );
  }
  if (request.state === 'revoked' || revocation.status === 'revoked') {
    return (
      <Alert variant="info" role="status">
        {t('requests.revoked')} {request.revoked_at ? t('delivery.revokedOn', { date: date(request.revoked_at) }) : ''}
      </Alert>
    );
  }
  if (request.state === 'expired') {
    return (
      <Alert variant="info" role="status">
        {t('requests.expiredReadOnly')}
      </Alert>
    );
  }
  return null;
}

/** Unlock a locked uploader (NFR-14): a new link is always emailed and the old one stops working, as the dialog says. */
function UnlockUploaderDialog({ request, open, onClose }: { request: UploadRequest; open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const close = () => {
    setError(null);
    onClose();
  };

  const unlock = async () => {
    setBusy(true);
    setError(null);
    try {
      // A `503` unlocked too: only its audit record is pending (`unlockUploader`).
      const outcome = await unlockUploader(request.id);
      const text = outcome === 'unlocked' ? 'delivery.unlocked' : 'delivery.unlockedUnconfirmed';
      toast('success', t(text, { email: request.uploader_email }));
      await queryClient.invalidateQueries({ queryKey: queryKeys.uploadRequest(request.id) });
      close();
    } catch (failure) {
      setError(errorMessage(failure, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={close} title={t('requests.unlockTitle')}>
      <div className="space-y-4">
        <p className="text-sm text-gray-700">{t('delivery.unlockBody', { email: request.uploader_email })}</p>
        {error && <Alert>{error}</Alert>}
        <div className="flex justify-end gap-3">
          <Button variant="secondary" onClick={close} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button onClick={() => void unlock()} loading={busy}>
            {t('delivery.unlockConfirm')}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
