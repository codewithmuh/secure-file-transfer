import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Inbox, Plus } from 'lucide-react';
import { PageShell } from '@/components/layout';
import {
  Alert,
  Button,
  Card,
  EmptyState,
  Select,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui';
import type { UploadRequestState } from '@/api';
import { AdminAccessNote } from '@/features/admin/AdminAccessNote';
import { useUserEmails } from '@/hooks/admin';
import { queryKeys, type ListScope } from '@/hooks/transfers';
import { revokeUploadRequest, useUploadRequestList } from '@/hooks/uploadRequests';
import { errorMessage, failureOf, isAccessProblem } from '@/lib/problems';
import { formatDate, formatFileSize } from '@/lib/formatters';
import { AccessStateBadge, DeliveryStateBadge, UploadRequestStateBadge } from './StateBadges';
import { ownerLabel } from './owners';
import { RevokeFromList, TenantScopeToggle } from './TenantScope';
import { UPLOAD_REQUEST_STATES } from './uploadRequests';

/**
 * The member's own upload requests (#212, UC-2): `listUploadRequests` (`scope=own`), newest first, with a state filter
 * and "load more" by cursor. Each row shows the request's state, its link email and the uploader's access as badges
 * with text, never colour alone. An admin can switch to every request of the tenant (#217, `scope=tenant`), with the
 * owner and a revoke action.
 */
export function UploadRequestListPage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [state, setState] = useState<UploadRequestState | null>(null);
  const [scope, setScope] = useState<ListScope>('own');
  const list = useUploadRequestList(state, 25, scope);
  const items = list.data?.pages.flatMap((page) => page.items) ?? [];
  const tenant = scope === 'tenant';
  const owners = useUserEmails(tenant);

  return (
    <PageShell
      title={t('sender.uploadRequests')}
      actions={
        <Button onClick={() => navigate('/upload-requests/new')}>
          <Plus className="mr-2 h-4 w-4" aria-hidden="true" />
          {t('sender.newUploadRequest')}
        </Button>
      }
    >
      <div className="flex flex-wrap items-end gap-6">
        <div className="w-full max-w-xs">
          <Select
            label={t('requests.stateFilter')}
            value={state ?? ''}
            onChange={(event) => setState((event.target.value || null) as UploadRequestState | null)}
            options={[
              { value: '', label: t('requests.allStates') },
              ...UPLOAD_REQUEST_STATES.map((value) => ({ value, label: t(`uploadRequestState.${value}`) })),
            ]}
          />
        </div>
        <TenantScopeToggle scope={scope} onChange={setScope} label={t('tenantScope.allUploadRequests')} />
      </div>
      <Card padding={false}>
        {list.isPending ? (
          <div className="flex justify-center py-12">
            <Spinner />
            <span className="sr-only">{t('common.loading')}</span>
          </div>
        ) : list.isError ? (
          isAccessProblem(list.error) ? (
            <div className="p-4">
              <AdminAccessNote error={list.error} />
            </div>
          ) : (
            <Alert className="m-4">{errorMessage(list.error, t)}</Alert>
          )
        ) : items.length === 0 ? (
          <EmptyState
            icon={Inbox}
            title={t('sender.noUploadRequests')}
            description={t('sender.noUploadRequestsHint')}
            action={<Button onClick={() => navigate('/upload-requests/new')}>{t('sender.newUploadRequest')}</Button>}
          />
        ) : (
          <Table label={t('sender.uploadRequests')}>
            <TableHead>
              <tr>
                <TableHeader>{t('common.createdAt')}</TableHeader>
                {tenant && <TableHeader>{t('tenantScope.owner')}</TableHeader>}
                <TableHeader>{t('common.status')}</TableHeader>
                <TableHeader>{t('requests.uploader')}</TableHeader>
                <TableHeader>{t('requests.linkEmail')}</TableHeader>
                <TableHeader>{t('requests.access')}</TableHeader>
                <TableHeader>{t('sender.files')}</TableHeader>
                <TableHeader>{t('common.size')}</TableHeader>
                <TableHeader>{t('common.expiresAt')}</TableHeader>
                {tenant && (
                  <TableHeader>
                    <span className="sr-only">{t('common.actions')}</span>
                  </TableHeader>
                )}
              </tr>
            </TableHead>
            <TableBody>
              {items.map((request) => (
                <TableRow key={request.id}>
                  <TableCell>
                    <Link
                      to={`/upload-requests/${request.id}`}
                      className="font-medium text-brand-700 underline hover:text-brand-800"
                    >
                      {formatDate(request.created_at, i18n.language)}
                    </Link>
                  </TableCell>
                  {tenant && <TableCell>{ownerLabel(owners.data, request.created_by)}</TableCell>}
                  <TableCell>
                    <UploadRequestStateBadge state={request.state} />
                  </TableCell>
                  <TableCell>{request.uploader_email}</TableCell>
                  <TableCell>
                    <DeliveryStateBadge state={request.delivery_state} />
                  </TableCell>
                  <TableCell>
                    <AccessStateBadge state={request.uploader_access_state} />
                  </TableCell>
                  <TableCell>{request.file_count}</TableCell>
                  <TableCell>{formatFileSize(request.total_size)}</TableCell>
                  <TableCell>{formatDate(request.expires_at, i18n.language)}</TableCell>
                  {tenant && (
                    <TableCell>
                      {request.state === 'open' && (
                        <RevokeFromList
                          label={t('tenantScope.revokeRequestFor', {
                            owner: ownerLabel(owners.data, request.created_by),
                            date: formatDate(request.created_at, i18n.language),
                          })}
                          title={t('requests.revokeTitle')}
                          body={t('requests.revokeBody')}
                          revoke={async () => {
                            try {
                              await revokeUploadRequest(request.id);
                              return 'revoked';
                            } catch (error) {
                              if (failureOf(error).status === 503) return 'unconfirmed';
                              throw error;
                            }
                          }}
                          invalidate={queryKeys.uploadRequests}
                        />
                      )}
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>
      {list.hasNextPage && (
        <div className="flex justify-center">
          <Button variant="secondary" onClick={() => void list.fetchNextPage()} loading={list.isFetchingNextPage}>
            {t('common.loadMore')}
          </Button>
        </div>
      )}
    </PageShell>
  );
}
