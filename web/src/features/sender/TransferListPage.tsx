import { useState } from 'react';
import { useNavigate, Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Send, Plus } from 'lucide-react';
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
import type { TransferState } from '@/api';
import { AdminAccessNote } from '@/features/admin/AdminAccessNote';
import { useUserEmails } from '@/hooks/admin';
import { queryKeys, revokeTransfer, useTransferList, type ListScope } from '@/hooks/transfers';
import { errorMessage, failureOf, isAccessProblem } from '@/lib/problems';
import { formatDate, formatFileSize } from '@/lib/formatters';
import { TransferStateBadge } from './StateBadges';
import { REVOCABLE_STATES, TRANSFER_STATES } from './states';
import { ownerLabel } from './owners';
import { RevokeFromList, TenantScopeToggle } from './TenantScope';

/**
 * The member's own transfers (#196): `listTransfers`, newest first, a state filter and "load more" by cursor. An admin
 * can switch to every transfer of the tenant (#217, `scope=tenant`), with the owner and a revoke action.
 */
export function TransferListPage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [state, setState] = useState<TransferState | null>(null);
  const [scope, setScope] = useState<ListScope>('own');
  const list = useTransferList(state, 25, scope);
  const items = list.data?.pages.flatMap((page) => page.items) ?? [];
  const tenant = scope === 'tenant';
  const owners = useUserEmails(tenant);

  return (
    <PageShell
      title={t('sender.transfers')}
      actions={
        <Button onClick={() => navigate('/transfers/new')}>
          <Plus className="mr-2 h-4 w-4" aria-hidden="true" />
          {t('sender.newTransfer')}
        </Button>
      }
    >
      <div className="flex flex-wrap items-end gap-6">
        <div className="w-full max-w-xs">
          <Select
            label={t('sender.stateFilter')}
            value={state ?? ''}
            onChange={(event) => setState((event.target.value || null) as TransferState | null)}
            options={[
              { value: '', label: t('sender.allStates') },
              ...TRANSFER_STATES.map((value) => ({ value, label: t(`transferState.${value}`) })),
            ]}
          />
        </div>
        <TenantScopeToggle scope={scope} onChange={setScope} label={t('tenantScope.allTransfers')} />
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
            icon={Send}
            title={t('common.noResults')}
            description={t('sender.noTransfers')}
            action={<Button onClick={() => navigate('/transfers/new')}>{t('sender.newTransfer')}</Button>}
          />
        ) : (
          <Table label={t('sender.transfers')}>
            <TableHead>
              <tr>
                <TableHeader>{t('common.createdAt')}</TableHeader>
                {tenant && <TableHeader>{t('tenantScope.owner')}</TableHeader>}
                <TableHeader>{t('common.status')}</TableHeader>
                <TableHeader>{t('sender.recipients')}</TableHeader>
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
              {items.map((transfer) => (
                <TableRow key={transfer.id}>
                  <TableCell>
                    <Link to={`/transfers/${transfer.id}`} className="font-medium text-brand-700 underline hover:text-brand-800">
                      {formatDate(transfer.created_at, i18n.language)}
                    </Link>
                  </TableCell>
                  {tenant && <TableCell>{ownerLabel(owners.data, transfer.created_by)}</TableCell>}
                  <TableCell>
                    <TransferStateBadge state={transfer.state} />
                  </TableCell>
                  <TableCell>{transfer.recipient_count}</TableCell>
                  <TableCell>{transfer.file_count}</TableCell>
                  <TableCell>{formatFileSize(transfer.total_size)}</TableCell>
                  <TableCell>{transfer.expires_at ? formatDate(transfer.expires_at, i18n.language) : '—'}</TableCell>
                  {tenant && (
                    <TableCell>
                      {REVOCABLE_STATES.includes(transfer.state) && (
                        <RevokeFromList
                          label={t('tenantScope.revokeTransferFor', {
                            owner: ownerLabel(owners.data, transfer.created_by),
                            date: formatDate(transfer.created_at, i18n.language),
                          })}
                          title={t('delivery.revokeTitle')}
                          body={t('delivery.revokeBody')}
                          revoke={async () => {
                            try {
                              await revokeTransfer(transfer.id);
                              return 'revoked';
                            } catch (error) {
                              if (failureOf(error).status === 503) return 'unconfirmed';
                              throw error;
                            }
                          }}
                          invalidate={queryKeys.transfers}
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
