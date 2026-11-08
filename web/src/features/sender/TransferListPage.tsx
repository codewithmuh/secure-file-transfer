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
import { useTransferList } from '@/hooks/transfers';
import { errorMessage } from '@/lib/problems';
import { formatDate, formatFileSize } from '@/lib/formatters';
import { TransferStateBadge } from './StateBadges';
import { TRANSFER_STATES } from './states';

/** The member's own transfers (#196): `listTransfers`, newest first, a state filter and "load more" by cursor. */
export function TransferListPage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [state, setState] = useState<TransferState | null>(null);
  const list = useTransferList(state);
  const items = list.data?.pages.flatMap((page) => page.items) ?? [];

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
      <div className="max-w-xs">
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
      <Card padding={false}>
        {list.isPending ? (
          <div className="flex justify-center py-12">
            <Spinner />
            <span className="sr-only">{t('common.loading')}</span>
          </div>
        ) : list.isError ? (
          <Alert className="m-4">{errorMessage(list.error, t)}</Alert>
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
                <TableHeader>{t('common.status')}</TableHeader>
                <TableHeader>{t('sender.recipients')}</TableHeader>
                <TableHeader>{t('sender.files')}</TableHeader>
                <TableHeader>{t('common.size')}</TableHeader>
                <TableHeader>{t('common.expiresAt')}</TableHeader>
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
                  <TableCell>
                    <TransferStateBadge state={transfer.state} />
                  </TableCell>
                  <TableCell>{transfer.recipient_count}</TableCell>
                  <TableCell>{transfer.file_count}</TableCell>
                  <TableCell>{formatFileSize(transfer.total_size)}</TableCell>
                  <TableCell>{transfer.expires_at ? formatDate(transfer.expires_at, i18n.language) : '—'}</TableCell>
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
