import { useNavigate } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Send, Plus } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Button, Card, Badge, Table, TableHead, TableBody, TableRow, TableHeader, TableCell, EmptyState } from '@/components/ui';
import { formatDate, formatFileSize } from '@/lib/formatters';
import type { TransferState, TransferSummary } from '@/api';

const stateBadge: Record<TransferState, { variant: 'default' | 'success' | 'warning' | 'danger' | 'info'; labelKey: string }> = {
  draft: { variant: 'default', labelKey: 'sender.statusDraft' },
  submitted: { variant: 'info', labelKey: 'sender.statusSubmitted' },
  awaiting_confirmation: { variant: 'warning', labelKey: 'sender.statusAwaitingConfirmation' },
  pending_approval: { variant: 'warning', labelKey: 'sender.statusPendingApproval' },
  sent: { variant: 'success', labelKey: 'sender.statusSent' },
  held: { variant: 'warning', labelKey: 'sender.statusHeld' },
  expired: { variant: 'default', labelKey: 'sender.statusExpired' },
  revoked: { variant: 'danger', labelKey: 'sender.statusRevoked' },
  cancelled: { variant: 'default', labelKey: 'sender.statusCancelled' },
};

// Mock data in the contract's shape (`listTransfers` answers `TransferSummary` items); replaced by TanStack Query
// when the API exists.
const mockTransfers: TransferSummary[] = [
  { id: '1', state: 'sent', created_by: 'u1', created_at: '2026-11-04T05:00:00Z', expires_at: '2026-11-11T00:00:00Z', sent_at: '2026-11-04T06:00:00Z', revoked_at: null, file_count: 3, recipient_count: 2, total_size: 15_000_000 },
  { id: '2', state: 'held', created_by: 'u1', created_at: '2026-11-04T07:00:00Z', expires_at: '2026-11-15T00:00:00Z', sent_at: null, revoked_at: null, file_count: 1, recipient_count: 1, total_size: 2_500_000_000 },
  { id: '3', state: 'expired', created_by: 'u1', created_at: '2026-10-25T09:00:00Z', expires_at: '2026-11-01T00:00:00Z', sent_at: '2026-10-25T10:00:00Z', revoked_at: null, file_count: 5, recipient_count: 3, total_size: 50_000_000 },
];

export function TransferListPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();

  return (
    <PageShell
      title={t('sender.transfers')}
      actions={
        <Button onClick={() => navigate('/transfers/new')}>
          <Plus className="mr-2 h-4 w-4" />
          {t('sender.newTransfer')}
        </Button>
      }
    >
      <Card padding={false}>
        {mockTransfers.length === 0 ? (
          <EmptyState
            icon={Send}
            title={t('common.noResults')}
            description={t('sender.noTransfers')}
            action={
              <Button onClick={() => navigate('/transfers/new')}>
                {t('sender.newTransfer')}
              </Button>
            }
          />
        ) : (
          <Table label={t('sender.transfers')}>
            <TableHead>
              <tr>
                <TableHeader>{t('common.status')}</TableHeader>
                <TableHeader>{t('common.createdAt')}</TableHeader>
                <TableHeader>{t('sender.recipients')}</TableHeader>
                <TableHeader>{t('sender.files')}</TableHeader>
                <TableHeader>{t('common.size')}</TableHeader>
                <TableHeader>{t('common.expiresAt')}</TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {mockTransfers.map((transfer) => {
                const badge = stateBadge[transfer.state];
                return (
                  <TableRow
                    key={transfer.id}
                    onClick={() => navigate(`/transfers/${transfer.id}`)}
                  >
                    <TableCell>
                      <Badge variant={badge.variant}>{t(badge.labelKey)}</Badge>
                    </TableCell>
                    <TableCell>
                      <span className="font-medium text-gray-900">{formatDate(transfer.created_at)}</span>
                    </TableCell>
                    <TableCell>{transfer.recipient_count}</TableCell>
                    <TableCell>{transfer.file_count}</TableCell>
                    <TableCell>{formatFileSize(transfer.total_size)}</TableCell>
                    <TableCell>{transfer.expires_at ? formatDate(transfer.expires_at) : '—'}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>
    </PageShell>
  );
}
