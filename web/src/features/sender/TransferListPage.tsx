import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Send, Plus, Search } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Button, Input, Card, Badge, Table, TableHead, TableBody, TableRow, TableHeader, TableCell, EmptyState } from '@/components/ui';
import { formatDate, formatFileSize } from '@/lib/formatters';
import type { Transfer, TransferStatus } from '@/types';

const statusBadge: Record<TransferStatus, { variant: 'default' | 'success' | 'warning' | 'danger' | 'info'; label: string }> = {
  draft: { variant: 'default', label: 'Draft' },
  sent: { variant: 'success', label: 'Sent' },
  held: { variant: 'warning', label: 'Held' },
  expired: { variant: 'default', label: 'Expired' },
  revoked: { variant: 'danger', label: 'Revoked' },
  cancelled: { variant: 'default', label: 'Cancelled' },
};

// Mock data — replaced by TanStack Query when API exists
const mockTransfers: Transfer[] = [
  { id: '1', status: 'sent', message: 'Q4 Reports', expires_in: null, expires_at: '2026-11-11T00:00:00Z', submitted_at: '2026-11-04T06:00:00Z', download_limit: 5, notify_on_first_download: true, file_count: 3, total_size: 15_000_000, recipient_count: 2, created_at: '2026-11-04T05:00:00Z', updated_at: '2026-11-04T06:00:00Z' },
  { id: '2', status: 'held', message: null, expires_in: null, expires_at: '2026-11-15T00:00:00Z', submitted_at: '2026-11-04T08:00:00Z', download_limit: null, notify_on_first_download: false, file_count: 1, total_size: 2_500_000_000, recipient_count: 1, created_at: '2026-11-04T07:00:00Z', updated_at: '2026-11-04T08:00:00Z' },
  { id: '3', status: 'expired', message: 'Contract draft', expires_in: null, expires_at: '2026-11-01T00:00:00Z', submitted_at: '2026-10-25T10:00:00Z', download_limit: null, notify_on_first_download: false, file_count: 5, total_size: 50_000_000, recipient_count: 3, created_at: '2026-10-25T09:00:00Z', updated_at: '2026-10-25T10:00:00Z' },
];

export function TransferListPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');

  const filtered = mockTransfers.filter((tr) =>
    tr.message?.toLowerCase().includes(search.toLowerCase()) ?? true,
  );

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
        <div className="border-b border-gray-200 p-4">
          <div className="relative max-w-sm">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
            <Input
              placeholder={t('common.search')}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>
        </div>
        {filtered.length === 0 ? (
          <EmptyState
            icon={Send}
            title={t('common.noResults')}
            description="No transfers match your search."
            action={
              <Button onClick={() => navigate('/transfers/new')}>
                {t('sender.newTransfer')}
              </Button>
            }
          />
        ) : (
          <Table>
            <TableHead>
              <tr>
                <TableHeader>{t('common.status')}</TableHeader>
                <TableHeader>Message</TableHeader>
                <TableHeader>{t('sender.recipients')}</TableHeader>
                <TableHeader>{t('sender.files')}</TableHeader>
                <TableHeader>Size</TableHeader>
                <TableHeader>{t('common.expiresAt')}</TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {filtered.map((transfer) => {
                const badge = statusBadge[transfer.status];
                return (
                  <TableRow
                    key={transfer.id}
                    onClick={() => navigate(`/transfers/${transfer.id}`)}
                  >
                    <TableCell>
                      <Badge variant={badge.variant}>{badge.label}</Badge>
                    </TableCell>
                    <TableCell>
                      <span className="font-medium text-gray-900">{transfer.message ?? '—'}</span>
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
