import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Upload, Plus } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Button, Card, Badge, Table, TableHead, TableBody, TableRow, TableHeader, TableCell, EmptyState } from '@/components/ui';
import { formatDate, formatFileSize } from '@/lib/formatters';
import type { UploadRequest } from '@/types';

const mockRequests: UploadRequest[] = [
  { id: '1', email: 'supplier@example.com', locale: 'en', status: 'active', message: 'Please upload the signed contract', expires_at: '2026-11-14T00:00:00Z', file_count: 2, total_size: 8_000_000, created_at: '2026-11-04T05:00:00Z' },
  { id: '2', email: 'accountant@example.com', locale: 'ja', status: 'expired', message: null, expires_at: '2026-11-01T00:00:00Z', file_count: 0, total_size: 0, created_at: '2026-10-25T09:00:00Z' },
];

const statusBadge = {
  active: { variant: 'success' as const, label: 'Active' },
  expired: { variant: 'default' as const, label: 'Expired' },
  revoked: { variant: 'danger' as const, label: 'Revoked' },
};

export function UploadRequestListPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();

  return (
    <PageShell
      title={t('sender.uploadRequests')}
      actions={
        <Button onClick={() => navigate('/upload-requests/new')}>
          <Plus className="mr-2 h-4 w-4" />
          {t('sender.newUploadRequest')}
        </Button>
      }
    >
      <Card padding={false}>
        {mockRequests.length === 0 ? (
          <EmptyState
            icon={Upload}
            title="No upload requests"
            description="Create an upload request to receive files from someone outside your company."
            action={
              <Button onClick={() => navigate('/upload-requests/new')}>
                {t('sender.newUploadRequest')}
              </Button>
            }
          />
        ) : (
          <Table>
            <TableHead>
              <tr>
                <TableHeader>{t('common.status')}</TableHeader>
                <TableHeader>Email</TableHeader>
                <TableHeader>Message</TableHeader>
                <TableHeader>{t('sender.files')}</TableHeader>
                <TableHeader>Size</TableHeader>
                <TableHeader>{t('common.expiresAt')}</TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {mockRequests.map((req) => {
                const badge = statusBadge[req.status];
                return (
                  <TableRow key={req.id}>
                    <TableCell><Badge variant={badge.variant}>{badge.label}</Badge></TableCell>
                    <TableCell><span className="font-medium">{req.email}</span></TableCell>
                    <TableCell>{req.message ?? '—'}</TableCell>
                    <TableCell>{req.file_count}</TableCell>
                    <TableCell>{formatFileSize(req.total_size)}</TableCell>
                    <TableCell>{formatDate(req.expires_at)}</TableCell>
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
