import { useNavigate } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Upload, Plus } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Button, Card, Badge, Table, TableHead, TableBody, TableRow, TableHeader, TableCell, EmptyState } from '@/components/ui';
import { formatDate, formatFileSize } from '@/lib/formatters';
import type { UploadRequest, UploadRequestState } from '@/api';

// Mock data in the contract's shape; replaced by TanStack Query when the API exists.
const mockRequests: UploadRequest[] = [
  { id: '1', state: 'open', created_by: 'u1', created_at: '2026-11-04T05:00:00Z', uploader_email: 'supplier@example.com', locale: 'en', message: 'Please upload the signed contract', expires_at: '2026-11-14T00:00:00Z', revoked_at: null, revoked_by: null, uploader_access_state: 'verified', delivery_state: 'sent', notified_at: '2026-11-04T05:00:05Z', failed_attempts: 0, locked_at: null, file_count: 2, total_size: 8_000_000 },
  { id: '2', state: 'expired', created_by: 'u1', created_at: '2026-10-25T09:00:00Z', uploader_email: 'accountant@example.com', locale: 'ja', message: null, expires_at: '2026-11-01T00:00:00Z', revoked_at: null, revoked_by: null, uploader_access_state: 'invited', delivery_state: 'sent', notified_at: '2026-10-25T09:00:05Z', failed_attempts: 0, locked_at: null, file_count: 0, total_size: 0 },
];

const stateBadge: Record<UploadRequestState, { variant: 'success' | 'default' | 'danger'; labelKey: string }> = {
  open: { variant: 'success', labelKey: 'sender.requestOpen' },
  expired: { variant: 'default', labelKey: 'sender.statusExpired' },
  revoked: { variant: 'danger', labelKey: 'sender.statusRevoked' },
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
            title={t('sender.noUploadRequests')}
            description={t('sender.noUploadRequestsHint')}
            action={
              <Button onClick={() => navigate('/upload-requests/new')}>
                {t('sender.newUploadRequest')}
              </Button>
            }
          />
        ) : (
          <Table label={t('sender.uploadRequests')}>
            <TableHead>
              <tr>
                <TableHeader>{t('common.status')}</TableHeader>
                <TableHeader>{t('common.email')}</TableHeader>
                <TableHeader>{t('sender.messageColumn')}</TableHeader>
                <TableHeader>{t('sender.files')}</TableHeader>
                <TableHeader>{t('common.size')}</TableHeader>
                <TableHeader>{t('common.expiresAt')}</TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {mockRequests.map((req) => {
                const badge = stateBadge[req.state];
                return (
                  <TableRow key={req.id}>
                    <TableCell><Badge variant={badge.variant}>{t(badge.labelKey)}</Badge></TableCell>
                    <TableCell><span className="font-medium">{req.uploader_email}</span></TableCell>
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
