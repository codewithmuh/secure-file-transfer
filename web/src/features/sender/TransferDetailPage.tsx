import { useParams, useNavigate } from 'react-router';
import { useTranslation } from 'react-i18next';
import { ArrowLeft, Shield, Mail, FileIcon, AlertTriangle } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Button, Card, CardTitle, Badge, Table, TableHead, TableBody, TableRow, TableHeader, TableCell, Dialog } from '@/components/ui';
import { formatDate, formatFileSize } from '@/lib/formatters';
import { useState } from 'react';

export function TransferDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [showRevoke, setShowRevoke] = useState(false);

  // Mock data
  const transfer = {
    id: id ?? '1',
    status: 'sent' as const,
    message: 'Q4 Financial Reports',
    expires_at: '2026-11-11T00:00:00Z',
    submitted_at: '2026-11-04T06:00:00Z',
    download_limit: 5,
    file_count: 3,
    total_size: 15_000_000,
  };

  const recipients = [
    { id: '1', email: 'alice@example.com', delivery_state: 'downloaded' as const, notified_at: '2026-11-04T06:01:00Z', verified_at: '2026-11-04T07:00:00Z', first_downloaded_at: '2026-11-04T07:05:00Z' },
    { id: '2', email: 'bob@example.com', delivery_state: 'notified' as const, notified_at: '2026-11-04T06:01:00Z', verified_at: null, first_downloaded_at: null },
  ];

  const files = [
    { id: '1', name: 'Q4-report.pdf', size: 5_000_000, scan_state: 'clean' as const },
    { id: '2', name: 'budget-summary.xlsx', size: 3_000_000, scan_state: 'clean' as const },
    { id: '3', name: 'projections.pptx', size: 7_000_000, scan_state: 'clean' as const },
  ];

  const deliveryBadge = {
    pending: { variant: 'default' as const, labelKey: 'sender.deliveryPending' },
    notified: { variant: 'info' as const, labelKey: 'sender.deliveryNotified' },
    verified: { variant: 'warning' as const, labelKey: 'sender.deliveryVerified' },
    downloaded: { variant: 'success' as const, labelKey: 'sender.deliveryDownloaded' },
    locked: { variant: 'danger' as const, labelKey: 'sender.deliveryLocked' },
  };

  return (
    <PageShell
      title={transfer.message ?? t('sender.transfer')}
      actions={
        <div className="flex gap-2">
          <Button variant="ghost" onClick={() => navigate('/transfers')}>
            <ArrowLeft className="mr-2 h-4 w-4" />
            {t('common.back')}
          </Button>
          {transfer.status === 'sent' && (
            <Button variant="danger" onClick={() => setShowRevoke(true)}>
              {t('sender.revoke')}
            </Button>
          )}
        </div>
      }
    >
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {/* Recipients */}
          <Card>
            <CardTitle>{t('sender.recipients')}</CardTitle>
            <Table label={t('sender.recipients')}>
              <TableHead>
                <tr>
                  <TableHeader>{t('common.email')}</TableHeader>
                  <TableHeader>{t('common.status')}</TableHeader>
                  <TableHeader>{t('sender.notifiedAt')}</TableHeader>
                  <TableHeader>{t('sender.verifiedAt')}</TableHeader>
                  <TableHeader>{t('sender.downloadedAt')}</TableHeader>
                </tr>
              </TableHead>
              <TableBody>
                {recipients.map((r) => {
                  const badge = deliveryBadge[r.delivery_state];
                  return (
                    <TableRow key={r.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Mail className="h-4 w-4 text-gray-500" />
                          <span className="font-medium">{r.email}</span>
                        </div>
                      </TableCell>
                      <TableCell><Badge variant={badge.variant}>{t(badge.labelKey)}</Badge></TableCell>
                      <TableCell>{r.notified_at ? formatDate(r.notified_at) : '—'}</TableCell>
                      <TableCell>{r.verified_at ? formatDate(r.verified_at) : '—'}</TableCell>
                      <TableCell>{r.first_downloaded_at ? formatDate(r.first_downloaded_at) : '—'}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Card>

          {/* Files */}
          <Card>
            <CardTitle>{t('sender.files')}</CardTitle>
            <ul className="mt-3 space-y-2">
              {files.map((file) => (
                <li key={file.id} className="flex items-center justify-between rounded-lg bg-gray-50 p-3">
                  <div className="flex items-center gap-3">
                    <FileIcon className="h-5 w-5 text-gray-500" />
                    <div>
                      <p className="text-sm font-medium text-gray-900">{file.name}</p>
                      <p className="text-xs text-gray-500">{formatFileSize(file.size)}</p>
                    </div>
                  </div>
                  <Badge variant={file.scan_state === 'clean' ? 'success' : 'warning'}>
                    <Shield className="mr-1 h-3 w-3" />
                    {t(`codes.${file.scan_state}`)}
                  </Badge>
                </li>
              ))}
            </ul>
          </Card>
        </div>

        {/* Details sidebar */}
        <div>
          <Card>
            <CardTitle>{t('common.details')}</CardTitle>
            <dl className="mt-3 space-y-3 text-sm">
              <div>
                <dt className="text-gray-500">{t('common.status')}</dt>
                <dd className="mt-0.5"><Badge variant="success">{t(`codes.${transfer.status}`)}</Badge></dd>
              </div>
              <div>
                <dt className="text-gray-500">{t('common.expiresAt')}</dt>
                <dd className="mt-0.5 font-medium">{formatDate(transfer.expires_at)}</dd>
              </div>
              <div>
                <dt className="text-gray-500">{t('sender.downloadLimit')}</dt>
                <dd className="mt-0.5 font-medium">{transfer.download_limit ?? t('common.noLimit')}</dd>
              </div>
              <div>
                <dt className="text-gray-500">{t('common.totalSize')}</dt>
                <dd className="mt-0.5 font-medium">{formatFileSize(transfer.total_size)}</dd>
              </div>
              <div>
                <dt className="text-gray-500">{t('sender.sentAt')}</dt>
                <dd className="mt-0.5 font-medium">{transfer.submitted_at ? formatDate(transfer.submitted_at) : '—'}</dd>
              </div>
            </dl>
          </Card>
        </div>
      </div>

      {/* Revoke dialog */}
      <Dialog open={showRevoke} onClose={() => setShowRevoke(false)} title={t('sender.revoke')}>
        <div className="flex items-start gap-3">
          <AlertTriangle className="h-6 w-6 shrink-0 text-red-500" />
          <p className="text-sm text-gray-600">{t('sender.revokeConfirm')}</p>
        </div>
        <div className="mt-6 flex justify-end gap-3">
          <Button variant="secondary" onClick={() => setShowRevoke(false)}>
            {t('common.cancel')}
          </Button>
          <Button variant="danger" onClick={() => { setShowRevoke(false); navigate('/transfers'); }}>
            {t('sender.revoke')}
          </Button>
        </div>
      </Dialog>
    </PageShell>
  );
}
