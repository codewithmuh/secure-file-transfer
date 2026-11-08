import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { Send, ArrowUpRight } from 'lucide-react';
import { Alert, Card, CardTitle, Button, Spinner } from '@/components/ui';
import { PageShell } from '@/components/layout';
import { useRecentTransfers } from '@/hooks/transfers';
import { errorMessage } from '@/lib/problems';
import { formatDate, formatFileSize } from '@/lib/formatters';
import { TransferStateBadge } from './StateBadges';

/**
 * The dashboard (#196): the five newest transfers and the way to send one. No counts: the API has no aggregate
 * operation, and counting one page would mislead. Upload requests are M5 and hidden (#195).
 */
export function DashboardPage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const recent = useRecentTransfers();

  return (
    <PageShell
      title={t('sender.dashboard')}
      actions={
        <Button onClick={() => navigate('/transfers/new')}>
          <Send className="mr-2 h-4 w-4" aria-hidden="true" />
          {t('sender.newTransfer')}
        </Button>
      }
    >
      <Card>
        <div className="mb-4 flex items-center justify-between">
          <CardTitle>{t('sender.recentTransfers')}</CardTitle>
          <Link to="/transfers" className="flex items-center gap-1 text-sm text-brand-700 hover:text-brand-800">
            {t('common.viewAll')}
            <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
          </Link>
        </div>
        {recent.isPending ? (
          <div className="flex justify-center py-6">
            <Spinner />
            <span className="sr-only">{t('common.loading')}</span>
          </div>
        ) : recent.isError ? (
          <Alert>{errorMessage(recent.error, t)}</Alert>
        ) : recent.data.length === 0 ? (
          <p className="py-6 text-center text-sm text-gray-500">{t('sender.noTransfers')}</p>
        ) : (
          <ul className="space-y-3">
            {recent.data.map((transfer) => (
              <li key={transfer.id}>
                <Link
                  to={`/transfers/${transfer.id}`}
                  className="flex items-center justify-between rounded-lg border border-gray-200 p-4 transition-colors hover:bg-gray-50"
                >
                  <div>
                    <p className="text-sm font-medium text-gray-900">
                      {t('sender.recipientCount', { count: transfer.recipient_count })} ·{' '}
                      {t('common.fileCount', { count: transfer.file_count })}
                    </p>
                    <p className="text-xs text-gray-500">
                      {formatFileSize(transfer.total_size)} · {formatDate(transfer.created_at, i18n.language)}
                    </p>
                  </div>
                  <TransferStateBadge state={transfer.state} />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </PageShell>
  );
}
