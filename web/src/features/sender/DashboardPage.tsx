import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { Send, Upload, FileText, ArrowUpRight } from 'lucide-react';
import { Card, CardTitle, Button } from '@/components/ui';
import { PageShell } from '@/components/layout';

const stats = [
  { labelKey: 'sender.activeTransfers', value: '12', icon: Send, color: 'text-blue-600 bg-blue-100' },
  { labelKey: 'sender.uploadRequests', value: '3', icon: Upload, color: 'text-purple-600 bg-purple-100' },
  { labelKey: 'sender.filesSent', value: '47', icon: FileText, color: 'text-green-600 bg-green-100' },
];

// Mock data; `hoursAgo` is shown in the page's language with Intl.RelativeTimeFormat.
const recentTransfers = [
  { id: '1', recipients: 'alice@example.com', files: 3, status: 'sent', hoursAgo: 2 },
  { id: '2', recipients: 'bob@example.com, carol@example.com', files: 1, status: 'held', hoursAgo: 5 },
  { id: '3', recipients: 'dave@example.com', files: 5, status: 'expired', hoursAgo: 48 },
] as const;

function timeAgo(hoursAgo: number, language: string): string {
  const format = new Intl.RelativeTimeFormat(language, { numeric: 'auto' });
  return hoursAgo < 24 ? format.format(-hoursAgo, 'hour') : format.format(-Math.round(hoursAgo / 24), 'day');
}

export function DashboardPage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();

  return (
    <PageShell
      title={t('sender.dashboard')}
      actions={
        <>
          <Button variant="secondary" onClick={() => navigate('/upload-requests/new')}>
            {t('sender.newUploadRequest')}
          </Button>
          <Button onClick={() => navigate('/transfers/new')}>
            <Send className="mr-2 h-4 w-4" />
            {t('sender.newTransfer')}
          </Button>
        </>
      }
    >
      {/* Stats */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {stats.map(({ labelKey, value, icon: Icon, color }) => (
          <Card key={labelKey}>
            <div className="flex items-center gap-4">
              <div className={`flex h-12 w-12 items-center justify-center rounded-xl ${color}`}>
                <Icon className="h-6 w-6" />
              </div>
              <div>
                <p className="text-sm text-gray-500">{t(labelKey)}</p>
                <p className="text-2xl font-bold text-gray-900">{value}</p>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {/* Recent transfers */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <CardTitle>{t('sender.recentTransfers')}</CardTitle>
          <button
            onClick={() => navigate('/transfers')}
            className="flex items-center gap-1 text-sm text-brand-600 hover:text-brand-700"
          >
            {t('common.viewAll')}
            <ArrowUpRight className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-3">
          {recentTransfers.map((transfer) => (
            <div
              key={transfer.id}
              onClick={() => navigate(`/transfers/${transfer.id}`)}
              className="flex items-center justify-between rounded-lg border border-gray-200 p-4 cursor-pointer hover:bg-gray-50 transition-colors"
            >
              <div>
                <p className="text-sm font-medium text-gray-900">{transfer.recipients}</p>
                <p className="text-xs text-gray-500">{t('common.fileCount', { count: transfer.files })} · {timeAgo(transfer.hoursAgo, i18n.language)}</p>
              </div>
              <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
                transfer.status === 'sent' ? 'bg-green-50 text-green-700' :
                transfer.status === 'held' ? 'bg-yellow-50 text-yellow-800' :
                'bg-gray-100 text-gray-700'
              }`}>
                {t(`codes.${transfer.status}`)}
              </span>
            </div>
          ))}
        </div>
      </Card>
    </PageShell>
  );
}
