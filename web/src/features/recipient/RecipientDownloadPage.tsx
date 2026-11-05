import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Download, FileIcon, Shield, AlertTriangle } from 'lucide-react';
import { Card, CardTitle, Button, Badge } from '@/components/ui';
import { formatFileSize } from '@/lib/formatters';

const mockFiles = [
  { id: '1', name: 'Q4-report.pdf', size: 5_000_000, scan_state: 'clean' as const },
  { id: '2', name: 'budget-summary.xlsx', size: 3_000_000, scan_state: 'clean' as const },
  { id: '3', name: 'projections.pptx', size: 7_000_000, scan_state: 'unscannable' as const },
];

export function RecipientDownloadPage() {
  const { t } = useTranslation();
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const handleDownload = async (fileId: string) => {
    setDownloadingId(fileId);
    await new Promise((resolve) => setTimeout(resolve, 1000));
    setDownloadingId(null);
  };

  return (
    <div className="space-y-6">
      <div className="text-center">
        <Shield className="mx-auto h-10 w-10 text-brand-600" />
        <h1 className="mt-3 text-xl font-bold text-gray-900">{t('recipient.title')}</h1>
        <p className="mt-1 text-sm text-gray-500">
          {t('recipient.filesAvailable', { count: mockFiles.length })}
        </p>
      </div>

      <Card>
        <CardTitle>{t('sender.files')}</CardTitle>
        <ul className="mt-3 space-y-3">
          {mockFiles.map((file) => (
            <li key={file.id} className="rounded-lg border border-gray-200 p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  <FileIcon className="mt-0.5 h-5 w-5 text-gray-500" />
                  <div>
                    <p className="text-sm font-medium text-gray-900">{file.name}</p>
                    <p className="text-xs text-gray-500">{formatFileSize(file.size)}</p>
                    {file.scan_state === 'unscannable' && (
                      <div className="mt-2 flex items-start gap-2 rounded-lg bg-yellow-50 p-2">
                        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-yellow-600" />
                        <p className="text-xs text-yellow-800">{t('recipient.unscannableWarning')}</p>
                      </div>
                    )}
                  </div>
                </div>
                {/* shrink-0: a long warning wraps instead of squeezing the badge and button (Japanese has no spaces). */}
                <div className="flex shrink-0 items-center gap-2">
                  <Badge variant={file.scan_state === 'clean' ? 'success' : 'warning'}>
                    {t(`codes.${file.scan_state}`)}
                  </Badge>
                  <Button
                    size="sm"
                    onClick={() => handleDownload(file.id)}
                    loading={downloadingId === file.id}
                  >
                    <Download className="mr-1 h-4 w-4" />
                    {t('recipient.download')}
                  </Button>
                </div>
              </div>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
