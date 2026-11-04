import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Upload } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Button, Input, Card, toast } from '@/components/ui';

export function CreateUploadRequestPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [expiryDays, setExpiryDays] = useState('7');
  const [sending, setSending] = useState(false);

  const handleCreate = async () => {
    if (!email) return;
    setSending(true);
    await new Promise((resolve) => setTimeout(resolve, 1000));
    toast('success', 'Upload request sent');
    navigate('/upload-requests');
  };

  return (
    <PageShell title={t('sender.newUploadRequest')}>
      <div className="mx-auto max-w-lg space-y-6">
        <Card>
          <div className="space-y-4">
            <Input
              label="Recipient email"
              type="email"
              placeholder={t('auth.emailPlaceholder')}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoFocus
            />
            <div>
              <label className="block text-sm font-medium text-gray-700">{t('sender.message')}</label>
              <textarea
                className="input-field mt-1 min-h-[80px] resize-y"
                placeholder={t('sender.messagePlaceholder')}
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                maxLength={2000}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">{t('sender.expiry')}</label>
              <select
                className="input-field mt-1"
                value={expiryDays}
                onChange={(e) => setExpiryDays(e.target.value)}
              >
                <option value="1">1 day</option>
                <option value="3">3 days</option>
                <option value="7">7 days</option>
                <option value="14">14 days</option>
                <option value="30">30 days</option>
              </select>
            </div>
          </div>
        </Card>
        <Button onClick={handleCreate} className="w-full" loading={sending} disabled={!email}>
          <Upload className="mr-2 h-4 w-4" />
          Create upload request
        </Button>
      </div>
    </PageShell>
  );
}
