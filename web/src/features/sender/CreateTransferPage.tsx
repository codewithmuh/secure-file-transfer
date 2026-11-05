import { useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Send, Upload, X, Plus, FileIcon } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Button, Input, Card, CardTitle, toast } from '@/components/ui';
import { formatFileSize } from '@/lib/formatters';

interface RecipientEntry {
  id: string;
  email: string;
}

interface FileEntry {
  id: string;
  file: File;
  progress: number;
}

export function CreateTransferPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [recipients, setRecipients] = useState<RecipientEntry[]>([]);
  const [recipientInput, setRecipientInput] = useState('');
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [message, setMessage] = useState('');
  const [expiryDays, setExpiryDays] = useState('7');
  const [downloadLimit, setDownloadLimit] = useState('');
  const [sending, setSending] = useState(false);

  const addRecipient = () => {
    const email = recipientInput.trim();
    if (email && email.includes('@') && !recipients.some((r) => r.email === email)) {
      setRecipients((prev) => [...prev, { id: crypto.randomUUID(), email }]);
      setRecipientInput('');
    }
  };

  const removeRecipient = (id: string) => {
    setRecipients((prev) => prev.filter((r) => r.id !== id));
  };

  const handleFileSelect = useCallback((selectedFiles: FileList | null) => {
    if (!selectedFiles) return;
    const newFiles = Array.from(selectedFiles).map((file) => ({
      id: crypto.randomUUID(),
      file,
      progress: 0,
    }));
    setFiles((prev) => [...prev, ...newFiles]);
  }, []);

  const removeFile = (id: string) => {
    setFiles((prev) => prev.filter((f) => f.id !== id));
  };

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      handleFileSelect(e.dataTransfer.files);
    },
    [handleFileSelect],
  );

  const handleSend = async () => {
    if (recipients.length === 0 || files.length === 0) return;
    setSending(true);
    // Mock — will use apiClient when backend exists
    await new Promise((resolve) => setTimeout(resolve, 1500));
    toast('success', t('sender.transferSent'));
    navigate('/transfers');
  };

  const totalSize = files.reduce((sum, f) => sum + f.file.size, 0);

  return (
    <PageShell title={t('sender.transferTitle')}>
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {/* Recipients */}
          <Card>
            <CardTitle>{t('sender.recipients')}</CardTitle>
            <div className="mt-3 flex flex-wrap gap-2">
              {recipients.map((r) => (
                <span
                  key={r.id}
                  className="inline-flex items-center gap-1 rounded-full bg-brand-50 px-3 py-1 text-sm text-brand-700"
                >
                  {r.email}
                  <button
                    onClick={() => removeRecipient(r.id)}
                    aria-label={t('sender.removeRecipient', { email: r.email })}
                    className="rounded-full p-0.5 hover:bg-brand-100"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </span>
              ))}
            </div>
            <div className="mt-3 flex gap-2">
              <Input
                placeholder={t('auth.emailPlaceholder')}
                value={recipientInput}
                onChange={(e) => setRecipientInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && addRecipient()}
              />
              <Button variant="secondary" onClick={addRecipient} aria-label={t('sender.addRecipient')}>
                <Plus className="h-4 w-4" />
              </Button>
            </div>
          </Card>

          {/* Files */}
          <Card>
            <CardTitle>{t('sender.files')}</CardTitle>
            <div
              onDrop={handleDrop}
              onDragOver={(e) => e.preventDefault()}
              onClick={() => fileInputRef.current?.click()}
              className="mt-3 flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed border-gray-300 p-8 text-center transition-colors hover:border-brand-400 hover:bg-brand-50/50"
            >
              <Upload className="mb-3 h-10 w-10 text-gray-500" />
              <p className="text-sm font-medium text-gray-700">{t('sender.dragDrop')}</p>
              <p className="mt-1 text-xs text-gray-500">{t('sender.maxFileSize')}</p>
              <input
                ref={fileInputRef}
                type="file"
                multiple
                className="hidden"
                onChange={(e) => handleFileSelect(e.target.files)}
              />
            </div>
            {files.length > 0 && (
              <ul className="mt-4 space-y-2">
                {files.map((entry) => (
                  <li
                    key={entry.id}
                    className="flex items-center justify-between rounded-lg bg-gray-50 p-3"
                  >
                    <div className="flex items-center gap-3">
                      <FileIcon className="h-5 w-5 text-gray-500" />
                      <div>
                        <p className="text-sm font-medium text-gray-900">{entry.file.name}</p>
                        <p className="text-xs text-gray-500">{formatFileSize(entry.file.size)}</p>
                      </div>
                    </div>
                    <button
                      onClick={() => removeFile(entry.id)}
                      aria-label={t('common.remove')}
                      className="rounded-sm p-1 text-gray-500 hover:bg-gray-200 hover:text-gray-600"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {/* Message */}
          <Card>
            <CardTitle>{t('sender.message')}</CardTitle>
            <textarea
              className="input-field mt-3 min-h-[100px] resize-y"
              placeholder={t('sender.messagePlaceholder')}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              maxLength={2000}
            />
            <p className="mt-1 text-right text-xs text-gray-500">{message.length}/2000</p>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          <Card>
            <CardTitle>{t('common.settings')}</CardTitle>
            <div className="mt-3 space-y-4">
              <div>
                <label htmlFor="expiry" className="block text-sm font-medium text-gray-700">{t('sender.expiry')}</label>
                <select id="expiry"
                  className="input-field mt-1"
                  value={expiryDays}
                  onChange={(e) => setExpiryDays(e.target.value)}
                >
                  <option value="1">{t('common.days', { count: 1 })}</option>
                  <option value="3">{t('common.days', { count: 3 })}</option>
                  <option value="7">{t('common.days', { count: 7 })}</option>
                  <option value="14">{t('common.days', { count: 14 })}</option>
                  <option value="30">{t('common.days', { count: 30 })}</option>
                </select>
              </div>
              <Input
                label={t('sender.downloadLimit')}
                type="number"
                min="1"
                max="100"
                placeholder={t('common.noLimit')}
                value={downloadLimit}
                onChange={(e) => setDownloadLimit(e.target.value)}
              />
            </div>
          </Card>

          <Card>
            <CardTitle>{t('common.summary')}</CardTitle>
            <dl className="mt-3 space-y-2 text-sm">
              <div className="flex justify-between">
                <dt className="text-gray-500">{t('sender.recipients')}</dt>
                <dd className="font-medium">{recipients.length}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-500">{t('sender.files')}</dt>
                <dd className="font-medium">{files.length}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-500">{t('common.totalSize')}</dt>
                <dd className="font-medium">{formatFileSize(totalSize)}</dd>
              </div>
            </dl>
          </Card>

          <Button
            onClick={handleSend}
            className="w-full"
            loading={sending}
            disabled={recipients.length === 0 || files.length === 0}
          >
            <Send className="mr-2 h-4 w-4" />
            {sending ? t('sender.sending') : t('sender.send')}
          </Button>
        </div>
      </div>
    </PageShell>
  );
}
