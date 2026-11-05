import { useState, useRef, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Upload, FileIcon, X, CheckCircle } from 'lucide-react';
import { Card, CardTitle, Button, toast } from '@/components/ui';
import { formatFileSize } from '@/lib/formatters';

interface UploadFileEntry {
  id: string;
  file: File;
  progress: number;
  status: 'pending' | 'uploading' | 'complete' | 'error';
}

export function UploaderUploadPage() {
  const { t } = useTranslation();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<UploadFileEntry[]>([]);
  const [uploading, setUploading] = useState(false);

  const handleFileSelect = useCallback((selectedFiles: FileList | null) => {
    if (!selectedFiles) return;
    const newFiles = Array.from(selectedFiles).map((file) => ({
      id: crypto.randomUUID(),
      file,
      progress: 0,
      status: 'pending' as const,
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

  const handleUpload = async () => {
    if (files.length === 0) return;
    setUploading(true);

    for (let i = 0; i < files.length; i++) {
      setFiles((prev) =>
        prev.map((f, idx) => (idx === i ? { ...f, status: 'uploading' } : f)),
      );
      await new Promise((resolve) => setTimeout(resolve, 800));
      setFiles((prev) =>
        prev.map((f, idx) => (idx === i ? { ...f, status: 'complete', progress: 100 } : f)),
      );
    }

    setUploading(false);
    toast('success', t('uploader.uploadComplete'));
  };

  const totalSize = files.reduce((sum, f) => sum + f.file.size, 0);
  const allComplete = files.length > 0 && files.every((f) => f.status === 'complete');

  return (
    <div className="space-y-6">
      <div className="text-center">
        <Upload className="mx-auto h-10 w-10 text-brand-600" />
        <h1 className="mt-3 text-xl font-bold text-gray-900">{t('uploader.title')}</h1>
      </div>

      <Card>
        <CardTitle>{t('uploader.uploadFiles')}</CardTitle>
        <div
          onDrop={handleDrop}
          onDragOver={(e) => e.preventDefault()}
          onClick={() => !uploading && fileInputRef.current?.click()}
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
            disabled={uploading}
          />
        </div>

        {files.length > 0 && (
          <ul className="mt-4 space-y-2">
            {files.map((entry) => (
              <li key={entry.id} className="flex items-center justify-between rounded-lg bg-gray-50 p-3">
                <div className="flex items-center gap-3">
                  {entry.status === 'complete' ? (
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  ) : (
                    <FileIcon className="h-5 w-5 text-gray-500" />
                  )}
                  <div>
                    <p className="text-sm font-medium text-gray-900">{entry.file.name}</p>
                    <p className="text-xs text-gray-500">{formatFileSize(entry.file.size)}</p>
                  </div>
                </div>
                {entry.status === 'pending' && (
                  <button onClick={() => removeFile(entry.id)} aria-label={t('common.remove')} className="rounded-sm p-1 text-gray-500 hover:bg-gray-200 hover:text-gray-600">
                    <X className="h-4 w-4" />
                  </button>
                )}
                {entry.status === 'uploading' && (
                  <div className="h-1.5 w-20 overflow-hidden rounded-full bg-gray-200">
                    <div className="h-full animate-pulse rounded-full bg-brand-500" style={{ width: '60%' }} />
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}

        <div className="mt-4 flex items-center justify-between">
          <p className="text-sm text-gray-500">{t('common.fileCount', { count: files.length })} · {formatFileSize(totalSize)}</p>
          <Button onClick={handleUpload} loading={uploading} disabled={files.length === 0 || allComplete}>
            <Upload className="mr-2 h-4 w-4" />
            {allComplete ? t('uploader.uploadComplete') : uploading ? t('uploader.uploading') : t('uploader.uploadFiles')}
          </Button>
        </div>
      </Card>
    </div>
  );
}
