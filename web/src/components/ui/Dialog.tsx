import { Fragment, type ReactNode } from 'react';
import { cn } from '@/lib/cn';
import { X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  children: ReactNode;
  className?: string;
}

export function Dialog({ open, onClose, title, children, className }: DialogProps) {
  const { t } = useTranslation();
  if (!open) return null;

  return (
    <Fragment>
      <div className="fixed inset-0 z-50 bg-black/50" onClick={onClose} aria-hidden="true" />
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div
          className={cn(
            'relative w-full max-w-lg rounded-2xl bg-white p-6 shadow-2xl',
            className,
          )}
          role="dialog"
          aria-modal="true"
          aria-label={title}
        >
          {title && (
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900">{title}</h2>
              <button
                onClick={onClose}
                className="rounded-lg p-1.5 text-gray-500 hover:bg-gray-100 hover:text-gray-700"
                aria-label={t('common.close')}
              >
                <X className="h-5 w-5" />
              </button>
            </div>
          )}
          {children}
        </div>
      </div>
    </Fragment>
  );
}
