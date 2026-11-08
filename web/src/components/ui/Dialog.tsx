import { Fragment, useEffect, useId, useRef, type ReactNode } from 'react';
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

const FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * A modal dialog that works by keyboard alone (#197): focus moves into it when it opens (its first field, or else its
 * first button), Tab stays inside it, Escape closes it, and focus goes back to what opened it. Its title names it.
 */
export function Dialog({ open, onClose, title, children, className }: DialogProps) {
  const { t } = useTranslation();
  const titleId = useId();
  const panel = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    if (!open) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const node = panel.current;
    const focusables = () => Array.from(node?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? []);
    const field = node?.querySelector<HTMLElement>('input:not([disabled]), select:not([disabled]), textarea:not([disabled])');
    // The close button comes first in the panel; start on the dialog's own content.
    (field ?? focusables().find((element) => !element.dataset.dialogClose) ?? focusables()[0])?.focus();

    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== 'Tab') return;
      const items = focusables();
      if (items.length === 0) return;
      const first = items[0] as HTMLElement;
      const last = items[items.length - 1] as HTMLElement;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      opener?.focus();
    };
  }, [open]);

  if (!open) return null;

  return (
    <Fragment>
      <div className="fixed inset-0 z-50 bg-black/50" onClick={onClose} aria-hidden="true" />
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div
          ref={panel}
          className={cn('relative w-full max-w-lg rounded-2xl bg-white p-6 shadow-2xl', className)}
          role="dialog"
          aria-modal="true"
          aria-labelledby={title ? titleId : undefined}
        >
          {title && (
            <div className="mb-4 flex items-center justify-between">
              <h2 id={titleId} className="text-lg font-semibold text-gray-900">
                {title}
              </h2>
              <button
                type="button"
                onClick={onClose}
                data-dialog-close="true"
                className="rounded-lg p-1.5 text-gray-500 hover:bg-gray-100 hover:text-gray-700"
                aria-label={t('common.close')}
              >
                <X className="h-5 w-5" aria-hidden="true" />
              </button>
            </div>
          )}
          {children}
        </div>
      </div>
    </Fragment>
  );
}
