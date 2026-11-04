import { useEffect, useCallback } from 'react';
import { cn } from '@/lib/cn';
import { CheckCircle, AlertCircle, XCircle, X, Info } from 'lucide-react';
import { create } from 'zustand';

type ToastType = 'success' | 'error' | 'warning' | 'info';

interface Toast {
  id: string;
  type: ToastType;
  message: string;
}

interface ToastStore {
  toasts: Toast[];
  addToast: (type: ToastType, message: string) => void;
  removeToast: (id: string) => void;
}

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],
  addToast: (type, message) =>
    set((state) => ({
      toasts: [...state.toasts, { id: crypto.randomUUID(), type, message }],
    })),
  removeToast: (id) =>
    set((state) => ({
      toasts: state.toasts.filter((t) => t.id !== id),
    })),
}));

export function toast(type: ToastType, message: string) {
  useToastStore.getState().addToast(type, message);
}

const icons = {
  success: CheckCircle,
  error: XCircle,
  warning: AlertCircle,
  info: Info,
};

const styles = {
  success: 'bg-green-50 text-green-800 ring-green-600/20',
  error: 'bg-red-50 text-red-800 ring-red-600/20',
  warning: 'bg-yellow-50 text-yellow-800 ring-yellow-600/20',
  info: 'bg-blue-50 text-blue-800 ring-blue-700/10',
};

function ToastItem({ toast: t, onDismiss }: { toast: Toast; onDismiss: () => void }) {
  const Icon = icons[t.type];

  useEffect(() => {
    const timer = setTimeout(onDismiss, 5000);
    return () => clearTimeout(timer);
  }, [onDismiss]);

  return (
    <div className={cn('flex items-center gap-3 rounded-lg p-4 shadow-lg ring-1 ring-inset', styles[t.type])}>
      <Icon className="h-5 w-5 shrink-0" />
      <p className="text-sm font-medium">{t.message}</p>
      <button onClick={onDismiss} className="ml-auto shrink-0 rounded p-1 hover:bg-black/5">
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}

export function ToastContainer() {
  const { toasts, removeToast } = useToastStore();

  const handleDismiss = useCallback(
    (id: string) => () => removeToast(id),
    [removeToast],
  );

  return (
    <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2">
      {toasts.map((t) => (
        <ToastItem key={t.id} toast={t} onDismiss={handleDismiss(t.id)} />
      ))}
    </div>
  );
}
