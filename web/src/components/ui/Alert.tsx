import { cn } from '@/lib/cn';

export interface AlertProps {
  children: React.ReactNode;
  variant?: 'error' | 'warning' | 'info';
  className?: string;
  /** `alert` interrupts the screen reader; `status` waits its turn. Errors from an action the member just took alert. */
  role?: 'alert' | 'status';
}

const styles = {
  error: 'bg-red-50 text-red-800',
  warning: 'bg-yellow-50 text-yellow-800',
  info: 'bg-blue-50 text-blue-800',
};

/** A message in the page: an error from the API, a warning, or a note. */
export function Alert({ children, variant = 'error', className, role = 'alert' }: AlertProps) {
  return (
    <div role={role} className={cn('rounded-lg p-3 text-sm', styles[variant], className)}>
      {children}
    </div>
  );
}
