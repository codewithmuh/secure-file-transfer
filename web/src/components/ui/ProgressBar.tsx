import { cn } from '@/lib/cn';

export interface ProgressBarProps {
  /** The bar's accessible name, translated: what a screen reader announces with its value. */
  label: string;
  value: number;
  max: number;
  /** The value as text, such as "12.3 MB of 40 MB", read instead of a bare percentage. */
  valueText?: string;
  className?: string;
}

/** A progress bar with a name and a value (WCAG 4.1.2), for uploads (#196). */
export function ProgressBar({ label, value, max, valueText, className }: ProgressBarProps) {
  const percent = max > 0 ? Math.min(100, Math.round((value / max) * 100)) : 0;
  return (
    <div
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={percent}
      aria-valuetext={valueText}
      className={cn('h-2 w-full overflow-hidden rounded-full bg-gray-200', className)}
    >
      <div className="h-full rounded-full bg-brand-600 transition-[width]" style={{ width: `${percent}%` }} />
    </div>
  );
}
