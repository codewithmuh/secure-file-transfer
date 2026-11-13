import { useId, type SelectHTMLAttributes } from 'react';
import { cn } from '@/lib/cn';

export interface SelectOption {
  value: string;
  label: string;
}

export interface SelectProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'id' | 'children'> {
  label: string;
  /** The label for screen readers only, where a table's column header already names the select for sighted users. */
  hideLabel?: boolean;
  options: readonly SelectOption[];
  hint?: string;
  error?: string;
}

/**
 * A labelled select with a generated ID (#169), so two on one page never share an ID, and its hint or error tied to
 * it by `aria-describedby`. Every select of the app is one of these (`Select.test.tsx` checks the pages hold no other).
 */
export function Select({ label, hideLabel, options, hint, error, className, ...props }: SelectProps) {
  const id = useId();
  const described = error ? `${id}-error` : hint ? `${id}-hint` : undefined;
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className={hideLabel ? 'sr-only' : 'block text-sm font-medium text-gray-700'}>
        {label}
      </label>
      <select
        id={id}
        className={cn('input-field', error && 'ring-red-500', className)}
        aria-invalid={error ? true : undefined}
        aria-describedby={described}
        {...props}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {error ? (
        <p id={`${id}-error`} className="text-sm text-red-600">
          {error}
        </p>
      ) : hint ? (
        <p id={`${id}-hint`} className="text-sm text-gray-500">
          {hint}
        </p>
      ) : null}
    </div>
  );
}
