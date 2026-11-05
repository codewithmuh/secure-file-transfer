import { cn } from '@/lib/cn';

interface TableProps {
  children: React.ReactNode;
  className?: string;
  /** The table's accessible name, translated: what a screen reader announces at the scroll region's tab stop. */
  label: string;
}

/**
 * A table in a horizontally scrollable region. The region is focusable so keyboard users can scroll a wide table
 * (WCAG 2.1.1), and `label` names it, so the tab stop is announced as, say, "Transfers, region" (WCAG 4.1.2).
 */
export function Table({ children, className, label }: TableProps) {
  return (
    <div className="overflow-x-auto" tabIndex={0} role="region" aria-label={label}>
      <table className={cn('min-w-full divide-y divide-gray-200', className)}>
        {children}
      </table>
    </div>
  );
}

export function TableHead({ children }: { children: React.ReactNode }) {
  return <thead className="bg-gray-50">{children}</thead>;
}

export function TableBody({ children }: { children: React.ReactNode }) {
  return <tbody className="divide-y divide-gray-200 bg-white">{children}</tbody>;
}

export function TableRow({ children, className, onClick }: { children: React.ReactNode; className?: string; onClick?: () => void }) {
  return (
    <tr
      className={cn(onClick && 'cursor-pointer hover:bg-gray-50', className)}
      onClick={onClick}
    >
      {children}
    </tr>
  );
}

export function TableHeader({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <th className={cn('px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500', className)}>
      {children}
    </th>
  );
}

export function TableCell({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <td className={cn('whitespace-nowrap px-4 py-3 text-sm text-gray-700', className)}>
      {children}
    </td>
  );
}
