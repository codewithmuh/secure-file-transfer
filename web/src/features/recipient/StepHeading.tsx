import { useEffect, useRef, type ReactNode } from 'react';

/**
 * A step's heading, the page's `h1`. It takes focus when the step appears, so a keyboard or screen reader user starts
 * at the new step instead of on a button that has gone (WCAG 2.4.3).
 */
export function StepHeading({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    ref.current?.focus();
  }, []);
  return (
    <h1 ref={ref} tabIndex={-1} className="mt-3 text-xl font-bold text-gray-900 focus:outline-none">
      {children}
    </h1>
  );
}
