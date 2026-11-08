import { useCallback, useState } from 'react';

/**
 * One write behind a confirmation dialog: whether it is running and how the last try failed. `run` resolves `true`
 * when the write succeeded, so the dialog closes only then and keeps the error on the screen otherwise.
 */
export function useWrite() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const run = useCallback(async (write: () => Promise<unknown>): Promise<boolean> => {
    setBusy(true);
    setError(null);
    try {
      await write();
      return true;
    } catch (failure) {
      setError(failure);
      return false;
    } finally {
      setBusy(false);
    }
  }, []);

  const reset = useCallback(() => setError(null), []);
  return { busy, error, run, reset };
}
