import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Dialog, toast } from '@/components/ui';
import type { ListScope } from '@/hooks/transfers';
import { errorMessage } from '@/lib/problems';
import { useAuthStore } from '@/stores/authStore';

/**
 * The admin's "all of the organization" switch on the transfer and upload request lists (#217; FR-20, UC-3): it lists
 * with `scope=tenant`, adds the owner column and a revoke action. Members don't see it: for them `scope=tenant` is
 * `403`. The role is the session's effective role, so a local admin without a passkey sign-in doesn't see it either.
 */
export function TenantScopeToggle({
  scope,
  onChange,
  label,
}: {
  scope: ListScope;
  onChange: (scope: ListScope) => void;
  label: string;
}) {
  const isAdmin = useAuthStore((state) => state.user?.role === 'admin');
  if (!isAdmin) return null;
  return (
    <label className="flex items-center gap-2 text-sm font-medium text-gray-700">
      <input
        type="checkbox"
        className="h-4 w-4 accent-brand-600"
        checked={scope === 'tenant'}
        onChange={(event) => onChange(event.target.checked ? 'tenant' : 'own')}
      />
      {label}
    </label>
  );
}

/**
 * Revoking another member's item from a tenant-wide list (FR-20). A `503` means the revocation stands but its record
 * isn't confirmed yet: the page says so and never that it failed; revoking again is always safe.
 */
export function RevokeFromList({
  label,
  title,
  body,
  revoke,
  invalidate,
}: {
  label: string;
  title: string;
  body: string;
  revoke: () => Promise<'revoked' | 'unconfirmed'>;
  invalidate: readonly unknown[];
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const close = () => {
    setError(null);
    setOpen(false);
  };

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      const outcome = await revoke();
      toast(outcome === 'revoked' ? 'success' : 'warning', t(outcome === 'revoked' ? 'tenantScope.revoked' : 'tenantScope.revokeUnconfirmed'));
      await queryClient.invalidateQueries({ queryKey: invalidate });
      close();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Button size="sm" variant="danger" onClick={() => setOpen(true)} aria-label={label}>
        {t('tenantScope.revoke')}
      </Button>
      <Dialog open={open} onClose={close} title={title}>
        <div className="space-y-4">
          <p className="text-sm text-gray-700">{body}</p>
          {error !== null && <Alert>{errorMessage(error, t)}</Alert>}
          <div className="flex justify-end gap-3">
            <Button variant="secondary" onClick={close} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button variant="danger" onClick={() => void confirm()} loading={busy}>
              {t('tenantScope.revoke')}
            </Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}
