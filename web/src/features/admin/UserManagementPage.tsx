import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { MoreHorizontal, UserPlus } from 'lucide-react';
import { PageShell } from '@/components/layout';
import {
  Alert,
  Badge,
  Button,
  Card,
  Dialog,
  Input,
  Menu,
  Select,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  toast,
  type MenuItem,
} from '@/components/ui';
import type { User } from '@/api';
import { adminKeys, useAllApiKeys } from '@/hooks/admin';
import { queryKeys } from '@/hooks/transfers';
import {
  deactivateUser,
  inviteUser,
  resetUserSignIn,
  signOutUser,
  updateUser,
  useUserList,
  type Role,
  type UserStatus,
} from '@/hooks/users';
import { formatDate } from '@/lib/formatters';
import { IdempotencyKeys, mayHaveHappened } from '@/lib/idempotency';
import { errorMessage, failureOf, fieldErrors, isAccessProblem, problemCode } from '@/lib/problems';
import { isPlainAddress } from '@/features/sender/limits';
import { AdminAccessNote } from './AdminAccessNote';
import { activeKeysOf } from './apiKeys';
import { userActions } from './userActions';

const statusVariant: Record<UserStatus, 'success' | 'default' | 'info'> = {
  active: 'success',
  invited: 'info',
  deactivated: 'default',
};

/** The actions that need the admin to confirm, each with its dialog. */
type Pending =
  | { kind: 'role'; user: User; role: Role }
  | { kind: 'deactivate'; user: User }
  | { kind: 'signOut'; user: User }
  | { kind: 'reset'; user: User }
  | { kind: 'resend'; user: User };

/**
 * The tenant's members and admins (#197; FR-22): the list with role and status filters, invitations, role and DLP
 * approver changes, a forced sign-out, a sign-in reset and deactivation, each from the row's action menu. A change that
 * ends the user's sessions asks first. `sso_fallback` is shown read-only: SSO arrives with M6. A DLP approver change is
 * emailed to every admin (#220), and the page says so.
 */
export function UserManagementPage() {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [role, setRole] = useState<Role | null>(null);
  const [status, setStatus] = useState<UserStatus | null>(null);
  const list = useUserList(role, status);
  const users = list.data?.pages.flatMap((page) => page.items) ?? [];
  const [inviting, setInviting] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);
  const [error, setError] = useState<unknown>(null);

  const refresh = () => queryClient.invalidateQueries({ queryKey: queryKeys.users });

  const setApprover = async (user: User, value: boolean) => {
    setError(null);
    try {
      await updateUser(user.id, { dlp_approver: value });
      toast('success', t(value ? 'admin.approverOn' : 'admin.approverOff', { email: user.email }));
      await refresh();
    } catch (failure) {
      setError(failure);
    }
  };

  const itemsFor = (user: User): MenuItem[] =>
    userActions(user).map((action): MenuItem => {
      switch (action) {
        case 'role':
          return user.role === 'admin'
            ? { key: 'member', label: t('admin.makeMember'), onSelect: () => setPending({ kind: 'role', user, role: 'member' }) }
            : { key: 'admin', label: t('admin.makeAdmin'), onSelect: () => setPending({ kind: 'role', user, role: 'admin' }) };
        case 'approver':
          return user.dlp_approver
            ? { key: 'approver-off', label: t('admin.removeApprover'), onSelect: () => void setApprover(user, false) }
            : {
                key: 'approver-on',
                label: t('admin.makeApprover'),
                onSelect: () => void setApprover(user, true),
                disabled: user.status !== 'active',
              };
        case 'signOut':
          return { key: 'sign-out', label: t('admin.signOutUser'), onSelect: () => setPending({ kind: 'signOut', user }) };
        case 'reset':
          return { key: 'reset', label: t('admin.resetSignIn'), onSelect: () => setPending({ kind: 'reset', user }) };
        case 'resend':
          return { key: 'resend', label: t('admin.resendInvitation'), onSelect: () => setPending({ kind: 'resend', user }) };
        case 'deactivate':
          return { key: 'deactivate', label: t('admin.deactivate'), danger: true, onSelect: () => setPending({ kind: 'deactivate', user }) };
      }
    });

  return (
    <PageShell
      title={t('admin.userManagement')}
      actions={
        <Button onClick={() => setInviting(true)}>
          <UserPlus className="mr-2 h-4 w-4" aria-hidden="true" />
          {t('admin.inviteUser')}
        </Button>
      }
    >
      <div className="flex flex-wrap gap-4">
        <div className="w-48">
          <Select
            label={t('admin.role')}
            value={role ?? ''}
            onChange={(event) => setRole((event.target.value || null) as Role | null)}
            options={[
              { value: '', label: t('admin.allRoles') },
              { value: 'admin', label: t('admin.roleAdmin') },
              { value: 'member', label: t('admin.roleMember') },
            ]}
          />
        </div>
        <div className="w-48">
          <Select
            label={t('common.status')}
            value={status ?? ''}
            onChange={(event) => setStatus((event.target.value || null) as UserStatus | null)}
            options={[
              { value: '', label: t('admin.allStatuses') },
              ...(['invited', 'active', 'deactivated'] as const).map((value) => ({ value, label: t(`admin.${value}`) })),
            ]}
          />
        </div>
      </div>

      <p className="text-sm text-gray-600">{t('admin.approverNote')}</p>

      {error !== null && (isAccessProblem(error) ? <AdminAccessNote error={error} /> : <Alert>{errorMessage(error, t)}</Alert>)}

      <Card padding={false}>
        {list.isPending ? (
          <div className="flex justify-center py-12">
            <Spinner />
            <span className="sr-only">{t('common.loading')}</span>
          </div>
        ) : list.isError ? (
          <div className="p-4">
            {isAccessProblem(list.error) ? <AdminAccessNote error={list.error} /> : <Alert>{errorMessage(list.error, t)}</Alert>}
          </div>
        ) : users.length === 0 ? (
          <p className="p-6 text-center text-sm text-gray-500">{t('common.noResults')}</p>
        ) : (
          <Table label={t('admin.users')}>
            <TableHead>
              <tr>
                <TableHeader>{t('common.email')}</TableHeader>
                <TableHeader>{t('admin.role')}</TableHeader>
                <TableHeader>{t('common.status')}</TableHeader>
                <TableHeader>{t('admin.dlpApprover')}</TableHeader>
                <TableHeader>{t('admin.ssoFallback')}</TableHeader>
                <TableHeader>{t('admin.added')}</TableHeader>
                <TableHeader>
                  <span className="sr-only">{t('common.actions')}</span>
                </TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {users.map((user) => {
                const items = itemsFor(user);
                return (
                  <TableRow key={user.id}>
                    <TableCell>
                      <span className="font-medium text-gray-900">{user.email}</span>
                    </TableCell>
                    <TableCell>
                      <Badge variant={user.role === 'admin' ? 'info' : 'default'}>
                        {user.role === 'admin' ? t('admin.roleAdmin') : t('admin.roleMember')}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={statusVariant[user.status]}>{t(`admin.${user.status}`)}</Badge>
                    </TableCell>
                    <TableCell>{user.dlp_approver ? t('common.yes') : t('common.no')}</TableCell>
                    <TableCell>{user.sso_fallback ? t('common.yes') : t('common.no')}</TableCell>
                    <TableCell>{formatDate(user.created_at, i18n.language)}</TableCell>
                    <TableCell>
                      {items.length > 0 && (
                        <Menu label={t('admin.actionsFor', { email: user.email })} items={items}>
                          <MoreHorizontal className="h-4 w-4" aria-hidden="true" />
                        </Menu>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>
      {list.hasNextPage && (
        <div className="flex justify-center">
          <Button variant="secondary" onClick={() => void list.fetchNextPage()} loading={list.isFetchingNextPage}>
            {t('common.loadMore')}
          </Button>
        </div>
      )}

      <InviteDialog open={inviting} onClose={() => setInviting(false)} onInvited={() => void refresh()} />
      <ConfirmDialog pending={pending} onClose={() => setPending(null)} onDone={() => void refresh()} />
    </PageShell>
  );
}

function InviteDialog({ open, onClose, onInvited }: { open: boolean; onClose: () => void; onInvited: () => void }) {
  const { t } = useTranslation();
  const keys = useRef(new IdempotencyKeys());
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<Role>('member');
  const [emailError, setEmailError] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const close = () => {
    setEmail('');
    setRole('member');
    setEmailError(null);
    setError(null);
    keys.current.reset();
    onClose();
  };

  const submit = async () => {
    setError(null);
    if (!isPlainAddress(email.trim())) {
      setEmailError(t('sender.recipientProblem.invalid'));
      return;
    }
    setBusy(true);
    try {
      const user = await inviteUser(email.trim(), role, keys.current.keyForBody('inviteUser', { email: email.trim(), role }));
      keys.current.done('inviteUser');
      toast('success', t('admin.inviteSent', { email: user.email }));
      onInvited();
      close();
    } catch (failure) {
      const code = problemCode(failure);
      if (code === 'user_exists') setEmailError(t('problems.user_exists'));
      else if (code === 'validation_failed' && fieldErrors(failureOf(failure)).email) setEmailError(t('sender.recipientProblem.invalid'));
      else setError(failure);
      // A lost answer or a server error keeps the key, so "Send invitation" again replays the first answer; a
      // definite refusal drops it.
      if (!mayHaveHappened(failure)) keys.current.done('inviteUser');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={close} title={t('admin.inviteUser')}>
      <form
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <Input
          id="invite-email"
          label={t('admin.emailAddress')}
          type="email"
          autoComplete="off"
          placeholder={t('auth.emailPlaceholder')}
          value={email}
          error={emailError ?? undefined}
          onChange={(event) => {
            setEmail(event.target.value);
            setEmailError(null);
          }}
        />
        <Select
          label={t('admin.role')}
          value={role}
          onChange={(event) => setRole(event.target.value as Role)}
          options={[
            { value: 'member', label: t('admin.roleMember') },
            { value: 'admin', label: t('admin.roleAdmin') },
          ]}
        />
        <p className="text-sm text-gray-600">{t('admin.inviteNote')}</p>
        {error !== null && (isAccessProblem(error) ? <AdminAccessNote error={error} /> : <Alert>{errorMessage(error, t)}</Alert>)}
        <div className="mt-6 flex justify-end gap-3">
          <Button type="button" variant="secondary" onClick={close}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" loading={busy} disabled={!email.trim()}>
            {t('admin.sendInvitation')}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

/** Deactivating or demoting an admin revokes the API keys they own (authn-authz 5.2), so the dialog lists them first. */
function revokesKeys(pending: Pending | null): boolean {
  if (!pending || pending.user.role !== 'admin') return false;
  return pending.kind === 'deactivate' || (pending.kind === 'role' && pending.role === 'member');
}

function ConfirmDialog({ pending, onClose, onDone }: { pending: Pending | null; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const listsKeys = revokesKeys(pending);
  const keys = useAllApiKeys(listsKeys);
  if (!pending) return null;
  const { user } = pending;

  const close = () => {
    setError(null);
    onClose();
  };

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      if (pending.kind === 'role') await updateUser(user.id, { role: pending.role });
      else if (pending.kind === 'deactivate') await deactivateUser(user.id);
      else if (pending.kind === 'signOut') await signOutUser(user.id);
      else await resetUserSignIn(user.id); // reset, or resend: the same operation (#197)
      toast('success', t(`admin.confirm.${pending.kind}.done`, { email: user.email }));
      if (listsKeys) void queryClient.invalidateQueries({ queryKey: adminKeys.apiKeys });
      onDone();
      close();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  const title = pending.kind === 'role' ? t(`admin.confirm.role.title_${pending.role}`) : t(`admin.confirm.${pending.kind}.title`);
  const body =
    pending.kind === 'role'
      ? t(`admin.confirm.role.body_${pending.role}`, { email: user.email })
      : t(`admin.confirm.${pending.kind}.body`, { email: user.email });
  const lastAdmin = problemCode(error) === 'last_admin';

  return (
    <Dialog open onClose={close} title={title}>
      <p className="text-sm text-gray-700">{body}</p>
      {listsKeys && <OwnedKeys userId={user.id} keys={keys} />}
      {error !== null && (
        <div className="mt-4">
          {isAccessProblem(error) ? (
            <AdminAccessNote error={error} />
          ) : (
            <Alert>{lastAdmin ? t('problems.last_admin') : errorMessage(error, t)}</Alert>
          )}
        </div>
      )}
      <div className="mt-6 flex justify-end gap-3">
        <Button variant="secondary" onClick={close}>
          {t('common.cancel')}
        </Button>
        <Button variant={pending.kind === 'deactivate' ? 'danger' : 'primary'} loading={busy} onClick={() => void confirm()}>
          {pending.kind === 'role' ? t(`admin.confirm.role.action_${pending.role}`) : t(`admin.confirm.${pending.kind}.action`)}
        </Button>
      </div>
    </Dialog>
  );
}

/** The API keys a user owns that still work, which the change revokes (authn-authz 5.2). */
function OwnedKeys({ userId, keys }: { userId: string; keys: ReturnType<typeof useAllApiKeys> }) {
  const { t, i18n } = useTranslation();
  if (keys.isPending) {
    return (
      <p className="mt-3 text-sm text-gray-600" role="status">
        {t('apiKeys.ownedLoading')}
      </p>
    );
  }
  // An admin acting as a member (no passkey) can't list keys: the confirmation still works, and says so.
  if (keys.isError) return <p className="mt-3 text-sm text-gray-600">{t('apiKeys.ownedUnknown')}</p>;
  const owned = activeKeysOf(keys.data, userId);
  if (owned.length === 0) return <p className="mt-3 text-sm text-gray-600">{t('admin.confirm.deactivate.noKeys')}</p>;
  return (
    <div className="mt-3 space-y-2">
      <p className="text-sm font-medium text-gray-800">{t('apiKeys.ownedRevoked', { count: owned.length })}</p>
      <ul className="list-disc space-y-1 pl-5 text-sm text-gray-700">
        {owned.map((key) => (
          <li key={key.id}>
            {key.name} (<code className="text-xs">{key.key_prefix}…</code>,{' '}
            {key.last_used_at
              ? t('apiKeys.lastUsedOn', { date: formatDate(key.last_used_at, i18n.language) })
              : t('apiKeys.neverUsed')}
            )
          </li>
        ))}
      </ul>
      <p className="text-sm text-gray-600">{t('apiKeys.ownedMove')}</p>
    </div>
  );
}
