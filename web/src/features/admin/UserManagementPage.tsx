import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { UserPlus, MoreHorizontal } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Button, Card, Badge, Input, Dialog, Table, TableHead, TableBody, TableRow, TableHeader, TableCell } from '@/components/ui';
import { formatDate } from '@/lib/formatters';
import type { User, UserStatus } from '@/api';

// Mock data in the contract's shape; replaced by TanStack Query when the API exists. The contract's `User` has no
// display name or last sign-in time, so the page shows the email address and when the user was added.
const mockUsers: User[] = [
  { id: '1', email: 'admin@company.com', role: 'admin', status: 'active', sso_fallback: false, dlp_approver: true, created_at: '2026-10-01T00:00:00Z' },
  { id: '2', email: 'alice@company.com', role: 'member', status: 'active', sso_fallback: false, dlp_approver: false, created_at: '2026-10-15T00:00:00Z' },
  { id: '3', email: 'bob@company.com', role: 'member', status: 'deactivated', sso_fallback: false, dlp_approver: false, created_at: '2026-10-10T00:00:00Z' },
];

const statusBadge: Record<UserStatus, { variant: 'success' | 'default' | 'info'; labelKey: string }> = {
  active: { variant: 'success', labelKey: 'admin.active' },
  invited: { variant: 'info', labelKey: 'admin.invited' },
  deactivated: { variant: 'default', labelKey: 'admin.deactivated' },
};

export function UserManagementPage() {
  const { t } = useTranslation();
  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'admin' | 'member'>('member');

  return (
    <PageShell
      title={t('admin.userManagement')}
      actions={
        <Button onClick={() => setShowInvite(true)}>
          <UserPlus className="mr-2 h-4 w-4" />
          {t('admin.inviteUser')}
        </Button>
      }
    >
      <Card padding={false}>
        <Table label={t('admin.users')}>
          <TableHead>
            <tr>
              <TableHeader>{t('common.email')}</TableHeader>
              <TableHeader>{t('admin.role')}</TableHeader>
              <TableHeader>{t('common.status')}</TableHeader>
              <TableHeader>{t('admin.added')}</TableHeader>
              <TableHeader>{t('common.actions')}</TableHeader>
            </tr>
          </TableHead>
          <TableBody>
            {mockUsers.map((user) => (
              <TableRow key={user.id}>
                <TableCell><span className="font-medium text-gray-900">{user.email}</span></TableCell>
                <TableCell>
                  <Badge variant={user.role === 'admin' ? 'info' : 'default'}>
                    {user.role === 'admin' ? t('admin.roleAdmin') : t('admin.roleMember')}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge variant={statusBadge[user.status].variant}>{t(statusBadge[user.status].labelKey)}</Badge>
                </TableCell>
                <TableCell>{formatDate(user.created_at)}</TableCell>
                <TableCell>
                  <button aria-label={t('common.actions')} className="rounded-sm p-1 text-gray-500 hover:bg-gray-100 hover:text-gray-600">
                    <MoreHorizontal className="h-4 w-4" />
                  </button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>

      <Dialog open={showInvite} onClose={() => setShowInvite(false)} title={t('admin.inviteUser')}>
        <div className="space-y-4">
          <Input id="invite-email" label={t('admin.emailAddress')} type="email" placeholder={t('auth.emailPlaceholder')} value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} autoFocus />
          <div>
            <label htmlFor="invite-role" className="block text-sm font-medium text-gray-700">{t('admin.role')}</label>
            <select id="invite-role" className="input-field mt-1" value={inviteRole} onChange={(e) => setInviteRole(e.target.value as 'admin' | 'member')}>
              <option value="member">{t('admin.roleMember')}</option>
              <option value="admin">{t('admin.roleAdmin')}</option>
            </select>
          </div>
        </div>
        <div className="mt-6 flex justify-end gap-3">
          <Button variant="secondary" onClick={() => setShowInvite(false)}>{t('common.cancel')}</Button>
          <Button onClick={() => setShowInvite(false)} disabled={!inviteEmail}>{t('admin.inviteUser')}</Button>
        </div>
      </Dialog>
    </PageShell>
  );
}
