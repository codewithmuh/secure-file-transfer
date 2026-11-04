import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { UserPlus, MoreHorizontal } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Button, Card, Badge, Input, Dialog, Table, TableHead, TableBody, TableRow, TableHeader, TableCell } from '@/components/ui';
import { formatDate } from '@/lib/formatters';
import type { TenantUser } from '@/types';

const mockUsers: TenantUser[] = [
  { id: '1', email: 'admin@company.com', name: 'Rashid', role: 'admin', status: 'active', last_sign_in_at: '2026-11-04T05:00:00Z', created_at: '2026-10-01T00:00:00Z' },
  { id: '2', email: 'alice@company.com', name: 'Alice', role: 'member', status: 'active', last_sign_in_at: '2026-11-03T12:00:00Z', created_at: '2026-10-15T00:00:00Z' },
  { id: '3', email: 'bob@company.com', name: 'Bob', role: 'member', status: 'deactivated', last_sign_in_at: '2026-10-20T08:00:00Z', created_at: '2026-10-10T00:00:00Z' },
];

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
        <Table>
          <TableHead>
            <tr>
              <TableHeader>Name</TableHeader>
              <TableHeader>Email</TableHeader>
              <TableHeader>{t('admin.role')}</TableHeader>
              <TableHeader>{t('common.status')}</TableHeader>
              <TableHeader>Last sign-in</TableHeader>
              <TableHeader>{t('common.actions')}</TableHeader>
            </tr>
          </TableHead>
          <TableBody>
            {mockUsers.map((user) => (
              <TableRow key={user.id}>
                <TableCell><span className="font-medium text-gray-900">{user.name}</span></TableCell>
                <TableCell>{user.email}</TableCell>
                <TableCell>
                  <Badge variant={user.role === 'admin' ? 'info' : 'default'}>
                    {user.role === 'admin' ? t('admin.roleAdmin') : t('admin.roleMember')}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge variant={user.status === 'active' ? 'success' : 'default'}>
                    {user.status === 'active' ? t('admin.active') : t('admin.deactivated')}
                  </Badge>
                </TableCell>
                <TableCell>{user.last_sign_in_at ? formatDate(user.last_sign_in_at) : '—'}</TableCell>
                <TableCell>
                  <button className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600">
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
          <Input label="Email address" type="email" placeholder="you@company.com" value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} autoFocus />
          <div>
            <label className="block text-sm font-medium text-gray-700">{t('admin.role')}</label>
            <select className="input-field mt-1" value={inviteRole} onChange={(e) => setInviteRole(e.target.value as 'admin' | 'member')}>
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
