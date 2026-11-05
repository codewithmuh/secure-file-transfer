import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Key, Plus, Trash2 } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Button, Card, Badge, Table, TableHead, TableBody, TableRow, TableHeader, TableCell, Dialog, Input, EmptyState } from '@/components/ui';
import { formatDate } from '@/lib/formatters';
import type { ApiKey } from '@/api';

// Mock data in the contract's shape; replaced by TanStack Query when the API exists.
const mockKeys: ApiKey[] = [
  { id: '1', name: 'CI Pipeline', key_prefix: 'sft_k1_', scopes: ['transfers:write', 'transfers:read'], created_by: 'u1', created_at: '2026-10-01T00:00:00Z', expires_at: '2027-02-01T00:00:00Z', last_used_at: '2026-11-04T04:00:00Z', revoked_at: null },
  { id: '2', name: 'Audit Export', key_prefix: 'sft_k2_', scopes: ['audit:read'], created_by: 'u1', created_at: '2026-11-01T00:00:00Z', expires_at: '2027-01-01T00:00:00Z', last_used_at: null, revoked_at: null },
];

export function ApiKeysPage() {
  const { t } = useTranslation();
  const [showCreate, setShowCreate] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');

  return (
    <PageShell
      title={t('admin.apiKeys')}
      actions={<Button onClick={() => setShowCreate(true)}><Plus className="mr-2 h-4 w-4" />{t('admin.createApiKey')}</Button>}
    >
      <Card padding={false}>
        {mockKeys.length === 0 ? (
          <EmptyState icon={Key} title={t('admin.noApiKeys')} description={t('admin.noApiKeysHint')} action={<Button onClick={() => setShowCreate(true)}>{t('admin.createApiKey')}</Button>} />
        ) : (
          <Table label={t('admin.apiKeys')}>
            <TableHead>
              <tr>
                <TableHeader>{t('common.name')}</TableHeader>
                <TableHeader>{t('admin.keyPrefix')}</TableHeader>
                <TableHeader>{t('admin.scopes')}</TableHeader>
                <TableHeader>{t('common.expiresAt')}</TableHeader>
                <TableHeader>{t('admin.lastUsed')}</TableHeader>
                <TableHeader>{t('common.actions')}</TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {mockKeys.map((key) => (
                <TableRow key={key.id}>
                  <TableCell><span className="font-medium text-gray-900">{key.name}</span></TableCell>
                  <TableCell><code className="text-xs">{key.key_prefix}…</code></TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {key.scopes.map((scope) => (<Badge key={scope} variant="info">{scope}</Badge>))}
                    </div>
                  </TableCell>
                  <TableCell>{formatDate(key.expires_at)}</TableCell>
                  <TableCell>{key.last_used_at ? formatDate(key.last_used_at) : '—'}</TableCell>
                  <TableCell>
                    <button aria-label={t('common.delete')} className="rounded-sm p-1 text-red-600 hover:bg-red-50 hover:text-red-700">
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      <Dialog open={showCreate} onClose={() => setShowCreate(false)} title={t('admin.createApiKey')}>
        <div className="space-y-4">
          <Input id="api-key-name" label={t('common.name')} placeholder={t('admin.apiKeyNamePlaceholder')} value={newKeyName} onChange={(e) => setNewKeyName(e.target.value)} autoFocus />
          <p className="text-xs text-gray-500">{t('admin.apiKeyShownOnce')}</p>
        </div>
        <div className="mt-6 flex justify-end gap-3">
          <Button variant="secondary" onClick={() => setShowCreate(false)}>{t('common.cancel')}</Button>
          <Button onClick={() => setShowCreate(false)} disabled={!newKeyName}>{t('common.create')}</Button>
        </div>
      </Dialog>
    </PageShell>
  );
}
