import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Search, Download, FileText } from 'lucide-react';
import { PageShell } from '@/components/layout';
import { Button, Card, Input, Badge, Table, TableHead, TableBody, TableRow, TableHeader, TableCell, EmptyState } from '@/components/ui';
import { formatDate } from '@/lib/formatters';
import type { AuditEvent } from '@/api';

// Mock data in the contract's shape; replaced by TanStack Query when the API exists.
const mockEvents: AuditEvent[] = [
  { id: '1', occurred_at: '2026-11-04T06:00:00Z', actor_type: 'member', actor_id: 'u_2', actor_email: 'rashid@company.com', action: 'transfer.created', target_type: 'transfer', target_id: 'tr_1', source_ip: '203.0.113.1', user_agent: 'Chrome/120', request_id: 'req_1', security_critical: false, details: {} },
  { id: '2', occurred_at: '2026-11-04T06:01:00Z', actor_type: 'member', actor_id: 'u_2', actor_email: 'rashid@company.com', action: 'transfer.sent', target_type: 'transfer', target_id: 'tr_1', source_ip: '203.0.113.1', user_agent: 'Chrome/120', request_id: 'req_2', security_critical: false, details: {} },
  { id: '3', occurred_at: '2026-11-04T07:00:00Z', actor_type: 'recipient', actor_id: 'r_1', actor_email: 'alice@example.com', action: 'link.verified', target_type: 'transfer', target_id: 'tr_1', source_ip: '198.51.100.5', user_agent: 'Firefox/121', request_id: 'req_3', security_critical: false, details: {} },
  { id: '4', occurred_at: '2026-11-04T07:05:00Z', actor_type: 'recipient', actor_id: 'r_1', actor_email: 'alice@example.com', action: 'file.downloaded', target_type: 'file', target_id: 'f_1', source_ip: '198.51.100.5', user_agent: 'Firefox/121', request_id: 'req_4', security_critical: true, details: {} },
  { id: '5', occurred_at: '2026-11-04T05:00:00Z', actor_type: 'member', actor_id: 'u_1', actor_email: 'admin@company.com', action: 'member.sign_in', target_type: 'user', target_id: 'u_1', source_ip: '192.0.2.10', user_agent: 'Chrome/120', request_id: 'req_5', security_critical: false, details: {} },
];

const actionBadge: Record<string, { variant: 'success' | 'info' | 'warning' | 'danger' | 'default'; label: string }> = {
  'transfer.created': { variant: 'info', label: 'Transfer Created' },
  'transfer.sent': { variant: 'success', label: 'Transfer Sent' },
  'transfer.revoked': { variant: 'danger', label: 'Transfer Revoked' },
  'link.verified': { variant: 'success', label: 'Link Verified' },
  'file.downloaded': { variant: 'info', label: 'File Downloaded' },
  'member.sign_in': { variant: 'default', label: 'Sign In' },
};

export function AuditLogPage() {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');

  const filtered = mockEvents.filter(
    (event) =>
      event.action.includes(search.toLowerCase()) ||
      event.actor_email?.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <PageShell
      title={t('audit.title')}
      actions={
        <div className="flex gap-2">
          <Button variant="secondary"><Download className="mr-2 h-4 w-4" />{t('audit.exportCsv')}</Button>
          <Button variant="secondary"><Download className="mr-2 h-4 w-4" />{t('audit.exportJson')}</Button>
        </div>
      }
    >
      <Card padding={false}>
        <div className="border-b border-gray-200 p-4">
          <div className="relative max-w-sm">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
            <Input placeholder={t('audit.searchPlaceholder')} value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" />
          </div>
        </div>
        {filtered.length === 0 ? (
          <EmptyState icon={FileText} title={t('common.noResults')} />
        ) : (
          <Table>
            <TableHead>
              <tr>
                <TableHeader>{t('audit.timestamp')}</TableHeader>
                <TableHeader>{t('audit.action')}</TableHeader>
                <TableHeader>{t('audit.actor')}</TableHeader>
                <TableHeader>{t('audit.target')}</TableHeader>
                <TableHeader>{t('audit.ipAddress')}</TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {filtered.map((event) => {
                const badge = actionBadge[event.action] ?? { variant: 'default' as const, label: event.action };
                return (
                  <TableRow key={event.id}>
                    <TableCell className="whitespace-nowrap">{formatDate(event.occurred_at)}</TableCell>
                    <TableCell><Badge variant={badge.variant}>{badge.label}</Badge></TableCell>
                    <TableCell>
                      <div>
                        <p className="text-sm font-medium">{event.actor_email ?? '—'}</p>
                        <p className="text-xs text-gray-400">{event.actor_type}</p>
                      </div>
                    </TableCell>
                    <TableCell>
                      {event.target_type && <span className="text-xs text-gray-500">{event.target_type}:{event.target_id}</span>}
                    </TableCell>
                    <TableCell><code className="text-xs">{event.source_ip ?? '—'}</code></TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>
    </PageShell>
  );
}
