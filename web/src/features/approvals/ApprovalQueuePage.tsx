import { useState } from 'react';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { ShieldCheck } from 'lucide-react';
import { PageShell } from '@/components/layout';
import {
  Alert,
  Badge,
  Button,
  Card,
  EmptyState,
  Select,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui';
import type { ApprovalState } from '@/api';
import { useApprovalRequests, type ApprovalScope } from '@/hooks/dlp';
import { formatDate } from '@/lib/formatters';
import { errorMessage } from '@/lib/problems';
import { useAuthStore } from '@/stores/authStore';
import { approvalScopes, approvalStateVariant, shortId } from './approvals';

const STATES: readonly ApprovalState[] = ['pending', 'approved', 'rejected', 'expired', 'withdrawn'];

/**
 * The approvals page (#220; FR-43, UC-7): an approver's queue of pending requests they may decide, never their own
 * transfers; an admin can also list every request in the tenant, by state. Each row opens the request's page.
 */
export function ApprovalQueuePage() {
  const { t, i18n } = useTranslation();
  const me = useAuthStore((state) => state.user);
  const scopes = approvalScopes(me);
  const [chosen, setChosen] = useState<ApprovalScope | null>(null);
  const scope = chosen && scopes.includes(chosen) ? chosen : (scopes[0] ?? null);
  const [state, setState] = useState<ApprovalState | null>(null);
  const list = useApprovalRequests(scope ?? 'queue', scope === 'tenant' ? state : 'pending', scope !== null);
  const items = list.data?.pages.flatMap((page) => page.items) ?? [];
  const date = (value: string) => formatDate(value, i18n.language);
  const person = (id: string) => (id === me?.id ? t('approvals.you') : t('approvals.person', { id: shortId(id) }));

  return (
    <PageShell title={t('approvals.title')} description={t('approvals.description')}>
      {scope === null ? (
        <Alert variant="info" role="status">
          {t('approvals.notApprover')}
        </Alert>
      ) : (
        <>
          {scopes.length > 1 && (
            <div className="flex flex-wrap gap-4">
              <div className="w-56">
                <Select
                  label={t('approvals.show')}
                  value={scope}
                  onChange={(event) => setChosen(event.target.value as ApprovalScope)}
                  options={scopes.map((value) => ({ value, label: t(`approvals.scope.${value}`) }))}
                />
              </div>
              {scope === 'tenant' && (
                <div className="w-48">
                  <Select
                    label={t('common.status')}
                    value={state ?? ''}
                    onChange={(event) => setState((event.target.value || null) as ApprovalState | null)}
                    options={[
                      { value: '', label: t('approvals.allStates') },
                      ...STATES.map((value) => ({ value, label: t(`approvalState.${value}`) })),
                    ]}
                  />
                </div>
              )}
            </div>
          )}

          <Card padding={false}>
            {list.isPending ? (
              <div className="flex justify-center py-12">
                <Spinner />
                <span className="sr-only">{t('common.loading')}</span>
              </div>
            ) : list.isError ? (
              <div className="p-4">
                <Alert>{errorMessage(list.error, t)}</Alert>
              </div>
            ) : items.length === 0 ? (
              <EmptyState icon={ShieldCheck} title={t(scope === 'queue' ? 'approvals.emptyQueue' : 'approvals.empty')} />
            ) : (
              <Table label={t('approvals.title')} caption={t(`approvals.caption.${scope}`)}>
                <TableHead>
                  <tr>
                    <TableHeader>{t('approvals.requestedAt')}</TableHeader>
                    <TableHeader>{t('approvals.sender')}</TableHeader>
                    <TableHeader>{t('approvals.rules')}</TableHeader>
                    <TableHeader>{t('approvals.approvals')}</TableHeader>
                    <TableHeader>{t('approvals.expiresAt')}</TableHeader>
                    <TableHeader>{t('common.status')}</TableHeader>
                  </tr>
                </TableHead>
                <TableBody>
                  {items.map((request) => (
                    <TableRow key={request.id}>
                      <th scope="row" className="whitespace-nowrap px-4 py-3 text-left text-sm font-medium">
                        <Link
                          to={`/approvals/${request.id}`}
                          className="text-brand-700 underline hover:text-brand-800"
                          aria-label={t('approvals.openRequest', { date: date(request.requested_at) })}
                        >
                          {date(request.requested_at)}
                        </Link>
                      </th>
                      <TableCell>{person(request.requested_by)}</TableCell>
                      <TableCell className="whitespace-normal">{request.rule_names.join(t('common.listSeparator'))}</TableCell>
                      <TableCell>{t('approvals.approvalsOf', { approvals: request.approvals, required: request.approvals_required })}</TableCell>
                      <TableCell>{date(request.expires_at)}</TableCell>
                      <TableCell>
                        <Badge variant={approvalStateVariant[request.state]}>{t(`approvalState.${request.state}`)}</Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Card>

          {list.hasNextPage && (
            <div className="flex justify-center">
              <Button variant="secondary" loading={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
                {t('common.loadMore')}
              </Button>
            </div>
          )}
        </>
      )}
    </PageShell>
  );
}
