import { useState } from 'react';
import { useSearchParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import { ChevronLeft, ChevronRight, Download, FileText, Search } from 'lucide-react';
import { PageShell } from '@/components/layout';
import {
  Alert,
  Badge,
  Button,
  Card,
  CardTitle,
  Dialog,
  EmptyState,
  Input,
  Select,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  toast,
} from '@/components/ui';
import type { ActorType, AuditEvent } from '@/api';
import { AdminAccessNote } from '@/features/admin/AdminAccessNote';
import { exportAuditEvents, saveExport, useAuditSearch } from '@/hooks/admin';
import { formatDate } from '@/lib/formatters';
import { errorMessage, isAccessProblem, problemCode } from '@/lib/problems';
import {
  ACTOR_TYPES,
  detailRows,
  EMPTY_FILTER,
  filterBody,
  filterProblems,
  formFromSearch,
  KNOWN_ACTIONS,
  MAX_ACTIONS,
  toggleAction,
  type ActionGroup,
  type AuditFilter,
  type ExportFormat,
  type FilterField,
  type FilterForm,
} from './auditFilter';

const PAGE_SIZE = 25;

const actorLabelKey: Record<ActorType, string> = {
  member: 'audit.actorMember',
  admin: 'audit.actorAdmin',
  recipient: 'audit.actorRecipient',
  uploader: 'audit.actorUploader',
  api_key: 'audit.actorApiKey',
  operator: 'audit.actorOperator',
  system: 'audit.actorSystem',
};

/**
 * The tenant's audit log (#216; FR-27, FR-28, FR-29, UC-4): a filter form, the results newest first with cursor paging,
 * an event's details in a dialog, and CSV and JSON exports. Every filter, the email and IP address included, travels
 * in the POST body of `searchAuditEvents` and `exportAuditEvents`, never in this page's address (T-47). Searching
 * needs the admin role; exporting also a sign-in in the last 15 minutes (`AdminAccessNote`). A link may start the page
 * with actions and a time range (`formFromSearch`), as the DLP report's "export with the audit log" does (#222): the
 * search runs with them, ready to export.
 */
export function AuditLogPage() {
  const { t } = useTranslation();
  const [searchParams] = useSearchParams();
  const [initial] = useState(() => {
    const linked = formFromSearch(searchParams);
    return linked && filterProblems(linked).length === 0 ? linked : null;
  });
  const [form, setForm] = useState<FilterForm>(initial ?? EMPTY_FILTER);
  const [touched, setTouched] = useState(false);
  /** The filter of the search shown: set when the admin searches, so typing doesn't search on every key. */
  const [filter, setFilter] = useState<AuditFilter | undefined>(() => (initial ? filterBody(initial) : undefined));
  /** The cursors of the pages before the one shown, and the one shown (`null` for the first page). */
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const cursor = cursors[cursors.length - 1] ?? null;
  const search = useAuditSearch(filter, cursor, PAGE_SIZE, true);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [exporting, setExporting] = useState<ExportFormat | null>(null);
  const [exportError, setExportError] = useState<unknown>(null);
  const problems = filterProblems(form);

  const submit = () => {
    setTouched(true);
    if (problems.length > 0) return;
    setFilter(filterBody(form));
    setCursors([null]);
  };

  const reset = () => {
    setForm(EMPTY_FILTER);
    setTouched(false);
    setFilter(undefined);
    setCursors([null]);
  };

  const runExport = async (format: ExportFormat) => {
    setExporting(format);
    setExportError(null);
    try {
      const file = await exportAuditEvents(filter, format);
      saveExport(file);
      toast('success', t('audit.exported', { name: file.fileName }));
    } catch (failure) {
      setExportError(failure);
    } finally {
      setExporting(null);
    }
  };

  const fieldError = (field: FilterField) => (touched && problems.includes(field) ? t(`audit.invalid.${field}`) : undefined);
  const set = <K extends keyof FilterForm>(key: K, value: FilterForm[K]) => setForm((previous) => ({ ...previous, [key]: value }));
  const items = search.data?.items ?? [];
  const nextCursor = search.data?.next_cursor ?? null;

  return (
    <PageShell
      title={t('audit.title')}
      actions={
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" loading={exporting === 'csv'} disabled={exporting !== null} onClick={() => void runExport('csv')}>
            <Download className="mr-2 h-4 w-4" aria-hidden="true" />
            {t('audit.exportCsv')}
          </Button>
          <Button variant="secondary" loading={exporting === 'json'} disabled={exporting !== null} onClick={() => void runExport('json')}>
            <Download className="mr-2 h-4 w-4" aria-hidden="true" />
            {t('audit.exportJson')}
          </Button>
        </div>
      }
    >
      {exportError !== null && (
        isAccessProblem(exportError) ? (
          <AdminAccessNote error={exportError} />
        ) : (
          <Alert>
            {problemCode(exportError) === 'export_too_large' ? t('audit.exportTooLarge') : errorMessage(exportError, t)}
          </Alert>
        )
      )}

      <Card>
        <CardTitle>{t('audit.filters')}</CardTitle>
        <form
          className="mt-4 space-y-4"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            submit();
          }}
        >
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Input
              id="audit-from"
              type="datetime-local"
              label={t('audit.from')}
              value={form.from}
              onChange={(event) => set('from', event.target.value)}
              error={fieldError('from')}
            />
            <Input
              id="audit-to"
              type="datetime-local"
              label={t('audit.to')}
              value={form.to}
              onChange={(event) => set('to', event.target.value)}
              error={fieldError('to')}
            />
            <Select
              label={t('audit.actorType')}
              value={form.actorType}
              onChange={(event) => set('actorType', event.target.value as FilterForm['actorType'])}
              options={[
                { value: '', label: t('audit.anyActor') },
                ...ACTOR_TYPES.map((value) => ({ value, label: t(actorLabelKey[value]) })),
              ]}
            />
            <Input
              id="audit-email"
              type="email"
              autoComplete="off"
              label={t('audit.email')}
              helperText={t('audit.emailHint')}
              value={form.email}
              onChange={(event) => set('email', event.target.value)}
              error={fieldError('email')}
            />
            <Input
              id="audit-actor-id"
              label={t('audit.actorId')}
              autoComplete="off"
              spellCheck={false}
              value={form.actorId}
              onChange={(event) => set('actorId', event.target.value)}
              error={fieldError('actorId')}
            />
            <Input
              id="audit-ip"
              label={t('audit.ipAddress')}
              autoComplete="off"
              spellCheck={false}
              value={form.sourceIp}
              onChange={(event) => set('sourceIp', event.target.value)}
              error={fieldError('sourceIp')}
            />
            <Input
              id="audit-target-type"
              label={t('audit.targetType')}
              placeholder="transfer"
              autoComplete="off"
              spellCheck={false}
              value={form.targetType}
              onChange={(event) => set('targetType', event.target.value)}
              error={fieldError('targetType')}
            />
            <Input
              id="audit-target-id"
              label={t('audit.targetId')}
              autoComplete="off"
              spellCheck={false}
              value={form.targetId}
              onChange={(event) => set('targetId', event.target.value)}
              error={fieldError('targetId')}
            />
          </div>

          <details className="rounded-lg border border-gray-200 p-3">
            <summary className="cursor-pointer text-sm font-medium text-gray-700">
              {t('audit.actions', { count: form.actions.length })}
            </summary>
            <fieldset className="mt-3" aria-describedby={fieldError('actions') ? 'audit-actions-error' : undefined}>
              <legend className="sr-only">{t('audit.actionsLegend', { max: MAX_ACTIONS })}</legend>
              <div className="grid gap-x-8 gap-y-4 sm:grid-cols-2">
                {(Object.keys(KNOWN_ACTIONS) as ActionGroup[]).map((group) => (
                  <div key={group}>
                    <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">{t(`audit.group.${group}`)}</p>
                    <div className="mt-2 space-y-2">
                      {KNOWN_ACTIONS[group].map((action) => (
                        <label key={action} className="flex items-center gap-2 text-sm text-gray-800">
                          <input
                            type="checkbox"
                            className="h-5 w-5 shrink-0 accent-brand-600"
                            checked={form.actions.includes(action)}
                            onChange={() => set('actions', toggleAction(form.actions, action))}
                          />
                          <code className="break-all text-xs">{action}</code>
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              {fieldError('actions') && (
                <p id="audit-actions-error" className="mt-2 text-sm text-red-600">
                  {fieldError('actions')}
                </p>
              )}
            </fieldset>
          </details>

          <div className="flex flex-wrap gap-3">
            <Button type="submit" loading={search.isFetching && touched}>
              <Search className="mr-2 h-4 w-4" aria-hidden="true" />
              {t('common.search')}
            </Button>
            <Button type="button" variant="secondary" onClick={reset}>
              {t('audit.clearFilters')}
            </Button>
          </div>
        </form>
      </Card>

      <Card padding={false}>
        {search.isPending ? (
          <div className="flex justify-center py-12">
            <Spinner />
            <span className="sr-only">{t('common.loading')}</span>
          </div>
        ) : search.isError ? (
          <div className="p-4">
            {isAccessProblem(search.error) ? (
              <AdminAccessNote error={search.error} />
            ) : (
              <Alert>{problemCode(search.error) === 'invalid_cursor' ? t('audit.cursorExpired') : errorMessage(search.error, t)}</Alert>
            )}
          </div>
        ) : items.length === 0 ? (
          <EmptyState icon={FileText} title={t('common.noResults')} description={t('audit.noEvents')} />
        ) : (
          <Table label={t('audit.title')} caption={t('audit.caption')}>
            <TableHead>
              <tr>
                <TableHeader>{t('audit.timestamp')}</TableHeader>
                <TableHeader>{t('audit.action')}</TableHeader>
                <TableHeader>{t('audit.actor')}</TableHeader>
                <TableHeader>{t('audit.target')}</TableHeader>
                <TableHeader>{t('audit.ipAddress')}</TableHeader>
                <TableHeader>
                  <span className="sr-only">{t('common.details')}</span>
                </TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {items.map((event) => (
                <EventRow key={event.id} event={event} onOpen={() => setSelected(event)} />
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      {(cursors.length > 1 || nextCursor) && (
        <nav className="flex items-center justify-between" aria-label={t('audit.paging')}>
          <Button
            variant="secondary"
            disabled={cursors.length <= 1 || search.isFetching}
            onClick={() => setCursors((previous) => previous.slice(0, -1))}
          >
            <ChevronLeft className="mr-1 h-4 w-4" aria-hidden="true" />
            {t('audit.newer')}
          </Button>
          <span className="text-sm text-gray-600">{t('audit.page', { page: cursors.length })}</span>
          <Button
            variant="secondary"
            disabled={!nextCursor || search.isFetching}
            onClick={() => nextCursor && setCursors((previous) => [...previous, nextCursor])}
          >
            {t('audit.older')}
            <ChevronRight className="ml-1 h-4 w-4" aria-hidden="true" />
          </Button>
        </nav>
      )}

      <EventDetails event={selected} onClose={() => setSelected(null)} />
    </PageShell>
  );
}

function EventRow({ event, onOpen }: { event: AuditEvent; onOpen: () => void }) {
  const { t, i18n } = useTranslation();
  return (
    <TableRow>
      <TableCell className="whitespace-nowrap">{formatDate(event.occurred_at, i18n.language)}</TableCell>
      <TableCell>
        <Badge variant={event.security_critical ? 'warning' : 'default'}>{event.action}</Badge>
      </TableCell>
      <TableCell>
        <p className="text-sm font-medium">{event.actor_email ?? event.actor_id ?? '—'}</p>
        <p className="text-xs text-gray-600">{t(actorLabelKey[event.actor_type])}</p>
      </TableCell>
      <TableCell>
        {event.target_type ? (
          <span className="text-xs text-gray-600">
            {event.target_type}
            {event.target_id ? `: ${event.target_id}` : ''}
          </span>
        ) : (
          '—'
        )}
      </TableCell>
      <TableCell>
        <code className="text-xs">{event.source_ip ?? '—'}</code>
      </TableCell>
      <TableCell>
        <Button
          size="sm"
          variant="secondary"
          onClick={onOpen}
          aria-label={t('audit.openEvent', { action: event.action, date: formatDate(event.occurred_at, i18n.language) })}
        >
          {t('common.details')}
        </Button>
      </TableCell>
    </TableRow>
  );
}

/** One event, every field, with `details` as key and value rows. */
function EventDetails({ event, onClose }: { event: AuditEvent | null; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  if (!event) return null;
  const rows: [string, string][] = [
    [t('audit.timestamp'), formatDate(event.occurred_at, i18n.language)],
    [t('audit.action'), event.action],
    [t('audit.actorType'), t(actorLabelKey[event.actor_type])],
    [t('audit.actorId'), event.actor_id ?? '—'],
    [t('audit.actorEmail'), event.actor_email ?? '—'],
    [t('audit.targetType'), event.target_type ?? '—'],
    [t('audit.targetId'), event.target_id ?? '—'],
    [t('audit.ipAddress'), event.source_ip ?? '—'],
    [t('audit.userAgent'), event.user_agent ?? '—'],
    [t('audit.requestId'), event.request_id ?? '—'],
    [t('audit.securityCritical'), event.security_critical ? t('common.yes') : t('common.no')],
  ];
  const details = detailRows(event.details);
  return (
    <Dialog open onClose={onClose} title={t('audit.eventTitle')} className="max-w-2xl">
      <div className="max-h-[70vh] space-y-4 overflow-y-auto">
        <dl className="grid grid-cols-1 gap-x-4 gap-y-2 text-sm sm:grid-cols-3">
          {rows.map(([label, value]) => (
            <div key={label} className="contents">
              <dt className="font-medium text-gray-600">{label}</dt>
              <dd className="break-all text-gray-900 sm:col-span-2">{value}</dd>
            </div>
          ))}
        </dl>
        <div>
          <h3 className="text-sm font-semibold text-gray-900">{t('audit.details')}</h3>
          {details.length === 0 ? (
            <p className="mt-1 text-sm text-gray-600">{t('audit.noDetails')}</p>
          ) : (
            <dl className="mt-2 grid grid-cols-1 gap-x-4 gap-y-2 text-sm sm:grid-cols-3">
              {details.map(([key, value]) => (
                <div key={key} className="contents">
                  <dt className="font-mono text-xs text-gray-600">{key}</dt>
                  <dd className="break-all font-mono text-xs text-gray-900 sm:col-span-2">{value}</dd>
                </div>
              ))}
            </dl>
          )}
        </div>
        <div className="flex justify-end">
          <Button variant="secondary" onClick={onClose}>
            {t('common.close')}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
