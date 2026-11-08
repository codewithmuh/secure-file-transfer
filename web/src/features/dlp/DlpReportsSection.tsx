import { useId, useMemo, useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Download } from 'lucide-react';
import {
  Badge,
  Button,
  Card,
  CardTitle,
  Input,
  Select,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui';
import type { DlpOutcome } from '@/api';
import { useUserEmails } from '@/hooks/admin';
import {
  useDlpDecisions,
  useDlpDetectors,
  useDlpReport,
  useDlpRules,
  type DlpDecision,
  type DlpRange,
  type DlpReport,
} from '@/hooks/dlp';
import { auditLink } from '@/features/audit/auditFilter';
import { shortId } from '@/features/approvals/approvals';
import { dlpActionVariant, type BadgeVariant } from '@/features/sender/states';
import { formatDate } from '@/lib/formatters';
import { errorMessage } from '@/lib/problems';
import { cn } from '@/lib/cn';
import { LoadError, Loading } from './DlpAdminPage';
import {
  barPercent,
  countRows,
  dailySeries,
  DEFAULT_RANGE_DAYS,
  localDay,
  medianParts,
  OUTCOMES,
  outcomeTotals,
  presetRange,
  RANGE_MAX_DAYS,
  RANGE_PRESETS,
  rangeDays,
  rangeProblem,
  rangeQuery,
  type CountRow,
  type DayRange,
  type DaySeries,
} from './reports';
import { detectorName } from './ruleText';

/** Each outcome's colour in the charts; the label is always text too (the legend, the table view; WCAG 1.4.1). */
const OUTCOME_FILL: Record<DlpOutcome, string> = {
  none: 'fill-gray-300',
  allow_and_record: 'fill-sky-500',
  warn: 'fill-amber-400',
  require_approval: 'fill-orange-600',
  block: 'fill-red-700',
};
const OUTCOME_SWATCH: Record<DlpOutcome, string> = {
  none: 'bg-gray-300',
  allow_and_record: 'bg-sky-500',
  warn: 'bg-amber-400',
  require_approval: 'bg-orange-600',
  block: 'bg-red-700',
};
const outcomeVariant = (outcome: DlpOutcome): BadgeVariant => (outcome === 'none' ? 'default' : dlpActionVariant[outcome]);

/** The names a report's IDs stand for: rules, detectors and people, each falling back to a short ID. */
interface Names {
  rule: (id: string) => string;
  detector: (id: string) => string;
  person: (id: string) => string;
}

/**
 * The DLP report (#222; FR-55, UC-4), for admins: a range of at most 92 days (presets of 7, 30 and 90), decisions by
 * outcome over time, matches by rule and by detector (each chart with a text alternative and a table view), the
 * senders, recipient domains and approvers with their decisions, files not fully inspected by reason, the policy
 * changes, and the decisions themselves with filters and "load more". The decisions are audit records, so "export with
 * the audit log" opens the audit log filtered to `dlp.decided` over the same range, where CSV and JSON exports are.
 * Each report read is audited (`dlp.report_viewed`), so it loads when the range is applied, not as it is typed.
 */
export function DlpReportsSection() {
  const { t, i18n } = useTranslation();
  const [days, setDays] = useState<DayRange>(() => presetRange(DEFAULT_RANGE_DAYS, new Date()));
  const [applied, setApplied] = useState<{ days: DayRange; range: DlpRange } | null>(() => {
    const range = rangeQuery(days, Date.now());
    return range && { days, range };
  });
  const [shown, setShown] = useState(false);
  const problem = rangeProblem(days);
  const today = localDay(new Date());
  const report = useDlpReport(applied?.range ?? null);
  const rules = useDlpRules();
  const detectors = useDlpDetectors();
  const emails = useUserEmails(true);

  const names: Names = useMemo(
    () => ({
      rule: (id) => rules.data?.items.find((rule) => rule.id === id)?.name ?? t('dlpReports.retiredRule', { id: shortId(id) }),
      detector: (id) => {
        const found = detectors.data?.items.some((detector) => detector.id === id);
        if (!found && id.startsWith('custom:')) return t('dlpReports.deletedDetector', { id: shortId(id.slice('custom:'.length)) });
        return detectorName(id, detectors.data?.items, t);
      },
      person: (id) => emails.data?.get(id) ?? t('approvals.person', { id: shortId(id) }),
    }),
    [rules.data, detectors.data, emails.data, t],
  );

  const apply = (next: DayRange) => {
    setShown(true);
    const range = rangeQuery(next, Date.now());
    if (range) setApplied({ days: next, range });
  };
  const choosePreset = (count: number) => {
    const next = presetRange(count, new Date());
    setDays(next);
    setShown(false);
    apply(next);
  };
  const rangeError = shown && problem ? t(`dlpReports.rangeProblem.${problem}`, { max: RANGE_MAX_DAYS }) : undefined;
  const appliedCount = applied ? rangeDays(applied.days) : null;

  return (
    <div className="space-y-6">
      <Card>
        <CardTitle>{t('dlpReports.range')}</CardTitle>
        <form
          className="mt-4 space-y-4"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            apply(days);
          }}
        >
          <div className="flex flex-wrap gap-2" role="group" aria-label={t('dlpReports.presets')}>
            {RANGE_PRESETS.map((count) => {
              const preset = presetRange(count, new Date());
              const current = applied?.days.from === preset.from && applied.days.to === preset.to;
              return (
                <Button key={count} type="button" size="sm" variant={current ? 'primary' : 'secondary'} aria-pressed={current} onClick={() => choosePreset(count)}>
                  {t('dlpReports.lastDays', { count })}
                </Button>
              );
            })}
          </div>
          <div className="grid gap-4 sm:grid-cols-[1fr_1fr_auto] sm:items-start">
            <Input
              id="dlp-report-from"
              type="date"
              label={t('dlpReports.from')}
              value={days.from}
              max={today}
              onChange={(event) => setDays((previous) => ({ ...previous, from: event.target.value }))}
              error={rangeError}
            />
            <Input
              id="dlp-report-to"
              type="date"
              label={t('dlpReports.to')}
              value={days.to}
              max={today}
              onChange={(event) => setDays((previous) => ({ ...previous, to: event.target.value }))}
              helperText={t('dlpReports.rangeHint', { max: RANGE_MAX_DAYS })}
            />
            <Button type="submit" className="sm:mt-7">
              {t('dlpReports.apply')}
            </Button>
          </div>
        </form>
        {applied && (
          <p className="mt-4 text-sm text-gray-700" aria-live="polite">
            {t('dlpReports.showing', {
              from: formatDay(applied.days.from, i18n.language),
              to: formatDay(applied.days.to, i18n.language),
              count: appliedCount ?? 0,
            })}
          </p>
        )}
      </Card>

      {applied &&
        (report.isPending ? (
          <Loading />
        ) : report.isError ? (
          <LoadError error={report.error} />
        ) : (
          <ReportView report={report.data} range={applied.range} names={names} />
        ))}

      {applied && <DecisionsList range={applied.range} names={names} />}
    </div>
  );
}

/** A `YYYY-MM-DD` day in the page's language. */
function formatDay(day: string, language: string): string {
  const [year, month, date] = day.split('-').map(Number) as [number, number, number];
  return new Intl.DateTimeFormat(language, { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(year, month - 1, date));
}

function ReportView({ report, range, names }: { report: DlpReport; range: DlpRange; names: Names }) {
  const { t, i18n } = useTranslation();
  const totals = outcomeTotals(report);
  const total = OUTCOMES.reduce((sum, outcome) => sum + totals[outcome], 0);
  const series = dailySeries(report);
  const byRule = countRows(report.matches_by_rule, names.rule);
  const byDetector = countRows(report.matches_by_detector, names.detector);
  const senders = countRows(report.decisions_by_sender, names.person);
  const domains = countRows(report.decisions_by_recipient_domain, (key) => key);
  const notInspected = countRows(report.not_inspected_by_reason, (key) => t(`inspectionReason.${key}`, { defaultValue: key }));
  const median = (seconds: number | null) => {
    const { unit, count } = medianParts(seconds);
    if (unit === 'none') return '—';
    if (unit === 'underMinute') return t('dlpReports.underMinute');
    return t(`durations.${unit}`, { count });
  };

  return (
    <div className="space-y-6">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <CardTitle>{t('dlpReports.summary')}</CardTitle>
          <div className="text-right">
            <Link to={auditLink({ actions: ['dlp.decided'], from: range.from, to: range.to })} className="btn-secondary">
              <Download className="mr-2 h-4 w-4" aria-hidden="true" />
              {t('dlpReports.export')}
            </Link>
            <p className="mt-1 max-w-xs text-xs text-gray-600">{t('dlpReports.exportHint')}</p>
          </div>
        </div>
        <dl className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <Stat label={t('dlpReports.decisions')} value={total} />
          {OUTCOMES.map((outcome) => (
            <Stat key={outcome} label={t(`dlpReports.outcome.${outcome}`)} value={totals[outcome]} />
          ))}
          <Stat label={t('dlpReports.policyChanges')} value={report.policy_changes} />
        </dl>
      </Card>

      <ChartCard
        title={t('dlpReports.overTime')}
        summary={overTimeSummary(series, total, t, i18n.language)}
        empty={total === 0}
        chart={<StackedBars series={series} />}
        table={<DailyTable series={series} />}
      />
      <ChartCard
        title={t('dlpReports.byRule')}
        summary={barsSummary(byRule, t)}
        empty={byRule.length === 0}
        chart={<BarList rows={byRule} />}
        table={<CountTable rows={byRule} label={t('dlpReports.byRule')} column={t('dlpReports.rule')} countColumn={t('dlpReports.matches')} />}
      />
      <ChartCard
        title={t('dlpReports.byDetector')}
        summary={barsSummary(byDetector, t)}
        empty={byDetector.length === 0}
        chart={<BarList rows={byDetector} />}
        table={
          <CountTable rows={byDetector} label={t('dlpReports.byDetector')} column={t('dlpReports.detector')} countColumn={t('dlpReports.matches')} />
        }
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <TableCard title={t('dlpReports.senders')} hint={t('dlpReports.topFifty')} empty={senders.length === 0}>
          <CountTable rows={senders} label={t('dlpReports.senders')} column={t('dlpReports.sender')} countColumn={t('dlpReports.decisions')} />
        </TableCard>
        <TableCard title={t('dlpReports.domains')} hint={t('dlpReports.domainsHint')} empty={domains.length === 0}>
          <CountTable rows={domains} label={t('dlpReports.domains')} column={t('dlpReports.domain')} countColumn={t('dlpReports.decisions')} />
        </TableCard>
        <TableCard title={t('dlpReports.approvers')} empty={report.approvals_by_approver.length === 0}>
          <Table label={t('dlpReports.approvers')} caption={t('dlpReports.approversCaption')}>
            <TableHead>
              <tr>
                <TableHeader>{t('dlpReports.approver')}</TableHeader>
                <TableHeader>{t('dlpReports.approved')}</TableHeader>
                <TableHeader>{t('dlpReports.rejected')}</TableHeader>
                <TableHeader>{t('dlpReports.medianTime')}</TableHeader>
              </tr>
            </TableHead>
            <TableBody>
              {report.approvals_by_approver.map((row) => (
                <TableRow key={row.approver_id}>
                  <th scope="row" className="px-4 py-3 text-left text-sm font-medium break-all text-gray-900">
                    {names.person(row.approver_id)}
                  </th>
                  <TableCell>{row.approved}</TableCell>
                  <TableCell>{row.rejected}</TableCell>
                  <TableCell>{median(row.median_seconds_to_decide)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableCard>
        <TableCard title={t('dlpReports.notInspected')} empty={notInspected.length === 0}>
          <CountTable rows={notInspected} label={t('dlpReports.notInspected')} column={t('dlpReports.reason')} countColumn={t('dlpReports.files')} />
        </TableCard>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg bg-gray-50 p-3">
      <dt className="text-xs text-gray-600">{label}</dt>
      <dd className="mt-1 text-xl font-semibold text-gray-900 tabular-nums">{value.toLocaleString()}</dd>
    </div>
  );
}

type T = ReturnType<typeof useTranslation>['t'];

function overTimeSummary(series: readonly DaySeries[], total: number, t: T, language: string): string {
  if (total === 0) return t('dlpReports.noDecisions');
  const peak = series.reduce((best, day) => (day.total > best.total ? day : best), series[0] as DaySeries);
  return t('dlpReports.overTimeSummary', { count: total, days: series.length, date: formatDay(peak.date, language), peak: peak.total });
}

function barsSummary(rows: readonly CountRow[], t: T): string {
  if (rows.length === 0) return t('dlpReports.noMatches');
  const top = rows[0] as CountRow;
  return t('dlpReports.barsSummary', { count: rows.length, name: top.label, top: top.count });
}

/**
 * A chart with its text alternative (the summary, which also names the SVG) and a table view of the same numbers, for
 * axe and for anyone who reads numbers better than bars.
 */
function ChartCard({ title, summary, empty, chart, table }: { title: string; summary: string; empty: boolean; chart: ReactNode; table: ReactNode }) {
  const { t } = useTranslation();
  const id = useId();
  const [asTable, setAsTable] = useState(false);
  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 id={`${id}-title`} className="text-lg font-semibold text-gray-900">
          {title}
        </h2>
        {!empty && (
          <Button size="sm" variant="secondary" aria-pressed={asTable} onClick={() => setAsTable((value) => !value)}>
            {t('dlpReports.tableView')}
          </Button>
        )}
      </div>
      <p id={`${id}-summary`} className="mt-1 text-sm text-gray-600">
        {summary}
      </p>
      {!empty && (
        <div className="mt-4" role="group" aria-labelledby={`${id}-title`} aria-describedby={`${id}-summary`}>
          {asTable ? table : chart}
        </div>
      )}
    </Card>
  );
}

/** Decisions per day, stacked by outcome, as an inline SVG named by its card (no chart library). */
function StackedBars({ series }: { series: readonly DaySeries[] }) {
  const { t, i18n } = useTranslation();
  const max = Math.max(1, ...series.map((day) => day.total));
  const width = series.length * 10;
  const first = series[0];
  const last = series[series.length - 1];
  return (
    <figure>
      <svg viewBox={`0 0 ${width} 100`} preserveAspectRatio="none" className="h-40 w-full" aria-hidden="true" focusable="false">
        <line x1={0} y1={100} x2={width} y2={100} className="stroke-gray-300" strokeWidth={0.5} />
        {series.map((day, index) => {
          let top = 100;
          return (
            <g key={day.date}>
              {OUTCOMES.map((outcome) => {
                const height = (day.counts[outcome] / max) * 100;
                if (height <= 0) return null;
                top -= height;
                return <rect key={outcome} x={index * 10 + 1} y={top} width={8} height={height} className={OUTCOME_FILL[outcome]} />;
              })}
            </g>
          );
        })}
      </svg>
      <div className="mt-1 flex justify-between text-xs text-gray-600">
        <span>{first && formatDay(first.date, i18n.language)}</span>
        <span>{t('dlpReports.peak', { count: max })}</span>
        <span>{last && formatDay(last.date, i18n.language)}</span>
      </div>
      <figcaption>
        <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-700" aria-label={t('dlpReports.legend')}>
          {OUTCOMES.map((outcome) => (
            <li key={outcome} className="flex items-center gap-1.5">
              <span className={cn('inline-block h-3 w-3 rounded-sm', OUTCOME_SWATCH[outcome])} aria-hidden="true" />
              {t(`dlpReports.outcome.${outcome}`)}
            </li>
          ))}
        </ul>
      </figcaption>
    </figure>
  );
}

function DailyTable({ series }: { series: readonly DaySeries[] }) {
  const { t, i18n } = useTranslation();
  return (
    <Table label={t('dlpReports.overTime')} caption={t('dlpReports.overTimeCaption')}>
      <TableHead>
        <tr>
          <TableHeader>{t('dlpReports.day')}</TableHeader>
          {OUTCOMES.map((outcome) => (
            <TableHeader key={outcome}>{t(`dlpReports.outcome.${outcome}`)}</TableHeader>
          ))}
          <TableHeader>{t('dlpReports.total')}</TableHeader>
        </tr>
      </TableHead>
      <TableBody>
        {series.map((day) => (
          <TableRow key={day.date}>
            <th scope="row" className="px-4 py-3 text-left text-sm font-medium whitespace-nowrap text-gray-900">
              {formatDay(day.date, i18n.language)}
            </th>
            {OUTCOMES.map((outcome) => (
              <TableCell key={outcome}>{day.counts[outcome]}</TableCell>
            ))}
            <TableCell>{day.total}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

/** A breakdown as labelled bars: each row's name and count are text; the bar only repeats the count. */
function BarList({ rows }: { rows: readonly CountRow[] }) {
  const max = Math.max(0, ...rows.map((row) => row.count));
  return (
    <ul className="space-y-3">
      {rows.map((row) => (
        <li key={row.key} className="text-sm">
          <div className="flex justify-between gap-3">
            <span className="break-words text-gray-900">{row.label}</span>
            <span className="tabular-nums text-gray-700">{row.count.toLocaleString()}</span>
          </div>
          <div className="mt-1 h-2 w-full rounded-full bg-gray-100" aria-hidden="true">
            <div className="h-2 rounded-full bg-brand-600" style={{ width: `${barPercent(row.count, max)}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

function CountTable({ rows, label, column, countColumn }: { rows: readonly CountRow[]; label: string; column: string; countColumn: string }) {
  return (
    <Table label={label}>
      <TableHead>
        <tr>
          <TableHeader>{column}</TableHeader>
          <TableHeader>{countColumn}</TableHeader>
        </tr>
      </TableHead>
      <TableBody>
        {rows.map((row) => (
          <TableRow key={row.key}>
            <th scope="row" className="px-4 py-3 text-left text-sm font-medium break-all text-gray-900">
              {row.label}
            </th>
            <TableCell>{row.count.toLocaleString()}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function TableCard({ title, hint, empty, children }: { title: string; hint?: string; empty: boolean; children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <Card>
      <h2 className="text-lg font-semibold text-gray-900">{title}</h2>
      {hint && <p className="mt-1 text-sm text-gray-600">{hint}</p>}
      <div className="mt-3">{empty ? <p className="text-sm text-gray-600">{t('dlpReports.none')}</p> : children}</div>
    </Card>
  );
}

// ---- the decisions list ----

/**
 * The decisions over the report's range, newest first (`listDlpDecisions`), filtered by outcome, rule and sender, with
 * "load more". Each row is a transfer's decision (linked) or a received file's, its outcome (and whether it was only
 * recorded, in monitor mode), the rules that matched and the policy version.
 */
function DecisionsList({ range, names }: { range: DlpRange; names: Names }) {
  const { t, i18n } = useTranslation();
  const rules = useDlpRules();
  const emails = useUserEmails(true);
  const [outcomes, setOutcomes] = useState<DlpOutcome[]>([]);
  const [ruleId, setRuleId] = useState('');
  const [senderId, setSenderId] = useState('');
  const decisions = useDlpDecisions({ outcomes, ruleId: ruleId || null, senderId: senderId || null, range });
  const items = decisions.data?.pages.flatMap((page) => page.items) ?? [];
  const senders = useMemo(
    () => [...(emails.data?.entries() ?? [])].sort(([, a], [, b]) => a.localeCompare(b)),
    [emails.data],
  );

  const toggle = (outcome: DlpOutcome) =>
    setOutcomes((previous) => (previous.includes(outcome) ? previous.filter((item) => item !== outcome) : [...previous, outcome]));

  return (
    <Card>
      <CardTitle>{t('dlpReports.decisionsList')}</CardTitle>
      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <fieldset>
          <legend className="text-sm font-medium text-gray-700">{t('dlpReports.outcomeFilter')}</legend>
          <div className="mt-2 space-y-2">
            {OUTCOMES.map((outcome) => (
              <label key={outcome} className="flex items-center gap-2 text-sm text-gray-900">
                <input type="checkbox" className="h-4 w-4 accent-brand-600" checked={outcomes.includes(outcome)} onChange={() => toggle(outcome)} />
                {t(`dlpReports.outcome.${outcome}`)}
              </label>
            ))}
          </div>
        </fieldset>
        <Select
          label={t('dlpReports.rule')}
          value={ruleId}
          onChange={(event) => setRuleId(event.target.value)}
          options={[{ value: '', label: t('dlpReports.anyRule') }, ...(rules.data?.items ?? []).map((rule) => ({ value: rule.id, label: rule.name }))]}
        />
        <Select
          label={t('dlpReports.sender')}
          value={senderId}
          onChange={(event) => setSenderId(event.target.value)}
          options={[{ value: '', label: t('dlpReports.anySender') }, ...senders.map(([id, email]) => ({ value: id, label: email }))]}
        />
      </div>

      <div className="mt-4">
        {decisions.isPending ? (
          <div className="flex justify-center py-6">
            <Spinner />
            <span className="sr-only">{t('common.loading')}</span>
          </div>
        ) : decisions.isError && !decisions.data ? (
          <LoadError error={decisions.error} />
        ) : (
          <>
            <p className="text-sm text-gray-700" aria-live="polite">
              {items.length === 0 ? t('dlpReports.noDecisionsFound') : t('dlpReports.decisionCount', { count: items.length })}
            </p>
            {items.length > 0 && (
              <Table label={t('dlpReports.decisionsList')} caption={t('dlpReports.decisionsCaption')} className="mt-3">
                <TableHead>
                  <tr>
                    <TableHeader>{t('dlpReports.decidedAt')}</TableHeader>
                    <TableHeader>{t('dlpReports.outcomeColumn')}</TableHeader>
                    <TableHeader>{t('dlpReports.subject')}</TableHeader>
                    <TableHeader>{t('dlpReports.rules')}</TableHeader>
                    <TableHeader>{t('dlpReports.policyVersion')}</TableHeader>
                  </tr>
                </TableHead>
                <TableBody>
                  {items.map((decision) => (
                    <DecisionRow key={decision.id} decision={decision} names={names} language={i18n.language} />
                  ))}
                </TableBody>
              </Table>
            )}
            {decisions.hasNextPage && (
              <div className="mt-4 flex justify-center">
                <Button variant="secondary" loading={decisions.isFetchingNextPage} onClick={() => void decisions.fetchNextPage()}>
                  {t('common.loadMore')}
                </Button>
              </div>
            )}
            {decisions.isFetchNextPageError && (
              <p className="mt-2 text-sm text-red-600" role="alert">
                {errorMessage(decisions.error, t)}
              </p>
            )}
          </>
        )}
      </div>
    </Card>
  );
}

function DecisionRow({ decision, names, language }: { decision: DlpDecision; names: Names; language: string }) {
  const { t } = useTranslation();
  const ruleNames = decision.matched_rules.map((rule) => rule.name || names.rule(rule.rule_id));
  return (
    <TableRow>
      <th scope="row" className="px-4 py-3 text-left text-sm font-medium whitespace-nowrap text-gray-900">
        {formatDate(decision.decided_at, language)}
      </th>
      <TableCell className="whitespace-normal">
        <Badge variant={outcomeVariant(decision.outcome)}>{t(`dlpReports.outcome.${decision.outcome}`)}</Badge>
        {!decision.enforced && <span className="mt-0.5 block text-xs text-gray-600">{t('dlpReports.recordedOnly')}</span>}
      </TableCell>
      <TableCell className="whitespace-normal">
        {decision.transfer_id ? (
          <Link to={`/transfers/${decision.transfer_id}`} className="font-semibold text-brand-700 underline hover:text-brand-800">
            {t('dlpReports.transfer', { id: shortId(decision.transfer_id) })}
          </Link>
        ) : (
          t('dlpReports.receivedFile', { id: shortId(decision.file_id ?? decision.id) })
        )}
      </TableCell>
      <TableCell className="whitespace-normal">{ruleNames.length > 0 ? ruleNames.join(t('common.listSeparator')) : '—'}</TableCell>
      <TableCell>{decision.policy_version}</TableCell>
    </TableRow>
  );
}
